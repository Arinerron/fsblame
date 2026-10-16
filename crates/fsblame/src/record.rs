//! Decoding of ring buffer records (layouts in `fsblame-abi`).

use std::iter;

use fsblame_abi::{self as abi, ExecRec, ExitRec, ForkRec, FsRec, RecHeader};
use procctx::ENV_KEYS;

/// A decoded record. Payload slices borrow from the ring buffer item.
#[derive(Clone, Copy, Debug)]
pub enum Record<'a> {
    /// A new process.
    Fork(ForkRec),
    /// A successful exec.
    Exec(Exec<'a>),
    /// A process exit.
    Exit(ExitRec),
    /// A file operation in scope.
    Fs(Fs<'a>),
}

/// [`ExecRec`] and its payload.
#[derive(Clone, Copy, Debug)]
pub struct Exec<'a> {
    /// Fixed part.
    pub rec: ExecRec,
    /// execve filename, without the NUL.
    pub filename: &'a [u8],
    /// Raw environment block; see [`Exec::env_entries`].
    pub env: &'a [u8],
    /// Raw argv (NUL-separated).
    pub argv: &'a [u8],
    /// cwd names, leaf first, when the kernel captured the cwd ([`abi::F_CWD`]); see
    /// [`Exec::cwd`].
    pub cwd_names: Option<&'a [u8]>,
}

impl Exec<'_> {
    /// The whole `KEY=VALUE\0` entries of the captured environment that set a variable
    /// procctx reads ([`ENV_KEYS`]), in order, built in `buf`: everything
    /// [`parse_env_facts`](procctx::parse_env_facts) looks at, found without scanning the
    /// rest of the block byte by byte. When the kernel kept only its head and tail
    /// ([`abi::F_ENV_TRUNC`]), the entry cut at each end of the gap is dropped, so no fragment
    /// can pose as a variable.
    pub fn env_entries<'b>(&self, buf: &'b mut Vec<u8>) -> &'b [u8] {
        /// Bytes the kernel keeps from each end of a truncated environment.
        const HALF: usize = abi::ENV_CAP as usize / 2;
        buf.clear();
        if self.rec.hdr.flags & abi::F_ENV_TRUNC == 0 {
            keep_read(self.env, buf);
        } else {
            let (head, tail) = self.env.split_at(HALF.min(self.env.len()));
            if let Some(end) = memchr::memrchr(0, head) {
                keep_read(&head[..end], buf);
            }
            if let Some(start) = memchr::memchr(0, tail) {
                keep_read(&tail[start + 1..], buf);
            }
        }
        buf
    }

    /// The cwd at exec as an absolute path, built in `buf`; `None` when the kernel did not
    /// capture it. A cwd whose walk stopped short of the root ([`abi::F_CWD_TRUNC`]) lost its
    /// upper components, which show as `/…`, as in truncated file paths.
    pub fn cwd<'b>(&self, buf: &'b mut Vec<u8>) -> Option<&'b [u8]> {
        let names = self.cwd_names?;
        buf.clear();
        if self.rec.hdr.flags & abi::F_CWD_TRUNC != 0 {
            buf.extend_from_slice("/…".as_bytes());
        }
        for name in names.split(|&b| b == 0).rev().filter(|n| !n.is_empty()) {
            buf.push(b'/');
            buf.extend_from_slice(name);
        }
        if buf.is_empty() {
            buf.push(b'/');
        }
        Some(buf.as_slice())
    }
}

/// [`FsRec`] and its payload.
#[derive(Clone, Copy, Debug)]
pub struct Fs<'a> {
    /// Fixed part.
    pub rec: FsRec,
    /// Primary path names.
    pub path: &'a [u8],
    /// Secondary path names or raw string.
    pub path2: &'a [u8],
}

/// A record that does not match the ABI: a stale BPF object or a kernel-side bug.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Malformed {
    /// Record kind, if the header was readable.
    pub kind: Option<u16>,
    /// Record size.
    pub len: usize,
}

impl std::fmt::Display for Malformed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.kind {
            Some(kind) => write!(f, "malformed record of kind {kind} ({} bytes)", self.len),
            None => write!(f, "malformed record ({} bytes)", self.len),
        }
    }
}

/// Splits `len` bytes off the front of `rest`.
fn take<'a>(rest: &mut &'a [u8], len: u16) -> Option<&'a [u8]> {
    let (head, tail) = rest.split_at_checked(usize::from(len))?;
    *rest = tail;
    Some(head)
}

/// Whether a byte starts a variable of [`ENV_KEYS`].
const KEY_STARTS: [bool; 256] = {
    let mut starts = [false; 256];
    let mut i = 0;
    while i < ENV_KEYS.len() {
        starts[ENV_KEYS[i].as_bytes()[0] as usize] = true;
        i += 1;
    }
    starts
};

/// Appends each entry of the NUL-separated `KEY=VALUE` `block` that sets a variable in
/// [`ENV_KEYS`] to `buf`, with its NUL. The entry ends are found with SIMD (`memchr`), and
/// most entries are passed over on their first byte.
fn keep_read(block: &[u8], buf: &mut Vec<u8>) {
    let mut start = 0;
    for end in memchr::memchr_iter(0, block).chain(iter::once(block.len())) {
        let entry = &block[start..end];
        start = end + 1;
        if entry.first().is_some_and(|&b| KEY_STARTS[usize::from(b)])
            && ENV_KEYS
                .iter()
                .any(|key| entry.get(key.len()) == Some(&b'=') && entry.starts_with(key.as_bytes()))
        {
            buf.extend_from_slice(entry);
            buf.push(0);
        }
    }
}

/// `bytes` up to the first NUL.
pub fn trim_nul(bytes: &[u8]) -> &[u8] {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    &bytes[..end]
}

/// Decodes one ring buffer item.
pub fn decode(bytes: &[u8]) -> Result<Record<'_>, Malformed> {
    let len = bytes.len();
    let hdr: RecHeader = wire::read(bytes).ok_or(Malformed { kind: None, len })?;
    let bad = Malformed {
        kind: Some(hdr.kind),
        len,
    };
    match hdr.kind {
        abi::REC_FORK => wire::read(bytes).map(Record::Fork).ok_or(bad),
        abi::REC_EXIT => wire::read(bytes).map(Record::Exit).ok_or(bad),
        abi::REC_EXEC => {
            let rec: ExecRec = wire::read(bytes).ok_or(bad)?;
            let mut rest = &bytes[size_of::<ExecRec>()..];
            let filename = trim_nul(take(&mut rest, rec.filename_len).ok_or(bad)?);
            let env = take(&mut rest, rec.env_len).ok_or(bad)?;
            let argv = take(&mut rest, rec.argv_len).ok_or(bad)?;
            let cwd = take(&mut rest, rec.cwd_len).ok_or(bad)?;
            Ok(Record::Exec(Exec {
                rec,
                filename,
                env,
                argv,
                cwd_names: (rec.hdr.flags & abi::F_CWD != 0).then_some(cwd),
            }))
        }
        abi::REC_FS => {
            let rec: FsRec = wire::read(bytes).ok_or(bad)?;
            let mut rest = &bytes[size_of::<FsRec>()..];
            let path = take(&mut rest, rec.path_len).ok_or(bad)?;
            let path2 = take(&mut rest, rec.path2_len).ok_or(bad)?;
            Ok(Record::Fs(Fs { rec, path, path2 }))
        }
        _ => Err(bad),
    }
}

/// A NUL-padded C string field as text.
pub fn c_str(bytes: &[u8]) -> String {
    String::from_utf8_lossy(trim_nul(bytes)).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exec_bytes(flags: u32, filename: &[u8], env: &[u8], argv: &[u8], cwd: &[u8]) -> Vec<u8> {
        let len = |b: &[u8]| u16::try_from(b.len()).unwrap();
        let rec = ExecRec {
            hdr: RecHeader {
                kind: abi::REC_EXEC,
                op: 0,
                flags,
                ts_ns: 5,
            },
            tgid: 10,
            ppid: 1,
            start_ns: 7,
            cgroup_id: 0,
            uid: 1000,
            gid: 1000,
            comm: *b"sh\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
            filename_len: len(filename),
            env_len: len(env),
            argv_len: len(argv),
            cwd_len: len(cwd),
        };
        let mut bytes = wire::as_bytes(&rec).to_vec();
        for part in [filename, env, argv, cwd] {
            bytes.extend_from_slice(part);
        }
        bytes
    }

    fn cwd_of(flags: u32, names: &[u8]) -> Option<String> {
        let bytes = exec_bytes(flags, b"/bin/mv\0", b"", b"mv\0", names);
        let Ok(Record::Exec(exec)) = decode(&bytes) else {
            panic!("not an exec");
        };
        let mut buf = Vec::new();
        exec.cwd(&mut buf)
            .map(|cwd| String::from_utf8(cwd.to_vec()).unwrap())
    }

    #[test]
    fn exec_payload_splits_at_declared_lengths() {
        let bytes = exec_bytes(0, b"/bin/sh\0", b"A=1\0TMUX_PANE=%1\0", b"sh\0-c\0x\0", b"");
        let Ok(Record::Exec(exec)) = decode(&bytes) else {
            panic!("not an exec");
        };
        assert_eq!(exec.filename, b"/bin/sh");
        assert_eq!(exec.env_entries(&mut Vec::new()), b"TMUX_PANE=%1\0");
        assert_eq!(exec.argv, b"sh\0-c\0x\0");
        assert_eq!(c_str(&exec.rec.comm), "sh");
    }

    #[test]
    fn kept_entries_give_the_facts_of_the_whole_environment() {
        let env = b"PATH=/bin\0npm_package_name=first\0MAKELEVEL=\0TMUX_PANE\0OUT_DIR=/o\0\
                    npm_package_name=second\0npm_lifecycle_event=install\0TMUX_PANE=%3\0\
                    LS_COLORS=npm_package_name=x\0CARGO_PKG_NAME=c";
        let bytes = exec_bytes(0, b"/bin/sh\0", env, b"sh\0", b"");
        let Ok(Record::Exec(exec)) = decode(&bytes) else {
            panic!("not an exec");
        };
        let facts = procctx::parse_env_facts(env);
        assert!(!facts.is_empty());
        assert_eq!(
            procctx::parse_env_facts(exec.env_entries(&mut Vec::new())),
            facts
        );
    }

    #[test]
    fn truncated_env_drops_the_entries_cut_at_the_gap() {
        let half = usize::try_from(abi::ENV_CAP / 2).unwrap();
        // Head: a whole entry, filler, then the start of an entry cut by the gap.
        let mut head = b"TMUX_PANE=%1\0".to_vec();
        head.resize(half - b"\0npm_package_name=cu".len(), b'x');
        head.extend_from_slice(b"\0npm_package_name=cu");
        // Tail: the end of an entry whose key was cut, then a whole entry.
        let tail = b"lifecycle_event=bogus\0npm_lifecycle_event=postinstall\0";
        let env = [&head[..], tail].concat();
        let bytes = exec_bytes(abi::F_ENV_TRUNC, b"/bin/sh\0", &env, b"sh\0", b"");
        let Ok(Record::Exec(exec)) = decode(&bytes) else {
            panic!("not an exec");
        };
        assert_eq!(
            exec.env_entries(&mut Vec::new()),
            b"TMUX_PANE=%1\0npm_lifecycle_event=postinstall\0"
        );
    }

    #[test]
    fn kernel_cwd_is_rebuilt_root_first() {
        assert_eq!(
            cwd_of(abi::F_CWD, b"proj\0u\0home\0").as_deref(),
            Some("/home/u/proj")
        );
        // No names: the walk started at the namespace root.
        assert_eq!(cwd_of(abi::F_CWD, b"").as_deref(), Some("/"));
        assert_eq!(
            cwd_of(abi::F_CWD | abi::F_CWD_TRUNC, b"b\0a\0").as_deref(),
            Some("/…/a/b")
        );
        // Without F_CWD the payload is ignored and procctx falls back to /proc.
        assert_eq!(cwd_of(0, b"stale\0"), None);
    }

    #[test]
    fn short_payload_is_malformed() {
        let mut bytes = exec_bytes(0, b"/bin/sh\0", b"", b"sh\0", b"");
        bytes.pop();
        assert_eq!(
            decode(&bytes).unwrap_err(),
            Malformed {
                kind: Some(abi::REC_EXEC),
                len: bytes.len()
            }
        );
        assert_eq!(
            decode(&[1, 0]).unwrap_err(),
            Malformed { kind: None, len: 2 }
        );
    }
}
