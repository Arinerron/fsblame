//! Decoding of ring buffer records (layouts in `fsblame-abi`).

use std::borrow::Cow;

use fsblame_abi::{self as abi, ExecRec, ExitRec, ForkRec, FsRec, RecHeader};

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
}

impl<'a> Exec<'a> {
    /// The whole `KEY=VALUE\0` entries of the captured environment. When the kernel kept only
    /// its head and tail ([`abi::F_ENV_TRUNC`]), the entry cut at each end of the gap is dropped,
    /// so no fragment can pose as a variable.
    pub fn env_entries(&self) -> Cow<'a, [u8]> {
        if self.rec.hdr.flags & abi::F_ENV_TRUNC == 0 {
            return Cow::Borrowed(self.env);
        }
        let half = usize::try_from(abi::ENV_CAP / 2).expect("small");
        let (head, tail) = self.env.split_at(half.min(self.env.len()));
        let head = head.iter().rposition(|&b| b == 0).map_or(&[][..], |end| &head[..=end]);
        let tail = tail.iter().position(|&b| b == 0).map_or(&[][..], |start| &tail[start + 1..]);
        Cow::Owned([head, tail].concat())
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
            Ok(Record::Exec(Exec {
                rec,
                filename,
                env,
                argv,
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

    fn exec_bytes(flags: u32, filename: &[u8], env: &[u8], argv: &[u8]) -> Vec<u8> {
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
            _pad: 0,
        };
        let mut bytes = wire::as_bytes(&rec).to_vec();
        for part in [filename, env, argv] {
            bytes.extend_from_slice(part);
        }
        bytes
    }

    #[test]
    fn exec_payload_splits_at_declared_lengths() {
        let bytes = exec_bytes(0, b"/bin/sh\0", b"TMUX_PANE=%1\0", b"sh\0-c\0x\0");
        let Ok(Record::Exec(exec)) = decode(&bytes) else {
            panic!("not an exec");
        };
        assert_eq!(exec.filename, b"/bin/sh");
        assert_eq!(&*exec.env_entries(), b"TMUX_PANE=%1\0");
        assert_eq!(exec.argv, b"sh\0-c\0x\0");
        assert_eq!(c_str(&exec.rec.comm), "sh");
    }

    #[test]
    fn truncated_env_drops_the_entries_cut_at_the_gap() {
        let half = usize::try_from(abi::ENV_CAP / 2).unwrap();
        // Head: a whole entry, filler, then the start of an entry cut by the gap.
        let mut head = b"A=1\0".to_vec();
        head.resize(half - b"\0npm_package_name=cu".len(), b'x');
        head.extend_from_slice(b"\0npm_package_name=cu");
        // Tail: the end of an entry whose key was cut, then a whole entry.
        let tail = b"lifecycle_event=bogus\0npm_lifecycle_event=postinstall\0";
        let env = [&head[..], tail].concat();
        let bytes = exec_bytes(abi::F_ENV_TRUNC, b"/bin/sh\0", &env, b"sh\0");
        let Ok(Record::Exec(exec)) = decode(&bytes) else {
            panic!("not an exec");
        };
        let entries = exec.env_entries();
        let kept: Vec<&[u8]> = entries.split(|&b| b == 0).filter(|e| e.contains(&b'=')).collect();
        assert_eq!(kept, [&b"A=1"[..], b"npm_lifecycle_event=postinstall"]);
    }

    #[test]
    fn short_payload_is_malformed() {
        let mut bytes = exec_bytes(0, b"/bin/sh\0", b"", b"sh\0");
        bytes.pop();
        assert_eq!(
            decode(&bytes).unwrap_err(),
            Malformed {
                kind: Some(abi::REC_EXEC),
                len: bytes.len()
            }
        );
        assert_eq!(decode(&[1, 0]).unwrap_err(), Malformed { kind: None, len: 2 });
    }
}
