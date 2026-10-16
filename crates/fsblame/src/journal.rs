//! The journal: report lines in size-bounded NDJSON files, written by `fsblame record` and
//! read by `fsblame blame`.
//!
//! A journal is a directory of files named `fsblame-<UTC start time>.ndjson`, such as
//! `fsblame-20261016T140211.123456Z.ndjson`, so their names sort in the order they were
//! started. Each line is one [`Line`] exactly as `--json` writes it. The [`Writer`] starts a
//! new file before the current one would grow beyond its size limit and then deletes the
//! oldest files beyond its count. It writes each line with one `write(2)` and keeps nothing
//! buffered, so every line written survives the recorder being killed; a crash or a full
//! disk can at most leave the last line torn, which readers skip.
//!
//! The directory is created with mode 0700 and the files with 0600: lines hold the command
//! lines and working directories of other users' processes.

use std::{
    ffi::CString,
    fs::{self, DirBuilder, File, OpenOptions},
    io::{self, Write as _},
    os::unix::{
        ffi::OsStrExt as _,
        fs::{DirBuilderExt as _, OpenOptionsExt as _},
    },
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::anyhow;

use crate::{
    cli::RecordArgs,
    clock::Rfc3339,
    fail::Failure,
    report::{Line, Sink},
    watch::{self, WatchOptions},
};

/// File name prefix of journal files.
const PREFIX: &str = "fsblame-";
/// File name suffix of journal files.
const SUFFIX: &str = ".ndjson";
/// Most names tried for a new file when the ones of its start time are taken.
const NAME_TRIES: u32 = 1000;
/// Resolution of the start times in file names.
const NAME_STEP_NS: i128 = 1000;

/// Whether `name` is the name of a journal file.
fn is_journal_name(name: &[u8]) -> bool {
    name.len() > PREFIX.len() + SUFFIX.len()
        && name.starts_with(PREFIX.as_bytes())
        && name.ends_with(SUFFIX.as_bytes())
}

/// The journal file name of a file started `unix_ns` nanoseconds after the Unix epoch: the
/// RFC 3339 time without its `-` and `:` separators.
fn file_name(unix_ns: i128) -> String {
    let mut name = String::with_capacity(PREFIX.len() + 23 + SUFFIX.len());
    name.push_str(PREFIX);
    name.extend(
        Rfc3339(unix_ns)
            .to_string()
            .chars()
            .filter(|&c| c != '-' && c != ':'),
    );
    name.push_str(SUFFIX);
    name
}

/// The journal files in `dir`, oldest first.
pub fn files(dir: &Path) -> io::Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if is_journal_name(entry.file_name().as_bytes()) && entry.file_type()?.is_file() {
            files.push(entry.path());
        }
    }
    files.sort_unstable();
    Ok(files)
}

/// Nanoseconds since the Unix epoch, now.
pub fn now_unix_ns() -> i128 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(after) => i128::try_from(after.as_nanos()).unwrap_or(i128::MAX),
        Err(before) => -i128::try_from(before.duration().as_nanos()).unwrap_or(i128::MAX),
    }
}

/// `e` with `path` in its message, keeping its kind.
fn at(path: &Path, e: &io::Error) -> io::Error {
    io::Error::new(e.kind(), format!("{}: {e}", path.display()))
}

/// Appends report lines to the journal in a directory: a [`Sink`].
#[derive(Debug)]
pub struct Writer {
    /// The journal directory.
    dir: PathBuf,
    /// Size a file may reach; a single longer line still gets a file of its own.
    max_size: u64,
    /// Files kept, the current one included.
    keep: usize,
    /// The current file and its path, once the first line was written.
    file: Option<(File, PathBuf)>,
    /// Bytes in the current file.
    size: u64,
    /// The start time in the name of the current file.
    started_ns: i128,
    /// The line being written, reused.
    buf: Vec<u8>,
}

impl Writer {
    /// A journal in `dir` of files up to `max_size` bytes, keeping the newest `keep` (at least
    /// one). Creates `dir` with mode 0700 if missing and checks that it is writable; the first
    /// file is created with the first line, so a run that fails to start leaves no file and
    /// deletes none.
    pub fn open(dir: &Path, max_size: u64, keep: usize) -> io::Result<Self> {
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|e| at(dir, &e))?;
        let c_dir = CString::new(dir.as_os_str().as_bytes())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        // SAFETY: `c_dir` is a NUL-terminated path; faccessat only reads it.
        let rc = unsafe {
            libc::faccessat(
                libc::AT_FDCWD,
                c_dir.as_ptr(),
                libc::W_OK | libc::X_OK,
                libc::AT_EACCESS,
            )
        };
        if rc != 0 {
            return Err(at(dir, &io::Error::last_os_error()));
        }
        Ok(Self {
            dir: dir.to_owned(),
            max_size,
            keep: keep.max(1),
            file: None,
            size: 0,
            started_ns: i128::MIN,
            buf: Vec::new(),
        })
    }

    /// Starts a new file, named after now but always after the previous one, then deletes
    /// the oldest files beyond `keep`.
    fn start(&mut self) -> io::Result<()> {
        let mut unix_ns = now_unix_ns().max(self.started_ns.saturating_add(NAME_STEP_NS));
        let mut tries = 0;
        let (file, path) = loop {
            let path = self.dir.join(file_name(unix_ns));
            match OpenOptions::new()
                .append(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
            {
                Ok(file) => break (file, path),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists && tries < NAME_TRIES => {
                    tries += 1;
                    unix_ns += NAME_STEP_NS;
                }
                Err(e) => return Err(at(&path, &e)),
            }
        };
        self.started_ns = unix_ns;
        self.size = 0;
        let current = self.file.insert((file, path));
        prune(&self.dir, self.keep, &current.1)
    }
}

/// Deletes the oldest journal files in `dir` beyond the newest `keep` (at least one), never
/// `current`.
fn prune(dir: &Path, keep: usize, current: &Path) -> io::Result<()> {
    let mut old = files(dir).map_err(|e| at(dir, &e))?;
    old.retain(|path| path != current);
    let excess = (old.len() + 1).saturating_sub(keep);
    for path in &old[..excess] {
        match fs::remove_file(path) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(at(path, &e)),
            _ => {}
        }
    }
    Ok(())
}

impl Sink for Writer {
    fn line(&mut self, line: &Line<'_>) -> io::Result<()> {
        self.buf.clear();
        serde_json::to_writer(&mut self.buf, line)?;
        self.buf.push(b'\n');
        let len = self.buf.len() as u64;
        if self.file.is_none() || (self.size > 0 && self.size.saturating_add(len) > self.max_size) {
            self.start()?;
        }
        let (file, path) = self.file.as_mut().expect("started above");
        file.write_all(&self.buf).map_err(|e| at(path, &e))?;
        self.size += len;
        Ok(())
    }

    /// Nothing to do: each line is written whole as it comes.
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// `fsblame record`: watches like `fsblame watch` and appends every line `watch --json`
/// would print to the journal.
pub fn command(args: &RecordArgs) -> Result<(), Failure> {
    let opts = WatchOptions {
        duration: args.stop.duration,
        ready_fd: args.stop.ready_fd,
        ..WatchOptions::new(&args.paths, &args.trace)
    };
    let keep = usize::try_from(args.keep).unwrap_or(usize::MAX);
    let mut writer = Writer::open(&args.journal, args.max_size, keep).map_err(|e| {
        if e.kind() == io::ErrorKind::PermissionDenied {
            Failure::Privileges(anyhow!(
                "cannot record to the journal: {e}; run fsblame record as root (sudo), or \
                 pass a --journal DIR it may write to"
            ))
        } else {
            Failure::Runtime(anyhow!("cannot record to the journal: {e}"))
        }
    })?;
    if !args.trace.quiet {
        eprintln!("fsblame: recording to {}", args.journal.display());
    }
    watch::run(&opts, &mut writer)?;
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;
    use crate::report::{LossReason, LostReport, Timestamp, Version};

    /// A fresh directory for one test, removed on drop. Tests keep its files tiny: the
    /// temporary directory may be a tmpfs with a tight quota.
    #[derive(Debug)]
    pub(crate) struct TestDir(pub(crate) PathBuf);

    impl TestDir {
        pub(crate) fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("fsblame-{name}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            Self(dir)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn lost(count: u64) -> Line<'static> {
        Line::Lost(LostReport {
            v: Version,
            ts: Timestamp::from_unix_ns(1_791_986_531_000_000_000),
            reason: LossReason::RingFull,
            count,
        })
    }

    fn lines(path: &Path) -> Vec<Line<'static>> {
        fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|line| Line::parse(line).unwrap())
            .collect()
    }

    #[test]
    fn names_sort_by_start_time_and_are_recognised() {
        let name = file_name(1_791_986_531_123_456_789);
        assert_eq!(name, "fsblame-20261014T140211.123456Z.ndjson");
        assert!(is_journal_name(name.as_bytes()));
        assert!(file_name(1_791_986_531_000_000_000) < file_name(1_791_986_531_000_001_000));
        assert!(file_name(1_791_986_531_999_999_000) < file_name(1_791_986_532_000_000_000));
        for other in ["fsblame-.ndjson", "fsblame-x.json", "other-1.ndjson"] {
            assert!(!is_journal_name(other.as_bytes()), "{other}");
        }
    }

    #[test]
    fn rotates_before_exceeding_the_size_and_keeps_the_newest() {
        let dir = TestDir::new("journal-rotate");
        let one = serde_json::to_vec(&lost(1)).unwrap().len() as u64 + 1;
        let mut writer = Writer::open(&dir.0, 2 * one, 2).unwrap();
        assert!(files(&dir.0).unwrap().is_empty(), "no file before a line");
        for count in 1..=7 {
            writer.line(&lost(count)).unwrap();
        }
        // Two lines per file: 1 2 | 3 4 | 5 6 | 7, of which the newest two files remain.
        let kept = files(&dir.0).unwrap();
        assert_eq!(kept.len(), 2);
        assert_eq!(lines(&kept[0]), [lost(5), lost(6)]);
        assert_eq!(lines(&kept[1]), [lost(7)]);
        for path in &kept {
            assert!(fs::metadata(path).unwrap().len() <= 2 * one);
        }
        let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir.0), 0o700);
        assert_eq!(mode(&kept[0]), 0o600);
    }

    #[test]
    fn a_line_longer_than_the_limit_gets_a_file_of_its_own() {
        let dir = TestDir::new("journal-long");
        let mut writer = Writer::open(&dir.0, 10, 8).unwrap();
        writer.line(&lost(1)).unwrap();
        writer.line(&lost(2)).unwrap();
        let kept = files(&dir.0).unwrap();
        assert_eq!(kept.len(), 2);
        assert_eq!(lines(&kept[1]), [lost(2)]);
    }

    #[test]
    fn keeps_counting_files_of_earlier_runs_and_ignores_other_files() {
        let dir = TestDir::new("journal-earlier");
        fs::create_dir_all(&dir.0).unwrap();
        for old in [file_name(1000), file_name(2000), "notes.txt".to_owned()] {
            fs::write(dir.0.join(old), "").unwrap();
        }
        let mut writer = Writer::open(&dir.0, 1 << 20, 2).unwrap();
        writer.line(&lost(1)).unwrap();
        let kept = files(&dir.0).unwrap();
        assert_eq!(kept.len(), 2);
        assert_eq!(kept[0], dir.0.join(file_name(2000)));
        assert_eq!(lines(&kept[1]), [lost(1)]);
        assert!(dir.0.join("notes.txt").exists());
    }
}
