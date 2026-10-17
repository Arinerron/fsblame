//! `fsblame run`: runs a command and reports every change made by it and by the processes it
//! starts, on every filesystem or below the given paths.
//!
//! The tracer is attached and armed before the command exists. The command is forked and
//! parks on a pipe until its pid is in the kernel's tracked set, so tracking covers it from
//! its first instruction; released, it drops to the invoking user (under sudo), restores the
//! signal handling fsblame changed and execs. A second, close-on-exec pipe reports a failed
//! exec back. Everything the child does between fork and exec is async-signal-safe: all
//! allocation happens before the fork.

use std::{
    env,
    ffi::{CString, OsStr, OsString},
    fs::{File, OpenOptions},
    io::{self, BufWriter, IsTerminal, Write},
    os::{
        fd::{AsFd as _, AsRawFd as _, BorrowedFd, FromRawFd as _, OwnedFd, RawFd},
        unix::{
            ffi::{OsStrExt as _, OsStringExt as _},
            fs::{MetadataExt as _, OpenOptionsExt as _, fchown},
        },
    },
    path::{Path, PathBuf},
    process::ExitCode,
    ptr,
};

use anyhow::{Context as _, anyhow};

use crate::{
    cli::RunArgs,
    fail::Failure,
    render::{self, Human, Json},
    tracer::Tracer,
    watch::{self, Follow, Outcome, WatchOptions},
};

/// `fsblame run`: the report goes to stderr (the command owns stdout) or `--output`; the
/// exit code is the command's (128 + N when signal N killed it).
pub fn command(args: &RunArgs) -> Result<ExitCode, Failure> {
    let opts = WatchOptions::new(&args.paths, &args.trace);
    let mut cmd = Command::new(&args.command)?;
    let outcome = match &args.output {
        Some(path) => {
            let file = open_output(path, cmd.creds.as_ref())
                .with_context(|| format!("cannot write --output {}", path.display()))
                .map_err(Failure::Usage)?;
            report(file, args, &opts, &mut cmd)
        }
        None => report(io::stderr(), args, &opts, &mut cmd),
    };
    // A run that ended early (closed output, error) leaves the command running: its exit is
    // still waited for, so that fsblame never returns before it.
    let status = cmd.child.as_ref().map(Child::wait);
    outcome?;
    let code = status
        .ok_or_else(|| anyhow!("the command did not start"))?
        .context("waiting for the command")?;
    Ok(ExitCode::from(code))
}

/// Opens the `--output` file. The report holds the argv, cwd and environment-derived facts
/// of the command's processes, so a new file gets mode 0600 and, under sudo, the invoking
/// user (`owner`) as its owner. An existing file is truncated and keeps its mode; it must be
/// a regular file of the invoking user (fsblame's effective user when not under sudo).
/// Symbolic links, FIFOs, sockets and devices are refused, so that a path planted by another
/// user cannot redirect, receive or stall fsblame's privileged write.
///
/// Without sudo, an existing file is reopened with `O_CREAT` too, so that
/// `fs.protected_regular` and `fs.protected_fifos` refuse another user's file in a sticky
/// world-writable directory such as /tmp before fsblame opens it. Under sudo they would
/// also refuse the invoking user's own file there, since fsblame opens it as root, so the
/// ownership and type checks alone guard that case. Opens use `O_NONBLOCK`, so that a FIFO
/// is refused without waiting for a reader; the flag does nothing to a regular file.
fn open_output(path: &Path, owner: Option<&Credentials>) -> io::Result<File> {
    let open = |create: bool, exclusive: bool| {
        OpenOptions::new()
            .write(true)
            .create(create)
            .create_new(exclusive)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
    };
    match open(true, true) {
        Ok(file) => {
            if let Some(owner) = owner {
                fchown(&file, Some(owner.uid), Some(owner.gid))?;
            }
            Ok(file)
        }
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            let file = open(owner.is_none(), false).map_err(|e| match e.raw_os_error() {
                Some(libc::ELOOP) => io::Error::other("it is a symbolic link"),
                // What a write-only, non-blocking open of a FIFO without a reader, or of a
                // socket, fails with.
                Some(libc::ENXIO) => io::Error::other("it is not a regular file"),
                _ => e,
            })?;
            let meta = file.metadata()?;
            if !meta.is_file() {
                return Err(io::Error::other("it is not a regular file"));
            }
            // SAFETY: geteuid cannot fail.
            let uid = owner.map_or_else(|| unsafe { libc::geteuid() }, |owner| owner.uid);
            if meta.uid() != uid {
                return Err(io::Error::other(format!(
                    "it belongs to uid {}, not to the invoking user (uid {uid})",
                    meta.uid()
                )));
            }
            file.set_len(0)?;
            Ok(file)
        }
        Err(e) => Err(e),
    }
}

/// Follows `cmd`, writing the report to `out`.
fn report<W: Write + IsTerminal>(
    out: W,
    args: &RunArgs,
    opts: &WatchOptions,
    cmd: &mut Command,
) -> Result<Outcome, Failure> {
    if args.view.json {
        return watch::follow(opts, cmd, &mut Json::new(BufWriter::new(out)));
    }
    let color = watch::use_color(args.view.color, &out);
    let mut sink = Human::new(
        BufWriter::new(out),
        watch::home_dir(),
        args.view.depth,
        color,
    );
    watch::follow(opts, cmd, &mut sink)
}

/// The command to run, and once started, its process.
#[derive(Debug)]
struct Command {
    argv: Vec<CString>,
    env: Vec<CString>,
    /// Who it runs as, when not as fsblame.
    creds: Option<Credentials>,
    /// The command line for messages, shortened as in the report.
    shown: String,
    child: Option<Child>,
}

impl Command {
    /// Prepares `argv` to run as the user who invoked sudo, if fsblame runs as root under
    /// sudo, else as fsblame.
    fn new(argv: &[OsString]) -> Result<Self, Failure> {
        let caller = sudo_caller()?;
        let argv = argv
            .iter()
            .map(|arg| {
                CString::new(arg.as_bytes())
                    .map_err(|_| Failure::Usage(anyhow!("{} contains a NUL byte", arg.display())))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let lossy: Vec<_> = argv.iter().map(|arg| arg.to_string_lossy()).collect();
        let shown = render::command_line(&lossy, "", watch::home_dir().as_deref());
        Ok(Self {
            argv,
            env: environment(caller.as_ref()),
            creds: caller.map(|caller| caller.creds),
            shown,
            child: None,
        })
    }
}

impl Follow for Command {
    fn start(&mut self, tracer: &mut Tracer) -> Result<(), Failure> {
        let child = Child::spawn(&self.argv, &self.env, self.creds.as_ref())
            .context("starting the command")?;
        let tracked = tracer.track(child.pid());
        // Kept before anything can fail, so that the command is waited for.
        let child = self.child.insert(child);
        if let Err(e) = tracked {
            // Still parked: it never runs the command.
            child.signal(libc::SIGKILL);
            return Err(Failure::Runtime(
                anyhow::Error::new(e).context("tracking the command"),
            ));
        }
        match child.release() {
            Ok(()) => Ok(()),
            // Like a shell: the exit status (127 or 126) reports it, and the run ends with
            // the child.
            Err(StartError::Exec(e)) => {
                eprintln!(
                    "fsblame: cannot run {}: {e}",
                    self.argv[0].to_string_lossy()
                );
                Ok(())
            }
            Err(StartError::Setup(e)) => Err(Failure::Runtime(
                anyhow::Error::new(e).context("switching to the invoking user"),
            )),
        }
    }

    fn end(&self) -> Option<BorrowedFd<'_>> {
        self.child.as_ref().map(|child| child.pidfd.as_fd())
    }

    /// SIGINT is ignored: the terminal sends it to the command too, which decides whether
    /// it ends. SIGTERM and SIGHUP are passed on. The run ends when the command does.
    fn signal(&mut self, signal: i32) -> bool {
        if signal != libc::SIGINT
            && let Some(child) = &self.child
        {
            child.signal(signal);
        }
        false
    }

    fn banner(&self) -> String {
        format!(
            " by `{}` and the processes it starts, until it exits",
            self.shown
        )
    }
}

/// Credentials the child switches to before exec.
#[derive(Debug)]
struct Credentials {
    uid: libc::uid_t,
    gid: libc::gid_t,
    /// Supplementary groups.
    groups: Vec<libc::gid_t>,
}

/// The user who ran `sudo fsblame`.
#[derive(Debug)]
struct Caller {
    creds: Credentials,
    /// Login name (`SUDO_USER`).
    name: OsString,
    home: Option<PathBuf>,
    shell: Option<OsString>,
}

/// The user who invoked sudo, when fsblame runs as root under sudo (`SUDO_UID`, `SUDO_GID`
/// and `SUDO_USER` set) for someone other than root.
fn sudo_caller() -> Result<Option<Caller>, Failure> {
    // SAFETY: geteuid cannot fail.
    if unsafe { libc::geteuid() } != 0 {
        return Ok(None);
    }
    let (Some(uid), Some(gid), Some(name)) = (
        env::var_os("SUDO_UID"),
        env::var_os("SUDO_GID"),
        env::var_os("SUDO_USER"),
    ) else {
        return Ok(None);
    };
    let id = |key: &str, value: &OsStr| {
        value.to_str().and_then(|v| v.parse().ok()).ok_or_else(|| {
            Failure::Runtime(anyhow!("{key}={} is not a numeric id", value.display()))
        })
    };
    let uid = id("SUDO_UID", &uid)?;
    let gid = id("SUDO_GID", &gid)?;
    if uid == 0 {
        return Ok(None);
    }
    let account = watch::account(uid);
    Ok(Some(Caller {
        creds: Credentials {
            uid,
            gid,
            groups: groups(&name, gid)?,
        },
        home: account
            .as_ref()
            .map(|a| a.home.clone())
            .or_else(|| env::var_os("SUDO_HOME").map(PathBuf::from)),
        shell: account.map(|a| a.shell).filter(|shell| !shell.is_empty()),
        name,
    }))
}

/// The groups of user `name` with primary group `gid`, as initgroups(3) sets them.
fn groups(name: &OsStr, gid: libc::gid_t) -> Result<Vec<libc::gid_t>, Failure> {
    let failed = || Failure::Runtime(anyhow!("cannot read the groups of {}", name.display()));
    let user = CString::new(name.as_bytes()).map_err(|_| failed())?;
    let mut groups: Vec<libc::gid_t> = vec![0; 64];
    loop {
        let mut n = libc::c_int::try_from(groups.len()).map_err(|_| failed())?;
        // SAFETY: `groups` has room for `n` ids; getgrouplist writes at most that many and
        // stores how many the user has in `n`.
        let rc = unsafe { libc::getgrouplist(user.as_ptr(), gid, groups.as_mut_ptr(), &raw mut n) };
        let n = usize::try_from(n).map_err(|_| failed())?;
        if rc >= 0 {
            groups.truncate(n);
            return Ok(groups);
        }
        if n <= groups.len() {
            return Err(failed());
        }
        groups.resize(n, 0);
    }
}

/// The command's environment: fsblame's, with the variables sudo sets for its target user
/// (`HOME`, `USER`, `LOGNAME`, `SHELL`) set for `caller` instead.
fn environment(caller: Option<&Caller>) -> Vec<CString> {
    let mut vars: Vec<(OsString, OsString)> = env::vars_os().collect();
    if let Some(caller) = caller {
        let set = [
            ("HOME", caller.home.clone().map(PathBuf::into_os_string)),
            ("USER", Some(caller.name.clone())),
            ("LOGNAME", Some(caller.name.clone())),
            ("SHELL", caller.shell.clone()),
        ];
        for (key, value) in set {
            if let Some(value) = value {
                vars.retain(|(k, _)| k != key);
                vars.push((key.into(), value));
            }
        }
    }
    vars.into_iter()
        .filter_map(|(key, value)| {
            let mut entry = key.into_vec();
            entry.push(b'=');
            entry.extend(value.into_vec());
            CString::new(entry).ok()
        })
        .collect()
}

/// Why the command did not start.
#[derive(Debug)]
enum StartError {
    /// Switching to the invoking user failed in the child.
    Setup(io::Error),
    /// `execvpe` failed.
    Exec(io::Error),
}

/// A forked child, parked before exec until [`release`](Self::release).
#[derive(Debug)]
struct Child {
    pid: libc::pid_t,
    pidfd: OwnedFd,
    /// Releases the child: one byte lets it go on.
    go: OwnedFd,
    /// The stage and errno of a failure before exec; closed by the exec.
    status: OwnedFd,
}

/// Stage byte the child writes before an errno.
const STAGE_SETUP: u8 = 0;
const STAGE_EXEC: u8 = 1;

/// Exit status of a child that did not run the command because fsblame failed.
const EXIT_SETUP: libc::c_int = 125;

impl Child {
    /// Forks the child for `argv` with environment `env`, parked until
    /// [`release`](Self::release). fsblame must be single-threaded.
    fn spawn(argv: &[CString], env: &[CString], creds: Option<&Credentials>) -> io::Result<Self> {
        let mut argv: Vec<*const libc::c_char> = argv.iter().map(|a| a.as_ptr()).collect();
        argv.push(ptr::null());
        let mut envp: Vec<*const libc::c_char> = env.iter().map(|e| e.as_ptr()).collect();
        envp.push(ptr::null());
        let (go_read, go_write) = pipe()?;
        let (status_read, status_write) = pipe()?;

        // SAFETY: fsblame is single-threaded, and the child only calls async-signal-safe
        // functions on memory prepared above before it execs or exits.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(io::Error::last_os_error());
        }
        if pid == 0 {
            // SAFETY: in the freshly forked child; see `child_main`.
            unsafe {
                child_main(
                    go_read.as_raw_fd(),
                    status_write.as_raw_fd(),
                    &argv,
                    &envp,
                    creds,
                )
            }
        }
        drop((go_read, status_write));
        // SAFETY: pidfd_open takes a pid and flags; the result is a new descriptor or -1.
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        let raw = match RawFd::try_from(raw) {
            Ok(fd) if fd >= 0 => fd,
            _ => {
                let err = io::Error::last_os_error();
                // SAFETY: killing and reaping our own parked child.
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                    libc::waitpid(pid, ptr::null_mut(), 0);
                }
                return Err(err);
            }
        };
        Ok(Self {
            pid,
            // SAFETY: `raw` is a fresh descriptor that nothing else owns.
            pidfd: unsafe { OwnedFd::from_raw_fd(raw) },
            go: go_write,
            status: status_read,
        })
    }

    /// Process id.
    fn pid(&self) -> u32 {
        self.pid.unsigned_abs()
    }

    /// Lets the child exec and reports whether it did. On failure the child has exited and
    /// must still be reaped with [`wait`](Self::wait).
    fn release(&self) -> Result<(), StartError> {
        let byte = [1_u8];
        // SAFETY: writing one byte from a valid buffer to our pipe.
        if unsafe { libc::write(self.go.as_raw_fd(), byte.as_ptr().cast(), 1) } != 1 {
            return Err(StartError::Setup(io::Error::last_os_error()));
        }
        let mut msg = [0_u8; 5];
        if read_full(self.status.as_raw_fd(), &mut msg) < msg.len() {
            // Closed by the successful exec (close-on-exec).
            return Ok(());
        }
        let err =
            io::Error::from_raw_os_error(i32::from_ne_bytes([msg[1], msg[2], msg[3], msg[4]]));
        Err(if msg[0] == STAGE_EXEC {
            StartError::Exec(err)
        } else {
            StartError::Setup(err)
        })
    }

    /// Sends `signal` to the child.
    fn signal(&self, signal: libc::c_int) {
        // SAFETY: pidfd_send_signal on our own pidfd, which cannot reach a reused pid.
        unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.pidfd.as_raw_fd(),
                signal,
                ptr::null::<libc::siginfo_t>(),
                0,
            );
        }
    }

    /// Waits for the child to exit; returns its exit code, or 128 + N if signal N killed it.
    fn wait(&self) -> io::Result<u8> {
        let mut status = 0;
        // SAFETY: waiting for our own child with a valid status pointer.
        while unsafe { libc::waitpid(self.pid, &raw mut status, 0) } < 0 {
            let err = io::Error::last_os_error();
            if err.kind() != io::ErrorKind::Interrupted {
                return Err(err);
            }
        }
        let code = if libc::WIFSIGNALED(status) {
            128 + libc::WTERMSIG(status)
        } else {
            libc::WEXITSTATUS(status)
        };
        Ok(u8::try_from(code).unwrap_or(u8::MAX))
    }
}

/// The child between fork and exec. Never returns.
///
/// # Safety
///
/// Must only be called in a freshly forked child of a single-threaded process; `argv` and
/// `envp` are NULL-terminated arrays of C strings.
unsafe fn child_main(
    go: RawFd,
    status: RawFd,
    argv: &[*const libc::c_char],
    envp: &[*const libc::c_char],
    creds: Option<&Credentials>,
) -> ! {
    // SAFETY: only async-signal-safe calls on valid, pre-allocated memory.
    unsafe {
        let mut byte = 0_u8;
        if libc::read(go, (&raw mut byte).cast(), 1) != 1 {
            // fsblame gave up before releasing it.
            libc::_exit(EXIT_SETUP);
        }
        if let Some(creds) = creds {
            if libc::setgroups(creds.groups.len(), creds.groups.as_ptr()) != 0
                || libc::setgid(creds.gid) != 0
                || libc::setuid(creds.uid) != 0
            {
                report_and_exit(status, STAGE_SETUP, EXIT_SETUP);
            }
            // The switch is complete and cannot be undone.
            if libc::getuid() != creds.uid
                || libc::geteuid() != creds.uid
                || libc::getgid() != creds.gid
                || libc::getegid() != creds.gid
                || libc::setuid(0) == 0
            {
                *libc::__errno_location() = libc::EPERM;
                report_and_exit(status, STAGE_SETUP, EXIT_SETUP);
            }
        }
        // Rust ignores SIGPIPE, and fsblame blocks the signals it reads from a signalfd; an
        // ignored or blocked signal stays so across exec.
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
        let mut empty: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&raw mut empty);
        libc::sigprocmask(libc::SIG_SETMASK, &raw const empty, ptr::null_mut());
        libc::execvpe(argv[0], argv.as_ptr(), envp.as_ptr());
        let code = if *libc::__errno_location() == libc::ENOENT {
            127
        } else {
            126
        };
        report_and_exit(status, STAGE_EXEC, code);
    }
}

/// Writes `stage` and the current errno to the status pipe, then exits with `code`.
///
/// # Safety
///
/// Child-only; async-signal-safe.
unsafe fn report_and_exit(status: RawFd, stage: u8, code: libc::c_int) -> ! {
    // SAFETY: the errno location is thread-local and valid; the buffer is on the stack.
    unsafe {
        let errno = (*libc::__errno_location()).to_ne_bytes();
        let msg = [stage, errno[0], errno[1], errno[2], errno[3]];
        libc::write(status, msg.as_ptr().cast(), msg.len());
        libc::_exit(code)
    }
}

/// A close-on-exec pipe: (read end, write end).
fn pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0; 2];
    // SAFETY: pipe2 writes two descriptors into `fds`.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: both descriptors are fresh and owned by us.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

/// Reads until `buf` is full or EOF; returns the bytes read.
fn read_full(fd: RawFd, buf: &mut [u8]) -> usize {
    let mut done = 0;
    while done < buf.len() {
        // SAFETY: reading into the unfilled tail of `buf`.
        let n = unsafe { libc::read(fd, buf[done..].as_mut_ptr().cast(), buf.len() - done) };
        match n {
            0 => break,
            n if n > 0 => done += n.unsigned_abs(),
            _ if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted => {}
            _ => break,
        }
    }
    done
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt as _};

    use super::*;
    use crate::journal::tests::TestDir;

    /// A fresh, empty directory for one test.
    fn test_dir(name: &str) -> TestDir {
        let dir = TestDir::new(name);
        fs::create_dir_all(&dir.0).unwrap();
        dir
    }

    fn mkfifo(path: &Path) {
        let c = CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: `c` is a valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o666) }, 0);
    }

    fn refusal(path: &Path, owner: Option<&Credentials>) -> String {
        open_output(path, owner).unwrap_err().to_string()
    }

    #[test]
    fn new_file_is_private() {
        let dir = test_dir("run-new");
        let path = dir.0.join("report");
        open_output(&path, None).unwrap();
        let meta = fs::symlink_metadata(&path).unwrap();
        assert!(meta.is_file());
        assert_eq!(meta.mode() & 0o7777, 0o600);
        // SAFETY: geteuid cannot fail.
        assert_eq!(meta.uid(), unsafe { libc::geteuid() });
    }

    #[test]
    fn own_file_is_truncated_and_keeps_its_mode() {
        let dir = test_dir("run-own");
        let path = dir.0.join("report");
        fs::write(&path, "old report").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        let mut file = open_output(&path, None).unwrap();
        file.write_all(b"new").unwrap();
        drop(file);
        assert_eq!(fs::read_to_string(&path).unwrap(), "new");
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o7777, 0o640);
    }

    #[test]
    fn file_of_another_user_is_left_alone() {
        let dir = test_dir("run-other");
        let path = dir.0.join("report");
        fs::write(&path, "theirs").unwrap();
        // SAFETY: geteuid and getegid cannot fail.
        let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
        let caller = Credentials {
            uid: uid + 1,
            gid,
            groups: Vec::new(),
        };
        assert_eq!(
            refusal(&path, Some(&caller)),
            format!(
                "it belongs to uid {uid}, not to the invoking user (uid {})",
                uid + 1
            )
        );
        assert_eq!(fs::read_to_string(&path).unwrap(), "theirs");
    }

    #[test]
    fn symbolic_link_is_refused() {
        let dir = test_dir("run-link");
        let target = dir.0.join("target");
        fs::write(&target, "kept").unwrap();
        let path = dir.0.join("report");
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert_eq!(refusal(&path, None), "it is a symbolic link");
        assert_eq!(fs::read_to_string(&target).unwrap(), "kept");
    }

    #[test]
    fn fifo_is_refused_without_blocking() {
        let dir = test_dir("run-fifo");
        let path = dir.0.join("report");
        mkfifo(&path);
        // Without a reader the open itself fails; with one it succeeds and the type check
        // refuses it. Neither waits.
        assert_eq!(refusal(&path, None), "it is not a regular file");
        let _reader = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&path)
            .unwrap();
        assert_eq!(refusal(&path, None), "it is not a regular file");
    }

    #[test]
    fn socket_is_refused() {
        let dir = test_dir("run-socket");
        let path = dir.0.join("report");
        let _listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        assert_eq!(refusal(&path, None), "it is not a regular file");
    }
}
