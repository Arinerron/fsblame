//! `fsblame watch`: attach, then stream touches until a signal or `--duration`.

use std::{
    ffi::{CStr, OsStr},
    fs::File,
    io::{self, BufWriter, Write as _},
    mem::MaybeUninit,
    os::{
        fd::{AsRawFd as _, FromRawFd as _, OwnedFd},
        unix::ffi::OsStrExt as _,
    },
    path::PathBuf,
    time::{Duration, Instant},
};

use anyhow::{Context as _, anyhow};
use bpfdoctor::RealEnv;

use crate::{
    cli::WatchArgs,
    clock::{self, Clock},
    doctor,
    engine::{Engine, Sink},
    fail::Failure,
    ops::OpSet,
    render::{Human, Json},
    roots::Roots,
    tracer::{Class, Tracer},
};

/// Longest wait for events, so pending writes are polled in time.
const TICK_MS: u64 = 100;
/// Longest final drain once stopping, so records already in the ring are still reported.
const STOP_DRAIN_MS: u64 = 1000;

fn os_error(what: &str) -> anyhow::Error {
    anyhow::Error::new(io::Error::last_os_error()).context(what.to_owned())
}

/// SIGINT, SIGTERM and SIGHUP, blocked and delivered through a signalfd.
struct Signals {
    fd: OwnedFd,
}

impl Signals {
    fn new() -> anyhow::Result<Self> {
        let mut set = MaybeUninit::<libc::sigset_t>::uninit();
        // SAFETY: sigemptyset initialises the set; the other calls use it initialised.
        let fd = unsafe {
            libc::sigemptyset(set.as_mut_ptr());
            for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
                libc::sigaddset(set.as_mut_ptr(), signal);
            }
            if libc::pthread_sigmask(libc::SIG_BLOCK, set.as_ptr(), std::ptr::null_mut()) != 0 {
                return Err(os_error("blocking signals"));
            }
            libc::signalfd(-1, set.as_ptr(), libc::SFD_CLOEXEC | libc::SFD_NONBLOCK)
        };
        if fd < 0 {
            return Err(os_error("signalfd"));
        }
        // SAFETY: signalfd returned a new descriptor that nothing else owns.
        Ok(Self {
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
        })
    }

    /// Consumes pending signals.
    fn drain(&self) {
        let mut info = MaybeUninit::<libc::signalfd_siginfo>::uninit();
        // SAFETY: reads at most one siginfo into `info`; the descriptor is non-blocking.
        while unsafe {
            libc::read(
                self.fd.as_raw_fd(),
                info.as_mut_ptr().cast(),
                size_of::<libc::signalfd_siginfo>(),
            )
        } > 0
        {}
    }
}

struct Epoll {
    fd: OwnedFd,
}

impl Epoll {
    fn new(fds: &[i32]) -> anyhow::Result<Self> {
        // SAFETY: plain syscall.
        let fd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
        if fd < 0 {
            return Err(os_error("epoll_create1"));
        }
        // SAFETY: epoll_create1 returned a new descriptor that nothing else owns.
        let epoll = Self {
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
        };
        for (token, &watched) in (0u64..).zip(fds) {
            let mut event = libc::epoll_event {
                events: libc::EPOLLIN as u32,
                u64: token,
            };
            // SAFETY: both descriptors are open and `event` is valid for the call.
            if unsafe { libc::epoll_ctl(fd, libc::EPOLL_CTL_ADD, watched, &raw mut event) } != 0 {
                return Err(os_error("epoll_ctl"));
            }
        }
        Ok(epoll)
    }

    /// Waits up to `timeout_ms`; returns the tokens that became ready.
    fn wait(&self, timeout_ms: i32) -> anyhow::Result<Vec<u64>> {
        let mut events = [libc::epoll_event { events: 0, u64: 0 }; 4];
        // SAFETY: `events` is writable for its length.
        let n = unsafe {
            libc::epoll_wait(
                self.fd.as_raw_fd(),
                events.as_mut_ptr(),
                i32::try_from(events.len()).expect("small"),
                timeout_ms,
            )
        };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                return Ok(Vec::new());
            }
            return Err(anyhow::Error::new(err).context("epoll_wait"));
        }
        let n = usize::try_from(n).expect("non-negative");
        Ok(events[..n].iter().map(|e| e.u64).collect())
    }
}

/// Checks that `fd` is open, so `--ready-fd` mistakes are usage errors before attaching.
fn check_fd(fd: i32) -> Result<(), Failure> {
    // SAFETY: F_GETFD only queries the descriptor table.
    if fd < 0 || unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
        return Err(Failure::Usage(anyhow!(
            "--ready-fd {fd} is not an open file descriptor"
        )));
    }
    Ok(())
}

fn signal_ready(fd: i32) -> io::Result<()> {
    // SAFETY: `--ready-fd` hands this open descriptor (checked by `check_fd`) to fsblame;
    // nothing else in the process uses it, and it is closed here.
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(b"ready\n")
}

/// Raises the `RLIMIT_MEMLOCK` soft limit to the hard limit; kernels before 5.11 charge BPF
/// memory there.
fn raise_memlock() {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` is valid for both calls.
    unsafe {
        if libc::getrlimit(libc::RLIMIT_MEMLOCK, &raw mut limit) == 0
            && limit.rlim_cur < limit.rlim_max
        {
            limit.rlim_cur = limit.rlim_max;
            libc::setrlimit(libc::RLIMIT_MEMLOCK, &raw const limit);
        }
    }
}

fn passwd_home(uid: libc::uid_t) -> Option<PathBuf> {
    let mut pwd = MaybeUninit::<libc::passwd>::uninit();
    let mut buf = vec![0 as libc::c_char; 16 * 1024];
    let mut result = std::ptr::null_mut();
    // SAFETY: all pointers are valid; on success `result` points at `pwd`, whose strings live
    // in `buf`.
    let rc = unsafe {
        libc::getpwuid_r(
            uid,
            pwd.as_mut_ptr(),
            buf.as_mut_ptr(),
            buf.len(),
            &raw mut result,
        )
    };
    if rc != 0 || result.is_null() {
        return None;
    }
    // SAFETY: getpwuid_r succeeded, so `pwd` is initialised and `pw_dir` is a C string in `buf`.
    let dir = unsafe { CStr::from_ptr(pwd.assume_init().pw_dir) };
    Some(PathBuf::from(OsStr::from_bytes(dir.to_bytes())))
}

/// The home directory of the user fsblame runs for (the sudo caller, if any), for `~`.
fn home_dir() -> Option<PathBuf> {
    if let Some(uid) = std::env::var("SUDO_UID")
        .ok()
        .and_then(|uid| uid.parse().ok())
    {
        return passwd_home(uid);
    }
    // SAFETY: getuid cannot fail.
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .or_else(|| passwd_home(unsafe { libc::getuid() }))
}

/// `fsblame watch`.
pub fn run(args: &WatchArgs) -> Result<(), Failure> {
    if let Some(fd) = args.ready_fd {
        check_fd(fd)?;
    }
    let ops = OpSet::new(&args.op);
    let roots = Roots::resolve(&args.paths, &args.exclude).map_err(Failure::Usage)?;

    let tool = doctor::tool();
    let report = doctor::preflight(args.paths.clone()).run(&RealEnv, &tool);
    if report.has_fail() {
        report
            .render_human(&mut io::stderr(), false)
            .context("writing diagnostics")?;
        return Err(doctor::failure(
            &report,
            "cannot start; see the FAIL lines above",
        ));
    }
    doctor::print_problems(&report).context("writing diagnostics")?;

    raise_memlock();
    let signals = Signals::new()?;
    let mut tracer = Tracer::load(&roots, ops).map_err(|error| {
        // Diagnostics are best effort; the load error itself is what gets reported.
        let _ = doctor::explain_load_failure(&error, &args.paths);
        let message = anyhow!("{error}");
        match error.class() {
            Class::Privileges => Failure::Privileges(message),
            Class::Unsupported => Failure::Unsupported(message),
            Class::Runtime => Failure::Runtime(message),
        }
    })?;
    for missing in &tracer.missing {
        eprintln!(
            "fsblame: warning: {}",
            missing.error.describe(&missing.hook)
        );
    }
    if !tracer.unavailable.is_empty() {
        let names: Vec<&str> = tracer.unavailable.iter().map(|op| op.name()).collect();
        eprintln!(
            "fsblame: warning: not reported on this kernel: {}",
            names.join(", ")
        );
    }

    let watched: Vec<String> = roots
        .iter()
        .filter(|(_, r)| !r.exclude && !r.nested)
        .map(|(_, r)| r.path.display().to_string())
        .collect();
    let nested = roots.iter().filter(|(_, r)| r.nested).count();
    let op_names: Vec<&str> = ops.iter().map(super::ops::Op::name).collect();
    eprintln!(
        "fsblame: watching {}{} for {}; Ctrl-C to stop",
        watched.join(", "),
        if nested > 0 {
            format!(" (+{nested} mounts below)")
        } else {
            String::new()
        },
        if args.op.is_empty() {
            "all ops".to_owned()
        } else {
            op_names.join(",")
        },
    );

    let clock = Clock::new();
    let out = BufWriter::new(io::stdout().lock());
    if args.json {
        stream(
            Engine::new(roots, Json::new(out, clock)),
            &mut tracer,
            &signals,
            args,
        )
    } else {
        let human = Human::new(out, clock, home_dir(), args.depth);
        stream(Engine::new(roots, human), &mut tracer, &signals, args)
    }
}

/// An output error ends the run; a closed pipe ends it cleanly.
fn output_result(result: io::Result<()>) -> Result<bool, Failure> {
    match result {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => Ok(false),
        Err(e) => Err(Failure::Runtime(
            anyhow::Error::new(e).context("writing output"),
        )),
    }
}

fn stream<S: Sink>(
    mut engine: Engine<S>,
    tracer: &mut Tracer,
    signals: &Signals,
    args: &WatchArgs,
) -> Result<(), Failure> {
    let epoll = Epoll::new(&[tracer.ring.as_raw_fd(), signals.fd.as_raw_fd()])?;
    if let Some(fd) = args.ready_fd {
        signal_ready(fd).with_context(|| format!("writing to --ready-fd {fd}"))?;
    }
    let deadline = args.duration.map(|d| Instant::now() + d);
    let mut open = true;
    while open {
        let left = deadline.map_or(TICK_MS, |d| {
            u64::try_from(d.saturating_duration_since(Instant::now()).as_millis())
                .unwrap_or(u64::MAX)
        });
        let ready = epoll.wait(i32::try_from(left.min(TICK_MS)).expect("at most TICK_MS"))?;
        if ready.contains(&1) {
            signals.drain();
            open = false;
        }
        if deadline.is_some_and(|d| Instant::now() >= d) {
            open = false;
        }
        // Drain for at most one tick (longer when stopping): under a flood of records (a busy
        // build forks and execs without pause) the ring never runs dry, and the stop checks
        // above must still run.
        let budget =
            Instant::now() + Duration::from_millis(if open { TICK_MS } else { STOP_DRAIN_MS });
        while let Some(item) = tracer.ring.next() {
            if !output_result(engine.handle(&item, &mut tracer.writes))? {
                return Ok(());
            }
            if Instant::now() >= budget {
                break;
            }
        }
        if !output_result(engine.poll(clock::boot_now_ns(), &mut tracer.writes))? {
            return Ok(());
        }
    }
    output_result(engine.finish(&mut tracer.writes))?;

    let drops = tracer.ring_drops();
    if drops > 0 {
        eprintln!(
            "fsblame: warning: {drops} kernel records were lost because the ring buffer was full"
        );
    }
    let counts = engine.counts();
    if counts.malformed > 0 {
        eprintln!(
            "fsblame: warning: {} malformed records were ignored",
            counts.malformed
        );
    }
    eprintln!("fsblame: {} changes reported", counts.touches);
    Ok(())
}
