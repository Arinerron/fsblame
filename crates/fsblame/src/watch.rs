//! The watch loop: attach, then stream report lines until a signal or a time limit.
//!
//! [`run`] is shared by the subcommands that watch: it attaches the tracer, writes every
//! reported change, every loss and (optionally) the summary to a [`Sink`], and returns the
//! run's totals. [`command`] is `fsblame watch` on top of it.

use std::{
    ffi::{CStr, OsStr},
    fs::File,
    io::{self, BufWriter, IsTerminal as _, Write as _},
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
    cli::{ColorMode, WatchArgs},
    clock::{self, Clock},
    doctor,
    engine::Engine,
    fail::Failure,
    filter::{Filter, FilterSpec},
    ops::{Op, OpSet},
    render::{Human, Json},
    report::{Line, LossReason, LossTotals, LostReport, Sink, Summary, Timestamp, Version},
    roots::Roots,
    tracer::{Class, Tracer},
};

/// Longest wait for events, so pending writes are polled in time.
const TICK_MS: u64 = 100;
/// Longest final drain once stopping, so records already in the ring are still reported.
const STOP_DRAIN_MS: u64 = 1000;
/// Least time between two `lost` lines of the same reason.
const LOSS_EVERY: Duration = Duration::from_secs(1);

/// What [`run`] watches and how.
#[derive(Clone, Debug)]
pub struct WatchOptions {
    /// Files or directories to watch; a directory includes its whole subtree.
    pub paths: Vec<PathBuf>,
    /// Subtrees to ignore.
    pub exclude: Vec<PathBuf>,
    /// Operations to report; empty for all.
    pub ops: Vec<Op>,
    /// Which changes to report.
    pub filter: Filter,
    /// Size of the kernel ring buffer in bytes: a power of two and a multiple of the page
    /// size.
    pub ring_bytes: u32,
    /// Stop after this long; otherwise at SIGINT, SIGTERM or SIGHUP.
    pub duration: Option<Duration>,
    /// Write `ready\n` to this file descriptor once attached, then close it.
    pub ready_fd: Option<i32>,
    /// Print only warnings and errors on stderr.
    pub quiet: bool,
    /// End the output with a summary line.
    pub summary: bool,
}

impl WatchOptions {
    /// The options `fsblame watch` was given.
    pub fn from_args(args: &WatchArgs) -> Self {
        Self {
            paths: args.paths.clone(),
            exclude: args.exclude.clone(),
            ops: args.op.clone(),
            filter: Filter::new(FilterSpec {
                include: args.include.clone(),
                comm: args.comm.clone(),
                ignore_comm: args.ignore_comm.clone(),
                uid: args.uid.clone(),
                unit: args.unit.clone(),
                pid: args.pid.clone(),
            }),
            ring_bytes: args.ring_size,
            duration: args.duration,
            ready_fd: args.ready_fd,
            quiet: args.quiet,
            summary: args.summary,
        }
    }
}

/// The totals of a finished run.
#[derive(Clone, Copy, Debug, Default)]
pub struct Outcome {
    /// Changes reported (after filtering).
    pub changes: u64,
    /// What the kernel side lost.
    pub lost: LossTotals,
    /// Records that did not decode.
    pub malformed: u64,
}

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

/// Whether human output gets colors: `auto` means stdout is a terminal and `NO_COLOR` is
/// unset or empty.
fn use_color(mode: ColorMode) -> bool {
    match mode {
        ColorMode::Always => true,
        ColorMode::Never => false,
        ColorMode::Auto => {
            io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none_or(|v| v.is_empty())
        }
    }
}

/// `fsblame watch`: the tree view or NDJSON on stdout.
pub fn command(args: &WatchArgs) -> Result<(), Failure> {
    let opts = WatchOptions::from_args(args);
    let color = !args.json && use_color(args.color);
    let out = BufWriter::new(io::stdout().lock());
    if args.json {
        run(&opts, &mut Json::new(out))?;
    } else {
        run(&opts, &mut Human::new(out, home_dir(), args.depth, color))?;
    }
    Ok(())
}

/// Attaches to the paths of `opts` and writes what changes there to `sink` until a signal
/// or `opts.duration` stops it: every admitted change, a `lost` line whenever the kernel
/// side loses data (at most one per reason per second), and the summary if asked for. The
/// start banner, warnings and the final count go to stderr. A closed output (broken pipe)
/// ends the run early without an error.
pub fn run(opts: &WatchOptions, sink: &mut dyn Sink) -> Result<Outcome, Failure> {
    if let Some(fd) = opts.ready_fd {
        check_fd(fd)?;
    }
    let selected = OpSet::new(&opts.ops);
    let roots = Roots::resolve(&opts.paths, &opts.exclude).map_err(Failure::Usage)?;

    let tool = doctor::tool();
    let report = doctor::preflight(opts.paths.clone()).run(&RealEnv, &tool);
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
    let mut tracer = Tracer::load(&roots, selected, opts.ring_bytes).map_err(|error| {
        // Diagnostics are best effort; the load error itself is what gets reported.
        let _ = doctor::explain_load_failure(&error, &opts.paths);
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

    if !opts.quiet {
        let watched: Vec<String> = roots
            .iter()
            .filter(|(_, r)| !r.exclude && !r.nested)
            .map(|(_, r)| r.path.display().to_string())
            .collect();
        let nested = roots.iter().filter(|(_, r)| r.nested).count();
        let op_names: Vec<&str> = selected.iter().map(Op::name).collect();
        eprintln!(
            "fsblame: watching {}{} for {}; Ctrl-C to stop",
            watched.join(", "),
            if nested > 0 {
                format!(" (+{nested} mounts below)")
            } else {
                String::new()
            },
            if opts.ops.is_empty() {
                "all ops".to_owned()
            } else {
                op_names.join(",")
            },
        );
    }

    let clock = Clock::new();
    let output = Output {
        sink,
        summary: opts.summary.then(Summary::new),
    };
    let engine = Engine::new(roots, clock, opts.filter.clone(), output);
    stream(engine, &mut tracer, &signals, opts, clock)
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

/// The caller's sink, tallying changes for the summary when one was asked for.
struct Output<'s> {
    sink: &'s mut dyn Sink,
    summary: Option<Summary>,
}

impl Sink for Output<'_> {
    fn line(&mut self, line: &Line<'_>) -> io::Result<()> {
        if let (Some(summary), Line::Touch(change)) = (&mut self.summary, line) {
            summary.add(change);
        }
        self.sink.line(line)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.sink.flush()
    }
}

/// Turns a growing loss counter into `lost` lines with the growth since the previous one,
/// at most one per [`LOSS_EVERY`] so a sustained overflow does not flood the output.
#[derive(Debug)]
struct LossMeter {
    reason: LossReason,
    /// The counter as of the last line.
    reported: u64,
    /// When the last line was written.
    last: Option<Instant>,
}

impl LossMeter {
    const fn new(reason: LossReason) -> Self {
        Self {
            reason,
            reported: 0,
            last: None,
        }
    }

    /// The losses to report now that the counter is at `total`: none if it has not grown,
    /// or if the previous line is recent, unless `all` (the end of the run).
    fn due(&mut self, total: u64, now: Instant, all: bool) -> Option<u64> {
        let recent = self
            .last
            .is_some_and(|at| now.duration_since(at) < LOSS_EVERY);
        if total <= self.reported || (recent && !all) {
            return None;
        }
        let count = total - self.reported;
        self.reported = total;
        self.last = Some(now);
        Some(count)
    }
}

/// Writes the `lost` lines due for `totals`; `all` writes every unreported loss.
fn report_losses(
    engine: &mut Engine<Output<'_>>,
    meters: &mut [LossMeter; 2],
    totals: LossTotals,
    clock: Clock,
    all: bool,
) -> io::Result<()> {
    let now = Instant::now();
    for (meter, total) in meters
        .iter_mut()
        .zip([totals.ring_full, totals.write_evicted])
    {
        if let Some(count) = meter.due(total, now, all) {
            engine.sink_mut().line(&Line::Lost(LostReport {
                v: Version,
                ts: Timestamp::from_boot(clock, clock::boot_now_ns()),
                reason: meter.reason,
                count,
            }))?;
        }
    }
    Ok(())
}

/// The totals so far.
fn outcome(engine: &Engine<Output<'_>>, tracer: &Tracer) -> Outcome {
    let counts = engine.counts();
    Outcome {
        changes: counts.touches,
        lost: LossTotals {
            ring_full: tracer.ring_drops(),
            write_evicted: counts.evicted,
        },
        malformed: counts.malformed,
    }
}

// One linear loop: wait, drain, poll, report losses; then the end-of-run output.
#[allow(clippy::too_many_lines)]
fn stream(
    mut engine: Engine<Output<'_>>,
    tracer: &mut Tracer,
    signals: &Signals,
    opts: &WatchOptions,
    clock: Clock,
) -> Result<Outcome, Failure> {
    let mut meters = [
        LossMeter::new(LossReason::RingFull),
        LossMeter::new(LossReason::WriteEvicted),
    ];
    let epoll = Epoll::new(&[tracer.ring.as_raw_fd(), signals.fd.as_raw_fd()])?;
    if let Some(fd) = opts.ready_fd {
        signal_ready(fd).with_context(|| format!("writing to --ready-fd {fd}"))?;
    }
    let deadline = opts.duration.map(|d| Instant::now() + d);
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
        let mut closed = false;
        while let Some(item) = tracer.ring.next() {
            if !output_result(engine.handle(&item, &mut tracer.writes))? {
                closed = true;
                break;
            }
            if Instant::now() >= budget {
                break;
            }
        }
        let totals = outcome(&engine, tracer).lost;
        if closed
            || !output_result(report_losses(
                &mut engine,
                &mut meters,
                totals,
                clock,
                false,
            ))?
            || !output_result(engine.poll(clock::boot_now_ns(), &mut tracer.writes))?
        {
            return Ok(outcome(&engine, tracer));
        }
    }
    if !output_result(engine.finish(&mut tracer.writes))? {
        return Ok(outcome(&engine, tracer));
    }
    let result = outcome(&engine, tracer);
    let ended = report_losses(&mut engine, &mut meters, result.lost, clock, true).and_then(|()| {
        let output = engine.sink_mut();
        if let Some(summary) = output.summary.take() {
            let ts = Timestamp::from_boot(clock, clock::boot_now_ns());
            output
                .sink
                .line(&Line::Summary(summary.report(ts, result.lost)))?;
        }
        output.flush()
    });
    if !output_result(ended)? {
        return Ok(result);
    }

    if result.lost.ring_full > 0 {
        eprintln!(
            "fsblame: warning: {} kernel records were lost because the ring buffer was full; \
             a larger --ring-size helps",
            result.lost.ring_full
        );
    }
    if result.lost.write_evicted > 0 {
        eprintln!(
            "fsblame: warning: the latest byte counts of {} open files were lost because the \
             kernel write table was full",
            result.lost.write_evicted
        );
    }
    if result.malformed > 0 {
        eprintln!(
            "fsblame: warning: {} malformed records were ignored",
            result.malformed
        );
    }
    if !opts.quiet {
        eprintln!("fsblame: {} changes reported", result.changes);
    }
    Ok(result)
}
