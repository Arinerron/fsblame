//! The watch loop: attach, then stream report lines until a signal or a time limit.
//!
//! [`run`] is shared by the subcommands that watch: it attaches the tracer, writes every
//! reported change, every loss and (optionally) the summary to a [`Sink`], and returns the
//! run's totals. [`follow`] is the same loop restricted to the processes of a [`Follow`],
//! which also decides when it ends. [`command`] is `fsblame watch` on top of them.

use std::{
    ffi::{CStr, OsStr, OsString},
    fs::{self, File},
    io::{self, BufWriter, IsTerminal, Write as _},
    mem::MaybeUninit,
    os::{
        fd::{AsRawFd as _, BorrowedFd, FromRawFd as _, OwnedFd},
        unix::ffi::OsStrExt as _,
    },
    path::PathBuf,
    time::{Duration, Instant},
};

use anyhow::{Context as _, anyhow};
use bpfdoctor::RealEnv;

use crate::{
    cli::{ColorMode, TraceArgs, WatchArgs},
    clock::{self, Clock},
    doctor,
    engine::Engine,
    fail::Failure,
    filter::{Filter, FilterSpec},
    ops::{Op, OpSet},
    render::{Human, Json},
    report::{Line, LossReason, LossTotals, LostReport, Sink, Summary, Timestamp, Version},
    roots::Roots,
    tracer::{Class, Processes, Tracer},
};

/// Longest wait for events, so pending writes are polled in time.
const TICK_MS: u64 = 100;
/// Longest final drain once stopping, so records already in the ring are still reported.
const STOP_DRAIN_MS: u64 = 1000;
/// Least time between two `lost` lines of the same reason.
const LOSS_EVERY: Duration = Duration::from_secs(1);
/// Output buffered between two flushes (every loop pass): a burst of NDJSON lines, a few KiB
/// each, goes out in a few writes.
const OUTPUT_BUFFER: usize = 1 << 16;

/// What [`run`] watches and how.
#[derive(Clone, Debug)]
pub struct WatchOptions {
    /// Files or directories to watch; a directory includes its whole subtree. Empty: every
    /// filesystem but the pseudo ones (`fsblame run` without paths).
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
    /// Watching `paths` as `trace` says, with no time limit and no readiness descriptor.
    pub fn new(paths: &[PathBuf], trace: &TraceArgs) -> Self {
        Self {
            paths: paths.to_vec(),
            exclude: trace.exclude.clone(),
            ops: trace.filter.op.clone(),
            filter: Filter::new(FilterSpec::from(&trace.filter)),
            ring_bytes: trace.ring_size,
            duration: None,
            ready_fd: None,
            quiet: trace.quiet,
            summary: trace.summary,
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

/// The processes a run follows ([`follow`]): only their changes are reported, and they
/// decide when the run ends.
pub trait Follow {
    /// Seeds the tracked set. Runs once the tracer is attached and armed and before the first
    /// record is read, so the kernel already tracks every process a tracked one starts.
    fn start(&mut self, tracer: &mut Tracer) -> Result<(), Failure>;
    /// A descriptor that becomes readable when the run is over, such as a command's pidfd.
    fn end(&self) -> Option<BorrowedFd<'_>>;
    /// Handles SIGINT, SIGTERM or SIGHUP; returns whether it stops the run.
    fn signal(&mut self, signal: i32) -> bool;
    /// Whose changes are reported and what stops the run, for the start banner, such as
    /// `by process 42 and its descendants; Ctrl-C to stop`.
    fn banner(&self) -> String;
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

    /// Takes the next pending signal, if any.
    fn pop(&self) -> Option<i32> {
        let mut info = MaybeUninit::<libc::signalfd_siginfo>::uninit();
        let size = size_of::<libc::signalfd_siginfo>();
        // SAFETY: reads at most one siginfo into `info`; the descriptor is non-blocking.
        let n = unsafe { libc::read(self.fd.as_raw_fd(), info.as_mut_ptr().cast(), size) };
        if usize::try_from(n).ok() != Some(size) {
            return None;
        }
        // SAFETY: the kernel filled the whole siginfo.
        i32::try_from(unsafe { info.assume_init() }.ssi_signo).ok()
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
    fn wait(&self, timeout_ms: i32) -> anyhow::Result<Ready> {
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
                return Ok(Ready(0));
            }
            return Err(anyhow::Error::new(err).context("epoll_wait"));
        }
        let n = usize::try_from(n).expect("non-negative");
        Ok(Ready(
            events[..n]
                .iter()
                .fold(0, |set, e| set | (1 << (e.u64 & 63))),
        ))
    }
}

/// The tokens (below 64) an [`Epoll::wait`] found ready.
#[derive(Clone, Copy)]
struct Ready(u64);

impl Ready {
    fn contains(self, token: u64) -> bool {
        self.0 & (1 << token) != 0
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

/// A user's entry in the user database.
#[derive(Clone, Debug)]
pub(crate) struct Account {
    /// Home directory.
    pub home: PathBuf,
    /// Login shell.
    pub shell: OsString,
}

/// The user database entry of `uid`.
pub(crate) fn account(uid: libc::uid_t) -> Option<Account> {
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
    // SAFETY: getpwuid_r succeeded, so `pwd` is initialised.
    let pwd = unsafe { pwd.assume_init() };
    let text = |field: *const libc::c_char| {
        if field.is_null() {
            return OsString::new();
        }
        // SAFETY: a non-null field of the entry is a C string in `buf`.
        OsStr::from_bytes(unsafe { CStr::from_ptr(field) }.to_bytes()).to_owned()
    };
    Some(Account {
        home: PathBuf::from(text(pwd.pw_dir)),
        shell: text(pwd.pw_shell),
    })
}

/// The home directory of the user fsblame runs for (the sudo caller, if any), for `~`.
pub fn home_dir() -> Option<PathBuf> {
    if let Some(uid) = std::env::var("SUDO_UID")
        .ok()
        .and_then(|uid| uid.parse().ok())
    {
        return account(uid).map(|a| a.home);
    }
    // SAFETY: getuid cannot fail.
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .or_else(|| account(unsafe { libc::getuid() }).map(|a| a.home))
}

/// Whether human output to `out` gets colors: `auto` means `out` is a terminal and
/// `NO_COLOR` is unset or empty.
pub fn use_color(mode: ColorMode, out: &impl IsTerminal) -> bool {
    match mode {
        ColorMode::Always => true,
        ColorMode::Never => false,
        ColorMode::Auto => {
            out.is_terminal() && std::env::var_os("NO_COLOR").is_none_or(|v| v.is_empty())
        }
    }
}

/// `fsblame watch`: the tree view or NDJSON on stdout.
pub fn command(args: &WatchArgs) -> Result<(), Failure> {
    let opts = WatchOptions {
        duration: args.stop.duration,
        ready_fd: args.stop.ready_fd,
        ..WatchOptions::new(&args.paths, &args.trace)
    };
    let mut tree = if args.tree.is_empty() {
        None
    } else {
        Some(Tree::new(&args.tree)?)
    };
    let follower = tree.as_mut().map(|tree| tree as &mut dyn Follow);
    let out = BufWriter::with_capacity(OUTPUT_BUFFER, io::stdout().lock());
    if args.view.json {
        watch(&opts, follower, &mut Json::new(out))?;
    } else {
        let color = use_color(args.view.color, &io::stdout());
        let mut sink = Human::new(out, home_dir(), args.view.depth, color);
        watch(&opts, follower, &mut sink)?;
    }
    Ok(())
}

/// `watch --tree`: the given processes and their descendants.
#[derive(Debug)]
struct Tree {
    /// Process ids.
    pids: Vec<u32>,
}

impl Tree {
    /// The processes of `pids`; a thread id stands for its process. Fails with a usage error
    /// for one that does not exist, and as unsupported when the kernel does not list the
    /// children of a process (`CONFIG_PROC_CHILDREN`).
    fn new(pids: &[u32]) -> Result<Self, Failure> {
        if !fs::exists("/proc/thread-self/children").unwrap_or(false) {
            return Err(Failure::Unsupported(anyhow!(
                "--tree needs /proc/<pid>/task/<tid>/children, which this kernel does not \
                 provide (CONFIG_PROC_CHILDREN)"
            )));
        }
        let mut tree = Self { pids: Vec::new() };
        for &pid in pids {
            let tgid = process_of(pid)
                .ok_or_else(|| Failure::Usage(anyhow!("--tree {pid}: no such process")))?;
            if !tree.pids.contains(&tgid) {
                tree.pids.push(tgid);
            }
        }
        Ok(tree)
    }
}

impl Follow for Tree {
    fn start(&mut self, tracer: &mut Tracer) -> Result<(), Failure> {
        for &pid in &self.pids {
            track_tree(tracer, pid)?;
        }
        Ok(())
    }

    fn end(&self) -> Option<BorrowedFd<'_>> {
        None
    }

    fn signal(&mut self, _signal: i32) -> bool {
        true
    }

    fn banner(&self) -> String {
        let pids: Vec<String> = self.pids.iter().map(u32::to_string).collect();
        if let [pid] = &pids[..] {
            format!(" by process {pid} and its descendants; Ctrl-C to stop")
        } else {
            format!(
                " by processes {} and their descendants; Ctrl-C to stop",
                pids.join(", ")
            )
        }
    }
}

/// The process (thread group) of `pid`, which may also be a thread id; `None` if there is
/// no such task.
fn process_of(pid: u32) -> Option<u32> {
    fs::read_to_string(format!("/proc/{pid}/status"))
        .ok()?
        .lines()
        .find_map(|line| line.strip_prefix("Tgid:"))
        .and_then(|tgid| tgid.trim().parse().ok())
}

/// Tracks process `root` and its descendants. Each process is tracked before its children
/// are read: a child it forks after that is tracked by the kernel, one it forked before is
/// listed. A process that exits meanwhile is skipped with its children, which its exit
/// handed to another parent.
fn track_tree(tracer: &mut Tracer, root: u32) -> Result<(), Failure> {
    let mut pending = vec![root];
    while let Some(pid) = pending.pop() {
        tracer.track(pid).map_err(|e| {
            Failure::Runtime(anyhow::Error::new(e).context(format!("tracking process {pid}")))
        })?;
        let Ok(tasks) = fs::read_dir(format!("/proc/{pid}/task")) else {
            continue;
        };
        for task in tasks.flatten() {
            // Children are listed per thread: the one that forked them.
            if let Ok(children) = fs::read_to_string(task.path().join("children")) {
                pending.extend(
                    children
                        .split_ascii_whitespace()
                        .filter_map(|child| child.parse::<u32>().ok()),
                );
            }
        }
    }
    Ok(())
}

/// Attaches to the paths of `opts` and writes what changes there to `sink` until a signal
/// or `opts.duration` stops it: every admitted change, a `lost` line whenever the kernel
/// side loses data (at most one per reason per second), and the summary if asked for. The
/// start banner, warnings and the final count go to stderr. A closed output (broken pipe)
/// ends the run early without an error.
pub fn run(opts: &WatchOptions, sink: &mut dyn Sink) -> Result<Outcome, Failure> {
    watch(opts, None, sink)
}

/// [`run`] for the changes of the processes `follower` tracks, which also handles the stop
/// signals and may end the run.
pub fn follow(
    opts: &WatchOptions,
    follower: &mut dyn Follow,
    sink: &mut dyn Sink,
) -> Result<Outcome, Failure> {
    watch(opts, Some(follower), sink)
}

fn watch(
    opts: &WatchOptions,
    mut follower: Option<&mut dyn Follow>,
    sink: &mut dyn Sink,
) -> Result<Outcome, Failure> {
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
    let processes = if follower.is_some() {
        Processes::Tracked
    } else {
        Processes::All
    };
    let mut tracer =
        Tracer::load(&roots, selected, opts.ring_bytes, processes).map_err(|error| {
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
        let place = if roots.everywhere() {
            "every filesystem".to_owned()
        } else {
            let watched: Vec<String> = roots
                .iter()
                .filter(|(_, r)| !r.exclude && !r.nested)
                .map(|(_, r)| r.path.display().to_string())
                .collect();
            let nested = roots.iter().filter(|(_, r)| r.nested).count();
            if nested > 0 {
                format!("{} (+{nested} mounts below)", watched.join(", "))
            } else {
                watched.join(", ")
            }
        };
        let op_names: Vec<&str> = selected.iter().map(Op::name).collect();
        eprintln!(
            "fsblame: watching {place} for {}{}",
            if opts.ops.is_empty() {
                "all ops".to_owned()
            } else {
                op_names.join(",")
            },
            follower
                .as_deref()
                .map_or_else(|| "; Ctrl-C to stop".to_owned(), Follow::banner),
        );
    }
    if let Some(follower) = follower.as_deref_mut() {
        follower.start(&mut tracer)?;
    }

    let clock = Clock::new();
    let output = Output {
        sink,
        summary: opts.summary.then(Summary::new),
    };
    let engine = Engine::new(roots, clock, opts.filter.clone(), output);
    stream(engine, &mut tracer, &signals, follower, opts, clock)
}

/// An output error ends the run; a closed pipe ends it cleanly (`false`).
pub fn output_result(result: io::Result<()>) -> Result<bool, Failure> {
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
    meters: &mut [LossMeter; 3],
    totals: LossTotals,
    clock: Clock,
    all: bool,
) -> io::Result<()> {
    let now = Instant::now();
    let totals = [totals.ring_full, totals.write_evicted, totals.track_full];
    for (meter, total) in meters.iter_mut().zip(totals) {
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
            track_full: tracer.track_full(),
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
    mut follower: Option<&mut dyn Follow>,
    opts: &WatchOptions,
    clock: Clock,
) -> Result<Outcome, Failure> {
    const SIGNALS: u64 = 1;
    const END: u64 = 2;
    let mut meters = [
        LossMeter::new(LossReason::RingFull),
        LossMeter::new(LossReason::WriteEvicted),
        LossMeter::new(LossReason::TrackFull),
    ];
    let mut fds = vec![tracer.ring.as_raw_fd(), signals.fd.as_raw_fd()];
    fds.extend(
        follower
            .as_deref()
            .and_then(Follow::end)
            .map(|fd| fd.as_raw_fd()),
    );
    let epoll = Epoll::new(&fds)?;
    if let Some(fd) = opts.ready_fd {
        signal_ready(fd).with_context(|| format!("writing to --ready-fd {fd}"))?;
    }
    let deadline = opts.duration.map(|d| Instant::now() + d);
    // The loss counters are kernel maps, each read with a system call: once a tick is enough
    // for `lost` lines, which come at most once a second, but under a stream of single
    // records every wakeup would read them.
    let mut losses_due = Instant::now();
    let mut open = true;
    while open {
        let left = deadline.map_or(TICK_MS, |d| {
            u64::try_from(d.saturating_duration_since(Instant::now()).as_millis())
                .unwrap_or(u64::MAX)
        });
        let ready = epoll.wait(i32::try_from(left.min(TICK_MS)).expect("at most TICK_MS"))?;
        if ready.contains(SIGNALS) {
            while let Some(signal) = signals.pop() {
                if follower.as_deref_mut().is_none_or(|f| f.signal(signal)) {
                    open = false;
                }
            }
        }
        if ready.contains(END) || deadline.is_some_and(|d| Instant::now() >= d) {
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
        if closed {
            return Ok(outcome(&engine, tracer));
        }
        let now = Instant::now();
        if now >= losses_due {
            losses_due = now + Duration::from_millis(TICK_MS);
            let totals = outcome(&engine, tracer).lost;
            if !output_result(report_losses(
                &mut engine,
                &mut meters,
                totals,
                clock,
                false,
            ))? {
                return Ok(outcome(&engine, tracer));
            }
        }
        if !output_result(engine.poll(clock::boot_now_ns(), &mut tracer.writes))? {
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
    if result.lost.track_full > 0 {
        eprintln!(
            "fsblame: warning: {} new processes were not followed because {} processes were \
             tracked; their changes are missing",
            result.lost.track_full,
            crate::tracer::TRACKED_MAX
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
