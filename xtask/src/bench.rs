//! `cargo xtask bench [--bin PATH] [--quick] [--json]`: what watching costs.
//!
//! Five synthetic workloads run in this process, as the invoking user, in a scratch tree under
//! the work directory (`$FSBLAME_BENCH_DIR`, default `~/.cache/fsblame-bench`): `watched/`,
//! which fsblame watches, and its sibling `outside/` on the same filesystem. Each repetition
//! times a workload without fsblame and with `sudo -n fsblame watch --json watched/` attached,
//! pinned to the fastest CPU both times. Once fsblame has reported everything the workload did,
//! its CPU time since attaching and its peak resident set are read from `/proc`, and it is
//! stopped with SIGINT; its NDJSON is tallied as it arrives (touches, and the `lost` lines).
//! The table shows the median of three repetitions; `--quick` runs one, with fewer
//! operations.
//!
//! `--quiet` is not passed: the `fsblame: watching` line it would suppress is the signal that
//! every probe is attached, and stderr is silent while the workload runs either way.

use std::{
    collections::HashMap,
    env,
    ffi::{CStr, CString, OsString},
    fs::{self, File, OpenOptions},
    io::{self, BufRead as _, BufReader, Write as _},
    iter, mem,
    os::{
        fd::{AsRawFd as _, FromRawFd as _, OwnedFd},
        unix::{
            ffi::{OsStrExt as _, OsStringExt as _},
            fs::FileExt as _,
            process::CommandExt as _,
        },
    },
    path::{Path, PathBuf},
    process::{Child, ChildStderr, ChildStdout, Command, Stdio},
    ptr,
    sync::{
        Arc,
        atomic::{AtomicU32, AtomicU64, Ordering},
        mpsc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use anyhow::{Context as _, Result, anyhow, bail, ensure};
use serde_json::{Value, json};

use crate::{MAX_RUN, READY_TIMEOUT, STOP_TIMEOUT, USAGE, build, check_work_fs};

/// fsblame has reported a workload once its output has been still this long: a write window
/// is reported 200 ms after the last write, at the next 100 ms tick.
const SETTLE: Duration = Duration::from_millis(700);
/// Longest wait for fsblame to report a workload.
const SETTLE_TIMEOUT: Duration = Duration::from_secs(60);
/// How often a running fsblame is checked on.
const SAMPLE: Duration = Duration::from_millis(50);
/// Repetitions per workload without `--quick`; the table shows the median.
const REPETITIONS: usize = 3;
/// Size of the scratch files, of each churn write and of each mapping.
const BLOCK: usize = 4096;
/// Size of each small write.
const SMALL: usize = 64;
/// The longest process name the kernel keeps (`TASK_COMM_LEN - 1`).
const COMM_MAX: usize = 15;
/// How touch lines start: serde writes the tag of a `report::Line` first.
const TOUCH_PREFIX: &[u8] = br#"{"type":"touch""#;
/// What the exec storm runs.
const TRUE: &CStr = c"/bin/true";

/// A synthetic workload.
struct Workload {
    /// Name in `--json`.
    id: &'static str,
    /// Name in the table.
    name: &'static str,
    /// Operations per run: up to about a second's worth on a recent laptop core.
    ops: u32,
    /// Operations per run with `--quick`.
    quick_ops: u32,
    /// Performs `n` operations in the tree and returns how long they took, setup excluded.
    run: fn(&Tree, u32) -> Result<Duration>,
}

const WORKLOADS: &[Workload] = &[
    Workload {
        id: "exec",
        name: "exec storm",
        ops: 2_000,
        quick_ops: 500,
        run: exec_storm,
    },
    Workload {
        id: "churn",
        name: "file churn",
        // Within what fsblame keeps up with: 60,000 files in a row overflow the default ring
        // buffer on a recent laptop.
        ops: 20_000,
        quick_ops: 5_000,
        run: file_churn,
    },
    Workload {
        id: "write-in",
        name: "writes inside",
        ops: 2_000_000,
        quick_ops: 500_000,
        run: writes_inside,
    },
    Workload {
        id: "write-out",
        name: "writes outside",
        ops: 2_000_000,
        quick_ops: 500_000,
        run: writes_outside,
    },
    Workload {
        id: "mmap",
        name: "mmap churn",
        ops: 500_000,
        quick_ops: 100_000,
        run: mmap_churn,
    },
];

/// `cargo xtask bench [--bin PATH] [--quick] [--json]`.
pub fn bench(args: &[OsString]) -> Result<bool> {
    let mut bin = None;
    let mut quick = false;
    let mut as_json = false;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.to_str() {
            Some("--bin") => bin = Some(PathBuf::from(it.next().context("--bin needs a path")?)),
            Some("--quick") => quick = true,
            Some("--json") => as_json = true,
            _ => bail!("unknown argument {}\n{USAGE}", arg.display()),
        }
    }

    // SAFETY: geteuid cannot fail.
    ensure!(
        unsafe { libc::geteuid() } != 0,
        "run as your normal user: the workloads run as you, fsblame through `sudo -n`"
    );
    let sudo = Command::new("sudo")
        .args(["-n", "true"])
        .stderr(Stdio::null())
        .status()
        .context("running sudo")?;
    ensure!(
        sudo.success(),
        "`sudo -n true` failed: the bench starts fsblame through passwordless sudo; allow it \
         (NOPASSWD) or refresh your credentials with `sudo -v` first"
    );

    let bin = match bin {
        Some(bin) => fs::canonicalize(&bin).with_context(|| format!("--bin {}", bin.display()))?,
        None => build()?,
    };
    let fsblame = Fsblame::new(bin)?;
    if let Some(pid) = find_process(&fsblame.comm, None)? {
        bail!(
            "another {} is running (pid {pid}); stop it first, its probes would be measured too",
            String::from_utf8_lossy(&fsblame.comm)
        );
    }
    let work = match env::var_os("FSBLAME_BENCH_DIR") {
        Some(dir) => PathBuf::from(dir),
        None => {
            Path::new(&env::var_os("HOME").context("HOME is not set")?).join(".cache/fsblame-bench")
        }
    };
    fs::create_dir_all(&work).with_context(|| format!("creating {}", work.display()))?;
    // fsblame resolves the watched path; the tree must name the same files.
    let work = fs::canonicalize(&work).with_context(|| format!("resolving {}", work.display()))?;
    check_work_fs(&work)?;
    let tree = Tree::create(work.join("tree"))?;
    eprintln!(
        "fsblame bench: {} (work dir {})",
        fsblame.bin.display(),
        work.display()
    );

    let bench = Bench {
        fsblame,
        tree,
        cpu: fastest_cpu()?,
        reps: if quick { 1 } else { REPETITIONS },
        quick,
    };
    let outcomes = WORKLOADS
        .iter()
        .map(|workload| {
            bench
                .measure(workload)
                .with_context(|| format!("workload {}", workload.name))
        })
        .collect::<Result<Vec<_>>>()?;
    let host = Host::read();
    if as_json {
        println!("{:#}", bench.report(&host, &outcomes));
    } else {
        bench.print_table(&host, &outcomes);
    }
    Ok(true)
}

/// What the workloads run with.
struct Bench {
    fsblame: Fsblame,
    tree: Tree,
    /// The CPU the workloads are pinned to.
    cpu: usize,
    /// Repetitions per workload.
    reps: usize,
    /// Fewer operations per run.
    quick: bool,
}

impl Bench {
    /// Runs `workload` [`Self::reps`] times, without and with fsblame.
    fn measure<'w>(&self, workload: &'w Workload) -> Result<Outcome<'w>> {
        let n = if self.quick {
            workload.quick_ops
        } else {
            workload.ops
        };
        // Warm the page and dentry caches, so the first timed run is not the slowest.
        self.time(workload, (n / 10).max(1)).context("warming up")?;
        let runs = (1..=self.reps)
            .map(|rep| {
                eprintln!(
                    "bench: {} ({n} ops), run {rep}/{}",
                    workload.name, self.reps
                );
                let without = || self.time(workload, n).context("running without fsblame");
                // Odd repetitions run without fsblame first, even ones last, so a drift
                // (clock speed, temperature) favours neither side.
                let first = if rep % 2 == 1 { Some(without()?) } else { None };
                let mut watch = Watch::start(&self.fsblame, &self.tree.watched)?;
                let with = self.time(workload, n).context("running with fsblame")?;
                let usage = watch.settle()?;
                let tally = watch.stop()?;
                Ok(Run {
                    without: match first {
                        Some(took) => took,
                        None => without()?,
                    },
                    with,
                    cpu: usage.cpu,
                    peak_rss_kib: usage.peak_rss_kib,
                    tally,
                })
            })
            .collect::<Result<_>>()?;
        Ok(Outcome { workload, n, runs })
    }

    /// Times `n` operations of `workload` on the bench CPU. Only the workload is pinned:
    /// threads started meanwhile (the watcher's readers) would inherit the pin.
    fn time(&self, workload: &Workload, n: u32) -> Result<Duration> {
        let _pin = Pin::to(self.cpu)?;
        (workload.run)(&self.tree, n)
    }

    /// The `--json` report.
    fn report(&self, host: &Host, outcomes: &[Outcome<'_>]) -> Value {
        json!({
            "fsblame": self.fsblame.bin.to_string_lossy(),
            "kernel": host.kernel,
            "cpu": host.cpu,
            "cpus": host.cpus,
            "pinned_cpu": self.cpu,
            "repetitions": self.reps,
            "quick": self.quick,
            "workloads": outcomes.iter().map(Outcome::json).collect::<Vec<_>>(),
        })
    }

    fn print_table(&self, host: &Host, outcomes: &[Outcome<'_>]) {
        println!("fsblame bench: {}", self.fsblame.bin.display());
        println!(
            "Linux {}, {} ({} CPUs); workloads on CPU {}; median of {} run{}",
            host.kernel,
            host.cpu,
            host.cpus,
            self.cpu,
            self.reps,
            if self.reps == 1 { "" } else { "s" }
        );
        println!();
        println!(
            "{:<14} {:>7} {:>11} {:>11} {:>9} {:>7} {:>8} {:>7} {:>9} {:>7} {:>9}",
            "workload",
            "ops",
            "without/s",
            "with/s",
            "overhead",
            "cpu",
            "cpu/op",
            "touches",
            "ring lost",
            "evicted",
            "peak rss"
        );
        for outcome in outcomes {
            println!(
                "{:<14} {:>7} {:>11.0} {:>11.0} {:>+8.1}% {:>6.2}s {:>6.1}us {:>7} {:>9} {:>7} \
                 {:>5.1} MiB",
                outcome.workload.name,
                outcome.n,
                rate(outcome.n, outcome.without()),
                rate(outcome.n, outcome.with()),
                outcome.overhead_pct(),
                outcome.cpu().as_secs_f64(),
                outcome.cpu_us_per_op(),
                outcome.touches(),
                outcome.ring_full(),
                outcome.write_evicted(),
                f64::from(outcome.peak_rss_kib()) / 1024.0,
            );
        }
        println!();
        println!("overhead: extra time per operation with fsblame attached");
        println!("cpu:      fsblame's CPU time from attaching until it had reported the workload");
        println!(
            "lost:     kernel records dropped with the ring buffer full; write counts evicted"
        );
        println!("peak rss: fsblame's VmHWM");
    }
}

/// Pins the calling thread to one CPU until dropped, so the runs with and without fsblame
/// are timed on the same core: the cores of a hybrid CPU differ severalfold.
struct Pin {
    /// The affinity to restore.
    previous: libc::cpu_set_t,
}

impl Pin {
    fn to(cpu: usize) -> Result<Self> {
        let previous = affinity()?;
        let mut only = empty_cpu_set();
        // SAFETY: `cpu` came from iterating over the bits of a set.
        unsafe { libc::CPU_SET(cpu, &mut only) };
        set_affinity(&only).with_context(|| format!("pinning to CPU {cpu}"))?;
        Ok(Self { previous })
    }
}

impl Drop for Pin {
    fn drop(&mut self) {
        if let Err(e) = set_affinity(&self.previous) {
            eprintln!("bench: restoring the CPU affinity: {e}");
        }
    }
}

/// The CPU the workloads run on: the fastest one this process may use (highest
/// `cpuinfo_max_freq`), the last of equals, as CPU 0 takes more interrupts.
fn fastest_cpu() -> Result<usize> {
    let allowed = affinity()?;
    let max_freq = |cpu: usize| -> u64 {
        fs::read_to_string(format!(
            "/sys/devices/system/cpu/cpu{cpu}/cpufreq/cpuinfo_max_freq"
        ))
        .ok()
        .and_then(|freq| freq.trim().parse().ok())
        .unwrap_or(0)
    };
    (0..8 * size_of::<libc::cpu_set_t>())
        // SAFETY: `cpu` is below the number of bits in the set.
        .filter(|&cpu| unsafe { libc::CPU_ISSET(cpu, &allowed) })
        .max_by_key(|&cpu| (max_freq(cpu), cpu))
        .context("this process may run on no CPU")
}

/// The calling thread's CPU affinity.
fn affinity() -> Result<libc::cpu_set_t> {
    let mut set = empty_cpu_set();
    // SAFETY: the kernel writes at most the given size into `set`.
    let got = unsafe { libc::sched_getaffinity(0, size_of::<libc::cpu_set_t>(), &raw mut set) };
    ensure!(
        got == 0,
        "sched_getaffinity: {}",
        io::Error::last_os_error()
    );
    Ok(set)
}

/// Sets the calling thread's CPU affinity.
fn set_affinity(set: &libc::cpu_set_t) -> io::Result<()> {
    // SAFETY: the kernel reads the given size from `set`.
    if unsafe { libc::sched_setaffinity(0, size_of::<libc::cpu_set_t>(), set) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn empty_cpu_set() -> libc::cpu_set_t {
    // SAFETY: a cpu_set_t is an array of integers; all zeros is the empty set.
    unsafe { mem::zeroed() }
}

/// Spawns `/bin/true` `n` times, waiting for each: the fork, exec and exit tracepoints (the
/// exec record carries the environment, argv and cwd) and fsblame's process table, with
/// nothing changed in the watched tree.
fn exec_storm(_tree: &Tree, n: u32) -> Result<Duration> {
    let env: Vec<CString> = env::vars_os()
        .map(|(key, value)| {
            let mut entry = key.into_vec();
            entry.push(b'=');
            entry.extend_from_slice(value.as_bytes());
            CString::new(entry)
        })
        .collect::<Result<_, _>>()
        .context("environment")?;
    let envp: Vec<*mut libc::c_char> = env
        .iter()
        .map(|entry| entry.as_ptr().cast_mut())
        .chain([ptr::null_mut()])
        .collect();
    let argv = [TRUE.as_ptr().cast_mut(), ptr::null_mut()];
    let start = Instant::now();
    for _ in 0..n {
        let mut pid = 0;
        // SAFETY: `argv` and `envp` are null-terminated arrays of C strings that outlive the
        // call; posix_spawn does not write through them.
        let err = unsafe {
            libc::posix_spawn(
                &raw mut pid,
                TRUE.as_ptr(),
                ptr::null(),
                ptr::null(),
                argv.as_ptr(),
                envp.as_ptr(),
            )
        };
        ensure!(
            err == 0,
            "spawning /bin/true: {}",
            io::Error::from_raw_os_error(err)
        );
        let mut status = 0;
        // SAFETY: waits for the child just spawned.
        let waited = unsafe { libc::waitpid(pid, &raw mut status, 0) };
        ensure!(
            waited == pid,
            "waiting for /bin/true: {}",
            io::Error::last_os_error()
        );
        ensure!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "/bin/true failed (wait status {status:#x})"
        );
    }
    Ok(start.elapsed())
}

/// Creates `n` files in `watched/churn`, writes 4 KiB to each, closes, renames and unlinks
/// it: four reported changes per file, through the hot path of every fentry hook involved
/// (scope walk, path emission) and of fsblame's reporting.
fn file_churn(tree: &Tree, n: u32) -> Result<Duration> {
    /// Runs so far: every run names its files afresh, so none finds the negative dentries of
    /// an earlier one.
    static RUNS: AtomicU32 = AtomicU32::new(0);
    let run = RUNS.fetch_add(1, Ordering::Relaxed);
    let dir =
        File::open(&tree.churn).with_context(|| format!("opening {}", tree.churn.display()))?;
    let dir = dir.as_raw_fd();
    let mode: libc::mode_t = 0o644;
    let block = [0x5a_u8; BLOCK];
    let (mut created, mut renamed) = ([0_u8; 32], [0_u8; 32]);
    let start = Instant::now();
    for i in 0..n {
        let from = churn_name(&mut created, run, i, "");
        let to = churn_name(&mut renamed, run, i, ".r");
        // SAFETY: `from` is a C string; the new descriptor is owned right below.
        let fd = unsafe {
            libc::openat(
                dir,
                from.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC,
                mode,
            )
        };
        ensure!(fd >= 0, "creating {from:?}: {}", io::Error::last_os_error());
        // SAFETY: `fd` was just opened and nothing else owns it.
        File::from(unsafe { OwnedFd::from_raw_fd(fd) })
            .write_all(&block)
            .with_context(|| format!("writing {from:?}"))?;
        // SAFETY: both names are C strings relative to the open directory.
        let moved = unsafe { libc::renameat(dir, from.as_ptr(), dir, to.as_ptr()) };
        ensure!(
            moved == 0,
            "renaming {from:?}: {}",
            io::Error::last_os_error()
        );
        // SAFETY: as above.
        let removed = unsafe { libc::unlinkat(dir, to.as_ptr(), 0) };
        ensure!(
            removed == 0,
            "removing {to:?}: {}",
            io::Error::last_os_error()
        );
    }
    Ok(start.elapsed())
}

/// Writes `{run}-{i}{suffix}` and a NUL into `buf` and returns that name.
fn churn_name<'b>(buf: &'b mut [u8; 32], run: u32, i: u32, suffix: &str) -> &'b CStr {
    let mut rest = &mut buf[..];
    write!(rest, "{run}-{i}{suffix}\0").expect("two numbers and a short suffix fit in 32 bytes");
    CStr::from_bytes_until_nul(buf).expect("the name ends with a NUL")
}

/// Small writes to `watched/small`: each passes `rw_verify_area` and
/// `security_file_permission(MAY_WRITE)`; the kernel counts them and fsblame reports one
/// write per second of them.
fn writes_inside(tree: &Tree, n: u32) -> Result<Duration> {
    small_writes(&tree.inside, n)
}

/// The same writes to `outside/small`, on the watched filesystem but outside the tree: what
/// every unrelated write pays (the device filter and the verdict cache).
fn writes_outside(tree: &Tree, n: u32) -> Result<Duration> {
    small_writes(&tree.outside, n)
}

/// `n` 64-byte `pwrite(2)`s to `path`, cycling through its first 4 KiB, so every call does
/// the same page cache work.
fn small_writes(path: &Path, n: u32) -> Result<Duration> {
    let file = OpenOptions::new()
        .write(true)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    let data = [0x5a_u8; SMALL];
    let mut offset = 0;
    let start = Instant::now();
    for _ in 0..n {
        file.write_all_at(&data, offset)
            .with_context(|| format!("writing {}", path.display()))?;
        offset = (offset + SMALL as u64) % BLOCK as u64;
    }
    Ok(start.elapsed())
}

/// Maps `watched/mapped` shared and writable and unmaps it, `n` times through one open file:
/// `security_mmap_file` scopes every call; fsblame reports the first.
fn mmap_churn(tree: &Tree, n: u32) -> Result<Duration> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&tree.mapped)
        .with_context(|| format!("opening {}", tree.mapped.display()))?;
    let start = Instant::now();
    for _ in 0..n {
        // SAFETY: a new shared mapping of the open file, at an address the kernel picks;
        // nothing reads or writes through it.
        let map = unsafe {
            libc::mmap(
                ptr::null_mut(),
                BLOCK,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                file.as_raw_fd(),
                0,
            )
        };
        ensure!(
            map != libc::MAP_FAILED,
            "mapping {}: {}",
            tree.mapped.display(),
            io::Error::last_os_error()
        );
        // SAFETY: unmaps exactly the mapping made above.
        let unmapped = unsafe { libc::munmap(map, BLOCK) };
        ensure!(
            unmapped == 0,
            "unmapping {}: {}",
            tree.mapped.display(),
            io::Error::last_os_error()
        );
    }
    Ok(start.elapsed())
}

/// The scratch tree the workloads run in, removed when dropped.
struct Tree {
    root: PathBuf,
    /// The directory fsblame watches.
    watched: PathBuf,
    /// `watched/churn`, where the churn files come and go.
    churn: PathBuf,
    /// `watched/small`, for the writes inside.
    inside: PathBuf,
    /// `watched/mapped`, for the mmap churn.
    mapped: PathBuf,
    /// `outside/small`: on the same filesystem, not watched.
    outside: PathBuf,
}

impl Tree {
    /// Creates the tree at `root`, replacing whatever an interrupted run left there. Its
    /// files exist before fsblame starts, so their creation is never reported.
    fn create(root: PathBuf) -> Result<Self> {
        if root.exists() {
            fs::remove_dir_all(&root).with_context(|| format!("removing {}", root.display()))?;
        }
        let watched = root.join("watched");
        let tree = Self {
            churn: watched.join("churn"),
            inside: watched.join("small"),
            mapped: watched.join("mapped"),
            outside: root.join("outside/small"),
            watched,
            root,
        };
        for dir in [&tree.churn, &tree.root.join("outside")] {
            fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        }
        for file in [&tree.inside, &tree.mapped, &tree.outside] {
            fs::write(file, [0_u8; BLOCK])
                .with_context(|| format!("creating {}", file.display()))?;
        }
        Ok(tree)
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        if let Err(e) = fs::remove_dir_all(&self.root) {
            eprintln!("bench: removing {}: {e}", self.root.display());
        }
    }
}

/// The binary under test.
struct Fsblame {
    bin: PathBuf,
    /// Its process name, as `/proc/<pid>/stat` shows it.
    comm: Vec<u8>,
    /// Clock ticks per second, the unit of CPU times in `/proc/<pid>/stat`.
    hz: u32,
}

impl Fsblame {
    fn new(bin: PathBuf) -> Result<Self> {
        let name = bin.file_name().context("--bin names no file")?.as_bytes();
        let comm = name[..name.len().min(COMM_MAX)].to_vec();
        // SAFETY: sysconf only reads a system constant.
        let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
        let hz = u32::try_from(hz)
            .ok()
            .filter(|&hz| hz > 0)
            .context("sysconf(_SC_CLK_TCK)")?;
        Ok(Self { bin, comm, hz })
    }
}

/// A running `sudo -n fsblame watch --json`, its output tallied as it arrives.
struct Watch {
    sudo: Child,
    /// fsblame itself, below sudo.
    pid: Option<u32>,
    /// Clock ticks per second.
    hz: u32,
    /// fsblame's CPU time when it attached, in clock ticks.
    attached_ticks: u64,
    /// Output lines so far.
    lines: Arc<AtomicU64>,
    stdout: Option<JoinHandle<Tally>>,
    stderr: Option<JoinHandle<String>>,
}

/// What fsblame used until it had reported a workload.
struct Usage {
    /// CPU time since attaching.
    cpu: Duration,
    /// Peak resident set (`VmHWM`), KiB.
    peak_rss_kib: u32,
}

impl Watch {
    /// Starts fsblame on `dir` and waits until every probe is attached.
    fn start(fsblame: &Fsblame, dir: &Path) -> Result<Self> {
        let mut sudo = Command::new("sudo")
            .arg("-n")
            .arg(&fsblame.bin)
            .args(["watch", "--json", "--duration", MAX_RUN])
            .arg(dir)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            // Its own process group, so a hung run can be killed as a whole.
            .process_group(0)
            .spawn()
            .context("starting sudo -n fsblame")?;
        let out = sudo.stdout.take().context("stdout")?;
        let err = sudo.stderr.take().context("stderr")?;
        let lines = Arc::new(AtomicU64::new(0));
        let counted = Arc::clone(&lines);
        let (ready_tx, ready_rx) = mpsc::channel();
        let mut watch = Self {
            sudo,
            pid: None,
            hz: fsblame.hz,
            attached_ticks: 0,
            lines,
            stdout: Some(thread::spawn(move || tally(out, &counted))),
            stderr: Some(thread::spawn(move || collect_stderr(err, &ready_tx))),
        };
        let deadline = Instant::now() + READY_TIMEOUT;
        loop {
            match ready_rx.recv_timeout(SAMPLE) {
                Ok(()) => break,
                // stderr closed without the line: fsblame has exited.
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    let status = watch.sudo.wait()?;
                    bail!(
                        "fsblame exited before attaching ({status}):\n{}",
                        watch.stderr_text()
                    );
                }
                Err(mpsc::RecvTimeoutError::Timeout) if Instant::now() >= deadline => {
                    watch.kill();
                    bail!(
                        "fsblame did not attach within {READY_TIMEOUT:?}:\n{}",
                        watch.stderr_text()
                    );
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
        }
        let pid = find_process(&fsblame.comm, Some(watch.sudo.id()))?
            .context("fsblame is attached, but its process is not found below sudo")?;
        watch.pid = Some(pid);
        watch.attached_ticks = Stat::read(pid)?.cpu_ticks;
        Ok(watch)
    }

    /// Waits until fsblame has reported everything the workload did (its output has been
    /// still for [`SETTLE`]), and returns what it used until then.
    fn settle(&mut self) -> Result<Usage> {
        let pid = self.pid.context("fsblame pid")?;
        let deadline = Instant::now() + SETTLE_TIMEOUT;
        let mut seen = self.lines.load(Ordering::Relaxed);
        let mut still_since = Instant::now();
        loop {
            thread::sleep(SAMPLE);
            if let Some(status) = self.sudo.try_wait()? {
                bail!(
                    "fsblame exited during the workload ({status}):\n{}",
                    self.stderr_text()
                );
            }
            let now = Instant::now();
            let lines = self.lines.load(Ordering::Relaxed);
            if lines != seen {
                seen = lines;
                still_since = now;
            } else if now - still_since >= SETTLE {
                break;
            }
            ensure!(
                now < deadline,
                "fsblame was still reporting {SETTLE_TIMEOUT:?} after the workload"
            );
        }
        let ticks = Stat::read(pid)?.cpu_ticks - self.attached_ticks;
        Ok(Usage {
            cpu: Duration::from_secs(ticks) / self.hz,
            peak_rss_kib: peak_rss_kib(pid)?,
        })
    }

    /// SIGINT (sudo relays it), then waits for a clean exit and returns the tally.
    fn stop(mut self) -> Result<Tally> {
        let pid = i32::try_from(self.sudo.id()).context("pid")?;
        // SAFETY: plain syscall on our own child.
        unsafe { libc::kill(pid, libc::SIGINT) };
        let deadline = Instant::now() + STOP_TIMEOUT;
        let status = loop {
            if let Some(status) = self.sudo.try_wait()? {
                break status;
            }
            if Instant::now() >= deadline {
                self.kill();
                bail!(
                    "fsblame did not exit within {STOP_TIMEOUT:?} of SIGINT:\n{}",
                    self.stderr_text()
                );
            }
            thread::sleep(Duration::from_millis(20));
        };
        let stderr = self.stderr_text();
        ensure!(
            status.success(),
            "fsblame exited with {status} after SIGINT:\n{stderr}"
        );
        let tally = self
            .stdout
            .take()
            .context("stdout")?
            .join()
            .map_err(|_| anyhow!("stdout reader panicked"))?;
        if let Some(line) = &tally.malformed {
            bail!("fsblame wrote an unexpected line: {line}");
        }
        Ok(tally)
    }

    /// Kills sudo's process group, and fsblame, which sudo runs in a session of its own when
    /// it gives the command a pseudo-terminal.
    fn kill(&mut self) {
        let mut kill = Command::new("sudo");
        kill.args(["-n", "kill", "-KILL", "--"])
            .arg(format!("-{}", self.sudo.id()));
        if let Some(pid) = self.pid {
            kill.arg(pid.to_string());
        }
        let _ = kill.stdout(Stdio::null()).stderr(Stdio::null()).status();
        let _ = self.sudo.wait();
    }

    /// fsblame's stderr, once it has exited.
    fn stderr_text(&mut self) -> String {
        self.stderr
            .take()
            .and_then(|reader| reader.join().ok())
            .unwrap_or_default()
    }
}

impl Drop for Watch {
    fn drop(&mut self) {
        if matches!(self.sudo.try_wait(), Ok(None)) {
            self.kill();
        }
    }
}

/// What fsblame's NDJSON reported.
#[derive(Default)]
struct Tally {
    touches: u64,
    /// Records the kernel dropped because the ring buffer was full.
    ring_full: u64,
    /// Write bindings evicted from the kernel's write table before their totals were read.
    write_evicted: u64,
    /// The first line that is neither a touch nor a loss, with why.
    malformed: Option<String>,
}

impl Tally {
    /// Adds a line that does not start like a touch.
    fn add(&mut self, line: &[u8]) -> Result<()> {
        let line: Value = serde_json::from_slice(line)?;
        match line["type"].as_str() {
            Some("touch") => self.touches += 1,
            Some("lost") => {
                let count = line["count"].as_u64().context("no count")?;
                match line["reason"].as_str() {
                    Some("ring-full") => self.ring_full += count,
                    Some("write-evicted") => self.write_evicted += count,
                    other => bail!("unknown loss reason {other:?}"),
                }
            }
            other => bail!("unknown line type {other:?}"),
        }
        Ok(())
    }
}

/// Tallies fsblame's output until it closes, counting lines into `lines` as they arrive.
fn tally(out: ChildStdout, lines: &AtomicU64) -> Tally {
    let mut reader = BufReader::with_capacity(1 << 16, out);
    let mut line = Vec::new();
    let mut tally = Tally::default();
    // A read error ends the output like EOF does; the exit status tells what happened.
    while reader.read_until(b'\n', &mut line).is_ok_and(|len| len > 0) {
        lines.fetch_add(1, Ordering::Relaxed);
        if line.starts_with(TOUCH_PREFIX) {
            tally.touches += 1;
        } else if let Err(e) = tally.add(&line)
            && tally.malformed.is_none()
        {
            tally.malformed = Some(format!("{e}: {}", String::from_utf8_lossy(&line)));
        }
        line.clear();
    }
    tally
}

/// Collects fsblame's stderr until it closes, signalling `ready` at `fsblame: watching`.
fn collect_stderr(err: ChildStderr, ready: &mpsc::Sender<()>) -> String {
    let mut reader = BufReader::new(err);
    let mut line = Vec::new();
    let mut text = String::new();
    while reader.read_until(b'\n', &mut line).is_ok_and(|len| len > 0) {
        if line.starts_with(b"fsblame: watching ") {
            let _ = ready.send(());
        }
        text.push_str(&String::from_utf8_lossy(&line));
        line.clear();
    }
    text
}

/// The parts of `/proc/<pid>/stat` the bench uses.
struct Stat {
    comm: Vec<u8>,
    ppid: u32,
    /// User plus system CPU time, in clock ticks.
    cpu_ticks: u64,
}

impl Stat {
    fn read(pid: u32) -> Result<Self> {
        let path = format!("/proc/{pid}/stat");
        let raw = fs::read(&path).with_context(|| format!("reading {path}"))?;
        Self::parse(&raw).with_context(|| format!("unexpected {path}"))
    }

    fn parse(raw: &[u8]) -> Option<Self> {
        // `pid (comm) state ppid ...`, where comm may hold spaces and parentheses.
        let open = raw.iter().position(|&b| b == b'(')?;
        let close = raw.iter().rposition(|&b| b == b')')?;
        let fields: Vec<&str> = std::str::from_utf8(raw.get(close + 1..)?)
            .ok()?
            .split_ascii_whitespace()
            .collect();
        // Field numbers as in proc_pid_stat(5); `fields` starts at field 3.
        let field = |n: usize| fields.get(n - 3)?.parse::<u64>().ok();
        Some(Self {
            comm: raw.get(open + 1..close)?.to_vec(),
            ppid: u32::try_from(field(4)?).ok()?,
            cpu_ticks: field(14)? + field(15)?,
        })
    }
}

/// A process named `comm`, if one runs; with `below`, only a descendant of that process.
fn find_process(comm: &[u8], below: Option<u32>) -> Result<Option<u32>> {
    let mut procs = HashMap::new();
    for entry in fs::read_dir("/proc").context("reading /proc")? {
        let Some(pid) = entry?
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        // A process may exit while /proc is read.
        if let Ok(stat) = Stat::read(pid) {
            procs.insert(pid, stat);
        }
    }
    // Bounded: a pid reused while /proc was read could close a cycle.
    let descends = |pid: u32, ancestor: u32| {
        iter::successors(Some(pid), |pid| procs.get(pid).map(|stat| stat.ppid))
            .skip(1)
            .take(procs.len())
            .any(|pid| pid == ancestor)
    };
    Ok(procs
        .iter()
        .find(|&(&pid, stat)| {
            stat.comm == comm && below.is_none_or(|ancestor| descends(pid, ancestor))
        })
        .map(|(&pid, _)| pid))
}

/// Peak resident set (`VmHWM`) of a process, KiB.
fn peak_rss_kib(pid: u32) -> Result<u32> {
    let path = format!("/proc/{pid}/status");
    fs::read_to_string(&path)
        .with_context(|| format!("reading {path}"))?
        .lines()
        .find_map(|line| line.strip_prefix("VmHWM:"))
        .and_then(|value| value.trim().strip_suffix(" kB")?.trim().parse().ok())
        .with_context(|| format!("no VmHWM in {path}"))
}

/// The machine the numbers come from.
struct Host {
    kernel: String,
    cpu: String,
    cpus: usize,
}

impl Host {
    fn read() -> Self {
        let kernel = fs::read_to_string("/proc/sys/kernel/osrelease").map_or_else(
            |_| "unknown".to_owned(),
            |release| release.trim().to_owned(),
        );
        let cpu = fs::read_to_string("/proc/cpuinfo")
            .ok()
            .and_then(|info| {
                info.lines()
                    .find_map(|line| line.strip_prefix("model name")?.split_once(':'))
                    .map(|(_, model)| model.trim().to_owned())
            })
            .unwrap_or_else(|| "unknown CPU".to_owned());
        let cpus = thread::available_parallelism().map_or(1, std::num::NonZero::get);
        Self { kernel, cpu, cpus }
    }
}

/// One repetition of a workload.
struct Run {
    without: Duration,
    with: Duration,
    /// fsblame's CPU time from attaching until it had reported the workload.
    cpu: Duration,
    /// fsblame's peak resident set (`VmHWM`), KiB.
    peak_rss_kib: u32,
    tally: Tally,
}

/// The repetitions of a workload: medians of the times, CPU and touches, maxima of the
/// losses and the peak resident set.
struct Outcome<'w> {
    workload: &'w Workload,
    /// Operations per run.
    n: u32,
    runs: Vec<Run>,
}

impl Outcome<'_> {
    fn without(&self) -> Duration {
        median(self.runs.iter().map(|run| run.without))
    }

    fn with(&self) -> Duration {
        median(self.runs.iter().map(|run| run.with))
    }

    fn cpu(&self) -> Duration {
        median(self.runs.iter().map(|run| run.cpu))
    }

    fn touches(&self) -> u64 {
        median(self.runs.iter().map(|run| run.tally.touches))
    }

    fn ring_full(&self) -> u64 {
        self.runs
            .iter()
            .map(|run| run.tally.ring_full)
            .max()
            .unwrap_or(0)
    }

    fn write_evicted(&self) -> u64 {
        self.runs
            .iter()
            .map(|run| run.tally.write_evicted)
            .max()
            .unwrap_or(0)
    }

    fn peak_rss_kib(&self) -> u32 {
        self.runs
            .iter()
            .map(|run| run.peak_rss_kib)
            .max()
            .unwrap_or(0)
    }

    /// Extra time per operation with fsblame attached, percent.
    fn overhead_pct(&self) -> f64 {
        (self.with().as_secs_f64() / self.without().as_secs_f64() - 1.0) * 100.0
    }

    /// fsblame's CPU time per operation, microseconds.
    fn cpu_us_per_op(&self) -> f64 {
        self.cpu().as_secs_f64() * 1e6 / f64::from(self.n)
    }

    fn json(&self) -> Value {
        let runs: Vec<Value> = self
            .runs
            .iter()
            .map(|run| {
                json!({
                    "without_s": run.without.as_secs_f64(),
                    "with_s": run.with.as_secs_f64(),
                    "fsblame_cpu_s": run.cpu.as_secs_f64(),
                    "touches": run.tally.touches,
                    "lost": {
                        "ring_full": run.tally.ring_full,
                        "write_evicted": run.tally.write_evicted,
                    },
                    "peak_rss_kib": run.peak_rss_kib,
                })
            })
            .collect();
        json!({
            "id": self.workload.id,
            "name": self.workload.name,
            "ops": self.n,
            "without_ops_per_s": rate(self.n, self.without()),
            "with_ops_per_s": rate(self.n, self.with()),
            "overhead_pct": self.overhead_pct(),
            "fsblame_cpu_s": self.cpu().as_secs_f64(),
            "fsblame_cpu_us_per_op": self.cpu_us_per_op(),
            "touches": self.touches(),
            "lost": {
                "ring_full": self.ring_full(),
                "write_evicted": self.write_evicted(),
            },
            "peak_rss_kib": self.peak_rss_kib(),
            "runs": runs,
        })
    }
}

/// The middle value (the upper middle one of an even count). `values` is never empty.
fn median<T: Ord>(values: impl Iterator<Item = T>) -> T {
    let mut values: Vec<T> = values.collect();
    values.sort_unstable();
    let middle = values.len() / 2;
    values.swap_remove(middle)
}

/// Operations per second.
fn rate(n: u32, took: Duration) -> f64 {
    f64::from(n) / took.as_secs_f64()
}
