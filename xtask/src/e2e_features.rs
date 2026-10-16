//! End-to-end scenarios s to ac: the features beyond reporting single operations.
//!
//! Shared writable mappings (s), the cwd captured at exec (t), `run` (u), `watch --tree` (v),
//! the filters (w), `record` and `blame` (x), completions (y), the output options (z), write
//! identity (aa), exec attribution (ab) and confirmed creates (ac). A scenario that compares
//! options starts one fsblame per option at once ([`start_all`]): each loads its own programs
//! and sees the same workload.

use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    ffi::{CStr, OsStr},
    fs::{self, File, OpenOptions},
    io::{self, Read, Write as _},
    os::{
        fd::{AsRawFd as _, FromRawFd as _},
        unix::{ffi::OsStrExt as _, fs::MetadataExt as _, process::CommandExt as _},
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    ptr, thread,
    time::{Duration, Instant},
};

use anyhow::{Context as _, Result, anyhow, bail, ensure};
use serde_json::{Value, json};

use crate::{Ctx, Finished, MAX_RUN, READY_TIMEOUT, Watcher, sh, summary, text, touch};

/// Longest a scenario waits for its own background workload to make progress.
const PROGRESS_TIMEOUT: Duration = Duration::from_secs(10);
/// Longest `fsblame run` may take once attached.
const RUN_TIMEOUT: Duration = Duration::from_secs(15);
/// A pid no process can have: the kernel's pids stay below `PID_MAX_LIMIT` (4194304).
const NO_PID: &str = "4194304";

/// `sudo -n fsblame`.
fn fsblame(ctx: &Ctx) -> Command {
    let mut cmd = Command::new("sudo");
    cmd.arg("-n").arg(&ctx.bin);
    cmd
}

/// `sudo -n fsblame watch --json` with `args` on `paths`, as [`Ctx::watch`] runs it.
fn watch_json(ctx: &Ctx, args: &[&str], paths: &[&Path]) -> Command {
    let mut cmd = fsblame(ctx);
    cmd.args(["watch", "--json", "--duration", MAX_RUN])
        .args(args)
        .args(paths);
    cmd
}

/// `sudo -n fsblame watch --color WHEN` (the tree view) on `dir`.
fn watch_human(ctx: &Ctx, when: &str, dir: &Path) -> Command {
    let mut cmd = fsblame(ctx);
    cmd.args(["watch", "--color", when, "--duration", MAX_RUN])
        .arg(dir);
    cmd
}

/// `sudo -n PREFIX... sh -c 'exec fsblame ARGS DIR REDIRECT"$target"'`: fsblame with one of
/// its descriptors opened on `target` by root's shell, since sudo closes every descriptor
/// above stderr. `prefix` runs the shell, such as `env NO_COLOR=1`.
fn redirected(
    ctx: &Ctx,
    prefix: &[&str],
    redirect: &str,
    target: &Path,
    args: &[&str],
    dir: &Path,
) -> Command {
    let mut cmd = Command::new("sudo");
    cmd.arg("-n")
        .args(prefix)
        .args(["sh", "-c"])
        .arg(format!(
            r#"target=$1; shift; exec "$@" {redirect}"$target""#
        ))
        .arg("sh")
        .arg(target)
        .arg(&ctx.bin)
        .args(args)
        .arg(dir);
    cmd
}

/// When a watcher being started is ready.
#[derive(Clone, Copy)]
enum Ready<'a> {
    /// At its `fsblame: watching` banner, as [`Watcher::start`] waits for it.
    Banner,
    /// Once its `--ready-fd` wrote `ready` into this file: `-q` prints no banner.
    File(&'a Path),
}

/// Starts `cmd` (`sudo -n fsblame ...`) and waits until it is `ready`.
fn start(mut cmd: Command, ready: Ready<'_>) -> Result<Watcher> {
    let Ready::File(ready) = ready else {
        return Watcher::start(cmd);
    };
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .context("starting fsblame")?;
    let stdout = collect(child.stdout.take().context("stdout")?);
    let stderr = collect(child.stderr.take().context("stderr")?);
    let mut watcher = Watcher {
        child,
        stdout,
        stderr,
        ready_at: Instant::now(),
    };
    let deadline = Instant::now() + READY_TIMEOUT;
    while !fs::read(ready).is_ok_and(|said| said == b"ready\n") {
        if watcher.child.try_wait()?.is_some() {
            let done = watcher.join()?;
            bail!(
                "fsblame exited before it was ready ({}):\n{}",
                done.status,
                done.stderr
            );
        }
        if Instant::now() >= deadline {
            watcher.kill();
            let done = watcher.join()?;
            bail!(
                "fsblame was not ready within {READY_TIMEOUT:?}:\n{}",
                done.stderr
            );
        }
        thread::sleep(Duration::from_millis(20));
    }
    watcher.ready_at = Instant::now();
    Ok(watcher)
}

/// Reads `pipe` to its end on a thread of its own.
fn collect(mut pipe: impl Read + Send + 'static) -> thread::JoinHandle<String> {
    thread::spawn(move || {
        let mut out = String::new();
        let _ = pipe.read_to_string(&mut out);
        out
    })
}

/// Starts every watcher at once, each ready as given; if one fails, kills the others.
fn start_all<const N: usize>(launches: [(Command, Ready<'_>); N]) -> Result<[Watcher; N]> {
    let started: Vec<Result<Watcher>> = thread::scope(|s| {
        let handles: Vec<_> = launches
            .into_iter()
            .map(|(cmd, ready)| s.spawn(move || start(cmd, ready)))
            .collect();
        handles
            .into_iter()
            .map(|h| {
                h.join()
                    .unwrap_or_else(|_| Err(anyhow!("starting fsblame panicked")))
            })
            .collect()
    });
    let mut watchers = Vec::with_capacity(N);
    let mut failure = None;
    for result in started {
        match result {
            Ok(watcher) => watchers.push(watcher),
            Err(e) => {
                failure.get_or_insert(e);
            }
        }
    }
    if let Some(e) = failure {
        for mut watcher in watchers {
            watcher.kill();
            let _ = watcher.join();
        }
        return Err(e);
    }
    Ok(watchers
        .try_into()
        .unwrap_or_else(|_: Vec<Watcher>| unreachable!("one watcher per launch")))
}

/// Stops every watcher at once ([`Watcher::stop`]).
fn stop_all<const N: usize>(watchers: [Watcher; N]) -> Result<[Finished; N]> {
    let stopped = thread::scope(|s| {
        let handles: Vec<_> = watchers
            .into_iter()
            .map(|watcher| s.spawn(move || watcher.stop()))
            .collect();
        handles
            .into_iter()
            .map(|h| {
                h.join()
                    .unwrap_or_else(|_| Err(anyhow!("stopping fsblame panicked")))
            })
            .collect::<Result<Vec<_>>>()
    })?;
    Ok(stopped
        .try_into()
        .unwrap_or_else(|_: Vec<Finished>| unreachable!("one result per watcher")))
}

/// A workload process running beside a scenario; killed when dropped.
struct Background(Child);

impl Background {
    /// `sh -c script` in `dir`, as the invoking user.
    fn spawn(dir: &Path, script: &str) -> Result<Self> {
        Command::new("sh")
            .arg("-c")
            .arg(script)
            .current_dir(dir)
            .stdin(Stdio::null())
            .spawn()
            .map(Self)
            .with_context(|| format!("starting sh -c {script:?}"))
    }

    fn pid(&self) -> u32 {
        self.0.id()
    }
}

impl Drop for Background {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Removes the tree at `path`; with `sudo` if `root` owns it.
fn remove_tree(path: &Path, root: bool) {
    if root {
        let _ = Command::new("sudo")
            .args(["-n", "rm", "-rf", "--"])
            .arg(path)
            .status();
    } else {
        let _ = fs::remove_dir_all(path);
    }
}

/// Removes a tree ([`remove_tree`]) whatever happens.
struct RemoveTree<'a> {
    path: &'a Path,
    root: bool,
}

impl Drop for RemoveTree<'_> {
    fn drop(&mut self) {
        remove_tree(self.path, self.root);
    }
}

/// Polls until `done` holds; fails after [`PROGRESS_TIMEOUT`] naming `what` it waited for.
fn wait_until(what: &str, mut done: impl FnMut() -> bool) -> Result<()> {
    let deadline = Instant::now() + PROGRESS_TIMEOUT;
    while !done() {
        ensure!(Instant::now() < deadline, "timed out waiting for {what}");
        thread::sleep(Duration::from_millis(20));
    }
    Ok(())
}

/// Lines in the file at `path`; 0 while it does not exist.
fn line_count(path: &Path) -> usize {
    fs::read_to_string(path).map_or(0, |lines| lines.lines().count())
}

/// Runs `cmd` to its end and returns its stdout; fails unless it succeeds.
fn stdout_of(cmd: &mut Command) -> Result<String> {
    let out = cmd
        .stdin(Stdio::null())
        .output()
        .with_context(|| format!("running {cmd:?}"))?;
    ensure!(
        out.status.success(),
        "{cmd:?}: {}\n{}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).with_context(|| format!("{cmd:?} printed non-UTF-8"))
}

/// The NDJSON lines of `ndjson`.
fn parse(ndjson: &str) -> Result<Vec<Value>> {
    ndjson
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).with_context(|| format!("not JSON: {l}")))
        .collect()
}

/// The touch lines among `lines`. A `lost` line fails: these workloads are far too small for
/// fsblame to lose anything.
fn changes_in(lines: Vec<Value>) -> Result<Vec<Value>> {
    if let Some(lost) = lines.iter().find(|l| l["type"] == "lost") {
        bail!("fsblame lost data: {lost}");
    }
    Ok(lines.into_iter().filter(|l| l["type"] == "touch").collect())
}

/// The touches a finished watcher printed ([`changes_in`]).
fn changes(done: &Finished) -> Result<Vec<Value>> {
    changes_in(done.touches()?)
}

/// How many touches have `op` on `path`.
fn count(touches: &[Value], op: &str, path: &Path) -> usize {
    let path = text(path);
    touches
        .iter()
        .filter(|t| t["op"] == op && t["path"] == path.as_str())
        .count()
}

/// `op path by comm` per touch, with paths relative to `base`.
fn shape(touches: &[Value], base: &Path) -> Vec<String> {
    let base = format!("{}/", base.display());
    touches
        .iter()
        .map(|t| {
            let path = t["path"].as_str().unwrap_or("?");
            format!(
                "{} {} by {}",
                t["op"].as_str().unwrap_or("?"),
                path.strip_prefix(&base).unwrap_or(path),
                t["proc"]["comm"].as_str().unwrap_or("?")
            )
        })
        .collect()
}

/// The argv of a process of a touch's lineage.
fn argv(proc: &Value) -> Vec<&str> {
    proc["argv"]
        .as_array()
        .map(|args| args.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}

/// Whether process `pid` made `touch` or is one of its ancestors.
fn in_chain(touch: &Value, pid: u64) -> bool {
    touch["proc"]["pid"] == pid
        || touch["ancestry"]
            .as_array()
            .is_some_and(|ancestry| ancestry.iter().any(|p| p["pid"] == pid))
}

/// Whether the running kernel's BTF names `function`.
fn in_btf(function: &str) -> Result<bool> {
    let btf = fs::read("/sys/kernel/btf/vmlinux").context("reading /sys/kernel/btf/vmlinux")?;
    let name = [b"\0", function.as_bytes(), b"\0"].concat();
    Ok(btf.windows(name.len()).any(|w| w == name))
}

/// The `group` a summary counts `touch` under: its build step, else its process's comm.
fn group_of(touch: &Value) -> String {
    let origin = &touch["origin"];
    let group = if origin.is_null() {
        json!({ "comm": touch["proc"]["comm"] })
    } else {
        json!({ "origin": {
            "kind": origin["kind"],
            "package": origin["package"],
            "version": origin["version"],
            "phase": origin["phase"],
        } })
    };
    group.to_string()
}

/// Checks the summary line `summary` against the touches it summarises: the total, nothing
/// lost, and per group the changes, the counts per op and the distinct paths.
fn check_summary(summary: &Value, touches: &[Value]) -> Result<()> {
    ensure!(
        summary["type"] == "summary",
        "the last line is not the summary: {summary}"
    );
    ensure!(
        summary["changes"] == touches.len() as u64,
        "the summary counts {} changes, {} were reported",
        summary["changes"],
        touches.len()
    );
    ensure!(
        summary["lost"] == json!({ "ring_full": 0, "write_evicted": 0, "track_full": 0 }),
        "the summary reports losses: {}",
        summary["lost"]
    );
    let mut tally: BTreeMap<String, (BTreeMap<String, u64>, BTreeSet<&str>)> = BTreeMap::new();
    for t in touches {
        let (ops, paths) = tally.entry(group_of(t)).or_default();
        *ops.entry(t["op"].as_str().unwrap_or("?").to_owned())
            .or_default() += 1;
        paths.insert(t["path"].as_str().unwrap_or("?"));
    }
    let want: BTreeMap<String, (BTreeMap<String, u64>, u64)> = tally
        .into_iter()
        .map(|(group, (ops, paths))| (group, (ops, paths.len() as u64)))
        .collect();
    let mut got = BTreeMap::new();
    for g in summary["groups"]
        .as_array()
        .context("the summary has no groups")?
    {
        let ops: BTreeMap<String, u64> = g["ops"]
            .as_object()
            .with_context(|| format!("group without ops: {g}"))?
            .iter()
            .map(|(op, n)| (op.clone(), n.as_u64().unwrap_or(0)))
            .collect();
        ensure!(
            g["changes"].as_u64() == Some(ops.values().sum()),
            "group {} counts {} changes but {ops:?} by op",
            g["group"],
            g["changes"]
        );
        got.insert(
            g["group"].to_string(),
            (ops, g["paths"].as_u64().unwrap_or(0)),
        );
    }
    ensure!(
        got == want,
        "summary groups (ops, distinct paths) {got:?}, but the touches give {want:?}"
    );
    Ok(())
}

/// `text` without ANSI SGR sequences (`ESC [ ... m`).
fn plain(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find('\x1b') {
        out.push_str(&rest[..at]);
        rest = &rest[at..];
        rest = &rest[rest.find('m').map_or(rest.len(), |m| m + 1)..];
    }
    out.push_str(rest);
    out
}

/// The header lines of a tree view (one per change; its process tree is indented below).
fn headers(view: &str) -> usize {
    view.lines()
        .filter(|l| !l.is_empty() && !l.starts_with(' '))
        .count()
}

/// The blocks of a tree view (header and process tree) of the changes to paths ending in
/// `suffix`.
fn blocks_of(view: &str, suffix: &str) -> String {
    let mut out = String::new();
    let mut keep = false;
    for line in view.lines() {
        if !line.starts_with(' ') {
            keep = line
                .split("  ")
                .next()
                .is_some_and(|path| path.ends_with(suffix));
        }
        if keep {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

/// A pseudo-terminal for fsblame's stdout: root's shell opens the terminal by its path, and
/// this process reads what fsblame writes there from the master.
struct Pty {
    master: File,
    path: PathBuf,
}

impl Pty {
    /// A new pseudo-terminal; nothing has its terminal side open yet.
    fn open() -> Result<Self> {
        // SAFETY: opens a new descriptor, owned below.
        let fd = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC) };
        ensure!(fd >= 0, "posix_openpt: {}", io::Error::last_os_error());
        // SAFETY: `fd` is open and nothing else owns it.
        let master = unsafe { File::from_raw_fd(fd) };
        let mut name = [0u8; 128];
        // SAFETY: plain calls on the master; ptsname_r writes at most `name.len()` bytes.
        let ok = unsafe {
            libc::grantpt(fd) == 0
                && libc::unlockpt(fd) == 0
                && libc::ptsname_r(fd, name.as_mut_ptr().cast(), name.len()) == 0
        };
        ensure!(
            ok,
            "setting up a pseudo-terminal: {}",
            io::Error::last_os_error()
        );
        let path = CStr::from_bytes_until_nul(&name)
            .context("ptsname_r")?
            .to_bytes();
        Ok(Self {
            master,
            path: PathBuf::from(OsStr::from_bytes(path)),
        })
    }

    /// Reads what is written to the terminal until its last writer closes it, with the
    /// terminal's `\r\n` line ends as `\n`.
    fn read_to_end(mut self) -> thread::JoinHandle<String> {
        thread::spawn(move || {
            let mut bytes = Vec::new();
            // Ends with EIO once no process has the terminal open; what was read is kept.
            let _ = self.master.read_to_end(&mut bytes);
            String::from_utf8_lossy(&bytes).replace('\r', "")
        })
    }
}

/// Bytes of each file scenario s maps.
const MAP_LEN: usize = 4096;

/// A shared mapping of the first [`MAP_LEN`] bytes of a file; unmapped on drop.
struct Mapping {
    addr: *mut libc::c_void,
    writable: bool,
}

impl Mapping {
    /// Maps `file` shared with protection `prot`.
    fn new(file: &File, prot: libc::c_int) -> Result<Self> {
        // SAFETY: a new mapping of an open file at an address the kernel picks; nothing else
        // refers to it.
        let addr = unsafe {
            libc::mmap(
                ptr::null_mut(),
                MAP_LEN,
                prot,
                libc::MAP_SHARED,
                file.as_raw_fd(),
                0,
            )
        };
        ensure!(
            addr != libc::MAP_FAILED,
            "mmap: {}",
            io::Error::last_os_error()
        );
        Ok(Self {
            addr,
            writable: prot & libc::PROT_WRITE != 0,
        })
    }

    /// Changes the mapping's protection to `prot`.
    fn protect(&mut self, prot: libc::c_int) -> Result<()> {
        // SAFETY: changes the protection of this mapping only.
        ensure!(
            unsafe { libc::mprotect(self.addr, MAP_LEN, prot) } == 0,
            "mprotect: {}",
            io::Error::last_os_error()
        );
        self.writable = prot & libc::PROT_WRITE != 0;
        Ok(())
    }

    /// Stores `byte` at `offset` through the mapping.
    fn store(&self, offset: usize, byte: u8) {
        assert!(
            self.writable && offset < MAP_LEN,
            "store outside the mapping"
        );
        // SAFETY: the mapping is MAP_LEN bytes long and writable.
        unsafe { self.addr.cast::<u8>().add(offset).write_volatile(byte) };
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: unmaps this mapping, which nothing refers to past this point.
        unsafe { libc::munmap(self.addr, MAP_LEN) };
    }
}

/// s: stores through a shared mapping change a file without a write call. This process maps
/// one file twice through one open file (one report), and makes a read-only shared mapping
/// of another writable with `mprotect`.
pub(crate) fn mapped_writes(ctx: &Ctx) -> Result<String> {
    let dir = ctx.dir("s-mmap")?;
    let (mmapped, protected) = (dir.join("mmap.bin"), dir.join("mprotect.bin"));
    for path in [&mmapped, &protected] {
        fs::write(path, [0u8; MAP_LEN])?;
    }
    let open = |path: &Path| {
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .with_context(|| format!("opening {}", path.display()))
    };
    let watcher = ctx.watch(&[&dir])?;
    let file = open(&mmapped)?;
    for byte in [1, 2] {
        Mapping::new(&file, libc::PROT_READ | libc::PROT_WRITE)?.store(0, byte);
    }
    drop(file);
    let file = open(&protected)?;
    let mut mapping = Mapping::new(&file, libc::PROT_READ)?;
    mapping.protect(libc::PROT_READ | libc::PROT_WRITE)?;
    mapping.store(0, 1);
    drop(mapping);
    drop(file);
    let touches = changes(&watcher.stop()?)?;

    let me = u64::from(std::process::id());
    for (path, via) in [(&mmapped, "mmap"), (&protected, "mprotect")] {
        let name = text(path);
        let on: Vec<&Value> = touches
            .iter()
            .filter(|t| t["path"] == name.as_str())
            .collect();
        ensure!(
            matches!(&on[..], [t] if t["op"] == "write"
                && t["change"]["mapped"] == via
                && t["bytes"].is_null()
                && t["proc"]["pid"] == me),
            "expected one write by pid {me} with change.mapped {via:?} for {name}, got {on:?}"
        );
    }
    ensure!(
        touches.len() == 2,
        "only the two mappings were expected; {}",
        summary(&touches)
    );
    Ok("one write per open file: change.mapped mmap (mapped twice), mprotect".to_owned())
}

/// t: the kernel captures the cwd at exec, so a process that exits before fsblame could read
/// `/proc/<pid>/cwd` still has it.
pub(crate) fn exec_cwd(ctx: &Ctx) -> Result<String> {
    let dir = ctx.dir("t-cwd")?;
    let sub = dir.join("sub");
    fs::create_dir(&sub)?;
    fs::write(sub.join("a"), "a\n")?;
    let watcher = ctx.watch(&[&dir])?;
    sh(&dir, "cd sub && exec mv a b")?;
    let touches = changes(&watcher.stop()?)?;
    let t = touch(&touches, "rename", &sub.join("b"))?;
    let old = text(&sub.join("a"));
    ensure!(
        t["old_path"] == old.as_str(),
        "rename old_path is {}, expected {old}",
        t["old_path"]
    );
    ensure!(
        t["proc"]["comm"] == "mv",
        "rename attributed to {}",
        t["proc"]["comm"]
    );
    let cwd = text(&sub);
    ensure!(
        t["proc"]["cwd"] == cwd.as_str(),
        "mv's cwd is {}, expected {cwd}",
        t["proc"]["cwd"]
    );
    Ok(format!("mv's cwd {cwd}"))
}

/// The command of scenario u, run as `sh -c RUN_SCRIPT sh ELSEWHERE` in its directory.
const RUN_SCRIPT: &str = r#"echo $$ > pid; id -u > uid; echo data > new.txt; mv new.txt moved.txt; sleep 0.3; mkdir "$1"; echo far > "$1/far.txt""#;

/// u: `run` reports the command's changes wherever they are (its directory, and a directory
/// on another filesystem: tmpfs at `/dev/shm`), made as the invoking user, and nothing of a
/// process writing beside it; it exits with the command's status.
pub(crate) fn run_command(ctx: &Ctx) -> Result<String> {
    let dir = ctx.dir("u-run")?;
    // SAFETY: getuid cannot fail.
    let me = unsafe { libc::getuid() };
    // fsblame reports resolved paths.
    let elsewhere = fs::canonicalize("/dev/shm")
        .context("resolving /dev/shm")?
        .join(format!("fsblame-e2e-u-{me}"));
    remove_tree(&elsewhere, false);
    let _elsewhere = RemoveTree {
        path: &elsewhere,
        root: false,
    };
    let unrelated = dir.join("unrelated.txt");
    let _writer = Background::spawn(
        &dir,
        "while :; do echo u >> unrelated.txt; sleep 0.05; done",
    )?;
    wait_until("the unrelated writer", || line_count(&unrelated) > 0)?;

    let report = dir.join("report.ndjson");
    let mut cmd = fsblame(ctx);
    cmd.current_dir(&dir)
        .args(["run", "--json", "-o"])
        .arg(&report)
        .args(["--", "sh", "-c", RUN_SCRIPT, "sh"])
        .arg(&elsewhere);
    let mut exit7 = fsblame(ctx);
    exit7.args(["run", "--", "sh", "-c", "exit 7"]);
    let [watcher, exit7] = start_all([(cmd, Ready::Banner), (exit7, Ready::Banner)])?;
    let before = line_count(&unrelated);
    let done = watcher.wait(RUN_TIMEOUT)?;
    let during = line_count(&unrelated) - before;
    let status = exit7.wait(RUN_TIMEOUT)?.status;
    ensure!(
        status.code() == Some(7),
        "run -- sh -c 'exit 7' exited {status}"
    );
    ensure!(
        done.status.success(),
        "fsblame run exited {}:\n{}",
        done.status,
        done.stderr
    );
    ensure!(
        during > 0,
        "the unrelated writer did not write during the run"
    );

    let uid = fs::read_to_string(dir.join("uid"))?;
    ensure!(
        uid.trim() == me.to_string(),
        "the command ran as uid {}, not as the invoking uid {me}",
        uid.trim()
    );
    let touches = changes_in(parse(
        &fs::read_to_string(&report).with_context(|| format!("reading {}", report.display()))?,
    )?)?;
    check_run(&touches, &dir, &elsewhere, me)?;
    Ok(format!(
        "{} changes in {} and {} as uid {me}, none of {during} unrelated writes; exit 7 passed on",
        touches.len(),
        dir.display(),
        elsewhere.display()
    ))
}

/// Checks the changes `fsblame run` reported for [`RUN_SCRIPT`] run in `dir` with
/// `elsewhere`: each exactly once, by the right program, all by the command's processes as
/// uid `me`.
fn check_run(touches: &[Value], dir: &Path, elsewhere: &Path, me: u32) -> Result<()> {
    let root: u64 = fs::read_to_string(dir.join("pid"))?
        .trim()
        .parse()
        .context("the command's pid")?;
    let at = |name: &str| dir.join(name);
    let expected = [
        ("create", at("pid"), "sh"),
        ("write", at("pid"), "sh"),
        ("create", at("uid"), "sh"),
        ("write", at("uid"), "id"),
        ("create", at("new.txt"), "sh"),
        ("write", at("new.txt"), "sh"),
        ("rename", at("moved.txt"), "mv"),
        ("mkdir", elsewhere.to_owned(), "mkdir"),
        ("create", elsewhere.join("far.txt"), "sh"),
        ("write", elsewhere.join("far.txt"), "sh"),
    ];
    for (op, path, comm) in &expected {
        let n = count(touches, op, path);
        ensure!(
            n == 1,
            "{n} {op} touches for {}, expected 1; {}",
            path.display(),
            summary(touches)
        );
        let t = touch(touches, op, path)?;
        ensure!(
            t["proc"]["comm"] == *comm,
            "{op} {} attributed to {}, not {comm}",
            path.display(),
            t["proc"]["comm"]
        );
    }
    ensure!(
        touches.len() == expected.len(),
        "only the command's changes were expected; {}",
        summary(touches)
    );
    for t in touches {
        ensure!(
            in_chain(t, root) && t["uid"] == me && t["proc"]["uid"] == me,
            "{} {} is not by the command (pid {root}) as uid {me}: {}",
            t["op"],
            t["path"],
            t["proc"]
        );
    }
    let renamed = touch(touches, "rename", &at("moved.txt"))?;
    let old = text(&at("new.txt"));
    ensure!(
        renamed["old_path"] == old.as_str(),
        "rename old_path is {}, expected {old}",
        renamed["old_path"]
    );
    let parent = &touch(touches, "create", &at("pid"))?["ancestry"][0];
    ensure!(
        parent["comm"] == "fsblame",
        "the command's parent is {}, not fsblame",
        parent["comm"]
    );
    Ok(())
}

/// v: `watch --tree PID` reports the changes of that process and its descendants only.
pub(crate) fn tree(ctx: &Ctx) -> Result<String> {
    let dir = ctx.dir("v-tree")?;
    let (looped, child, other) = (
        dir.join("loop.txt"),
        dir.join("child.txt"),
        dir.join("other.txt"),
    );
    let tracked = Background::spawn(
        &dir,
        "while :; do echo x >> loop.txt; sh -c 'echo y >> child.txt'; sleep 0.1; done",
    )?;
    let _untracked = Background::spawn(&dir, "while :; do echo z >> other.txt; sleep 0.1; done")?;
    let pid = tracked.pid().to_string();
    if !Path::new("/proc/thread-self/children").exists() {
        let out = fsblame(ctx)
            .args(["watch", "--tree", &pid])
            .arg(&dir)
            .stdin(Stdio::null())
            .output()?;
        let stderr = String::from_utf8_lossy(&out.stderr);
        ensure!(
            out.status.code() == Some(5) && stderr.contains("CONFIG_PROC_CHILDREN"),
            "--tree without /proc/<pid>/task/<tid>/children: {}\n{stderr}",
            out.status
        );
        return Ok("this kernel lists no children (CONFIG_PROC_CHILDREN): --tree exits 5".into());
    }

    let watcher = Watcher::start(watch_json(ctx, &["--tree", &pid], &[&dir]))?;
    let (start, others) = (line_count(&looped), line_count(&other));
    wait_until("the tracked loop to write 3 times", || {
        line_count(&looped) >= start + 3
    })?;
    let touches = changes(&watcher.stop()?)?;
    ensure!(
        line_count(&other) > others,
        "the untracked writer did not write while watched"
    );
    let pid64 = u64::from(tracked.pid());
    let (looped, child) = (text(&looped), text(&child));
    ensure!(
        touches.iter().any(|t| t["op"] == "write"
            && t["path"] == looped.as_str()
            && t["proc"]["pid"] == pid64),
        "no write to {looped} by the tracked shell {pid}; {}",
        summary(&touches)
    );
    ensure!(
        touches.iter().any(|t| t["op"] == "write"
            && t["path"] == child.as_str()
            && t["ancestry"][0]["pid"] == pid64),
        "no write to {child} by a child of {pid}; {}",
        summary(&touches)
    );
    for t in &touches {
        ensure!(
            in_chain(t, pid64),
            "{} {} by {} (pid {}) is outside the tree of {pid}",
            t["op"],
            t["path"],
            t["proc"]["comm"],
            t["proc"]["pid"]
        );
    }

    let out = fsblame(ctx)
        .args(["watch", "--tree", NO_PID])
        .arg(&dir)
        .stdin(Stdio::null())
        .output()?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    ensure!(
        out.status.code() == Some(2) && stderr.contains("no such process"),
        "--tree {NO_PID}: {}, expected exit 2 for no such process:\n{stderr}",
        out.status
    );
    Ok(format!(
        "{} changes by {pid} and its children, none by the writer beside it; --tree {NO_PID} exits 2",
        touches.len()
    ))
}

/// Whether a filter of scenario w admits a change to the file `name` by `comm`.
type Admits<'a> = dyn Fn(&str, &str) -> bool + 'a;

/// w: each filter reports exactly the matching changes, and its summary counts only them.
/// One fsblame per filter watches the same workload.
pub(crate) fn filters(ctx: &Ctx) -> Result<String> {
    let dir = ctx.dir("w-filters")?;
    let own = fs::read_to_string("/proc/self/comm")?.trim_end().to_owned();
    let pid = std::process::id().to_string();
    let all = [
        ("create", "a.txt", "sh"),
        ("write", "a.txt", "sh"),
        ("create", "b.log", "sh"),
        ("write", "b.log", "sh"),
        ("create", "c.txt", "tee"),
        ("write", "c.txt", "tee"),
        ("create", "d.txt", own.as_str()),
        ("write", "d.txt", own.as_str()),
    ];
    let cases: [(&[&str], &Admits<'_>); 4] = [
        (&["--include", "*.txt"], &|name: &str, _: &str| {
            Path::new(name).extension().is_some_and(|ext| ext == "txt")
        }),
        (&["--ignore-comm", "sh"], &|_: &str, comm: &str| {
            comm != "sh"
        }),
        (&["--comm", "sh,tee"], &|_: &str, comm: &str| {
            matches!(comm, "sh" | "tee")
        }),
        (&["--pid", &pid], &|_: &str, comm: &str| comm == own),
    ];
    let watchers = start_all(cases.map(|(args, _)| {
        let args = [args, &["--summary"]].concat();
        (watch_json(ctx, &args, &[&dir]), Ready::Banner)
    }))?;
    sh(
        &dir,
        "echo a > a.txt; echo b > b.log; echo c | tee c.txt > /dev/null",
    )?;
    fs::write(dir.join("d.txt"), "d\n")?;
    let finished = stop_all(watchers)?;

    for ((args, admits), done) in cases.iter().zip(&finished) {
        let filter = args.join(" ");
        let lines = done.touches()?;
        let (last, rest) = lines
            .split_last()
            .with_context(|| format!("{filter}: no output"))?;
        let touches = changes_in(rest.to_vec())?;
        let mut got = shape(&touches, &dir);
        got.sort();
        let mut want: Vec<String> = all
            .iter()
            .filter(|(_, name, comm)| admits(name, comm))
            .map(|(op, name, comm)| format!("{op} {name} by {comm}"))
            .collect();
        want.sort();
        ensure!(got == want, "{filter}: reported {got:?}, expected {want:?}");
        check_summary(last, &touches).with_context(|| filter.clone())?;
    }
    Ok(
        "--include '*.txt', --ignore-comm sh, --comm sh,tee, --pid: the matching changes only, \
         and summaries of them"
            .to_owned(),
    )
}

/// Runs `sudo -n fsblame blame PATH --journal JOURNAL ARGS` and returns its stdout.
fn blame(ctx: &Ctx, journal: &Path, path: &Path, args: &[&str]) -> Result<String> {
    stdout_of(
        fsblame(ctx)
            .arg("blame")
            .arg(path)
            .arg("--journal")
            .arg(journal)
            .args(args),
    )
}

/// x: `record` keeps a private journal from which `blame` returns exactly a file's changes,
/// the latest with `--limit`, none `--since` a future time, and the tree `watch` printed
/// live; unprivileged, it exits 4 with a sudo hint.
pub(crate) fn record_blame(ctx: &Ctx) -> Result<String> {
    // Root owns the journal: a run stopped halfway leaves one the user cannot remove.
    let journal = ctx.work.join("x-journal/journal");
    remove_tree(&journal, true);
    let base = ctx.dir("x-journal")?;
    let _journal = RemoveTree {
        path: &journal,
        root: true,
    };
    let dir = base.join("watched");
    fs::create_dir(&dir)?;
    let (f, g) = (dir.join("f"), dir.join("g"));
    let mut record = fsblame(ctx);
    record
        .args(["record", "--duration", MAX_RUN, "--journal"])
        .arg(&journal)
        .arg(&dir);
    let watchers = start_all([
        (record, Ready::Banner),
        (watch_human(ctx, "never", &dir), Ready::Banner),
    ])?;
    sh(
        &dir,
        "echo one > f; echo two >> f; chmod 600 f; echo other > g",
    )?;
    sh(&dir, "echo three >> f")?;
    let [recorded, live] = stop_all(watchers)?;
    ensure!(
        recorded.stdout.is_empty(),
        "record printed to stdout:\n{}",
        recorded.stdout
    );

    let mode = stdout_of(
        Command::new("sudo")
            .args(["-n", "stat", "-c", "%a"])
            .arg(&journal),
    )?;
    ensure!(
        mode.trim() == "700",
        "the journal directory has mode {mode}"
    );
    let files = stdout_of(
        Command::new("sudo")
            .args(["-n", "find"])
            .arg(&journal)
            .args(["-type", "f", "-printf", "%m %f\n"]),
    )?;
    ensure!(
        !files.is_empty() && files.lines().all(|l| l.starts_with("600 ")),
        "journal files (mode name):\n{files}"
    );
    let recorded = stdout_of(
        Command::new("sudo")
            .args(["-n", "sh", "-c", r#"cat -- "$0"/*.ndjson"#])
            .arg(&journal),
    )?;
    let (f_path, g_path) = (text(&f), text(&g));
    let mut of_f = Vec::new();
    let mut of_g = 0;
    for line in recorded.lines() {
        let v: Value = serde_json::from_str(line).with_context(|| format!("journal: {line}"))?;
        if v["path"] == f_path.as_str() {
            of_f.push((line, v));
        } else if v["path"] == g_path.as_str() {
            of_g += 1;
        }
    }
    let ops: Vec<&str> = of_f.iter().filter_map(|(_, v)| v["op"].as_str()).collect();
    ensure!(
        ops == ["create", "write", "chmod", "write"] && of_g == 2,
        "the journal holds {ops:?} for {f_path} and {of_g} changes of {g_path}:\n{recorded}"
    );
    let of_f: Vec<&str> = of_f.iter().map(|(line, _)| *line).collect();

    let blamed = blame(ctx, &journal, &f, &["--json"])?;
    ensure!(
        blamed.lines().eq(of_f.iter().copied()),
        "blame --json {f_path}:\n{blamed}\nthe journal's lines of it:\n{}",
        of_f.join("\n")
    );
    let latest = blame(ctx, &journal, &f, &["--json", "--limit", "1"])?;
    ensure!(
        latest.lines().eq(of_f.last().copied()),
        "blame --json --limit 1 {f_path}:\n{latest}"
    );
    let future = blame(
        ctx,
        &journal,
        &f,
        &["--json", "--since", "2100-01-01T00:00:00Z"],
    )?;
    ensure!(future.is_empty(), "blame --since 2100 returned:\n{future}");
    let out = Command::new(&ctx.bin)
        .arg("blame")
        .arg(&f)
        .arg("--journal")
        .arg(&journal)
        .stdin(Stdio::null())
        .output()?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    ensure!(
        out.status.code() == Some(4) && stderr.contains("sudo"),
        "unprivileged blame: {}, expected exit 4 with a sudo hint:\n{stderr}",
        out.status
    );
    let human = blame(ctx, &journal, &f, &["--color", "never"])?;
    let shown = blocks_of(&live.stdout, "/watched/f");
    ensure!(
        !human.is_empty() && human == shown,
        "blame's tree:\n{human}\nwatch's tree of the file:\n{shown}"
    );
    Ok(format!(
        "{} of {} changes recorded are f's; journal 0700/0600; --limit 1, --since, exit 4 \
         unprivileged; same tree as watch",
        of_f.len(),
        of_f.len() + of_g
    ))
}

/// The subcommands every completion script must offer.
const SUBCOMMANDS: [&str; 6] = ["watch", "run", "record", "blame", "doctor", "completions"];

/// Whether `word` occurs in `script` with no letter or digit on either side.
fn has_word(script: &str, word: &str) -> bool {
    let alnum = |c: Option<char>| c.is_some_and(|c| c.is_ascii_alphanumeric());
    script.match_indices(word).any(|(at, _)| {
        !alnum(script[..at].chars().next_back()) && !alnum(script[at + word.len()..].chars().next())
    })
}

/// y: `completions` prints a script for each shell that offers every subcommand and, where
/// that shell is installed, parses.
pub(crate) fn completions(ctx: &Ctx) -> Result<String> {
    let dir = ctx.dir("y-completions")?;
    let mut parsed = Vec::new();
    for shell in ["bash", "zsh", "fish"] {
        let out = Command::new(&ctx.bin)
            .args(["completions", shell])
            .stdin(Stdio::null())
            .output()?;
        ensure!(
            out.status.success(),
            "completions {shell}: {}\n{}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
        let script = String::from_utf8(out.stdout).context("completion script")?;
        let missing: Vec<&str> = SUBCOMMANDS
            .into_iter()
            .filter(|sub| !has_word(&script, sub))
            .collect();
        ensure!(
            missing.is_empty(),
            "the {shell} script ({} bytes) does not offer {}",
            script.len(),
            missing.join(", ")
        );
        let file = dir.join(format!("fsblame.{shell}"));
        fs::write(&file, &script)?;
        let check = if shell == "fish" {
            "--no-execute"
        } else {
            "-n"
        };
        match Command::new(shell).arg(check).arg(&file).output() {
            Ok(out) => {
                ensure!(
                    out.status.success(),
                    "{shell} {check} rejects the script: {}",
                    String::from_utf8_lossy(&out.stderr)
                );
                parsed.push(shell);
            }
            // Not installed; a PATH directory this user may not search turns the miss into
            // EACCES.
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
                ) => {}
            Err(e) => return Err(e).with_context(|| format!("running {shell}")),
        }
    }
    Ok(format!(
        "bash, zsh and fish scripts offer every subcommand; parsed by {}",
        if parsed.is_empty() {
            "no installed shell".to_owned()
        } else {
            parsed.join(", ")
        }
    ))
}

/// z: every NDJSON line has `"v":1`; `--summary` ends with the counts of what was reported;
/// `-q` prints neither banner nor count (readiness comes through `--ready-fd`); colors follow
/// `--color`, and `auto` colors a terminal unless `NO_COLOR` is set.
// One workload seen six ways: the checks read best next to each other.
#[allow(clippy::too_many_lines)]
pub(crate) fn output_options(ctx: &Ctx) -> Result<String> {
    let base = ctx.dir("z-output")?;
    let dir = base.join("watched");
    fs::create_dir(&dir)?;
    let ready = base.join("ready");
    let (tty, no_color_tty) = (Pty::open()?, Pty::open()?);
    let quiet = redirected(
        ctx,
        &[],
        "3>",
        &ready,
        &[
            "watch",
            "-q",
            "--json",
            "--ready-fd",
            "3",
            "--duration",
            MAX_RUN,
        ],
        &dir,
    );
    let on_tty = |env: &[&str], pty: &Pty| {
        redirected(
            ctx,
            env,
            ">",
            &pty.path,
            &["watch", "--duration", MAX_RUN],
            &dir,
        )
    };
    let watchers = start_all([
        (watch_json(ctx, &["--summary"], &[&dir]), Ready::Banner),
        (quiet, Ready::File(&ready)),
        (watch_human(ctx, "always", &dir), Ready::Banner),
        (watch_human(ctx, "never", &dir), Ready::Banner),
        (on_tty(&["env", "-u", "NO_COLOR"], &tty), Ready::Banner),
        (on_tty(&["env", "NO_COLOR=1"], &no_color_tty), Ready::Banner),
    ])?;
    let (tty, no_color_tty) = (tty.read_to_end(), no_color_tty.read_to_end());
    sh(
        &dir,
        "mkdir d && echo x > d/f && chmod 600 d/f && mv d/f d/g && rm d/g && rmdir d",
    )?;
    let [json, quiet, always, never, _, _] = stop_all(watchers)?;
    let tty = tty
        .join()
        .map_err(|_| anyhow!("terminal reader panicked"))?;
    let no_color_tty = no_color_tty
        .join()
        .map_err(|_| anyhow!("terminal reader panicked"))?;

    let expected = [
        "mkdir d by mkdir",
        "create d/f by sh",
        "write d/f by sh",
        "chmod d/f by chmod",
        "rename d/g by mv",
        "unlink d/g by rm",
        "rmdir d by rmdir",
    ];
    let lines = json.touches()?;
    let quiet_lines = quiet.touches()?;
    if let Some(line) = lines.iter().chain(&quiet_lines).find(|l| l["v"] != 1) {
        bail!("a line without \"v\":1: {line}");
    }
    let (last, rest) = lines.split_last().context("--json printed nothing")?;
    let touches = changes_in(rest.to_vec())?;
    ensure!(
        shape(&touches, &dir) == expected,
        "--json reported {:?}, expected {expected:?}",
        shape(&touches, &dir)
    );
    check_summary(last, &touches)?;
    let count_line = format!("fsblame: {} changes reported", expected.len());
    ensure!(
        json.stderr.contains(&count_line),
        "no {count_line:?} on stderr:\n{}",
        json.stderr
    );

    ensure!(
        !quiet.stderr.contains("fsblame: watching") && !quiet.stderr.contains("changes reported"),
        "-q printed the banner or the count:\n{}",
        quiet.stderr
    );
    let quiet_touches = changes_in(quiet_lines)?;
    ensure!(
        shape(&quiet_touches, &dir) == expected,
        "-q reported {:?}, expected {expected:?}",
        shape(&quiet_touches, &dir)
    );

    let views = [
        ("--color always", &always.stdout, true),
        ("--color never", &never.stdout, false),
        ("auto on a terminal", &tty, true),
        ("auto on a terminal with NO_COLOR=1", &no_color_tty, false),
    ];
    for (view, out, colored) in views {
        ensure!(
            if colored {
                out.contains("\x1b[")
            } else {
                !out.contains('\x1b')
            },
            "{view}: expected {} color:\n{out:?}",
            if colored { "" } else { "no" }
        );
        let shown = headers(&plain(out));
        ensure!(
            shown == expected.len(),
            "{view} shows {shown} changes, expected {}:\n{out}",
            expected.len()
        );
    }
    Ok(format!(
        "{} lines v1, summary matches, -q silent until --ready-fd, colors per --color and NO_COLOR",
        lines.len() + quiet_touches.len()
    ))
}

/// Files scenario aa writes, renames and removes one after the other.
const FILES: usize = 300;
/// Times scenario aa opens, appends to and closes one file.
const APPENDS: u64 = 200;
/// What scenario aa writes to each of its files.
const PAYLOAD: &[u8] = b"payload\n";

/// aa: writes are told apart by file, not by inode number or `struct file`, which a removed
/// file hands on to the next: each of [`FILES`] short-lived files gets its own write. Reopened
/// for each append, one file still gets one write for all of them.
pub(crate) fn write_identity(ctx: &Ctx) -> Result<String> {
    let dir = ctx.dir("aa-identity")?;
    let same = dir.join("same.txt");
    fs::write(&same, "")?;
    let watcher = ctx.watch(&[&dir])?;
    let mut inodes = HashSet::new();
    for i in 0..FILES {
        let (path, moved) = (dir.join(format!("f{i}")), dir.join(format!("g{i}")));
        fs::write(&path, PAYLOAD)?;
        inodes.insert(fs::metadata(&path)?.ino());
        fs::rename(&path, &moved)?;
        fs::remove_file(&moved)?;
    }
    for _ in 0..APPENDS {
        OpenOptions::new()
            .append(true)
            .open(&same)?
            .write_all(b"x")?;
    }
    let touches = changes(&watcher.stop()?)?;

    let me = u64::from(std::process::id());
    let prefix = format!("{}/f", dir.display());
    let writes: Vec<&Value> = touches
        .iter()
        .filter(|t| {
            t["op"] == "write" && t["path"].as_str().is_some_and(|p| p.starts_with(&prefix))
        })
        .collect();
    let got: HashSet<&str> = writes.iter().filter_map(|t| t["path"].as_str()).collect();
    let want: Vec<String> = (0..FILES)
        .map(|i| text(&dir.join(format!("f{i}"))))
        .collect();
    ensure!(
        writes.len() == FILES && want.iter().all(|path| got.contains(path.as_str())),
        "{} write touches for {} distinct paths, expected one for each of f0..f{}",
        writes.len(),
        got.len(),
        FILES - 1
    );
    if let Some(bad) = writes
        .iter()
        .find(|t| t["bytes"] != PAYLOAD.len() as u64 || t["calls"] != 1 || t["proc"]["pid"] != me)
    {
        bail!(
            "expected {} bytes in 1 call by pid {me}: {bad}",
            PAYLOAD.len()
        );
    }
    for op in ["create", "rename", "unlink"] {
        let n = touches.iter().filter(|t| t["op"] == op).count();
        ensure!(n == FILES, "{n} {op} touches, expected {FILES}");
    }
    let appended: Vec<&Value> = touches
        .iter()
        .filter(|t| t["op"] == "write" && t["path"] == text(&same).as_str())
        .collect();
    ensure!(
        matches!(&appended[..], [t] if t["calls"] == APPENDS && t["bytes"] == APPENDS),
        "expected one write of {APPENDS} calls and bytes for {}, got {appended:?}",
        same.display()
    );
    ensure!(
        touches.len() == 4 * FILES + 1,
        "{} touches, expected {}",
        touches.len(),
        4 * FILES + 1
    );
    Ok(format!(
        "{FILES} files over {} inode numbers: {FILES} writes at distinct paths; {APPENDS} \
         reopened appends: 1 write of {APPENDS} calls",
        inodes.len()
    ))
}

/// ab: a write window still open when its process execs is the old image's: the write of
/// `sh -c 'echo x >> f; exec mkdir d'` is sh's, the mkdir is mkdir's, in one process.
pub(crate) fn exec_attribution(ctx: &Ctx) -> Result<String> {
    let dir = ctx.dir("ab-exec")?;
    let script = "echo x >> f; exec mkdir d";
    let watcher = ctx.watch(&[&dir])?;
    sh(&dir, script)?;
    let touches = changes(&watcher.stop()?)?;
    let file = dir.join("f");
    ensure!(
        count(&touches, "write", &file) == 1,
        "expected one write to {}; {}",
        file.display(),
        summary(&touches)
    );
    for op in ["create", "write"] {
        let t = touch(&touches, op, &file)?;
        ensure!(
            t["proc"]["comm"] == "sh"
                && t["comm"] == "sh"
                && argv(&t["proc"]) == ["sh", "-c", script],
            "{op} of f attributed to {} {:?} (thread {})",
            t["proc"]["comm"],
            argv(&t["proc"]),
            t["comm"]
        );
    }
    let write = touch(&touches, "write", &file)?;
    let mkdir = touch(&touches, "mkdir", &dir.join("d"))?;
    ensure!(
        mkdir["proc"]["comm"] == "mkdir" && mkdir["proc"]["pid"] == write["proc"]["pid"],
        "mkdir attributed to {} (pid {}), expected mkdir in pid {}",
        mkdir["proc"]["comm"],
        mkdir["proc"]["pid"],
        write["proc"]["pid"]
    );
    Ok(format!(
        "pid {}: write by sh, then mkdir by mkdir",
        write["proc"]["pid"]
    ))
}

/// ac: appending to an existing file whose name left the dentry cache runs the create check
/// of an `open(O_CREAT)`; with `security_file_post_open` (Linux 6.9) fsblame confirms the open
/// created nothing, and reports no create. Dropping the reclaimable slab objects (dentries
/// and inodes, `drop_caches` 2) evicts the name; the page cache plays no part.
pub(crate) fn confirmed_creates(ctx: &Ctx) -> Result<String> {
    const HOOK: &str = "security_file_post_open";
    let dir = ctx.dir("ac-confirmed")?;
    let file = dir.join("existing.txt");
    fs::write(&file, "old\n")?;
    let confirmable = in_btf(HOOK)?;
    let watcher = ctx.watch(&[&dir])?;
    let status = Command::new("sudo")
        .args(["-n", "sh", "-c", "echo 2 > /proc/sys/vm/drop_caches"])
        .status()?;
    ensure!(status.success(), "dropping the caches failed: {status}");
    sh(&dir, "echo more >> existing.txt")?;
    let done = watcher.stop()?;
    let touches = changes(&done)?;
    let creates = count(&touches, "create", &file);
    ensure!(
        count(&touches, "write", &file) == 1 && touches.len() == 1 + creates,
        "expected one write to {} and no other change but a create; {}",
        file.display(),
        summary(&touches)
    );
    if !confirmable {
        ensure!(
            creates <= 1,
            "{creates} create touches; {}",
            summary(&touches)
        );
        return Ok(format!(
            "{creates} create for the append: no {HOOK} on this kernel, so creates are not \
             confirmed"
        ));
    }
    ensure!(
        !done.stderr.contains(HOOK),
        "{HOOK} is in BTF but fsblame did not attach it:\n{}",
        done.stderr
    );
    ensure!(
        creates == 0,
        "a create touch for {}, which existed; {}",
        file.display(),
        summary(&touches)
    );
    Ok(format!("no create for the cold append ({HOOK} confirms)"))
}
