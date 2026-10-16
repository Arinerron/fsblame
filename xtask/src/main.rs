//! fsblame's development tasks.
//!
//! `cargo xtask test-e2e [--bin PATH] [--only ID,...]` runs fsblame against the running kernel:
//! it builds the release binary (static musl), then for each scenario starts
//! `sudo -n fsblame watch --json` on a fresh directory under `~/.cache/fsblame-e2e`, runs a
//! workload as the invoking user, stops the watcher with SIGINT and asserts on the NDJSON.
//! Run it as your normal user; it needs passwordless `sudo -n`, `setcap`, and a work directory
//! on a filesystem that honours file capabilities (not `/tmp`, which is tmpfs and nosuid).

use std::{
    env,
    ffi::OsString,
    fmt::Write as _,
    fs,
    io::{BufRead as _, BufReader, Read as _},
    os::unix::{ffi::OsStrExt as _, process::CommandExt as _},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context as _, Result, bail, ensure};
use serde_json::Value;

/// Longest wait for `fsblame: watching` (programs load and attach).
const READY_TIMEOUT: Duration = Duration::from_secs(60);
/// Longest wait for the watcher to exit after SIGINT.
const STOP_TIMEOUT: Duration = Duration::from_secs(15);
/// Safety net: every watcher stops by itself after this long.
const MAX_RUN: &str = "120s";
/// The verifier's instruction limit, for reporting program sizes.
const VERIFIER_LIMIT: u64 = 1_000_000;

const USAGE: &str = "usage: cargo xtask test-e2e [--bin PATH] [--only ID,...]

  --bin PATH     test this fsblame binary instead of building the release one
  --only IDS     run only these scenarios (comma-separated ids, see below)

Runs as your normal user; each scenario calls `sudo -n` itself.";

fn main() {
    let args: Vec<OsString> = env::args_os().skip(1).collect();
    let result = match args.first().and_then(|a| a.to_str()) {
        Some("test-e2e") => test_e2e(&args[1..]),
        Some("-h" | "--help") | None => {
            println!("{USAGE}");
            print_scenarios();
            Ok(true)
        }
        Some(other) => Err(anyhow::anyhow!("unknown task {other:?}\n{USAGE}")),
    };
    match result {
        Ok(true) => {}
        Ok(false) => std::process::exit(1),
        Err(e) => {
            eprintln!("xtask: {e:#}");
            std::process::exit(2);
        }
    }
}

/// One end-to-end scenario.
struct Scenario {
    id: &'static str,
    name: &'static str,
    run: fn(&Ctx) -> Result<String>,
}

const SCENARIOS: &[Scenario] = &[
    Scenario {
        id: "a",
        name: "write + fsync is a write touch with bytes and comm",
        run: write_fsync,
    },
    Scenario {
        id: "b",
        name: "create + unlink are both reported",
        run: create_unlink,
    },
    Scenario {
        id: "c",
        name: "rename across two watch roots has old and new path; hard link",
        run: rename_link,
    },
    Scenario {
        id: "d",
        name: "chmod is reported with the new mode",
        run: chmod,
    },
    Scenario {
        id: "e",
        name: "subtree: mkdir -p a/b/c and a deep write have full paths",
        run: subtree,
    },
    Scenario {
        id: "f",
        name: "lineage keeps an exited ancestor shell chain",
        run: lineage,
    },
    Scenario {
        id: "g",
        name: "npm lifecycle environment gives origin npm-lifecycle",
        run: origin,
    },
    Scenario {
        id: "h",
        name: "unprivileged run exits 4 with a setcap hint",
        run: unprivileged,
    },
    Scenario {
        id: "i",
        name: "setcap'd copy runs as the normal user",
        run: setcap,
    },
    Scenario {
        id: "j",
        name: "doctor --json reports every op available",
        run: doctor_ops,
    },
    Scenario {
        id: "k",
        name: "--duration stops the watcher on time",
        run: duration,
    },
];

fn print_scenarios() {
    println!("\nscenarios:");
    for s in SCENARIOS {
        println!("  {}  {}", s.id, s.name);
    }
}

fn test_e2e(args: &[OsString]) -> Result<bool> {
    let mut bin = None;
    let mut only: Option<Vec<String>> = None;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.to_str() {
            Some("--bin") => bin = Some(PathBuf::from(it.next().context("--bin needs a path")?)),
            Some("--only") => {
                let ids = it
                    .next()
                    .and_then(|v| v.to_str())
                    .context("--only needs scenario ids")?;
                only = Some(ids.split(',').map(str::to_owned).collect());
            }
            _ => bail!("unknown argument {}\n{USAGE}", arg.display()),
        }
    }

    // SAFETY: geteuid cannot fail.
    ensure!(
        unsafe { libc::geteuid() } != 0,
        "run as your normal user: the scenarios use `sudo -n` themselves and test unprivileged runs"
    );
    let sudo = Command::new("sudo")
        .args(["-n", "true"])
        .status()
        .context("running sudo")?;
    ensure!(sudo.success(), "needs passwordless `sudo -n`");

    let bin = match bin {
        Some(bin) => fs::canonicalize(&bin).with_context(|| format!("--bin {}", bin.display()))?,
        None => build()?,
    };
    let home = env::var_os("HOME").context("HOME is not set")?;
    let work = Path::new(&home).join(".cache/fsblame-e2e");
    fs::create_dir_all(&work).with_context(|| format!("creating {}", work.display()))?;
    check_work_fs(&work)?;
    let ctx = Ctx { bin, work };
    println!(
        "fsblame e2e: {} (work dir {})",
        ctx.bin.display(),
        ctx.work.display()
    );

    let mut failed = 0;
    let mut ran = 0;
    for scenario in SCENARIOS {
        if only
            .as_ref()
            .is_some_and(|ids| !ids.iter().any(|id| id == scenario.id))
        {
            continue;
        }
        ran += 1;
        let started = Instant::now();
        match (scenario.run)(&ctx) {
            Ok(note) => println!(
                "PASS {}  {}  [{:.1}s] {note}",
                scenario.id,
                scenario.name,
                started.elapsed().as_secs_f64()
            ),
            Err(e) => {
                failed += 1;
                println!("FAIL {}  {}\n     {e:#}", scenario.id, scenario.name);
            }
        }
    }
    ensure!(ran > 0, "no scenario matches --only");
    println!("{} passed, {failed} failed", ran - failed);
    Ok(failed == 0)
}

/// Builds the release binary and returns its path.
fn build() -> Result<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .context("workspace root")?;
    let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let out = Command::new(cargo)
        .current_dir(root)
        .args([
            "build",
            "--release",
            "--target",
            "x86_64-unknown-linux-musl",
            "--package",
            "fsblame",
            "--message-format=json-render-diagnostics",
        ])
        .stderr(Stdio::inherit())
        .output()
        .context("running cargo build")?;
    ensure!(out.status.success(), "cargo build failed: {}", out.status);
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|msg| msg["reason"] == "compiler-artifact" && msg["target"]["name"] == "fsblame")
        .find_map(|msg| msg["executable"].as_str().map(PathBuf::from))
        .context("cargo build did not report the fsblame executable")
}

/// The work directory must hold file capabilities (scenario i) and be a real filesystem.
fn check_work_fs(dir: &Path) -> Result<()> {
    const TMPFS_MAGIC: i64 = 0x0102_1994;
    let path = std::ffi::CString::new(dir.as_os_str().as_bytes())?;
    let mut st = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: `path` is a C string and `st` is writable for one statfs.
    ensure!(
        unsafe { libc::statfs(path.as_ptr(), st.as_mut_ptr()) } == 0,
        "statfs {}: {}",
        dir.display(),
        std::io::Error::last_os_error()
    );
    // SAFETY: statfs succeeded and filled `st`.
    let st = unsafe { st.assume_init() };
    ensure!(
        st.f_type != TMPFS_MAGIC,
        "{} is on tmpfs; the e2e work dir must be on a disk filesystem",
        dir.display()
    );
    let mut vfs = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: as above, for statvfs.
    ensure!(
        unsafe { libc::statvfs(path.as_ptr(), vfs.as_mut_ptr()) } == 0,
        "statvfs {}: {}",
        dir.display(),
        std::io::Error::last_os_error()
    );
    // SAFETY: statvfs succeeded and filled `vfs`.
    let vfs = unsafe { vfs.assume_init() };
    ensure!(
        vfs.f_flag & libc::ST_NOSUID == 0,
        "{} is on a nosuid mount, which ignores file capabilities",
        dir.display()
    );
    Ok(())
}

struct Ctx {
    bin: PathBuf,
    work: PathBuf,
}

impl Ctx {
    /// A fresh, empty directory for one scenario.
    fn dir(&self, name: &str) -> Result<PathBuf> {
        let dir = self.work.join(name);
        if dir.exists() {
            fs::remove_dir_all(&dir).with_context(|| format!("removing {}", dir.display()))?;
        }
        fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        Ok(dir)
    }

    /// `sudo -n fsblame watch --json <paths>`, attached and ready.
    fn watch(&self, paths: &[&Path]) -> Result<Watcher> {
        let mut cmd = Command::new("sudo");
        cmd.arg("-n")
            .arg(&self.bin)
            .args(["watch", "--json", "--duration", MAX_RUN])
            .args(paths);
        Watcher::start(cmd)
    }
}

/// A running `fsblame watch` whose stdout and stderr are collected.
struct Watcher {
    child: Child,
    stdout: thread::JoinHandle<String>,
    stderr: thread::JoinHandle<String>,
    /// When `fsblame: watching` appeared.
    ready_at: Instant,
}

/// What a finished watcher produced.
struct Finished {
    status: ExitStatus,
    stdout: String,
    stderr: String,
}

impl Finished {
    fn touches(&self) -> Result<Vec<Value>> {
        self.stdout
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str::<Value>(l).with_context(|| format!("not JSON: {l}")))
            .collect()
    }
}

impl Watcher {
    fn start(mut cmd: Command) -> Result<Self> {
        let mut child = cmd
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            // Its own process group, so a hung run can be killed as a whole.
            .process_group(0)
            .spawn()
            .context("starting fsblame")?;
        let mut out = child.stdout.take().context("stdout")?;
        let stdout = thread::spawn(move || {
            let mut text = String::new();
            let _ = out.read_to_string(&mut text);
            text
        });
        let err = child.stderr.take().context("stderr")?;
        let (ready_tx, ready_rx) = mpsc::channel();
        let stderr = thread::spawn(move || {
            let mut text = String::new();
            for line in BufReader::new(err).lines().map_while(Result::ok) {
                if line.starts_with("fsblame: watching ") {
                    let _ = ready_tx.send(());
                }
                text.push_str(&line);
                text.push('\n');
            }
            text
        });
        let mut watcher = Self {
            child,
            stdout,
            stderr,
            ready_at: Instant::now(),
        };
        let deadline = Instant::now() + READY_TIMEOUT;
        loop {
            match ready_rx.recv_timeout(Duration::from_millis(50)) {
                Ok(()) => break,
                Err(mpsc::RecvTimeoutError::Timeout) if Instant::now() < deadline => {
                    if watcher.child.try_wait()?.is_some() {
                        let done = watcher.join()?;
                        bail!(
                            "fsblame exited before attaching ({}):\n{}",
                            done.status,
                            done.stderr
                        );
                    }
                }
                Err(_) => {
                    watcher.kill();
                    let done = watcher.join()?;
                    bail!(
                        "fsblame did not attach within {READY_TIMEOUT:?}:\n{}",
                        done.stderr
                    );
                }
            }
        }
        watcher.ready_at = Instant::now();
        Ok(watcher)
    }

    /// SIGINT (sudo relays it), then waits for a clean exit.
    fn stop(self) -> Result<Finished> {
        // Let the last records of the workload reach the ring buffer.
        thread::sleep(Duration::from_millis(200));
        let pid = i32::try_from(self.child.id()).context("pid")?;
        // SAFETY: plain syscall on our own child.
        unsafe { libc::kill(pid, libc::SIGINT) };
        let done = self.wait(STOP_TIMEOUT)?;
        ensure!(
            done.status.success(),
            "fsblame exited with {} after SIGINT:\n{}",
            done.status,
            done.stderr
        );
        Ok(done)
    }

    /// Waits up to `timeout` for the watcher to exit by itself.
    fn wait(mut self, timeout: Duration) -> Result<Finished> {
        let deadline = Instant::now() + timeout;
        while self.child.try_wait()?.is_none() {
            if Instant::now() >= deadline {
                self.kill();
                let done = self.join()?;
                bail!("fsblame did not exit within {timeout:?}:\n{}", done.stderr);
            }
            thread::sleep(Duration::from_millis(20));
        }
        self.join()
    }

    fn kill(&mut self) {
        let group = format!("-{}", self.child.id());
        let _ = Command::new("sudo")
            .args(["-n", "kill", "-KILL", "--", &group])
            .status();
    }

    fn join(mut self) -> Result<Finished> {
        let status = self.child.wait()?;
        let stdout = self
            .stdout
            .join()
            .map_err(|_| anyhow::anyhow!("stdout reader panicked"))?;
        let stderr = self
            .stderr
            .join()
            .map_err(|_| anyhow::anyhow!("stderr reader panicked"))?;
        Ok(Finished {
            status,
            stdout,
            stderr,
        })
    }
}

/// Runs `sh -c script` in `dir` as the invoking user.
fn sh(dir: &Path, script: &str) -> Result<()> {
    let status = Command::new("sh")
        .arg("-c")
        .arg(script)
        .current_dir(dir)
        .status()
        .with_context(|| format!("running sh -c {script:?}"))?;
    ensure!(status.success(), "sh -c {script:?}: {status}");
    Ok(())
}

fn text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// `op path [<- old_path] [-> target]` per touch, for failure messages.
fn summary(touches: &[Value]) -> String {
    let lines: Vec<String> = touches
        .iter()
        .map(|t| {
            let mut line = format!(
                "{} {} by {}",
                t["op"].as_str().unwrap_or("?"),
                t["path"].as_str().unwrap_or("?"),
                t["proc"]["comm"].as_str().unwrap_or("?")
            );
            if let Some(old) = t["old_path"].as_str() {
                let _ = write!(line, " (from {old})");
            }
            if let Some(target) = t["target"].as_str() {
                let _ = write!(line, " (target {target})");
            }
            line
        })
        .collect();
    if lines.is_empty() {
        "no touches reported".to_owned()
    } else {
        format!("touches reported:\n       {}", lines.join("\n       "))
    }
}

/// The first touch with `op` on `path`.
fn touch<'a>(touches: &'a [Value], op: &str, path: &Path) -> Result<&'a Value> {
    let path = text(path);
    touches
        .iter()
        .find(|t| t["op"] == op && t["path"] == path.as_str())
        .with_context(|| format!("no {op} touch for {path}; {}", summary(touches)))
}

fn write_fsync(ctx: &Ctx) -> Result<String> {
    let dir = ctx.dir("a-write")?;
    let file = dir.join("data.bin");
    let watcher = ctx.watch(&[&dir])?;
    sh(
        &dir,
        "dd if=/dev/zero of=data.bin bs=1024 count=8 conv=fsync status=none",
    )?;
    let touches = watcher.stop()?.touches()?;
    let t = touch(&touches, "write", &file)?;
    let bytes = t["bytes"].as_u64().unwrap_or(0);
    ensure!(
        bytes > 0,
        "write reported {bytes} bytes; {}",
        summary(&touches)
    );
    ensure!(
        t["proc"]["comm"] == "dd",
        "write attributed to {}, not dd",
        t["proc"]["comm"]
    );
    Ok(format!("{bytes} B by dd"))
}

fn create_unlink(ctx: &Ctx) -> Result<String> {
    let dir = ctx.dir("b-create-unlink")?;
    let file = dir.join("scratch.txt");
    let watcher = ctx.watch(&[&dir])?;
    sh(&dir, "touch scratch.txt && rm scratch.txt")?;
    let touches = watcher.stop()?.touches()?;
    let created = touch(&touches, "create", &file)?;
    let removed = touch(&touches, "unlink", &file)?;
    ensure!(
        created["proc"]["comm"] == "touch",
        "create attributed to {}",
        created["proc"]["comm"]
    );
    ensure!(
        removed["proc"]["comm"] == "rm",
        "unlink attributed to {}",
        removed["proc"]["comm"]
    );
    Ok("create by touch, unlink by rm".to_owned())
}

fn rename_link(ctx: &Ctx) -> Result<String> {
    let base = ctx.dir("c-rename")?;
    let (src, dst) = (base.join("src"), base.join("dst"));
    fs::create_dir_all(&src)?;
    fs::create_dir_all(&dst)?;
    fs::write(src.join("moved.txt"), "payload\n")?;
    let watcher = ctx.watch(&[&src, &dst])?;
    sh(
        &base,
        "mv src/moved.txt dst/renamed.txt && ln dst/renamed.txt src/hardlink",
    )?;
    let touches = watcher.stop()?.touches()?;
    let renamed = touch(&touches, "rename", &dst.join("renamed.txt"))?;
    let old = text(&src.join("moved.txt"));
    ensure!(
        renamed["old_path"] == old.as_str(),
        "rename old_path is {}, expected {old}",
        renamed["old_path"]
    );
    ensure!(
        renamed["proc"]["comm"] == "mv",
        "rename attributed to {}",
        renamed["proc"]["comm"]
    );
    let linked = touch(&touches, "link", &src.join("hardlink"))?;
    let target = text(&dst.join("renamed.txt"));
    ensure!(
        linked["target"] == target.as_str(),
        "link target is {}, expected {target}",
        linked["target"]
    );
    Ok("src/moved.txt -> dst/renamed.txt, src/hardlink = dst/renamed.txt".to_owned())
}

fn chmod(ctx: &Ctx) -> Result<String> {
    let dir = ctx.dir("d-chmod")?;
    let file = dir.join("mode.txt");
    fs::write(&file, "x\n")?;
    let watcher = ctx.watch(&[&dir])?;
    sh(&dir, "chmod 600 mode.txt")?;
    let touches = watcher.stop()?.touches()?;
    let t = touch(&touches, "chmod", &file)?;
    ensure!(
        t["change"]["mode"] == "0600",
        "chmod change is {}",
        t["change"]
    );
    ensure!(
        t["proc"]["comm"] == "chmod",
        "chmod attributed to {}",
        t["proc"]["comm"]
    );
    Ok(format!(
        "{} -> {}",
        t["change"]["old_mode"], t["change"]["mode"]
    ))
}

fn subtree(ctx: &Ctx) -> Result<String> {
    let dir = ctx.dir("e-subtree")?;
    let watcher = ctx.watch(&[&dir])?;
    sh(&dir, "mkdir -p a/b/c && echo deep > a/b/c/deep.txt")?;
    let touches = watcher.stop()?.touches()?;
    for sub in ["a", "a/b", "a/b/c"] {
        touch(&touches, "mkdir", &dir.join(sub))?;
    }
    let deep = dir.join("a/b/c/deep.txt");
    touch(&touches, "create", &deep)?;
    let t = touch(&touches, "write", &deep)?;
    ensure!(t["truncated"] == false, "path reported as truncated");
    Ok(text(&deep))
}

fn lineage(ctx: &Ctx) -> Result<String> {
    let dir = ctx.dir("f-lineage")?;
    let file = dir.join("f");
    let watcher = ctx.watch(&[&dir])?;
    // The outer shell starts the writer in the background and exits at once, so the writer's
    // parent is gone (a tombstone) when the write happens.
    sh(&dir, r#"sh -c "sleep 0.3; echo x > f" & exit 0"#)?;
    let deadline = Instant::now() + Duration::from_secs(10);
    while fs::read_to_string(&file).map_or(true, |s| s != "x\n") {
        ensure!(
            Instant::now() < deadline,
            "the background writer never wrote {}",
            file.display()
        );
        thread::sleep(Duration::from_millis(50));
    }
    let touches = watcher.stop()?.touches()?;
    let t = touch(&touches, "write", &file)?;
    let argv = |v: &Value| -> String {
        v["argv"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .unwrap_or_default()
    };
    ensure!(t["proc"]["comm"] == "sh", "writer is {}", t["proc"]["comm"]);
    ensure!(
        argv(&t["proc"]).contains("sleep 0.3; echo x > f"),
        "writer argv: {}",
        argv(&t["proc"])
    );
    let ancestry = t["ancestry"].as_array().context("no ancestry")?;
    let outer = ancestry.first().context("empty ancestry")?;
    ensure!(
        outer["comm"] == "sh" && argv(outer).contains("& exit 0"),
        "parent is {} ({}), not the outer shell",
        outer["comm"],
        argv(outer)
    );
    ensure!(
        outer["exited"] == true,
        "the outer shell is not marked exited: {outer}"
    );
    let me = u64::from(std::process::id());
    ensure!(
        ancestry.iter().any(|p| p["pid"] == me),
        "ancestry does not reach the xtask (pid {me}): {:?}",
        ancestry
            .iter()
            .map(|p| p["comm"].clone())
            .collect::<Vec<_>>()
    );
    let chain: Vec<&str> = std::iter::once(&t["proc"])
        .chain(ancestry.iter().take(3))
        .filter_map(|p| p["comm"].as_str())
        .collect();
    Ok(format!("{} (outer sh exited)", chain.join(" <- ")))
}

fn origin(ctx: &Ctx) -> Result<String> {
    let dir = ctx.dir("g-origin")?;
    let file = dir.join("generated.js");
    let watcher = ctx.watch(&[&dir])?;
    let status = Command::new("sh")
        .args(["-c", "echo 'module.exports = 1' > generated.js"])
        .current_dir(&dir)
        .env("npm_lifecycle_event", "postinstall")
        .env("npm_package_name", "demo")
        .env("npm_package_version", "1.0.0")
        .env("npm_config_user_agent", "npm/10")
        .status()?;
    ensure!(status.success(), "writer failed: {status}");
    let touches = watcher.stop()?.touches()?;
    let t = touch(&touches, "write", &file)?;
    let origin = &t["origin"];
    ensure!(
        origin["kind"] == "npm-lifecycle"
            && origin["package"] == "demo"
            && origin["phase"] == "postinstall",
        "origin is {origin}"
    );
    Ok(format!(
        "{} {}@{} {}",
        origin["kind"], origin["package"], origin["version"], origin["phase"]
    ))
}

fn unprivileged(ctx: &Ctx) -> Result<String> {
    let dir = ctx.dir("h-unprivileged")?;
    let out = Command::new(&ctx.bin)
        .args(["watch", "--duration", "1s"])
        .arg(&dir)
        .stdin(Stdio::null())
        .output()
        .context("running fsblame unprivileged")?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    ensure!(
        out.status.code() == Some(4),
        "exit status {}, expected 4:\n{stderr}",
        out.status
    );
    ensure!(
        stderr.contains("setcap cap_bpf,cap_perfmon+ep"),
        "no setcap hint on stderr:\n{stderr}"
    );
    Ok("exit 4, setcap hint printed".to_owned())
}

/// Removes the capabilities from the copy, whatever happens.
struct Uncap<'a>(&'a Path);

impl Drop for Uncap<'_> {
    fn drop(&mut self) {
        let _ = Command::new("sudo")
            .arg("-n")
            .arg("setcap")
            .arg("-r")
            .arg(self.0)
            .status();
    }
}

fn setcap(ctx: &Ctx) -> Result<String> {
    let dir = ctx.dir("i-setcap")?;
    let bin_dir = ctx.work.join("bin");
    fs::create_dir_all(&bin_dir)?;
    let copy = bin_dir.join("fsblame");
    let _ = fs::remove_file(&copy);
    fs::copy(&ctx.bin, &copy).with_context(|| format!("copying to {}", copy.display()))?;
    let status = Command::new("sudo")
        .arg("-n")
        .args(["setcap", "cap_bpf,cap_perfmon+ep"])
        .arg(&copy)
        .status()?;
    ensure!(status.success(), "setcap failed: {status}");
    let _uncap = Uncap(&copy);

    let file = dir.join("as-user.txt");
    let mut cmd = Command::new(&copy);
    cmd.args(["watch", "--json", "--duration", MAX_RUN])
        .arg(&dir);
    let watcher = Watcher::start(cmd)?;
    sh(&dir, "echo capable > as-user.txt")?;
    let touches = watcher.stop()?.touches()?;
    touch(&touches, "write", &file)?;
    Ok(format!(
        "{} with cap_bpf,cap_perfmon+ep, no sudo",
        copy.display()
    ))
}

fn doctor_ops(ctx: &Ctx) -> Result<String> {
    let dir = ctx.dir("j-doctor")?;
    let out = Command::new("sudo")
        .arg("-n")
        .arg(&ctx.bin)
        .args(["doctor", "--json"])
        .arg(&dir)
        .stdin(Stdio::null())
        .output()
        .context("running fsblame doctor")?;
    ensure!(
        out.status.success(),
        "doctor exited {}:\n{}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    let report: Value = serde_json::from_slice(&out.stdout).context("doctor --json output")?;
    let ops = report["ops"]
        .as_array()
        .context("no ops in doctor --json")?;
    ensure!(
        ops.len() == 14,
        "doctor lists {} ops, expected 14",
        ops.len()
    );
    let disabled: Vec<String> = ops
        .iter()
        .filter(|op| op["status"] != "available")
        .map(|op| format!("{} ({}: {})", op["name"], op["reason"], op["detail"]))
        .collect();
    ensure!(
        disabled.is_empty(),
        "ops not available: {}",
        disabled.join(", ")
    );
    let check = report["checks"]
        .as_array()
        .and_then(|checks| checks.iter().find(|c| c["id"] == "probe.ops"))
        .context("no probe.ops check")?;
    ensure!(
        check["status"] == "pass",
        "probe.ops is {}: {}",
        check["status"],
        check["observed"]
    );
    let insns = |name: &str| -> Result<u64> {
        let op = ops
            .iter()
            .find(|op| op["name"] == name)
            .context("op missing")?;
        let n = op["insns"]
            .as_u64()
            .with_context(|| format!("no insns for {name}"))?;
        ensure!(n < VERIFIER_LIMIT, "{name} at {n} insns");
        Ok(n)
    };
    Ok(format!(
        "all 14 available; on_rename {} insns, on_link {} insns (limit {VERIFIER_LIMIT})",
        insns("rename")?,
        insns("link")?
    ))
}

fn duration(ctx: &Ctx) -> Result<String> {
    let dir = ctx.dir("k-duration")?;
    let mut cmd = Command::new("sudo");
    cmd.arg("-n")
        .arg(&ctx.bin)
        .args(["watch", "--duration", "2s"])
        .arg(&dir);
    let watcher = Watcher::start(cmd)?;
    let ready_at = watcher.ready_at;
    let done = watcher.wait(Duration::from_secs(10))?;
    let elapsed = ready_at.elapsed();
    ensure!(
        done.status.success(),
        "exit {}:\n{}",
        done.status,
        done.stderr
    );
    ensure!(
        elapsed >= Duration::from_millis(1500) && elapsed <= Duration::from_secs(4),
        "stopped {elapsed:?} after attaching, expected about 2s"
    );
    Ok(format!(
        "exited {:.2}s after attaching",
        elapsed.as_secs_f64()
    ))
}
