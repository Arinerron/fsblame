//! End-to-end scenarios ah and ai: writes through a descriptor a process keeps, and the end of
//! `run`.
//!
//! A file renamed while a process keeps writing to it has the later writes at its new name,
//! and writes after an exec through an inherited descriptor are the new program's (ah). Under
//! `run`, a Ctrl-C that comes after the command exited, while fsblame still reads the records
//! of the command's last changes, is the command's as before: every change is still reported
//! (ai).

use std::{
    fs,
    io::{BufRead as _, BufReader, Read as _},
    os::unix::{fs::symlink, process::CommandExt as _},
    path::Path,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context as _, Result, anyhow, bail, ensure};
use serde_json::Value;

use crate::{Ctx, sh, summary, text, touch, workload_loss};

/// The command of scenario ah, run in its directory: one descriptor written before and after
/// a rename of its file, then by `printer` (a link to `sh`) that the shell execs.
const KEPT_SCRIPT: &str = "{ echo one; sleep 0.3; mv app.log app.log.1; sleep 0.3; echo two; \
                           sleep 0.3; exec ./printer -c 'sleep 0.3; echo three'; } >> app.log";

/// ah: logrotate's `mv access.log access.log.1` while the server keeps writing: the later
/// writes are at the new name. `sh -c 'echo building; exec make' >> build.log`: the writes
/// after the exec are the new program's.
pub fn kept_descriptor(ctx: &Ctx) -> Result<String> {
    let dir = ctx.dir("ah-kept")?;
    fs::write(dir.join("app.log"), "")?;
    symlink("/bin/sh", dir.join("printer"))?;
    let watcher = ctx.watch(&[&dir])?;
    sh(&dir, KEPT_SCRIPT)?;
    let lines = watcher.stop()?.touches()?;
    if let Some(lost) = lines.iter().find(|l| workload_loss(l)) {
        bail!("fsblame lost data: {lost}");
    }
    let touches: Vec<Value> = lines.into_iter().filter(|l| l["type"] == "touch").collect();
    let (old, new) = (dir.join("app.log"), dir.join("app.log.1"));
    let renamed = touch(&touches, "rename", &new)?;
    ensure!(
        renamed["old_path"] == text(&old).as_str(),
        "rename old_path is {}",
        renamed["old_path"]
    );
    let writes: Vec<(&str, &str, u64)> = touches
        .iter()
        .filter(|t| t["op"] == "write")
        .map(|t| {
            (
                t["path"].as_str().unwrap_or("?"),
                t["comm"].as_str().unwrap_or("?"),
                t["bytes"].as_u64().unwrap_or(0),
            )
        })
        .collect();
    let (old, new) = (text(&old), text(&new));
    let expected = [
        (old.as_str(), "sh", 4),
        (new.as_str(), "sh", 4),
        (new.as_str(), "printer", 6),
    ];
    ensure!(
        writes == expected,
        "writes (path, comm, bytes) {writes:?}, expected {expected:?}; {}",
        summary(&touches)
    );
    Ok("one fd: written, renamed, written, exec'd and written: each write at its name, by its program".to_owned())
}

/// Files the command of scenario ai creates.
const DRAIN_FILES: usize = 3000;
/// How long scenario ai reads the report slowly once the command has exited, before the
/// Ctrl-C: fsblame is past its last loop pass and in the final read of the ring well before.
const SLOW_READ: Duration = Duration::from_secs(1);
/// Longest scenario ai waits for the command, or for fsblame once the report is read.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

/// Kills the process group of `child` (sudo and fsblame) when dropped before it exited.
struct Group(Child);

impl Drop for Group {
    fn drop(&mut self) {
        if matches!(self.0.try_wait(), Ok(None)) {
            let _ = Command::new("sudo")
                .args(["-n", "kill", "-KILL", "--", &format!("-{}", self.0.id())])
                .status();
            let _ = self.0.wait();
        }
    }
}

/// Whether process `pid` has exited (and is a zombie its parent has not waited for yet).
fn exited(pid: u32) -> bool {
    fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .is_none_or(|stat| {
            stat.rsplit_once(')')
                .is_some_and(|(_, rest)| rest.trim_start().starts_with('Z'))
        })
}

/// The pid the command of scenario ai wrote to `dir/pid`, once it is there.
fn command_pid(dir: &Path, deadline: Instant) -> Result<u32> {
    loop {
        if let Ok(pid) = fs::read_to_string(dir.join("pid"))
            && let Ok(pid) = pid.trim().parse()
        {
            return Ok(pid);
        }
        ensure!(Instant::now() < deadline, "the command did not start");
        thread::sleep(Duration::from_millis(20));
    }
}

/// ai: fsblame writes the report of `run` to stderr, which this scenario stops reading until
/// the command (thousands of creates) has exited, then reads slowly: fsblame is still reading
/// the command's records when the Ctrl-C comes, and must not stop before it has reported them.
pub fn run_drain_sigint(ctx: &Ctx) -> Result<String> {
    let dir = ctx.dir("ai-run-drain")?;
    let script = format!(
        "echo $$ > pid; i=0; while [ $i -lt {DRAIN_FILES} ]; do : > f$i; i=$((i + 1)); done"
    );
    let mut sudo = Command::new("sudo");
    sudo.arg("-n")
        .arg(&ctx.bin)
        .args(["run", "--json", "--summary", "--", "sh", "-c", &script])
        .current_dir(&dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut group = Group(sudo.spawn().context("starting fsblame run")?);
    let mut report = BufReader::new(group.0.stderr.take().context("stderr")?);
    let mut messages = String::new();
    while !messages.contains("fsblame: watching ") {
        ensure!(
            report.read_line(&mut messages)? > 0,
            "fsblame run ended before watching:\n{messages}"
        );
    }

    let deadline = Instant::now() + DRAIN_TIMEOUT;
    let pid = command_pid(&dir, deadline)?;
    while !exited(pid) {
        ensure!(Instant::now() < deadline, "the command did not exit");
        thread::sleep(Duration::from_millis(20));
    }
    let mut out = Vec::new();
    let mut chunk = [0; 2048];
    let slow = Instant::now() + SLOW_READ;
    while Instant::now() < slow {
        let n = report.read(&mut chunk)?;
        ensure!(n > 0, "fsblame ended the report before the Ctrl-C");
        out.extend_from_slice(&chunk[..n]);
        thread::sleep(Duration::from_millis(10));
    }
    let before = String::from_utf8_lossy(&out)
        .matches(r#""op":"create""#)
        .count();
    let sudo_pid = i32::try_from(group.0.id()).context("pid")?;
    // SAFETY: plain syscall on our own child; sudo relays the signal to fsblame.
    unsafe { libc::kill(sudo_pid, libc::SIGINT) };
    let rest = thread::spawn(move || {
        let mut rest = Vec::new();
        report.read_to_end(&mut rest).map(|_| rest)
    });
    let status = loop {
        if let Some(status) = group.0.try_wait()? {
            break status;
        }
        ensure!(Instant::now() < deadline, "fsblame run did not exit");
        thread::sleep(Duration::from_millis(20));
    };
    out.extend(
        rest.join()
            .map_err(|_| anyhow!("the report reader panicked"))??,
    );
    let out = String::from_utf8(out).context("the report is not UTF-8")?;
    ensure!(status.success(), "fsblame run exited {status}:\n{out}");

    let lines: Vec<Value> = out
        .lines()
        .filter(|l| l.starts_with('{'))
        .map(|l| serde_json::from_str(l).with_context(|| format!("not JSON: {l}")))
        .collect::<Result<_>>()?;
    if let Some(lost) = lines.iter().find(|l| workload_loss(l)) {
        bail!("fsblame lost data after the Ctrl-C: {lost}");
    }
    let prefix = format!("{}/f", text(&dir));
    let created = lines
        .iter()
        .filter(|l| l["type"] == "touch" && l["op"] == "create")
        .filter(|l| l["path"].as_str().is_some_and(|p| p.starts_with(&prefix)))
        .count();
    ensure!(
        created == DRAIN_FILES,
        "{created} of {DRAIN_FILES} creates reported"
    );
    ensure!(
        before < DRAIN_FILES,
        "the whole report was read before the Ctrl-C ({before} creates): it tested nothing"
    );
    let end = lines.last().context("no report")?;
    ensure!(
        end["type"] == "summary" && end["lost"]["unread"] == 0,
        "the report ends with {end}"
    );
    Ok(format!(
        "{DRAIN_FILES} creates reported, {} of them after the Ctrl-C",
        DRAIN_FILES - before
    ))
}
