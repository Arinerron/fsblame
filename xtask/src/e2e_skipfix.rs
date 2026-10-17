//! End-to-end scenario ak: a storm of parallel writers in a watched directory, four per CPU.
//!
//! The kernel runs a BPF program at most once per CPU at a time. While a writer is preempted in
//! the middle of one of fsblame's hooks, another writer's change on that CPU skips the hook,
//! which only counts in the program's `recursion_misses`; fsblame reports those runs as the loss
//! reason `skipped`. Every file must be reported created and written, or the `lost` lines (every
//! reason, `skipped` included) must cover what is missing, and repeat in the summary and the
//! warnings on stderr. Whether a run is skipped depends on the scheduler, so a storm without
//! skips passes too.

use std::{
    collections::HashSet,
    io,
    path::Path,
    process::{Child, Command},
    thread,
};

use anyhow::{Context as _, Result, ensure};
use serde_json::Value;

use crate::{
    Ctx, MAX_RUN, Watcher,
    e2e_startup::{REASONS, losses},
    text,
};

/// Writers per CPU.
const PER_CPU: usize = 4;
/// Files each writer creates and writes.
const FILES: usize = 250;
/// The changes of each file.
const OPS: [&str; 2] = ["create", "write"];

/// Starts `writers` shells in `dir`, each running `echo x > w<writer>-<i>` for [`FILES`] files,
/// all at once: each waits for the end of its stdin, which closes when the last has started.
fn storm(dir: &Path, writers: usize) -> Result<()> {
    let script = format!(
        "read -r _; i=0; while [ $i -lt {FILES} ]; do echo x > \"w$0-$i\"; i=$((i + 1)); done"
    );
    let (gate, start) = io::pipe().context("creating the start pipe")?;
    let children = (0..writers)
        .map(|writer| {
            Command::new("sh")
                .arg("-c")
                .arg(&script)
                .arg(writer.to_string())
                .current_dir(dir)
                .stdin(gate.try_clone()?)
                .spawn()
        })
        .collect::<io::Result<Vec<Child>>>()
        .context("starting the writers")?;
    drop((gate, start));
    for mut child in children {
        let status = child.wait().context("waiting for a writer")?;
        ensure!(status.success(), "a writer failed: {status}");
    }
    Ok(())
}

/// The `(op, writer, file)` changes of the storm in `lines`.
fn reported(lines: &[Value], dir: &Path) -> HashSet<(usize, usize, usize)> {
    let prefix = format!("{}/w", text(dir));
    lines
        .iter()
        .filter(|l| l["type"] == "touch")
        .filter_map(|t| {
            let op = OPS.iter().position(|&op| t["op"] == op)?;
            let (writer, file) = t["path"].as_str()?.strip_prefix(&prefix)?.split_once('-')?;
            Some((op, writer.parse().ok()?, file.parse().ok()?))
        })
        .collect()
}

pub fn write_storm(ctx: &Ctx) -> Result<String> {
    let writers = PER_CPU * thread::available_parallelism().map_or(1, usize::from);
    let dir = ctx.dir("ak-storm")?;
    let mut cmd = Command::new("sudo");
    cmd.arg("-n")
        .arg(&ctx.bin)
        .args(["watch", "--json", "--summary", "--duration", MAX_RUN])
        .arg(&dir);
    let watcher = Watcher::start(cmd)?;
    storm(&dir, writers)?;
    let done = watcher.stop()?;
    let lines = done.touches()?;
    let seen = reported(&lines, &dir);
    let totals = losses(&done, &lines)?;
    let lost: u64 = totals.iter().sum();
    let expected = OPS.len() * writers * FILES;
    let missing = expected - seen.len();
    let first = (0..writers)
        .flat_map(|writer| (0..FILES).map(move |file| (writer, file)))
        .flat_map(|(writer, file)| (0..OPS.len()).map(move |op| (op, writer, file)))
        .find(|change| !seen.contains(change))
        .map(|(op, writer, file)| format!("; first missing: {} of w{writer}-{file}", OPS[op]));
    let by_reason: Vec<String> = REASONS
        .iter()
        .zip(totals)
        .map(|(&(reason, _, _), total)| format!("{reason} {total}"))
        .collect();
    ensure!(
        u64::try_from(missing)? <= lost,
        "{missing} of {expected} changes missing, {lost} lost ({}){}",
        by_reason.join(", "),
        first.unwrap_or_default()
    );
    Ok(format!(
        "{writers} writers x {FILES} files at once: {}/{expected} changes reported; lost: {}",
        seen.len(),
        by_reason.join(", ")
    ))
}
