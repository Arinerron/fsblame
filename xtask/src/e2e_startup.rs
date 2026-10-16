//! End-to-end scenario ad: a churn of changes from the moment fsblame says it is watching to
//! the moment it is told to stop.
//!
//! A workload that waits for the `fsblame: watching` line starts while fsblame is still
//! setting up its consumer, so its first records reach a ring buffer nobody drains yet; the
//! stop comes right after the last change, while a slow consumer (a debug build) is still
//! behind. Each change must be reported, or its record counted in the `lost` lines, which the
//! summary and the warnings on stderr must repeat.

use std::{
    collections::HashSet,
    fs::{self, File},
    io::Write as _,
    path::Path,
    process::Command,
};

use anyhow::{Context as _, Result, ensure};
use serde_json::Value;

use crate::{Ctx, Finished, MAX_RUN, Watcher, text};

/// Files the churn goes through, each created, written, renamed and unlinked: a third of a
/// second of changes, the first of them made while fsblame is still starting to drain.
const FILES: usize = 10_000;
/// The changes each churned file makes.
const OPS: [&str; 4] = ["create", "write", "rename", "unlink"];
/// Every `lost` reason, with its key in the summary's `lost` totals.
const REASONS: [(&str, &str); 4] = [
    ("ring-full", "ring_full"),
    ("write-evicted", "write_evicted"),
    ("track-full", "track_full"),
    ("unread", "unread"),
];

/// Creates, writes, renames and unlinks [`FILES`] files in `dir` as fast as it can.
fn churn(dir: &Path) -> Result<()> {
    let block = [b'Z'; 4096];
    for i in 0..FILES {
        let (name, moved) = (dir.join(format!("f{i}")), dir.join(format!("f{i}.r")));
        File::create_new(&name)
            .and_then(|mut f| f.write_all(&block))
            .with_context(|| format!("writing {}", name.display()))?;
        fs::rename(&name, &moved).with_context(|| format!("renaming {}", name.display()))?;
        fs::remove_file(&moved).with_context(|| format!("removing {}", moved.display()))?;
    }
    Ok(())
}

/// The `(op, file)` changes of the churn in `lines`; a write may name the file before or
/// after its rename.
fn churned(lines: &[Value], dir: &Path) -> HashSet<(usize, usize)> {
    let prefix = format!("{}/f", text(dir));
    lines
        .iter()
        .filter(|l| l["type"] == "touch")
        .filter_map(|t| {
            let op = OPS.iter().position(|&op| t["op"] == op)?;
            let name = t["path"].as_str()?.strip_prefix(&prefix)?;
            let file = name.strip_suffix(".r").unwrap_or(name).parse().ok()?;
            Some((op, file))
        })
        .collect()
}

/// The records lost, by the `lost` lines of every reason: their totals must be the summary's
/// and lost records must be warned about on stderr.
fn records_lost(done: &Finished, lines: &[Value]) -> Result<u64> {
    let mut totals = [0; REASONS.len()];
    for line in lines.iter().filter(|l| l["type"] == "lost") {
        let reason = REASONS
            .iter()
            .position(|&(reason, _)| line["reason"] == reason)
            .with_context(|| format!("lost line with an unknown reason: {line}"))?;
        totals[reason] += line["count"]
            .as_u64()
            .filter(|&n| n > 0)
            .with_context(|| format!("lost line without a count: {line}"))?;
    }
    let end = lines.last().context("no output")?;
    ensure!(
        end["type"] == "summary",
        "the run ends with {end}, not a summary"
    );
    let summary = end["lost"]
        .as_object()
        .context("a summary without lost totals")?;
    ensure!(
        summary.len() == REASONS.len(),
        "the summary's lost totals are not those of {REASONS:?}: {}",
        end["lost"]
    );
    for (&(reason, key), total) in REASONS.iter().zip(totals) {
        ensure!(
            summary.get(key).and_then(Value::as_u64) == Some(total),
            "the {reason} lines count {total}, the summary's lost totals are {}",
            end["lost"]
        );
    }
    let [ring_full, _, _, unread] = totals;
    for (count, warning) in [
        (ring_full, "a larger --ring-size helps"),
        (unread, "left unread"),
    ] {
        ensure!(
            count == 0 || done.stderr.contains(warning),
            "{count} records lost without the warning {warning:?} on stderr:\n{}",
            done.stderr
        );
    }
    Ok(ring_full + unread)
}

/// One watcher with `ring` (the default if `None`), churned at once and stopped right after:
/// every change is reported or its record counted lost. Returns how many were reported and
/// how many records were lost.
fn churn_at_start(ctx: &Ctx, ring: Option<&str>) -> Result<(usize, u64)> {
    let dir = ctx.dir("ad-startup")?;
    let mut cmd = Command::new("sudo");
    cmd.arg("-n")
        .arg(&ctx.bin)
        .args(["watch", "--json", "--summary", "--duration", MAX_RUN]);
    if let Some(size) = ring {
        cmd.args(["--ring-size", size]);
    }
    cmd.arg(&dir);
    let watcher = Watcher::start(cmd)?;
    churn(&dir)?;
    let done = watcher.stop()?;
    let lines = done.touches()?;
    let seen = churned(&lines, &dir);
    let lost = records_lost(&done, &lines)?;
    let expected = OPS.len() * FILES;
    let missing = expected - seen.len();
    let by_op: Vec<String> = OPS
        .iter()
        .enumerate()
        .map(|(op, name)| {
            let reported = seen.iter().filter(|&&(o, _)| o == op).count();
            format!("{name} {}", FILES - reported)
        })
        .collect();
    let first = (0..FILES)
        .flat_map(|file| (0..OPS.len()).map(move |op| (op, file)))
        .find(|change| !seen.contains(change))
        .map(|(op, file)| format!("; first missing: {} of f{file}", OPS[op]));
    ensure!(
        u64::try_from(missing)? <= lost,
        "ring {}: {missing} of {expected} changes missing ({}), {lost} records reported lost{}",
        ring.unwrap_or("default"),
        by_op.join(", "),
        first.unwrap_or_default()
    );
    Ok((seen.len(), lost))
}

pub fn startup_churn(ctx: &Ctx) -> Result<String> {
    let (reported, lost) = churn_at_start(ctx, None)?;
    let (small, small_lost) = churn_at_start(ctx, Some("256K"))?;
    let expected = OPS.len() * FILES;
    Ok(format!(
        "{FILES} files churned from the watching line to the stop: {reported}/{expected} \
         changes reported ({lost} records lost); with a 256K ring {small} reported, \
         {small_lost} records lost"
    ))
}
