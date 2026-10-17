//! End-to-end scenarios m to r: excluded subtrees, nested mounts, cached verdicts across
//! directory moves, truncated paths, hard links across and out of the watch roots, and a ring
//! buffer overflow.

use std::{
    ffi::{OsStr, OsString},
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context as _, Result, anyhow, ensure};
use serde_json::Value;

use super::{Ctx, Finished, MAX_RUN, Watcher, sh, summary, text, touch, workload_loss};

/// `sudo -n fsblame watch --json ARGS PATHS`, attached and ready.
fn watch_with(ctx: &Ctx, args: &[&OsStr], paths: &[&Path]) -> Result<Watcher> {
    let mut cmd = Command::new("sudo");
    cmd.arg("-n")
        .arg(&ctx.bin)
        .args(["watch", "--json", "--duration", MAX_RUN])
        .args(args)
        .args(paths);
    Watcher::start(cmd)
}

/// The `touch` lines of a finished run.
fn touches(done: &Finished) -> Result<Vec<Value>> {
    Ok(done
        .touches()?
        .into_iter()
        .filter(|t| t["type"] == "touch")
        .collect())
}

/// Each `(op, path)` was reported exactly once, and nothing else was.
fn exactly(touches: &[Value], expected: &[(&str, &Path)]) -> Result<()> {
    for &(op, path) in expected {
        let path = text(path);
        let count = touches
            .iter()
            .filter(|t| t["op"] == op && t["path"] == path.as_str())
            .count();
        ensure!(
            count == 1,
            "{count} {op} touches for {path}, expected 1; {}",
            summary(touches)
        );
    }
    ensure!(
        touches.len() == expected.len(),
        "only the {} changes listed were expected; {}",
        expected.len(),
        summary(touches)
    );
    Ok(())
}

/// `t[field]` is `path`.
fn ensure_path(t: &Value, field: &str, path: &Path) -> Result<()> {
    let path = text(path);
    ensure!(
        t[field] == path.as_str(),
        "{} {}: {field} is {}, expected {path}",
        t["op"],
        t["path"],
        t[field]
    );
    Ok(())
}

/// Appends to the existing file `path` in a `dd` process of its own. `dd` opens it without
/// `O_CREAT`, so even a kernel that cannot confirm creates (before Linux 6.9) reports none.
fn append(path: &Path) -> Result<()> {
    let mut of = OsString::from("of=");
    of.push(path);
    let status = Command::new("dd")
        .args([
            "if=/dev/zero",
            "bs=4",
            "count=1",
            "conv=notrunc,nocreat",
            "oflag=append",
            "status=none",
        ])
        .arg(of)
        .status()
        .context("running dd")?;
    ensure!(
        status.success(),
        "dd appending to {}: {status}",
        path.display()
    );
    Ok(())
}

pub fn exclude(ctx: &Ctx) -> Result<String> {
    let dir = ctx.dir("m-exclude")?;
    let skip = dir.join("skip");
    let inner = skip.join("inner");
    fs::create_dir_all(&inner)?;
    fs::write(skip.join("leaving.txt"), "x\n")?;
    // `inner` is watched although it lies in the excluded tree: the nearest watch root or
    // exclude above a file decides. `skipper.txt` shares the exclude's name as a prefix.
    let watcher = watch_with(
        ctx,
        &[OsStr::new("--exclude"), skip.as_os_str()],
        &[&dir, &inner],
    )?;
    sh(
        &dir,
        "echo a > kept.txt && echo b > skipper.txt && mkdir -p skip/deep \
         && echo c > skip/deep/c.txt && echo d > skip/d.txt && chmod 600 skip/d.txt \
         && rm skip/d.txt && mv skip/leaving.txt left.txt && echo e > skip/inner/e.txt",
    )?;
    let touches = touches(&watcher.stop()?)?;
    let [kept, skipper, left, kept_inner] = [
        &dir.join("kept.txt"),
        &dir.join("skipper.txt"),
        &dir.join("left.txt"),
        &inner.join("e.txt"),
    ];
    exactly(
        &touches,
        &[
            ("create", kept),
            ("write", kept),
            ("create", skipper),
            ("write", skipper),
            ("rename", left),
            ("create", kept_inner),
            ("write", kept_inner),
        ],
    )?;
    // A rename into the watched tree is reported, naming where the file came from.
    ensure_path(
        touch(&touches, "rename", left)?,
        "old_path",
        &skip.join("leaving.txt"),
    )?;
    Ok("skip/ silent but for the watched skip/inner; a file moved out names it".to_owned())
}

/// Unmounts the mounts of scenario n in `base` and removes `base`; quiet when nothing is
/// mounted.
fn remove_nested(base: &Path) {
    let _ = Command::new("sudo")
        .arg("-n")
        .args(["umount", "-R"])
        .arg(base.join("tree/disk"))
        .stderr(Stdio::null())
        .status();
    // Never into a mount that is still there.
    let _ = Command::new("sudo")
        .arg("-n")
        .args(["rm", "-rf", "--one-file-system"])
        .arg(base)
        .status();
}

/// Removes the mounts of scenario n, whatever happens.
struct NestedMounts<'a>(&'a Path);

impl Drop for NestedMounts<'_> {
    fn drop(&mut self) {
        remove_nested(self.0);
    }
}

/// The invoking user's uid and gid.
fn ids() -> (u32, u32) {
    // SAFETY: getuid and getgid cannot fail.
    unsafe { (libc::getuid(), libc::getgid()) }
}

/// Mounts a tmpfs owned by the invoking user on `point`.
fn mount_tmpfs(point: &Path) -> Result<()> {
    let (uid, gid) = ids();
    let status = Command::new("sudo")
        .arg("-n")
        .args(["mount", "-t", "tmpfs", "-o"])
        .arg(format!("size=4m,mode=0755,uid={uid},gid={gid}"))
        .arg("fsblame-e2e")
        .arg(point)
        .status()
        .context("running mount")?;
    ensure!(
        status.success(),
        "mounting a tmpfs on {} failed: {status}",
        point.display()
    );
    Ok(())
}

/// Mounts a fresh filesystem owned by the invoking user on `point`: ext4 in `image` on a loop
/// device, or a tmpfs where `mkfs.ext4` or loop devices are missing. Returns its type.
fn mount_disk(image: &Path, point: &Path) -> Result<&'static str> {
    let (uid, gid) = ids();
    fs::File::create(image)
        .and_then(|f| f.set_len(16 << 20))
        .with_context(|| format!("creating {}", image.display()))?;
    let quiet = |cmd: &mut Command| {
        cmd.stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    };
    let ext4 = quiet(
        Command::new("mkfs.ext4")
            .args(["-q", "-F", "-E"])
            .arg(format!("root_owner={uid}:{gid}"))
            .arg(image),
    ) && quiet(
        Command::new("sudo")
            .arg("-n")
            .args(["mount", "-t", "ext4", "-o", "loop"])
            .arg(image)
            .arg(point),
    );
    if ext4 {
        return Ok("ext4");
    }
    mount_tmpfs(point)?;
    Ok("tmpfs")
}

pub fn nested_mount(ctx: &Ctx) -> Result<String> {
    // A run killed halfway leaves the mounts behind.
    remove_nested(&ctx.work.join("n-nested"));
    let base = ctx.dir("n-nested")?;
    let _mounted = NestedMounts(&base);
    let tree = base.join("tree");
    let disk = tree.join("disk");
    let mem = disk.join("mem");
    fs::create_dir_all(&disk)?;
    let fstype = mount_disk(&base.join("disk.img"), &disk)?;
    // A mount on a nested mount: every mount below the watch root is watched.
    fs::create_dir(&mem).with_context(|| format!("creating {}", mem.display()))?;
    mount_tmpfs(&mem)?;

    let watcher = ctx.watch(&[&tree])?;
    sh(
        &tree,
        "echo a > top.txt && echo b > disk/b.txt && mkdir disk/sub && mv disk/b.txt disk/sub/b.txt \
         && echo c > disk/mem/c.txt",
    )?;
    let touches = touches(&watcher.stop()?)?;
    let [top, moved_from, moved, sub, in_mem] = [
        &tree.join("top.txt"),
        &disk.join("b.txt"),
        &disk.join("sub/b.txt"),
        &disk.join("sub"),
        &mem.join("c.txt"),
    ];
    exactly(
        &touches,
        &[
            ("create", top),
            ("write", top),
            ("create", moved_from),
            ("write", moved_from),
            ("mkdir", sub),
            ("rename", moved),
            ("create", in_mem),
            ("write", in_mem),
        ],
    )?;
    ensure_path(touch(&touches, "rename", moved)?, "old_path", moved_from)?;
    Ok(format!(
        "full paths through {fstype} on disk/ and tmpfs on disk/mem/"
    ))
}

pub fn rename_epoch(ctx: &Ctx) -> Result<String> {
    let base = ctx.dir("o-rename-epoch")?;
    let w = base.join("w");
    for sub in ["w/sub", "w/deep/x", "in", "out"] {
        fs::create_dir_all(base.join(sub))?;
    }
    for file in ["w/sub/f", "w/deep/x/h", "in/g"] {
        fs::write(base.join(file), "x\n")?;
    }
    let watcher = ctx.watch(&[&w])?;
    // Each write caches the verdict on its file: in the tree (sub/f, deep/x/h, the latter
    // three names below the root) or out of it (in/g). A directory move keeps the file's
    // dentry, parent and inode; only the epoch the move bumps can invalidate the verdict.
    append(&w.join("sub/f"))?;
    append(&base.join("in/g"))?;
    append(&w.join("deep/x/h"))?;
    sh(&base, "mv w/sub out/sub && mv in w/in && mv w/deep/x w/x")?;
    // Moved out: no longer watched. Moved in: watched. Moved up: one name shorter.
    append(&base.join("out/sub/f"))?;
    append(&w.join("in/g"))?;
    append(&w.join("x/h"))?;
    let touches = touches(&watcher.stop()?)?;
    let renames = [
        (base.join("out/sub"), w.join("sub")),
        (w.join("in"), base.join("in")),
        (w.join("x"), w.join("deep/x")),
    ];
    let mut expected: Vec<(&str, &Path)> = renames
        .iter()
        .map(|(path, _)| ("rename", path.as_path()))
        .collect();
    let writes = [
        w.join("sub/f"),
        w.join("deep/x/h"),
        w.join("in/g"),
        w.join("x/h"),
    ];
    expected.extend(writes.iter().map(|path| ("write", path.as_path())));
    exactly(&touches, &expected)?;
    for (path, old) in &renames {
        ensure_path(touch(&touches, "rename", path)?, "old_path", old)?;
    }
    Ok("moved out: silent; moved in: reported; moved up: the new, shorter path".to_owned())
}

/// The tail `reported` kept of `real`: `reported` is `root/…/tail`, where `tail` is a proper
/// suffix of `real`'s names below `root`.
fn kept_tail<'a>(reported: &'a Value, root: &Path, real: &Path) -> Result<&'a Path> {
    let shown = reported
        .as_str()
        .with_context(|| format!("path {reported} is not a string"))?;
    let tail = Path::new(shown)
        .strip_prefix(root.join("…"))
        .with_context(|| format!("{shown} does not start with {}/…/", root.display()))?;
    let below = real.strip_prefix(root)?;
    ensure!(
        !tail.as_os_str().is_empty() && tail != below && below.ends_with(tail),
        "{shown} does not end with a proper tail of {}",
        real.display()
    );
    Ok(tail)
}

/// `real` as reported when its path is cut to its lowest `keep` names below `root`:
/// `root/…/tail`.
fn cut_path(root: &Path, real: &Path, keep: usize) -> Result<PathBuf> {
    let below = real.strip_prefix(root)?;
    let skip = below.components().count().saturating_sub(keep);
    Ok(root
        .join("…")
        .join(below.components().skip(skip).collect::<PathBuf>()))
}

pub fn truncation(ctx: &Ctx) -> Result<String> {
    /// Depth of the files cut by `WALK_MAX`.
    const FAR: usize = 100;
    let base = ctx.dir("p-truncation")?;
    // Eight directories of 200-byte names: 1.6 KB below the root, past the PATH_CAP bytes
    // the kernel walk emits per path.
    let wide = (0..8).fold(base.clone(), |path, i| {
        path.join(format!("{i}{}", "d".repeat(199)))
    });
    // A chain of short names past WALK_MAX components but far from PATH_CAP bytes: files
    // in `mid` lie exactly WALK_MAX components below the root, those in `far` FAR.
    let walk_max = usize::try_from(fsblame_abi::WALK_MAX)?;
    let path_cap = usize::try_from(fsblame_abi::PATH_CAP)?;
    let chain = |depth: usize| (0..depth).fold(base.clone(), |path, i| path.join(i.to_string()));
    let (mid, far) = (chain(walk_max - 1), chain(FAR - 1));
    ensure!(
        FAR > walk_max && far.strip_prefix(&base)?.as_os_str().len() + 16 < path_cap,
        "the short chain must pass WALK_MAX components within PATH_CAP bytes"
    );
    for dir in [&wide, &far] {
        fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    let watcher = ctx.watch(&[&base])?;
    sh(&wide, "echo x > leaf.txt && mv leaf.txt renamed.txt")?;
    sh(&mid, "echo x > whole.txt")?;
    sh(&far, "echo x > far.txt && mv far.txt moved.txt")?;
    let touches = touches(&watcher.stop()?)?;
    let (leaf, renamed) = (wide.join("leaf.txt"), wide.join("renamed.txt"));
    let (by_bytes, by_names): (Vec<Value>, Vec<Value>) = touches.into_iter().partition(|t| {
        t["path"].as_str().is_some_and(|p| {
            Path::new(p)
                .file_name()
                .is_some_and(|n| n == "leaf.txt" || n == "renamed.txt")
        })
    });

    // WALK_MAX: exactly WALK_MAX names are whole; deeper paths keep their lowest WALK_MAX.
    let whole = mid.join("whole.txt");
    let far_cut = cut_path(&base, &far.join("far.txt"), walk_max)?;
    let moved_cut = cut_path(&base, &far.join("moved.txt"), walk_max)?;
    exactly(
        &by_names,
        &[
            ("create", &whole),
            ("write", &whole),
            ("create", &far_cut),
            ("write", &far_cut),
            ("rename", &moved_cut),
        ],
    )?;
    for t in &by_names {
        let cut = t["path"] != text(&whole).as_str();
        ensure!(
            t["truncated"] == cut,
            "{} {}: truncated is {}, expected {cut}",
            t["op"],
            t["path"],
            t["truncated"]
        );
    }
    ensure_path(
        touch(&by_names, "rename", &moved_cut)?,
        "old_path",
        &far_cut,
    )?;

    // PATH_CAP.
    let touches = by_bytes;
    let mut ops: Vec<&str> = touches.iter().filter_map(|t| t["op"].as_str()).collect();
    ops.sort_unstable();
    ensure!(
        ops == ["create", "rename", "write"],
        "expected a create, a write and a rename; {}",
        summary(&touches)
    );
    let name_cap = usize::try_from(fsblame_abi::NAME_CAP)?;
    let mut kept = 0;
    for t in &touches {
        ensure!(
            t["truncated"] == true,
            "{} {} is not marked truncated",
            t["op"],
            t["path"]
        );
        let real = if t["op"] == "rename" { &renamed } else { &leaf };
        let mut tails = vec![kept_tail(&t["path"], &base, real)?];
        if t["op"] == "rename" {
            tails.push(kept_tail(&t["old_path"], &base, &leaf)?);
        }
        for tail in tails {
            // The kernel emits names (each with its NUL) until PATH_CAP bytes are used;
            // the last one may run past it by less than a name.
            let bytes = tail.as_os_str().len() + 1;
            ensure!(
                (path_cap..path_cap + name_cap).contains(&bytes),
                "{} kept {bytes} bytes of names, expected {path_cap} to {}",
                tail.display(),
                path_cap + name_cap - 1
            );
            kept = kept.max(tail.components().count());
        }
    }
    Ok(format!(
        "{path_cap} bytes: root/…/ plus the last {kept} of {} names; {walk_max} names whole, \
         {FAR} cut to the last {walk_max}",
        wide.strip_prefix(&base)?.components().count() + 1
    ))
}

pub fn hardlinks(ctx: &Ctx) -> Result<String> {
    let base = ctx.dir("q-hardlink")?;
    let (a, b, out) = (base.join("a"), base.join("b"), base.join("out"));
    for dir in [&a, &b, &out] {
        fs::create_dir_all(dir)?;
    }
    fs::write(a.join("f"), "a\n")?;
    fs::write(out.join("o"), "o\n")?;
    let watcher = ctx.watch(&[&a, &b])?;
    sh(&base, "ln a/f b/g && ln out/o a/in && ln a/f out/away")?;
    let touches = touches(&watcher.stop()?)?;
    // Across the roots; into one from outside (the target is named relative to its
    // filesystem's root in the kernel and mapped back through mountinfo); out of one.
    let links: [(PathBuf, PathBuf); 3] = [
        (b.join("g"), a.join("f")),
        (a.join("in"), out.join("o")),
        (out.join("away"), a.join("f")),
    ];
    let expected: Vec<(&str, &Path)> = links
        .iter()
        .map(|(path, _)| ("link", path.as_path()))
        .collect();
    exactly(&touches, &expected)?;
    for (path, target) in &links {
        let t = touch(&touches, "link", path)?;
        ensure_path(t, "target", target)?;
        ensure!(
            t["truncated"] == false,
            "link {} is marked truncated",
            path.display()
        );
    }
    Ok("b/g = a/f, a/in = out/o, out/away = a/f".to_owned())
}

/// Threads of [`exec_storm`], all on one CPU: enough to keep it busy while each waits for its
/// child.
const STORM_THREADS: usize = 16;
/// Execs of each [`exec_storm`] thread.
const STORM_EXECS_PER_THREAD: usize = 100;

/// The first CPU this process may run on.
fn first_cpu() -> Result<usize> {
    // SAFETY: an all-zero cpu_set_t is the empty set.
    let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    // SAFETY: `set` is writable for its size.
    let got = unsafe { libc::sched_getaffinity(0, size_of::<libc::cpu_set_t>(), &raw mut set) };
    ensure!(
        got == 0,
        "sched_getaffinity: {}",
        std::io::Error::last_os_error()
    );
    // SAFETY: CPU_ISSET reads `set` within its size for every index below CPU_SETSIZE.
    (0..usize::try_from(libc::CPU_SETSIZE)?)
        .find(|&cpu| unsafe { libc::CPU_ISSET(cpu, &set) })
        .context("the affinity mask is empty")
}

/// Pins the calling thread, and the processes it starts, to `cpu`.
fn pin(cpu: usize) -> Result<()> {
    // SAFETY: an all-zero cpu_set_t is the empty set.
    let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    // SAFETY: `cpu` is below CPU_SETSIZE (it came from first_cpu); `set` is writable.
    unsafe { libc::CPU_SET(cpu, &mut set) };
    // SAFETY: `set` is readable for its size.
    let set_ok =
        unsafe { libc::sched_setaffinity(0, size_of::<libc::cpu_set_t>(), &raw const set) };
    ensure!(
        set_ok == 0,
        "sched_setaffinity: {}",
        std::io::Error::last_os_error()
    );
    Ok(())
}

/// Execs `true` [`STORM_EXECS_PER_THREAD`] times in each of [`STORM_THREADS`] threads pinned
/// to `cpu`, and returns how many execs that made. Each carries more environment than
/// `ENV_CAP` and an argv near `ARGV_CAP`, so its exec record is about 12 KiB: a 256 KiB ring
/// holds some twenty.
fn exec_storm(cpu: usize) -> Result<usize> {
    let env_cap = usize::try_from(fsblame_abi::ENV_CAP)?;
    let argv_cap = usize::try_from(fsblame_abi::ARGV_CAP)?;
    let pad: Vec<(String, String)> = (0..env_cap / 1000 + 2)
        .map(|i| (format!("FSBLAME_E2E_PAD{i}"), "p".repeat(1000)))
        .collect();
    let arg = "a".repeat(argv_cap - 100);
    thread::scope(|scope| {
        let workers: Vec<_> = (0..STORM_THREADS)
            .map(|_| {
                scope.spawn(|| -> Result<()> {
                    pin(cpu)?;
                    for _ in 0..STORM_EXECS_PER_THREAD {
                        let status = Command::new("true")
                            .arg(&arg)
                            .envs(pad.iter().map(|(k, v)| (k, v)))
                            .status()
                            .context("running true")?;
                        ensure!(status.success(), "true: {status}");
                    }
                    Ok(())
                })
            })
            .collect();
        for worker in workers {
            worker
                .join()
                .map_err(|_| anyhow!("an exec storm thread panicked"))??;
        }
        Ok(STORM_THREADS * STORM_EXECS_PER_THREAD)
    })
}

/// Unix time now, in nanoseconds.
fn unix_now_ns() -> Result<i128> {
    Ok(i128::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos(),
    )?)
}

pub fn ring_overflow(ctx: &Ctx) -> Result<String> {
    let dir = ctx.dir("r-ring")?;
    // fsblame nearly keeps up with execs from every CPU at once (a release build lost a
    // handful of records), so here it runs SCHED_IDLE on one CPU that the storm keeps busy:
    // it drains the ring only when that CPU idles, in practice once the storm is over.
    let cpu = first_cpu()?;
    let mut cmd = Command::new("sudo");
    cmd.arg("-n")
        .args(["chrt", "--idle", "0", "taskset", "--cpu-list"])
        .arg(cpu.to_string())
        .arg(&ctx.bin)
        .args(["watch", "--json", "--duration", MAX_RUN])
        .args(["--ring-size", "256K", "--summary"])
        .arg(&dir);
    let watcher = Watcher::start(cmd)?;
    let execs = exec_storm(cpu)?;
    // Once the storm is over fsblame drains the ring, and changes are reported again.
    thread::sleep(Duration::from_millis(300));
    sh(&dir, "echo after > after.txt")?;
    let stopping = unix_now_ns()?;
    let done = watcher.stop()?;
    let lines = done.touches()?;
    touch(&lines, "write", &dir.join("after.txt"))?;

    let lost: Vec<&Value> = lines.iter().filter(|l| workload_loss(l)).collect();
    ensure!(
        !lost.is_empty(),
        "no lost line after {execs} execs with a 256K ring:\n{}",
        done.stderr
    );
    let mut total = 0;
    for line in &lost {
        ensure!(line["reason"] == "ring-full", "unexpected loss: {line}");
        total += line["count"]
            .as_u64()
            .filter(|&n| n > 0)
            .with_context(|| format!("lost line without a count: {line}"))?;
    }
    // Reported as it happened, not only by the end-of-run report of what is left.
    let first = lost[0]["ts"]
        .as_str()
        .and_then(crate::clock::parse_rfc3339)
        .with_context(|| format!("lost line without an RFC 3339 ts: {}", lost[0]))?;
    ensure!(
        first < stopping,
        "the first lost line ({}) is from after the watcher was told to stop",
        lost[0]["ts"]
    );
    let end = lines.last().context("no output")?;
    ensure!(
        end["type"] == "summary" && end["lost"]["ring_full"] == total,
        "the run ends with {end}, expected a summary with ring_full {total}"
    );
    let warned = done
        .stderr
        .lines()
        .find_map(|l| {
            l.strip_prefix("fsblame: warning: ")?
                .split_once(" kernel records were lost")?
                .0
                .parse::<u64>()
                .ok()
        })
        .with_context(|| format!("no warning about lost records on stderr:\n{}", done.stderr))?;
    ensure!(
        warned == total,
        "stderr says {warned} records were lost, the lost lines {total}"
    );
    Ok(format!(
        "{execs} execs: {total} records lost in {} lost lines, first while running; still \
         reporting after",
        lost.len()
    ))
}
