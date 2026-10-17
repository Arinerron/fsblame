//! End-to-end scenarios ae to ag, al and am: only changes that are made are reported, a chown
//! that clears the setuid and setgid bits is a chown, a symlink target longer than
//! `PATH_CAP - 1` bytes is cut there and marked truncated, a record held for a change that was
//! not made is never reported for a later one, and a name made is reported with the inode it
//! got.

use std::{
    fs,
    os::unix::fs::{MetadataExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use anyhow::{Context as _, Result, ensure};
use fsblame_abi::PATH_CAP;
use serde_json::Value;

use crate::{Ctx, Finished, sh, summary, text, touch};

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

/// ae: the checks fsblame hooks run before the filesystem makes a change, which can still fail.
/// An rmdir of a directory that is not empty, a chmod and a chown of a file the user does not
/// own, and a rename onto a directory that is not empty each pass their check and fail: none is
/// reported. The same ops that succeed are.
pub(crate) fn failed_ops(ctx: &Ctx) -> Result<String> {
    let dir = ctx.dir("ae-failed")?;
    let [full, occupied, moving, mine, theirs] =
        ["full", "occupied", "moving", "mine", "theirs"].map(|name| dir.join(name));
    for parent in [&full, &occupied] {
        fs::create_dir(parent)?;
        fs::write(parent.join("x"), "")?;
    }
    fs::create_dir(&moving)?;
    fs::write(&mine, "")?;
    let status = Command::new("sudo")
        .args(["-n", "touch"])
        .arg(&theirs)
        .status()
        .context("running sudo touch")?;
    ensure!(status.success(), "creating root's file failed: {status}");

    let watcher = ctx.watch(&[&dir])?;
    // Each failure is asserted, so a change that is made cannot pass for one that failed.
    sh(
        &dir,
        "! rmdir full 2>/dev/null && ! chmod 777 theirs 2>/dev/null \
         && ! chown root mine 2>/dev/null && ! mv -T moving occupied 2>/dev/null \
         && mkdir empty && rmdir empty && chmod 600 mine && mv moving moved",
    )?;
    let touches = touches(&watcher.stop()?)?;
    let (empty, moved) = (dir.join("empty"), dir.join("moved"));
    exactly(
        &touches,
        &[
            ("mkdir", &empty),
            ("rmdir", &empty),
            ("chmod", &mine),
            ("rename", &moved),
        ],
    )?;
    Ok("failed rmdir, chmod, chown and rename not reported; the four that succeed are".to_owned())
}

/// af: a chown of a setuid or setgid file clears those bits, which `notify_change` does as a
/// mode change in the same call: it is reported as the chown, with the new owner, not as a chmod.
pub(crate) fn chown_setuid(ctx: &Ctx) -> Result<String> {
    let dir = ctx.dir("af-chown")?;
    let (setuid, setgid) = (dir.join("setuid"), dir.join("setgid"));
    for path in [&setuid, &setgid] {
        fs::write(path, "")?;
    }
    let watcher = ctx.watch(&[&dir])?;
    sh(&dir, "chmod 4755 setuid && chmod 2755 setgid")?;
    let status = Command::new("sudo")
        .args(["-n", "chown", "root"])
        .args([&setuid, &setgid])
        .status()
        .context("running sudo chown")?;
    ensure!(status.success(), "sudo chown failed: {status}");
    let touches = touches(&watcher.stop()?)?;
    exactly(
        &touches,
        &[
            ("chmod", &setuid),
            ("chmod", &setgid),
            ("chown", &setuid),
            ("chown", &setgid),
        ],
    )?;
    for path in [&setuid, &setgid] {
        let chown = touch(&touches, "chown", path)?;
        ensure!(
            chown["change"]["uid"] == 0,
            "chown of {} has change {}",
            path.display(),
            chown["change"]
        );
        let mode = fs::metadata(path)?.permissions().mode();
        ensure!(
            mode & 0o6000 == 0,
            "{} kept mode {mode:o}: the chown cleared no bit",
            path.display()
        );
    }
    Ok("chown of a setuid and of a setgid file reported as chown to uid 0".to_owned())
}

/// ag: a symlink target is kept up to `PATH_CAP - 1` bytes; a longer one is cut there, marked
/// truncated, and shown with `…` for its missing end.
pub(crate) fn long_symlink(ctx: &Ctx) -> Result<String> {
    let kept = usize::try_from(PATH_CAP)? - 1;
    let dir = ctx.dir("ag-symlink")?;
    let lens = [kept, kept + 1, 3000];
    let watcher = ctx.watch(&[&dir])?;
    for len in lens {
        let link = dir.join(format!("link{len}"));
        std::os::unix::fs::symlink("t".repeat(len), &link)
            .with_context(|| format!("symlinking {}", link.display()))?;
    }
    let touches = touches(&watcher.stop()?)?;
    let links = lens.map(|len| dir.join(format!("link{len}")));
    let expected: Vec<(&str, &Path)> = links.iter().map(|l| ("symlink", l.as_path())).collect();
    exactly(&touches, &expected)?;
    for (len, link) in lens.into_iter().zip(&links) {
        let t = touch(&touches, "symlink", link)?;
        let cut = len > kept;
        let target = if cut {
            format!("{}…", "t".repeat(kept))
        } else {
            "t".repeat(len)
        };
        ensure!(
            t["target"] == target.as_str() && t["truncated"] == cut,
            "{len}-byte target reported as {} bytes, truncated {}",
            t["target"].as_str().map_or(0, str::len),
            t["truncated"]
        );
    }
    Ok(format!(
        "targets of {kept} bytes whole, {} and 3000 cut at {kept} and marked truncated",
        kept + 1
    ))
}

/// Unmounts the filesystem of scenario al in `base` and removes `base`, whatever happens; quiet
/// when nothing is mounted.
struct StaleMount(PathBuf);

impl Drop for StaleMount {
    fn drop(&mut self) {
        let _ = Command::new("sudo")
            .args(["-n", "umount"])
            .arg(self.0.join("disk"))
            .stderr(Stdio::null())
            .status();
        // Never into a mount that is still there.
        let _ = Command::new("sudo")
            .args(["-n", "rm", "-rf", "--one-file-system"])
            .arg(&self.0)
            .status();
    }
}

/// al: an `open(O_CREAT)` that fails for want of an inode passed its create check, whose
/// record is held for an open that never creates. The same shell then moves the name's
/// directory out of the watch root, frees an inode, and opens the name again: that create is
/// not watched, and the record held for the failed one must not be reported for it.
pub(crate) fn stale_create(ctx: &Ctx) -> Result<String> {
    const HOOK: &str = "security_file_post_open";
    // A run killed halfway leaves the mount behind.
    drop(StaleMount(ctx.work.join("al-stale")));
    let base = ctx.dir("al-stale")?;
    let _mounted = StaleMount(base.clone());
    let (disk, image) = (base.join("disk"), base.join("disk.img"));
    fs::create_dir(&disk)?;
    fs::File::create(&image)
        .and_then(|f| f.set_len(4 << 20))
        .with_context(|| format!("creating {}", image.display()))?;
    // SAFETY: getuid and getgid cannot fail.
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    let made = Command::new("mkfs.ext4")
        .args(["-q", "-F", "-N", "64", "-E"])
        .arg(format!("root_owner={uid}:{gid}"))
        .arg(&image)
        .status()
        .context("running mkfs.ext4")?;
    ensure!(made.success(), "mkfs.ext4 failed: {made}");
    // ext4 keeps the negative dentry of a failed create, which the second open finds again.
    let mounted = Command::new("sudo")
        .args(["-n", "mount", "-t", "ext4", "-o", "loop"])
        .arg(&image)
        .arg(&disk)
        .status()
        .context("running mount")?;
    ensure!(
        mounted.success(),
        "mounting {} failed: {mounted}",
        image.display()
    );
    let (root, out) = (disk.join("w"), disk.join("out"));
    fs::create_dir_all(root.join("a"))?;
    fs::create_dir(&out)?;
    let mut filled = 0;
    loop {
        match fs::File::create(disk.join(format!("fill{filled}"))) {
            Ok(_) => filled += 1,
            Err(e) if e.raw_os_error() == Some(libc::ENOSPC) => break,
            Err(e) => return Err(e).context("using up the inodes"),
        }
        ensure!(filled < 10_000, "{} kept making inodes", disk.display());
    }

    let watcher = ctx.watch(&[&root])?;
    // `true` rather than `:`, whose failed redirection would end the shell. The opens are the
    // shell's own, by one thread.
    sh(
        &disk,
        "! true 2>/dev/null > w/a/new && mv w/a out/a && rm fill0 && true > out/a/new",
    )?;
    let done = watcher.stop()?;
    let touches = touches(&done)?;
    let moved = out.join("a");
    ensure!(
        moved.join("new").exists(),
        "the second open created nothing"
    );
    if done.stderr.contains(HOOK) {
        // Creates are reported at the check here, the failed one too.
        exactly(
            &touches,
            &[("create", &root.join("a/new")), ("rename", &moved)],
        )?;
        return Ok(format!(
            "the failed create reported at its check: no {HOOK} on this kernel; nothing after"
        ));
    }
    exactly(&touches, &[("rename", &moved)])?;
    Ok("no create for the failed open, at its old path or the new one".to_owned())
}

/// am: a create, mkdir, mknod or symlink confirmed once it is made is reported with the inode
/// the name got, its number and its mode as the filesystem settled it: past the umask, and with
/// the setgid bit a directory passes on. A create where `security_file_post_open` is missing
/// (before Linux 6.9) is reported at its check, before the inode exists: inode 0.
pub(crate) fn made_inodes(ctx: &Ctx) -> Result<String> {
    const HOOK: &str = "security_file_post_open";
    let dir = ctx.dir("am-made")?;
    let setgid = dir.join("g");
    fs::create_dir(&setgid)?;
    fs::set_permissions(&setgid, fs::Permissions::from_mode(0o2755))?;
    let watcher = ctx.watch(&[&dir])?;
    sh(
        &dir,
        "umask 022 && true > file && mkdir dir g/sub && mkfifo fifo && ln -s file link",
    )?;
    let done = watcher.stop()?;
    let touches = touches(&done)?;
    let names = [
        ("create", dir.join("file")),
        ("mkdir", dir.join("dir")),
        ("mkdir", setgid.join("sub")),
        ("mknod", dir.join("fifo")),
        ("symlink", dir.join("link")),
    ];
    let expected: Vec<(&str, &Path)> = names.iter().map(|(op, p)| (*op, p.as_path())).collect();
    exactly(&touches, &expected)?;
    let confirmed = !done.stderr.contains(HOOK);
    for (op, path) in &names {
        let file = &touch(&touches, op, path)?["file"];
        let meta = fs::symlink_metadata(path)?;
        if *op == "create" && !confirmed {
            ensure!(
                file["ino"] == 0,
                "create of {} reported at its check has {file}",
                path.display()
            );
            continue;
        }
        let mode = format!("{:o}", meta.mode());
        ensure!(
            file["ino"] == meta.ino() && file["mode"] == mode.as_str(),
            "{op} of {} has {file}, the inode made is {} with mode {mode}",
            path.display(),
            meta.ino()
        );
    }
    Ok(if confirmed {
        "create, mkdir, mknod and symlink with the inode made: its number and settled mode"
            .to_owned()
    } else {
        format!(
            "mkdir, mknod and symlink with the inode made; the create at its check, inode 0: no \
             {HOOK} on this kernel"
        )
    })
}
