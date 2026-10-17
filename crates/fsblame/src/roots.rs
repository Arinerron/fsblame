//! Watch roots: resolving paths to the (superblock device, inode) pairs the kernel matches,
//! and turning reported dentry names back into paths.
//!
//! # Overlay filesystems
//!
//! An overlayfs mount shows one tree, the merged view, built from read-only lower layers and
//! one writable upper layer (`upperdir=`), beside which overlayfs keeps a private work
//! directory (`workdir=`). A change made through the merged view reaches the kernel's
//! security hooks twice, both times in the context of the process that made it: first as the
//! operation on the overlay's own dentry, which is exactly that change, then as overlayfs's
//! operations on the upper filesystem. Those repeat the change on the upper file and add the
//! steps of a copy-up (the first change to a lower file copies it into the work directory,
//! sets its attributes and links or renames it into the upper layer) or of a whiteout
//! (removing a lower name moves a 0:0 character device over it in the upper layer).
//!
//! fsblame therefore reports the overlay's own operations, at their merged paths, and never
//! the upper layer's. [`Roots::resolve`] watches a path inside an upper layer through its
//! merged counterpart, watches the merged view of an upper layer that lies in a watched
//! tree, and excludes the upper layer and work directory of every overlay it watches or
//! excludes. A merged-view root is identified by the device in mountinfo and `stat`'s inode
//! number, which are the overlay's `s_dev` and `i_ino` that the kernel walk compares
//! (`stat`'s device is a layer's for some files and is not used).
//!
//! Inode numbers identify files on an overlay unless its layers span filesystems and `xino`
//! is off. overlayfs then numbers a directory inode from a counter each time it loads it,
//! and those numbers can equal a file's, which keeps the number it has on its layer. Roots
//! below the root of such an overlay are kept open so that their number stays fixed;
//! `fsblame.watchfs` warns about the collisions.

use std::{
    collections::HashSet,
    ffi::{OsStr, OsString},
    fs::{self, File, OpenOptions},
    io, mem,
    os::{
        fd::AsRawFd as _,
        unix::{
            ffi::{OsStrExt as _, OsStringExt as _},
            fs::{MetadataExt as _, OpenOptionsExt as _},
        },
    },
    path::{Path, PathBuf},
};

use anyhow::{Context as _, anyhow};
use fsblame_abi::{self as abi, DevFilter};

/// One line of `/proc/self/mountinfo`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mount {
    /// Mount id.
    pub id: u32,
    /// Kernel `dev_t` of the superblock (`sb->s_dev`, which is what BPF sees; `stat`'s
    /// `st_dev` differs on btrfs subvolumes and for some files on overlays).
    pub dev: u32,
    /// Path of the mount's root inside its filesystem (`/` unless a bind or subvolume mount).
    pub root: PathBuf,
    /// Mount point.
    pub point: PathBuf,
    /// Filesystem type, such as `ext4` or `fuse.sshfs`.
    pub fstype: String,
    /// Superblock options, such as overlayfs's `upperdir=`.
    pub super_opts: String,
}

/// Kernel-internal `dev_t` encoding (`MAJOR << 20 | MINOR`).
pub const fn kernel_dev(major: u32, minor: u32) -> u32 {
    (major << 20) | (minor & 0xf_ffff)
}

/// `MAJOR:MINOR` of a kernel `dev_t`.
pub fn dev_string(dev: u32) -> String {
    format!("{}:{}", dev >> 20, dev & 0xf_ffff)
}

/// Undoes mountinfo's octal escapes (`\040` for space and so on).
fn unescape(field: &str) -> PathBuf {
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let octal = bytes
            .get(i + 1..i + 4)
            .filter(|d| d.iter().all(|b| (b'0'..=b'7').contains(b)));
        match (bytes[i], octal) {
            (b'\\', Some(d)) => {
                out.push((d[0] - b'0') << 6 | (d[1] - b'0') << 3 | (d[2] - b'0'));
                i += 4;
            }
            (b, _) => {
                out.push(b);
                i += 1;
            }
        }
    }
    PathBuf::from(OsString::from_vec(out))
}

/// Parses `/proc/<pid>/mountinfo`; malformed lines are skipped.
pub fn parse_mountinfo(text: &str) -> Vec<Mount> {
    text.lines()
        .filter_map(|line| {
            let (head, tail) = line.split_once(" - ")?;
            let mut head = head.split(' ');
            let id = head.next()?.parse().ok()?;
            let _parent = head.next()?;
            let (major, minor) = head.next()?.split_once(':')?;
            let root = unescape(head.next()?);
            let point = unescape(head.next()?);
            let mut tail = tail.split(' ');
            let fstype = tail.next()?.to_owned();
            let _source = tail.next()?;
            let super_opts = tail.next().unwrap_or_default().to_owned();
            Some(Mount {
                id,
                dev: kernel_dev(major.parse().ok()?, minor.parse().ok()?),
                root,
                point,
                fstype,
                super_opts,
            })
        })
        .collect()
}

/// The mounts of this process's mount namespace.
pub fn mounts() -> io::Result<Vec<Mount>> {
    Ok(parse_mountinfo(&fs::read_to_string(
        "/proc/self/mountinfo",
    )?))
}

/// Opens `path` without following permissions (`O_PATH`), for identity queries only.
fn open_path(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
        .open(path)
}

/// Id of the mount an open file lives on, from `/proc/self/fdinfo`.
fn mount_id(file: &File) -> io::Result<u32> {
    let info = fs::read_to_string(format!("/proc/self/fdinfo/{}", file.as_raw_fd()))?;
    info.lines()
        .find_map(|line| line.strip_prefix("mnt_id:"))
        .and_then(|id| id.trim().parse().ok())
        .ok_or_else(|| io::Error::other("no mnt_id in fdinfo"))
}

/// Opens `path` (`O_PATH`) and finds the mount and inode number holding it.
fn open_located<'m>(path: &Path, mounts: &'m [Mount]) -> io::Result<(File, &'m Mount, u64)> {
    let file = open_path(path)?;
    let ino = file.metadata()?.ino();
    let id = mount_id(&file)?;
    let mount = mounts
        .iter()
        .find(|m| m.id == id)
        .ok_or_else(|| io::Error::other(format!("mount {id} is not in /proc/self/mountinfo")))?;
    Ok((file, mount, ino))
}

/// The mount and inode number holding `path` (canonical).
pub fn locate<'m>(path: &Path, mounts: &'m [Mount]) -> io::Result<(&'m Mount, u64)> {
    open_located(path, mounts).map(|(_, mount, ino)| (mount, ino))
}

/// Where the path `rel`, relative to the root of filesystem `dev`, is visible: below the
/// shortest mount point of a mount of that filesystem whose root contains it.
fn visible(mounts: &[Mount], dev: u32, rel: &Path) -> Option<PathBuf> {
    let rel = Path::new("/").join(rel);
    mounts
        .iter()
        .filter(|m| m.dev == dev)
        .filter_map(|m| Some((m, rel.strip_prefix(&m.root).ok()?)))
        .min_by_key(|(m, _)| m.point.as_os_str().len())
        .map(|(m, below)| {
            if below.as_os_str().is_empty() {
                m.point.clone()
            } else {
                m.point.join(below)
            }
        })
}

/// The canonical form of `path`, which must name the same file in this mount namespace. A
/// path through a `/proc/<pid>/` link (`root`, `cwd`) of a process in another mount
/// namespace does not: the kernel follows the link into that namespace, but canonicalizing
/// yields the path there, which names another file here or none (for a container,
/// `/proc/<pid>/root/etc` would become the host's `/etc`). Such a path is refused, naming
/// where this namespace sees the same file, if it does.
pub fn canonical(path: &Path, mounts: &[Mount]) -> anyhow::Result<PathBuf> {
    let identity = |m: fs::Metadata| (m.dev(), m.ino());
    let file = identity(fs::metadata(path)?);
    if let Ok(found) = fs::canonicalize(path)
        && fs::metadata(&found).is_ok_and(|m| identity(m) == file)
    {
        return Ok(found);
    }
    let here = std::path::absolute(path)
        .ok()
        .and_then(|path| seen_here(&path, mounts));
    Err(match here {
        Some(here) => anyhow!(
            "it leads into another mount namespace; watch {}, where this one sees the same file",
            here.display()
        ),
        None => anyhow!(
            "it leads into another mount namespace and is not visible in this one; run fsblame \
             in a mount namespace that has it"
        ),
    })
}

/// Where this mount namespace sees the file that the absolute `path` reaches through a
/// `/proc/<pid>/` link into another one: below a mount here of the same filesystem and
/// directory. `None` when there is none, or `path` does not start with such a link.
fn seen_here(path: &Path, mounts: &[Mount]) -> Option<PathBuf> {
    let mut parts = path.components().skip(1);
    if parts.next()?.as_os_str() != "proc" {
        return None;
    }
    let pid: u32 = parts.next()?.as_os_str().to_str()?.parse().ok()?;
    let file = open_path(path).ok()?;
    let id = mount_id(&file).ok()?;
    let theirs = fs::read_to_string(format!("/proc/{pid}/mountinfo")).ok()?;
    let mount = parse_mountinfo(&theirs).into_iter().find(|m| m.id == id)?;
    // The kernel names a file outside this namespace by its path in its own.
    let named = fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd())).ok()?;
    let below = named.strip_prefix(&mount.point).ok()?;
    let rel = if below.as_os_str().is_empty() {
        mount.root
    } else {
        mount.root.join(below)
    };
    visible(mounts, mount.dev, &rel)
}

/// Values of the superblock option `key` (`key=value`), unescaped. mountinfo escapes commas
/// inside values, so splitting at commas is exact.
fn options<'o>(super_opts: &'o str, key: &'o str) -> impl Iterator<Item = PathBuf> + 'o {
    super_opts
        .split(',')
        .filter_map(move |opt| opt.strip_prefix(key)?.strip_prefix('='))
        .map(unescape)
}

/// The directories of an overlay's lower layers: `lowerdir=` (separated by `:`, data-only
/// layers after `::`, a literal colon escaped as `\:`), then `lowerdir+=` and `datadir+=`.
fn lower_dirs(super_opts: &str) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    for list in options(super_opts, "lowerdir") {
        let mut dir = Vec::new();
        let mut bytes = list.as_os_str().as_bytes().iter();
        while let Some(&b) = bytes.next() {
            match b {
                b'\\' if bytes.as_slice().first() == Some(&b':') => {
                    bytes.next();
                    dir.push(b':');
                }
                b':' if dir.is_empty() => {}
                b':' => dirs.push(PathBuf::from(OsString::from_vec(mem::take(&mut dir)))),
                b => dir.push(b),
            }
        }
        if !dir.is_empty() {
            dirs.push(PathBuf::from(OsString::from_vec(dir)));
        }
    }
    dirs.extend(options(super_opts, "lowerdir+"));
    dirs.extend(options(super_opts, "datadir+"));
    dirs
}

/// Whether overlayfs turns `xino` on when the mount options do not say: `xino=auto` is the
/// default when the module parameter `xino_auto` is set.
fn xino_default() -> bool {
    fs::read_to_string("/sys/module/overlay/parameters/xino_auto").is_ok_and(|v| v.trim() == "Y")
}

/// A directory an overlay mount option names, found in this mount namespace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Layer {
    /// Canonical path.
    pub path: PathBuf,
    /// Kernel `dev_t` of its superblock.
    pub dev: u32,
    /// Inode number.
    pub ino: u64,
    /// Filesystem type.
    pub fstype: String,
}

impl Layer {
    fn find(path: &Path, mounts: &[Mount]) -> io::Result<Self> {
        let path = fs::canonicalize(path)?;
        let (mount, ino) = locate(&path, mounts)?;
        Ok(Self {
            dev: mount.dev,
            fstype: mount.fstype.clone(),
            path,
            ino,
        })
    }
}

/// The writable side of an overlay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Writable {
    /// The upper layer (`upperdir=`): every file changed through the overlay lives there.
    pub upper: Layer,
    /// overlayfs's work directory (`workdir=`), where copy-ups and whiteouts are prepared.
    pub work: Layer,
    /// What relative layer options are relative to.
    base: PathBuf,
}

/// The upper layer and work directory named by an overlay mounted at `point`. A relative
/// option was relative to the mounting process's working directory, which container engines
/// set to a directory above the mount point (Docker and Podman pass relative options when
/// absolute ones would not fit in a page), so it is looked up below each ancestor of the
/// mount point, nearest first. overlayfs keeps a `work` subdirectory in its work directory,
/// on the upper layer's filesystem, which confirms a candidate.
fn find_writable(point: &Path, upper: &Path, work: &Path, mounts: &[Mount]) -> Option<Writable> {
    let bases: Vec<&Path> = if upper.is_absolute() && work.is_absolute() {
        vec![Path::new("/")]
    } else {
        point.ancestors().skip(1).collect()
    };
    bases.into_iter().find_map(|base| {
        let work_dir = base.join(work);
        if !work_dir.join("work").is_dir() {
            return None;
        }
        let writable = Writable {
            upper: Layer::find(&base.join(upper), mounts).ok()?,
            work: Layer::find(&work_dir, mounts).ok()?,
            base: base.to_path_buf(),
        };
        (writable.upper.dev == writable.work.dev).then_some(writable)
    })
}

/// An overlayfs superblock as this mount namespace sees it (see the module docs).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Overlay {
    /// Superblock device of the merged view.
    pub dev: u32,
    /// The shortest mount point showing the root of the merged view; `None` when only parts
    /// of it are mounted here.
    pub point: Option<PathBuf>,
    /// `upperdir=` as given at mount time; `None` for a read-only overlay.
    pub upperdir: Option<PathBuf>,
    /// The upper layer and work directory, when `upperdir=` and `workdir=` resolve here.
    pub writable: Option<Writable>,
    /// Superblock options.
    super_opts: String,
}

impl Overlay {
    fn new(mount: &Mount, mounts: &[Mount]) -> Self {
        let upperdir = options(&mount.super_opts, "upperdir").next();
        let writable = upperdir
            .as_deref()
            .zip(options(&mount.super_opts, "workdir").next())
            .and_then(|(upper, work)| find_writable(&mount.point, upper, &work, mounts));
        Self {
            dev: mount.dev,
            point: visible(mounts, mount.dev, Path::new("")),
            upperdir,
            writable,
            super_opts: mount.super_opts.clone(),
        }
    }

    /// Whether inode numbers identify files on it (see the module docs): `xino` is on, or the
    /// upper layer and every lower layer share a superblock. Layers that cannot be found count
    /// as shared, all of them when the upper layer is not found or there is none (a read-only
    /// overlay does not change).
    pub fn unique_inodes(&self, mounts: &[Mount]) -> bool {
        let Some(writable) = &self.writable else {
            return true;
        };
        let xino = options(&self.super_opts, "xino")
            .next()
            .map_or_else(xino_default, |v| v.as_os_str() != "off");
        xino || lower_dirs(&self.super_opts).iter().all(|dir| {
            locate(&writable.base.join(dir), mounts)
                .ok()
                .is_none_or(|(m, _)| m.dev == writable.upper.dev)
        })
    }
}

/// Every overlayfs superblock mounted in this mount namespace, once each.
pub fn overlays(mounts: &[Mount]) -> Vec<Overlay> {
    let mut seen = HashSet::new();
    mounts
        .iter()
        .filter(|m| m.fstype == "overlay" && seen.insert(m.dev))
        .map(|m| Overlay::new(m, mounts))
        .collect()
}

/// The merged-view counterpart of `path` when it lies in the upper layer of a mounted
/// overlay.
fn merged_counterpart(path: &Path, overlays: &[Overlay], mounts: &[Mount]) -> Option<PathBuf> {
    overlays.iter().find_map(|overlay| {
        let rel = path
            .strip_prefix(&overlay.writable.as_ref()?.upper.path)
            .ok()?;
        visible(mounts, overlay.dev, rel)
    })
}

/// A watched or excluded file or directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Root {
    /// Canonical path.
    pub path: PathBuf,
    /// Events below it are ignored.
    pub exclude: bool,
    /// A watch root added for a mount below a watch root, or for the merged view of an
    /// overlay whose upper layer is watched.
    pub nested: bool,
    /// Kernel `dev_t` of its superblock.
    pub dev: u32,
    /// Inode number.
    pub ino: u64,
    /// Filesystem type.
    pub fstype: String,
}

/// Whether `path` is in scope by its path: the deepest root containing it is a watch root.
fn watched(roots: &[Root], path: &Path) -> bool {
    roots
        .iter()
        .filter(|r| path.starts_with(&r.path))
        .max_by_key(|r| r.path.as_os_str().len())
        .is_some_and(|r| !r.exclude)
}

/// All roots, indexed by the id the kernel reports.
#[derive(Debug)]
pub struct Roots {
    entries: Vec<Root>,
    mounts: Vec<Mount>,
    /// No watch paths were given: every filesystem is watched, and the entries are excludes.
    everywhere: bool,
    /// Roots on overlays without unique inode numbers, held open so that overlayfs keeps
    /// their inode, and its number, loaded (see the module docs).
    _pins: Vec<File>,
}

impl Roots {
    /// Resolves the watch and exclude paths, adding every mount below a watch root (the
    /// kernel's `d_parent` walk does not cross mounts) and applying the overlay rules of the
    /// module docs. Without watch paths every filesystem is watched (`fsblame run`): the
    /// roots are the excludes and the upper layer and work directory of every overlay, whose
    /// changes are reported through its merged view. Fails on paths that do not exist.
    pub fn resolve(watch: &[PathBuf], exclude: &[PathBuf]) -> anyhow::Result<Self> {
        let everywhere = watch.is_empty();
        let mounts = mounts().context("reading /proc/self/mountinfo")?;
        let overlays = overlays(&mounts);
        let mut roots: Vec<Root> = Vec::new();
        let mut seen = HashSet::new();
        let mut pins = Vec::new();
        let given = watch
            .iter()
            .map(|p| (p, false))
            .chain(exclude.iter().map(|p| (p, true)));
        for (path, exclude) in given {
            let canonical = canonical(path, &mounts)
                .with_context(|| format!("cannot watch {}", path.display()))?;
            let canonical = merged_counterpart(&canonical, &overlays, &mounts)
                .filter(|merged| merged.exists())
                .unwrap_or(canonical);
            let (file, mount, ino) = open_located(&canonical, &mounts)
                .with_context(|| format!("cannot identify {}", canonical.display()))?;
            if !seen.insert((mount.dev, ino)) {
                continue;
            }
            // A mount's root stays loaded while it is mounted.
            if canonical != mount.point
                && overlays
                    .iter()
                    .any(|o| o.dev == mount.dev && !o.unique_inodes(&mounts))
            {
                pins.push(file);
            }
            roots.push(Root {
                path: canonical,
                exclude,
                nested: false,
                dev: mount.dev,
                ino,
                fstype: mount.fstype.clone(),
            });
        }
        let mut nested = Vec::new();
        for mount in &mounts {
            let enclosing = roots
                .iter()
                .filter(|r| mount.point.starts_with(&r.path) && mount.point != r.path)
                .max_by_key(|r| r.path.as_os_str().len());
            if enclosing.is_none_or(|r| r.exclude) {
                continue;
            }
            // A mount hidden by another one on the same point is unreachable; skip it.
            let Ok((top, ino)) = locate(&mount.point, &mounts) else {
                continue;
            };
            if top.id == mount.id && seen.insert((mount.dev, ino)) {
                nested.push(Root {
                    path: mount.point.clone(),
                    exclude: false,
                    nested: true,
                    dev: mount.dev,
                    ino,
                    fstype: mount.fstype.clone(),
                });
            }
        }
        roots.extend(nested);
        for overlay in &overlays {
            cover_overlay(&mut roots, &mut seen, overlay, &mounts, everywhere);
        }
        if !everywhere && !roots.iter().any(|r| !r.exclude) {
            return Err(anyhow!("every watch path is also excluded"));
        }
        Ok(Self {
            entries: roots,
            mounts,
            everywhere,
            _pins: pins,
        })
    }

    /// Whether every filesystem is watched (no watch paths): the roots are all excludes.
    pub fn everywhere(&self) -> bool {
        self.everywhere
    }

    /// Number of roots.
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    /// Roots made of `entries` alone, with no mounts (sides outside every root map to
    /// `<dev …>` paths), for tests of code that rebuilds paths.
    #[cfg(test)]
    pub(crate) fn from_entries(entries: Vec<Root>) -> Self {
        Self {
            entries,
            mounts: Vec::new(),
            everywhere: false,
            _pins: Vec::new(),
        }
    }

    /// Roots with their ids.
    pub fn iter(&self) -> impl Iterator<Item = (u32, &Root)> {
        (0u32..).zip(&self.entries)
    }

    /// The `.rodata` device prefilter: every superblock where the kernel's scope walk can
    /// meet a root that decides, which is a watch root, or an exclude when watching
    /// [`everywhere`](Self::everywhere).
    pub fn dev_filter(&self) -> DevFilter {
        let mut devs: Vec<u32> = self
            .entries
            .iter()
            .filter(|r| self.everywhere || !r.exclude)
            .map(|r| r.dev)
            .collect();
        devs.sort_unstable();
        devs.dedup();
        let mut filter = DevFilter {
            count: 0,
            _pad: 0,
            devs: [0; abi::MAX_DEVS as usize],
        };
        if let Ok(count) = u32::try_from(devs.len())
            && count <= abi::MAX_DEVS
        {
            filter.devs[..devs.len()].copy_from_slice(&devs);
            filter.count = count;
        }
        filter
    }

    /// The absolute path for dentry names reported relative to `root` (leaf first, each
    /// NUL-terminated). `None` for `ROOT_NONE` or an unknown root id. A truncated walk lost
    /// its upper components, which show as `…`; a truncated raw string (`ROOT_RAW`, a symlink
    /// target) lost its end, which shows as `…` too.
    pub fn path(&self, root: u32, dev: u32, names: &[u8], truncated: bool) -> Option<PathBuf> {
        if root == abi::ROOT_RAW {
            let raw = names.split(|&b| b == 0).next().unwrap_or_default();
            let mut raw = OsStr::from_bytes(raw).to_os_string();
            if truncated {
                raw.push("…");
            }
            return Some(PathBuf::from(raw));
        }
        let mut rel = PathBuf::new();
        if truncated {
            rel.push("…");
        }
        let mut parts: Vec<&[u8]> = names.split(|&b| b == 0).filter(|n| !n.is_empty()).collect();
        parts.reverse();
        for part in parts {
            rel.push(OsStr::from_bytes(part));
        }
        match root {
            abi::ROOT_NONE => None,
            abi::ROOT_FSROOT => Some(
                visible(&self.mounts, dev, &rel)
                    .unwrap_or_else(|| Path::new(&format!("<dev {}>", dev_string(dev))).join(&rel)),
            ),
            id => {
                let root = self.entries.get(usize::try_from(id).ok()?)?;
                Some(if rel.as_os_str().is_empty() {
                    root.path.clone()
                } else {
                    root.path.join(rel)
                })
            }
        }
    }
}

/// Applies the overlay rules of the module docs to one overlay, after the given roots and
/// the nested mounts: a watched upper layer brings the merged view into scope, and the
/// upper layer and work directory are excluded once the merged view has a root or either of
/// them is watched, or when watching `everywhere` (where the merged view is in scope anyway).
fn cover_overlay(
    roots: &mut Vec<Root>,
    seen: &mut HashSet<(u32, u64)>,
    overlay: &Overlay,
    mounts: &[Mount],
    everywhere: bool,
) {
    let Some(writable) = &overlay.writable else {
        return;
    };
    let upper_watched = !everywhere && watched(roots, &writable.upper.path);
    if upper_watched
        && let Some(point) = &overlay.point
        && let Ok((mount, ino)) = locate(point, mounts)
        && mount.dev == overlay.dev
        && seen.insert((mount.dev, ino))
    {
        roots.push(Root {
            path: point.clone(),
            exclude: false,
            nested: true,
            dev: mount.dev,
            ino,
            fstype: mount.fstype.clone(),
        });
    }
    if everywhere
        || upper_watched
        || watched(roots, &writable.work.path)
        || roots.iter().any(|r| r.dev == overlay.dev)
    {
        for layer in [&writable.upper, &writable.work] {
            if seen.insert((layer.dev, layer.ino)) {
                roots.push(Root {
                    path: layer.path.clone(),
                    exclude: true,
                    nested: false,
                    dev: layer.dev,
                    ino: layer.ino,
                    fstype: layer.fstype.clone(),
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MOUNTINFO: &str = "\
22 1 259:2 / / rw,relatime shared:1 - ext4 /dev/nvme0n1p2 rw
40 22 0:35 / /tmp rw,nosuid,nodev shared:17 - tmpfs tmpfs rw,size=16G
61 22 259:2 /srv/data /mnt/with\\040space rw,relatime shared:30 - ext4 /dev/nvme0n1p2 rw
77 22 0:52 / /merged rw - overlay overlay rw,lowerdir=/l,upperdir=/u,workdir=/w
78 22 0:52 /etc /ctr/etc rw - overlay overlay rw,lowerdir=/l,upperdir=/u,workdir=/w
";

    fn roots() -> Roots {
        Roots {
            entries: vec![Root {
                path: PathBuf::from("/home/u/proj"),
                exclude: false,
                nested: false,
                dev: kernel_dev(259, 2),
                ino: 42,
                fstype: "ext4".into(),
            }],
            mounts: parse_mountinfo(MOUNTINFO),
            everywhere: false,
            _pins: Vec::new(),
        }
    }

    fn root(path: &str, exclude: bool) -> Root {
        Root {
            path: PathBuf::from(path),
            exclude,
            nested: false,
            dev: 0,
            ino: 0,
            fstype: String::new(),
        }
    }

    #[test]
    fn mountinfo_fields_and_escapes() {
        let mounts = parse_mountinfo(MOUNTINFO);
        assert_eq!(mounts.len(), 5);
        assert_eq!(mounts[1].dev, kernel_dev(0, 35));
        assert_eq!(mounts[2].point, PathBuf::from("/mnt/with space"));
        assert_eq!(mounts[2].root, PathBuf::from("/srv/data"));
        assert_eq!(mounts[3].fstype, "overlay");
        assert!(mounts[3].super_opts.contains("upperdir=/u"));
        assert_eq!(dev_string(kernel_dev(259, 2)), "259:2");
    }

    #[test]
    fn names_are_reversed_below_their_root() {
        let roots = roots();
        let names = b"deep.txt\0c\0b\0a\0";
        assert_eq!(
            roots.path(0, 0, names, false),
            Some(PathBuf::from("/home/u/proj/a/b/c/deep.txt"))
        );
        assert_eq!(
            roots.path(0, 0, b"", false),
            Some(PathBuf::from("/home/u/proj"))
        );
        assert_eq!(
            roots.path(0, 0, b"f\0d\0", true),
            Some(PathBuf::from("/home/u/proj/…/d/f"))
        );
        assert_eq!(roots.path(abi::ROOT_NONE, 0, names, false), None);
        assert_eq!(roots.path(7, 0, names, false), None);
        assert_eq!(
            roots.path(abi::ROOT_RAW, 0, b"../target\0", false),
            Some(PathBuf::from("../target"))
        );
        // A symlink target the kernel cut lost its end, not its start.
        assert_eq!(
            roots.path(abi::ROOT_RAW, 0, b"../tar\0", true),
            Some(PathBuf::from("../tar…"))
        );
    }

    #[test]
    fn filesystem_relative_paths_map_through_the_best_mount() {
        let roots = roots();
        let dev = kernel_dev(259, 2);
        assert_eq!(
            roots.path(abi::ROOT_FSROOT, dev, b"x\0outside\0", false),
            Some(PathBuf::from("/outside/x"))
        );
        // Both `/` and the bind mount show /srv/data; the shorter mount point wins.
        assert_eq!(
            roots.path(abi::ROOT_FSROOT, dev, b"f\0data\0srv\0", false),
            Some(PathBuf::from("/srv/data/f"))
        );
        assert_eq!(
            roots.path(abi::ROOT_FSROOT, kernel_dev(0, 35), b"f\0", false),
            Some(PathBuf::from("/tmp/f"))
        );
        assert_eq!(
            roots.path(abi::ROOT_FSROOT, kernel_dev(9, 9), b"f\0", false),
            Some(PathBuf::from("<dev 9:9>/f"))
        );
    }

    #[test]
    fn overlay_layer_options() {
        let opts = "rw,lowerdir=/l1:/l\\134:2::/data,upperdir=/u\\054v,workdir=/w,xino=off";
        assert_eq!(
            lower_dirs(opts),
            [
                PathBuf::from("/l1"),
                PathBuf::from("/l:2"),
                PathBuf::from("/data")
            ]
        );
        assert_eq!(
            options(opts, "upperdir").collect::<Vec<_>>(),
            [PathBuf::from("/u,v")]
        );
        assert_eq!(
            lower_dirs("rw,lowerdir+=/a,lowerdir+=/b,datadir+=/d,upperdir=/u"),
            [
                PathBuf::from("/a"),
                PathBuf::from("/b"),
                PathBuf::from("/d")
            ]
        );
    }

    #[test]
    fn upper_layer_paths_map_into_the_merged_view() {
        let mounts = parse_mountinfo(MOUNTINFO);
        let layer = |path: &str| Layer {
            path: PathBuf::from(path),
            dev: kernel_dev(259, 2),
            ino: 0,
            fstype: "ext4".into(),
        };
        let overlays = [Overlay {
            dev: kernel_dev(0, 52),
            point: Some(PathBuf::from("/merged")),
            upperdir: Some(PathBuf::from("/u")),
            writable: Some(Writable {
                upper: layer("/u"),
                work: layer("/w"),
                base: PathBuf::from("/"),
            }),
            super_opts: String::new(),
        }];
        let merged = |path: &str| merged_counterpart(Path::new(path), &overlays, &mounts);
        assert_eq!(merged("/u"), Some(PathBuf::from("/merged")));
        assert_eq!(merged("/u/a/b"), Some(PathBuf::from("/merged/a/b")));
        // /etc is also bind-mounted at /ctr/etc, but /merged is the shorter mount point.
        assert_eq!(merged("/u/etc/x"), Some(PathBuf::from("/merged/etc/x")));
        assert_eq!(merged("/uv/a"), None);
        assert_eq!(merged("/w/work"), None);
    }

    #[test]
    fn everywhere_excludes_overlay_layers_and_filters_exclude_devices() {
        let layer = |path: &str, ino| Layer {
            path: PathBuf::from(path),
            dev: kernel_dev(259, 2),
            ino,
            fstype: "ext4".into(),
        };
        let overlay = Overlay {
            dev: kernel_dev(0, 52),
            point: Some(PathBuf::from("/merged")),
            upperdir: Some(PathBuf::from("/u")),
            writable: Some(Writable {
                upper: layer("/u", 2),
                work: layer("/w", 3),
                base: PathBuf::from("/"),
            }),
            super_opts: String::new(),
        };
        let excluded = Root {
            dev: kernel_dev(0, 35),
            ino: 9,
            ..root("/tmp/cache", true)
        };
        let mut entries = vec![excluded];
        let mut seen = HashSet::from([(kernel_dev(0, 35), 9)]);
        let mounts = parse_mountinfo(MOUNTINFO);
        cover_overlay(&mut entries, &mut seen, &overlay, &mounts, true);
        // The merged view is in scope as part of everything; its layers never are.
        let paths: Vec<(&Path, bool)> = entries
            .iter()
            .map(|r| (r.path.as_path(), r.exclude))
            .collect();
        assert_eq!(
            paths,
            [
                (Path::new("/tmp/cache"), true),
                (Path::new("/u"), true),
                (Path::new("/w"), true),
            ]
        );
        let roots = Roots {
            entries,
            mounts,
            everywhere: true,
            _pins: Vec::new(),
        };
        let filter = roots.dev_filter();
        assert_eq!(
            &filter.devs[..filter.count as usize],
            [kernel_dev(0, 35), kernel_dev(259, 2)]
        );
    }

    #[test]
    fn scope_by_path_follows_the_deepest_root() {
        let roots = [root("/var", false), root("/var/lib/docker", true)];
        assert!(watched(&roots, Path::new("/var/log")));
        assert!(!watched(
            &roots,
            Path::new("/var/lib/docker/overlay2/x/diff")
        ));
        assert!(!watched(&roots, Path::new("/srv")));
    }

    #[test]
    fn relative_layer_options_resolve_below_an_ancestor_of_the_mount_point() {
        // Docker's layout when absolute options would not fit in a page: the engine mounts
        // from its root directory with `upperdir=<id>/diff,workdir=<id>/work`.
        let home = std::env::temp_dir().join(format!("fsblame-roots-{}", std::process::id()));
        let id = home.join("c0ffee");
        for dir in ["diff", "work/work", "merged"] {
            fs::create_dir_all(id.join(dir)).unwrap();
        }
        let mounts = mounts().unwrap();
        let canonical = fs::canonicalize(&home).unwrap();
        let found = find_writable(
            &id.join("merged"),
            Path::new("c0ffee/diff"),
            Path::new("c0ffee/work"),
            &mounts,
        );
        let missing = find_writable(
            &id.join("merged"),
            Path::new("c0ffee/diff"),
            Path::new("c0ffee/nowork"),
            &mounts,
        );
        fs::remove_dir_all(&home).unwrap();
        let writable = found.unwrap();
        assert_eq!(writable.base, home);
        assert_eq!(writable.upper.path, canonical.join("c0ffee/diff"));
        assert_eq!(writable.work.path, canonical.join("c0ffee/work"));
        assert!(missing.is_none());
    }
}
