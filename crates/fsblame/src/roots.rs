//! Watch roots: resolving paths to the (superblock device, inode) pairs the kernel matches,
//! and turning reported dentry names back into paths.

use std::{
    collections::HashSet,
    ffi::OsStr,
    fs::{self, File, OpenOptions},
    io,
    os::{
        fd::AsRawFd as _,
        unix::{ffi::OsStrExt as _, fs::MetadataExt as _, fs::OpenOptionsExt as _},
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
    /// `st_dev` differs on btrfs subvolumes).
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
        let octal = bytes.get(i + 1..i + 4).filter(|d| d.iter().all(|b| (b'0'..=b'7').contains(b)));
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
    PathBuf::from(OsStr::from_bytes(&out))
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
    Ok(parse_mountinfo(&fs::read_to_string("/proc/self/mountinfo")?))
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

/// The mount and inode number holding `path` (canonical).
pub fn locate<'m>(path: &Path, mounts: &'m [Mount]) -> io::Result<(&'m Mount, u64)> {
    let file = open_path(path)?;
    let ino = file.metadata()?.ino();
    let id = mount_id(&file)?;
    let mount = mounts
        .iter()
        .find(|m| m.id == id)
        .ok_or_else(|| io::Error::other(format!("mount {id} is not in /proc/self/mountinfo")))?;
    Ok((mount, ino))
}

/// A watched or excluded file or directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Root {
    /// Canonical path.
    pub path: PathBuf,
    /// Events below it are ignored.
    pub exclude: bool,
    /// Added because a mount sits below a watch root.
    pub nested: bool,
    /// Kernel `dev_t` of its superblock.
    pub dev: u32,
    /// Inode number.
    pub ino: u64,
    /// Filesystem type.
    pub fstype: String,
}

/// All roots, indexed by the id the kernel reports.
#[derive(Debug)]
pub struct Roots {
    roots: Vec<Root>,
    mounts: Vec<Mount>,
}

impl Roots {
    /// Resolves the watch and exclude paths, adding every mount below a watch root (the
    /// kernel's d_parent walk does not cross mounts). Fails on paths that do not exist.
    pub fn resolve(watch: &[PathBuf], exclude: &[PathBuf]) -> anyhow::Result<Self> {
        let mounts = mounts().context("reading /proc/self/mountinfo")?;
        let mut roots: Vec<Root> = Vec::new();
        let mut seen = HashSet::new();
        let given = watch.iter().map(|p| (p, false)).chain(exclude.iter().map(|p| (p, true)));
        for (path, exclude) in given {
            let canonical = fs::canonicalize(path)
                .with_context(|| format!("cannot watch {}", path.display()))?;
            let (mount, ino) = locate(&canonical, &mounts)
                .with_context(|| format!("cannot identify {}", canonical.display()))?;
            if seen.insert((mount.dev, ino)) {
                roots.push(Root {
                    path: canonical,
                    exclude,
                    nested: false,
                    dev: mount.dev,
                    ino,
                    fstype: mount.fstype.clone(),
                });
            }
        }
        let mut nested = Vec::new();
        for mount in &mounts {
            let enclosing = roots
                .iter()
                .filter(|r| mount.point.starts_with(&r.path) && mount.point != r.path)
                .max_by_key(|r| r.path.as_os_str().len());
            if !enclosing.is_some_and(|r| !r.exclude) {
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
        if !roots.iter().any(|r| !r.exclude) {
            return Err(anyhow!("every watch path is also excluded"));
        }
        Ok(Self { roots, mounts })
    }

    /// Number of roots.
    pub fn len(&self) -> usize {
        self.roots.len()
    }

    /// Roots with their ids.
    pub fn iter(&self) -> impl Iterator<Item = (u32, &Root)> {
        (0u32..).zip(&self.roots)
    }

    /// The `.rodata` device prefilter: every superblock holding a watch root.
    pub fn dev_filter(&self) -> DevFilter {
        let mut devs: Vec<u32> = self.roots.iter().filter(|r| !r.exclude).map(|r| r.dev).collect();
        devs.sort_unstable();
        devs.dedup();
        let mut filter = DevFilter {
            count: 0,
            _pad: 0,
            devs: [0; abi::MAX_DEVS as usize],
        };
        if devs.len() <= filter.devs.len() {
            filter.devs[..devs.len()].copy_from_slice(&devs);
            filter.count = u32::try_from(devs.len()).expect("at most MAX_DEVS");
        }
        filter
    }

    /// The absolute path for dentry names reported relative to `root` (leaf first, each
    /// NUL-terminated). `None` for `ROOT_NONE` or an unknown root id. A truncated walk lost
    /// its upper components, which show as `…`.
    pub fn path(&self, root: u32, dev: u32, names: &[u8], truncated: bool) -> Option<PathBuf> {
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
            abi::ROOT_RAW => {
                let raw = names.split(|&b| b == 0).next().unwrap_or_default();
                Some(PathBuf::from(OsStr::from_bytes(raw)))
            }
            abi::ROOT_FSROOT => Some(self.fs_path(dev, &rel)),
            id => {
                let root = self.roots.get(usize::try_from(id).ok()?)?;
                Some(if rel.as_os_str().is_empty() { root.path.clone() } else { root.path.join(rel) })
            }
        }
    }

    /// Where a path relative to the root of filesystem `dev` is visible: below the shortest
    /// mount point of a mount of that filesystem whose root contains it.
    fn fs_path(&self, dev: u32, rel: &Path) -> PathBuf {
        let rel = Path::new("/").join(rel);
        self.mounts
            .iter()
            .filter(|m| m.dev == dev)
            .filter_map(|m| Some((m, rel.strip_prefix(&m.root).ok()?)))
            .min_by_key(|(m, _)| m.point.as_os_str().len())
            .map_or_else(
                || Path::new(&format!("<dev {}>", dev_string(dev))).join(rel.strip_prefix("/").unwrap_or(&rel)),
                |(m, below)| m.point.join(below),
            )
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
";

    fn roots() -> Roots {
        Roots {
            roots: vec![Root {
                path: PathBuf::from("/home/u/proj"),
                exclude: false,
                nested: false,
                dev: kernel_dev(259, 2),
                ino: 42,
                fstype: "ext4".into(),
            }],
            mounts: parse_mountinfo(MOUNTINFO),
        }
    }

    #[test]
    fn mountinfo_fields_and_escapes() {
        let mounts = parse_mountinfo(MOUNTINFO);
        assert_eq!(mounts.len(), 4);
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
        assert_eq!(roots.path(0, 0, b"", false), Some(PathBuf::from("/home/u/proj")));
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
}
