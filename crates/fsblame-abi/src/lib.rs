//! Kernel/user ABI of fsblame.
//!
//! Everything the BPF program (`crates/fsblame-bpf/bpf/fsblame.bpf.c`) and the loader exchange
//! is declared here once. The BPF build script renders it into `fsblame_wire.h` with
//! [`header`] (feature `std`); the header static-asserts every size and offset, so drift is a
//! clang error.
//!
//! # Records
//!
//! Every ring buffer record starts with a [`RecHeader`]. [`ForkRec`] and [`ExitRec`] are fixed
//! size. [`ExecRec`] and [`FsRec`] are fixed headers followed by a variable payload whose
//! layout is described by their `*_len` fields; the kernel submits only the used bytes.
//!
//! Paths in an [`FsRec`] payload are a sequence of NUL-terminated dentry names, leaf first.
//! The record's `root`/`root2` field says what they are relative to: a watch root id (an index
//! into the loader's root table), [`ROOT_FSROOT`] (the root of the filesystem `dev`), or
//! [`ROOT_RAW`] (not components but one raw string, such as a symlink target).

#![no_std]
#![warn(missing_docs)]

wire::wire! {
    /// Prefix of every ring buffer record.
    pub struct RecHeader {
        /// `REC_*`.
        pub kind: u16,
        /// `OP_*` for [`FsRec`]; 0 for other kinds.
        pub op: u16,
        /// `F_*` flags.
        pub flags: u32,
        /// Event time, `CLOCK_BOOTTIME` nanoseconds.
        pub ts_ns: u64,
    }

    /// A new process (thread creation is not reported).
    pub struct ForkRec {
        /// Common header, `kind == REC_FORK`.
        pub hdr: RecHeader,
        /// Thread-group id of the forking process.
        pub parent_tgid: u32,
        /// Pid of the new process.
        pub child_tgid: u32,
        /// `start_boottime` of the new process.
        pub child_start_ns: u64,
    }

    /// The last thread of a process exited.
    pub struct ExitRec {
        /// Common header, `kind == REC_EXIT`.
        pub hdr: RecHeader,
        /// Pid of the process.
        pub tgid: u32,
        /// `task->exit_code` (a `wait(2)` status).
        pub code: i32,
        /// `start_boottime` of the group leader.
        pub start_ns: u64,
    }

    /// A successful exec. Followed by `filename_len` bytes of the execve filename (NUL
    /// included), `env_len` bytes of the raw environment block (`KEY=VALUE\0` entries; see
    /// [`F_ENV_TRUNC`]), `argv_len` bytes of raw argv and `cwd_len` bytes of the working
    /// directory. The cwd is a sequence of NUL-terminated dentry names, leaf first, up to the
    /// root of the process's mount namespace; it is present only with [`F_CWD`] (no names:
    /// `/`) and its upper part is missing with [`F_CWD_TRUNC`].
    pub struct ExecRec {
        /// Common header, `kind == REC_EXEC`; flags `F_ENV_TRUNC`, `F_ARGV_TRUNC`, `F_CWD`,
        /// `F_CWD_TRUNC`.
        pub hdr: RecHeader,
        /// Pid.
        pub tgid: u32,
        /// Pid of the real parent.
        pub ppid: u32,
        /// `start_boottime` of the group leader.
        pub start_ns: u64,
        /// cgroup v2 id.
        pub cgroup_id: u64,
        /// Real uid.
        pub uid: u32,
        /// Real gid.
        pub gid: u32,
        /// `comm` after the exec.
        pub comm: [u8; 16],
        /// Bytes of execve filename.
        pub filename_len: u16,
        /// Bytes of environment.
        pub env_len: u16,
        /// Bytes of argv.
        pub argv_len: u16,
        /// Bytes of cwd names.
        pub cwd_len: u16,
    }

    /// A modifying file operation on a watched path. Followed by `path_len` bytes of the
    /// primary path and `path2_len` bytes of the secondary path (see the crate docs).
    ///
    /// | op | path | path2 | aux | aux2 |
    /// |----|------|-------|-----|------|
    /// | `OP_WRITE` | file | – | replaced binding's bytes (`F_REPLACED`) | replaced binding's calls |
    /// | `OP_WRITE` + `F_MAPPED` | file | – | `MAP_VIA_*` | – |
    /// | `OP_RENAME` | new name | old name | rename flags | inode replaced at the new name |
    /// | `OP_LINK` | new link | existing name | – | – |
    /// | `OP_SYMLINK` | new link | target (`ROOT_RAW`) | – | – |
    /// | `OP_CHMOD`… | file | – | `ia_valid` | new mode, size, or `uid << 32 \| gid` |
    pub struct FsRec {
        /// Common header, `kind == REC_FS`; flags `F_PATH_TRUNC`, `F_PATH2_TRUNC`, `F_REPLACED`,
        /// `F_MAPPED`.
        pub hdr: RecHeader,
        /// Pid of the acting process.
        pub tgid: u32,
        /// Thread id of the acting thread.
        pub tid: u32,
        /// Pid of the acting process in its own pid namespace; 0 when that is the initial one.
        pub ns_tgid: u32,
        /// Always zero.
        pub _pad: u32,
        /// `start_boottime` of the acting process's group leader.
        pub start_ns: u64,
        /// `comm` of the acting thread.
        pub comm: [u8; 16],
        /// Real uid of the acting thread.
        pub uid: u32,
        /// Kernel `dev_t` (`MAJOR << 20 | MINOR`) of the filesystem.
        pub dev: u32,
        /// Inode number; 0 for a name being created.
        pub ino: u64,
        /// `i_mode`, or the requested mode for creations.
        pub mode: u32,
        /// What `path` is relative to (`ROOT_*` or a watch root id).
        pub root: u32,
        /// What `path2` is relative to.
        pub root2: u32,
        /// Bytes of `path`.
        pub path_len: u16,
        /// Bytes of `path2`.
        pub path2_len: u16,
        /// Op-specific, see the table.
        pub aux: u64,
        /// Op-specific, see the table.
        pub aux2: u64,
        /// `OP_WRITE`: bytes requested by the first write; 0 with `F_MAPPED`.
        pub bytes: u64,
        /// `OP_WRITE`: `struct file` address, the second half of the [`WriteKey`].
        pub file: u64,
    }

    /// Key of the `roots` map: a watched or excluded directory (or file).
    pub struct RootKey {
        /// Kernel `dev_t` of the superblock.
        pub dev: u32,
        /// Always zero.
        pub _pad: u32,
        /// Inode number.
        pub ino: u64,
    }

    /// Value of the `roots` map.
    pub struct RootVal {
        /// Watch root id reported in [`FsRec::root`].
        pub id: u32,
        /// `ROOT_F_*`.
        pub flags: u32,
    }

    /// Key of the `writes` coalescing map: one open file of one process.
    pub struct WriteKey {
        /// Pid of the writer.
        pub tgid: u32,
        /// Always zero.
        pub _pad: u32,
        /// `struct file` address.
        pub file: u64,
    }

    /// Value of the `writes` map: running totals since the binding was created.
    pub struct WriteVal {
        /// Kernel `dev_t` of the file.
        pub dev: u32,
        /// Always zero.
        pub _pad: u32,
        /// Inode number of the file; a mismatch means the `struct file` was reused for another
        /// file.
        pub ino: u64,
        /// Bytes requested by all writes.
        pub bytes: u64,
        /// Write calls.
        pub calls: u64,
        /// Time of the first write; identifies the binding.
        pub first_ns: u64,
        /// Time of the latest write.
        pub last_ns: u64,
    }

    /// `.rodata` device prefilter: the superblocks that hold watch roots.
    pub struct DevFilter {
        /// Number of valid `devs`; 0 disables the prefilter.
        pub count: u32,
        /// Always zero.
        pub _pad: u32,
        /// Kernel `dev_t`s.
        pub devs: [u32; MAX_DEVS as usize],
    }
}

wire::wire_consts! {
    /// Constants shared with the BPF program.
    pub group ABI_CONSTS;

    /// [`ForkRec`].
    pub const REC_FORK: u16 = 1;
    /// [`ExecRec`].
    pub const REC_EXEC: u16 = 2;
    /// [`ExitRec`].
    pub const REC_EXIT: u16 = 3;
    /// [`FsRec`].
    pub const REC_FS: u16 = 4;

    /// Data written to a regular file (`write`, `pwrite`, `writev`, `splice`, `copy_file_range`,
    /// `fallocate`, reflinks).
    pub const OP_WRITE: u16 = 1;
    /// Regular file created.
    pub const OP_CREATE: u16 = 2;
    /// Directory created.
    pub const OP_MKDIR: u16 = 3;
    /// Special file created.
    pub const OP_MKNOD: u16 = 4;
    /// Symbolic link created.
    pub const OP_SYMLINK: u16 = 5;
    /// Hard link created.
    pub const OP_LINK: u16 = 6;
    /// Name removed.
    pub const OP_UNLINK: u16 = 7;
    /// Directory removed.
    pub const OP_RMDIR: u16 = 8;
    /// Name moved.
    pub const OP_RENAME: u16 = 9;
    /// Mode changed.
    pub const OP_CHMOD: u16 = 10;
    /// Owner or group changed.
    pub const OP_CHOWN: u16 = 11;
    /// Size changed (`truncate`, `O_TRUNC`).
    pub const OP_TRUNCATE: u16 = 12;
    /// Timestamps set (`utimensat`, `touch`).
    pub const OP_UTIMES: u16 = 13;
    /// Other attribute change (privilege stripping).
    pub const OP_SETATTR: u16 = 14;
    /// One past the largest op.
    pub const OP_COUNT: u16 = 15;

    /// `path` was cut at `PATH_CAP` bytes or `WALK_MAX` components; its upper part is missing.
    pub const F_PATH_TRUNC: u32 = 1;
    /// `path2` was cut short.
    pub const F_PATH2_TRUNC: u32 = 2;
    /// `OP_WRITE`: this binding replaced one from an earlier open instance of its `struct file`
    /// (reused for another file, or another open of the same one); `aux`/`aux2` carry the old
    /// binding's final totals.
    pub const F_REPLACED: u32 = 4;
    /// `OP_WRITE`: not a write call but a shared mapping of the file that became writable
    /// (`mmap(MAP_SHARED, PROT_WRITE)`, or `mprotect(PROT_WRITE)` of a shared read-only one);
    /// stores through it change the file without a write. `aux` says how (`MAP_VIA_*`).
    /// Reported once per `(tgid, struct file)` open instance, outside write coalescing.
    pub const F_MAPPED: u32 = 8;
    /// argv was longer than `ARGV_CAP`.
    pub const F_ARGV_TRUNC: u32 = 16;
    /// The environment was longer than `ENV_CAP`: the payload is its first and last
    /// `ENV_CAP / 2` bytes, so the entries in between (and the two cut ones) are missing.
    pub const F_ENV_TRUNC: u32 = 32;
    /// The exec record carries the cwd.
    pub const F_CWD: u32 = 64;
    /// The cwd walk stopped short of the mount namespace root (`PATH_CAP` bytes, `WALK_MAX`
    /// hops, or a disconnected directory); the upper part of the cwd is missing.
    pub const F_CWD_TRUNC: u32 = 128;

    /// `F_MAPPED` `aux`: `mmap` of the file, shared and writable.
    pub const MAP_VIA_MMAP: u64 = 1;
    /// `F_MAPPED` `aux`: `mprotect` made a shared mapping of the file writable.
    pub const MAP_VIA_MPROTECT: u64 = 2;

    /// The side of an operation that is outside every watch root: no path captured.
    pub const ROOT_NONE: u32 = 0xffff_ffff;
    /// Path relative to the root of the filesystem `dev`.
    pub const ROOT_FSROOT: u32 = 0xffff_fffe;
    /// One raw NUL-terminated string.
    pub const ROOT_RAW: u32 = 0xffff_fffd;
    /// Root flag: excluded subtree; events below it are out of scope.
    pub const ROOT_F_EXCLUDE: u32 = 1;

    /// `scope` (`.rodata`): the paths below a watch root in `roots` are in scope.
    pub const SCOPE_ROOTS: u32 = 0;
    /// `scope`: every path is in scope, relative to its filesystem root (`ROOT_FSROOT`),
    /// except on pseudo and kernel-internal filesystems; `roots` is empty.
    pub const SCOPE_ALL: u32 = 1;
    /// `scope`: as `SCOPE_ALL`, except below the excludes in `roots`, which are on the
    /// superblocks of the device filter.
    pub const SCOPE_ALL_EXCLUDES: u32 = 2;

    /// Capacity of [`DevFilter::devs`].
    pub const MAX_DEVS: u32 = 16;
    /// Path bytes after which a dentry walk stops.
    pub const PATH_CAP: u32 = 1024;
    /// Longest dentry name read (`NAME_MAX` plus NUL).
    pub const NAME_CAP: u32 = 256;
    /// Most names a path walk emits (deeper paths are cut at the top and marked truncated);
    /// the cwd walk also counts each mount it crosses. The scope check walks further
    /// (`SCOPE_WALK_MAX` in the BPF source) so a deep change is still matched to its root.
    pub const WALK_MAX: u32 = 64;
    /// Longest execve filename captured.
    pub const FILENAME_CAP: u32 = 256;
    /// Longest argv captured.
    pub const ARGV_CAP: u32 = 4096;
    /// Bytes of environment captured; a longer one keeps its first and last halves, since
    /// tools append their own variables (npm's lifecycle variables follow the inherited ones).
    pub const ENV_CAP: u32 = 8192;
    /// Default ring buffer size; `--ring-size` overrides it.
    pub const RINGBUF_BYTES: u32 = 16 << 20;

    /// `stats` slot: records lost because the ring buffer was full.
    pub const STAT_RING_DROPS: u32 = 0;
    /// `stats` slot: new processes of tracked ones left untracked because the `tracked` map
    /// was full; their changes are not reported.
    pub const STAT_TRACK_FULL: u32 = 1;
    /// Number of `stats` slots.
    pub const STAT_COUNT: u32 = 2;
}

#[cfg(feature = "user")]
wire::impl_aya_pod!(RootKey, RootVal, WriteKey, WriteVal, DevFilter);

/// The C header for the BPF program, with every struct and constant above.
#[cfg(feature = "std")]
pub fn header() -> wire::HeaderBuilder {
    let mut header = wire::HeaderBuilder::new("FSBLAME_WIRE_H");
    header
        .structs::<RecHeader>()
        .structs::<ForkRec>()
        .structs::<ExitRec>()
        .structs::<ExecRec>()
        .structs::<FsRec>()
        .structs::<RootKey>()
        .structs::<RootVal>()
        .structs::<WriteKey>()
        .structs::<WriteVal>()
        .structs::<DevFilter>()
        .consts(&ABI_CONSTS);
    header
}
