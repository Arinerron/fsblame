//! Event processing: feeds process events to procctx, coalesces writes, selects changes and
//! emits them, with their lineage, as report lines.

use std::{
    collections::HashMap,
    io,
    path::{Path, PathBuf},
    rc::Rc,
    sync::Arc,
};

use aya::maps::{HashMap as BpfHashMap, MapData};
use fsblame_abi::{self as abi, WriteKey, WriteVal};
use procctx::{
    Config, Context, ExecEvent, ExitEvent, ForkEvent, Origin, ProcFs, ProcInfo, ProcKey, ProcTable,
    StartClock, Stop, classify_origin,
};
use serde::{Deserialize, Serialize};

use crate::{
    clock::{self, Clock},
    filter::{Candidate, Filter},
    ops::Op,
    record::{self, Exec, Fs, Record},
    report::{ChangeReport, Line, LineageId, Sink},
    roots::Roots,
};

/// Poll interval for a binding that was written recently.
const POLL_NS: u64 = 100_000_000;
/// Poll interval for a binding idle longer than [`IDLE_NS`].
const IDLE_POLL_NS: u64 = 1_000_000_000;
const IDLE_NS: u64 = 5_000_000_000;
/// A write window is reported once the file has been quiet this long...
const QUIET_NS: u64 = 200_000_000;
/// ...or has been open this long, whichever comes first.
const HOLD_NS: u64 = 1_000_000_000;
/// A binding the kernel replaced before the record of the replacement was read waits for that
/// record, which carries its final totals, until the ring has been read this far past the
/// replacement. Records reach the ring in about the order of their times, so by then the record
/// is lost (the ring was full).
const REPLACED_WAIT_NS: u64 = 1_000_000_000;
/// How often exited processes past their TTL are dropped.
const EXPIRE_EVERY_NS: u64 = 10_000_000_000;

/// `iattr.ia_valid` bits (include/linux/fs.h).
const ATTR_UID: u64 = 1 << 1;
const ATTR_GID: u64 = 1 << 2;
/// `renameat2` flags (include/uapi/linux/fs.h).
pub const RENAME_NOREPLACE: u32 = 1 << 0;
/// See [`RENAME_NOREPLACE`].
pub const RENAME_EXCHANGE: u32 = 1 << 1;

/// Read access to the kernel's write totals (the `writes` map).
pub trait Totals {
    /// Current totals of a binding; `None` once the kernel no longer has it.
    fn get(&self, key: &WriteKey) -> Option<WriteVal>;
    /// Drops a binding whose process has exited.
    fn remove(&mut self, key: &WriteKey);
}

impl Totals for BpfHashMap<MapData, WriteKey, WriteVal> {
    fn get(&self, key: &WriteKey) -> Option<WriteVal> {
        BpfHashMap::get(self, key, 0).ok()
    }

    fn remove(&mut self, key: &WriteKey) {
        // Already evicted by the LRU is fine.
        let _ = BpfHashMap::remove(self, key);
    }
}

/// The task behind an operation, as the kernel saw it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Actor {
    /// Process id.
    pub tgid: u32,
    /// Thread id.
    pub tid: u32,
    /// Process id in the actor's own pid namespace; `None` when that is the initial one.
    pub ns_tgid: Option<u32>,
    /// Start time of the process (`CLOCK_BOOTTIME` ns), the second half of its identity.
    pub start_ns: u64,
    /// Thread `comm`.
    pub comm: String,
    /// Real uid.
    pub uid: u32,
}

/// Identity of a file.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FileId {
    /// Kernel `dev_t`.
    pub dev: u32,
    /// Inode number; for a created name, the inode it got once the creation was confirmed, or
    /// 0 when it was reported at its check.
    pub ino: u64,
}

/// How a shared mapping of a file became writable; in JSON, the system call's name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MapVia {
    /// `mmap(MAP_SHARED)` with `PROT_WRITE`.
    Mmap,
    /// `mprotect(PROT_WRITE)` of a read-only shared mapping.
    Mprotect,
}

impl MapVia {
    /// The `MAP_VIA_*` code of a mapped-write record's `aux`.
    pub const fn from_code(code: u64) -> Option<Self> {
        match code {
            abi::MAP_VIA_MMAP => Some(Self::Mmap),
            abi::MAP_VIA_MPROTECT => Some(Self::Mprotect),
            _ => None,
        }
    }

    /// Name in output: the system call.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Mmap => "mmap",
            Self::Mprotect => "mprotect",
        }
    }
}

/// What an operation changed, beyond its op.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Change {
    /// Nothing more to say.
    None,
    /// Coalesced writes: bytes requested and calls.
    Write {
        /// Bytes requested.
        bytes: u64,
        /// Write calls.
        calls: u64,
    },
    /// A shared mapping of the file became writable: stores through it change the file
    /// without write calls, so there is nothing to count.
    Mapped {
        /// How it became writable.
        via: MapVia,
    },
    /// New mode (`chmod`).
    Mode(u32),
    /// New owner and/or group (`chown`).
    Owner {
        /// New uid, if changed.
        uid: Option<u32>,
        /// New gid, if changed.
        gid: Option<u32>,
    },
    /// New size (`truncate`).
    Size(u64),
    /// `renameat2` flags and whether an existing name was replaced.
    Rename {
        /// `RENAME_*` flags.
        flags: u32,
        /// An existing file at the new name was replaced.
        replaced: bool,
    },
    /// Device number of a new special file (`mknod`).
    Node(u32),
}

/// One reported change.
#[derive(Clone, Debug)]
pub struct Touch {
    /// Time (`CLOCK_BOOTTIME` ns); for writes, the latest write of the window.
    pub ts_ns: u64,
    /// Operation.
    pub op: Op,
    /// Affected path (for renames the new name, for links the new link).
    pub path: PathBuf,
    /// Some upper components of a path were lost to the walk limits.
    pub truncated: bool,
    /// Rename source.
    pub old_path: Option<PathBuf>,
    /// Symlink target, or the existing name a hard link points at.
    pub target: Option<PathBuf>,
    /// File identity.
    pub file: FileId,
    /// `i_mode`; for a creation reported at its check (not confirmed), the requested mode.
    pub mode: u32,
    /// Op-specific detail.
    pub change: Change,
    /// Who did it.
    pub actor: Actor,
}

impl Touch {
    /// What a [`Filter`] needs to know about this change; `unit` is the actor's systemd
    /// unit, if resolved.
    pub fn candidate<'a>(&'a self, unit: Option<&'a str>) -> Candidate<'a> {
        Candidate {
            paths: [
                Some(self.path.as_path()),
                self.old_path.as_deref(),
                self.target.as_deref(),
            ],
            comm: &self.actor.comm,
            uid: self.actor.uid,
            tgid: self.actor.tgid,
            unit,
        }
    }
}

/// Process lineage of an actor at the time a touch is reported.
#[derive(Clone, Debug, Default)]
pub struct Lineage {
    /// The actor first, then its ancestors; empty if the process is unknown.
    pub chain: Vec<Arc<ProcInfo>>,
    /// The chain reached a root rather than an unknown ancestor.
    pub complete: bool,
    /// cgroup, systemd unit, container and tmux pane.
    pub context: Context,
    /// Build step the actor runs under.
    pub origin: Option<Origin>,
    /// Identity of this lineage, `None` for an unknown process.
    pub id: Option<LineageId>,
}

/// One open instance of a file in one process, as the kernel's `writes` map counts it.
#[derive(Debug)]
struct Binding {
    /// Kernel `first_ns`: tells this binding from a later one for the same key.
    first_ns: u64,
    path: PathBuf,
    truncated: bool,
    file: FileId,
    mode: u32,
    actor: Actor,
    /// Totals (bytes, calls) last read from the kernel.
    seen: (u64, u64),
    /// Totals already added to a [`Window`].
    credited: (u64, u64),
    /// Latest write as last read from the kernel.
    last_ns: u64,
    next_poll_ns: u64,
    /// Kernel `first_ns` of the binding seen replacing this one before the record of the
    /// replacement, which hands this one's final totals over, was read. Such a binding is
    /// no longer polled; it waits for that record.
    superseded: Option<u64>,
}

impl Binding {
    /// The window this binding's writes go to.
    fn window_key(&self) -> WindowKey {
        WindowKey {
            tgid: self.actor.tgid,
            start_ns: self.actor.start_ns,
            file: self.file,
        }
    }
}

/// Identity of a write window: one process and one file.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct WindowKey {
    tgid: u32,
    /// Start time of the process: a reused pid is another process.
    start_ns: u64,
    file: FileId,
}

/// Unreported writes of one process to one file, summed over every binding (open instance)
/// that wrote it, so a process that opens, appends to and closes a file over and over reports
/// one change, as one that keeps it open does.
#[derive(Debug)]
struct Window {
    path: PathBuf,
    truncated: bool,
    mode: u32,
    actor: Actor,
    bytes: u64,
    calls: u64,
    /// When the window opened.
    opened_ns: u64,
    /// Latest write.
    last_ns: u64,
    /// When the window is next checked for quiet or hold, with its bindings refreshed.
    next_poll_ns: u64,
}

impl Window {
    /// An empty window for `binding`'s file, opened at `now`.
    fn new(binding: &Binding, now: u64) -> Self {
        Self {
            path: binding.path.clone(),
            truncated: binding.truncated,
            mode: binding.mode,
            actor: binding.actor.clone(),
            bytes: 0,
            calls: 0,
            opened_ns: now,
            last_ns: 0,
            next_poll_ns: now + POLL_NS,
        }
    }

    fn into_touch(self, file: FileId) -> Touch {
        Touch {
            ts_ns: self.last_ns,
            op: Op::Write,
            path: self.path,
            truncated: self.truncated,
            old_path: None,
            target: None,
            file,
            mode: self.mode,
            change: Change::Write {
                bytes: self.bytes,
                calls: self.calls,
            },
            actor: self.actor,
        }
    }
}

/// Counters for the end-of-run summary.
#[derive(Clone, Copy, Debug, Default)]
pub struct Counts {
    /// Changes reported (after filtering).
    pub touches: u64,
    /// Records that did not decode.
    pub malformed: u64,
    /// Write bindings whose latest totals were lost: the kernel's `writes` LRU evicted them
    /// before they were read, or the record handing them over was dropped with the ring full.
    /// The bytes and calls since the previous poll are missing from the reports.
    pub evicted: u64,
}

/// The event processor.
#[derive(Debug)]
pub struct Engine<S> {
    procs: ProcTable<ProcFs>,
    start_clock: StartClock,
    clock: Clock,
    roots: Roots,
    filter: Filter,
    sink: S,
    /// Keyed by (tgid, `struct file` address), as the kernel's `writes` map.
    bindings: HashMap<(u32, u64), Binding>,
    /// Write windows not reported yet.
    windows: HashMap<WindowKey, Window>,
    /// Scratch for the cwd of an exec record, reused across execs.
    cwd: Vec<u8>,
    /// Scratch for the environment entries of an exec record that procctx reads.
    env: Vec<u8>,
    /// The lineage last reported for each live process, reused while its chain is the same
    /// records: reports keep their lineage id, and sinks what they made of it.
    lineages: HashMap<u32, Rc<Lineage>>,
    /// The lineage of an unknown process.
    unknown: Rc<Lineage>,
    last_expire_ns: u64,
    /// The latest time of a record read: how far the ring has been read.
    read_ns: u64,
    counts: Counts,
}

fn write_key((tgid, file): (u32, u64)) -> WriteKey {
    WriteKey {
        tgid,
        _pad: 0,
        file,
    }
}

fn flag(flags: u32, bit: u32) -> bool {
    flags & bit != 0
}

/// The part of `path` strictly below the directory `dir`, unless `dir` is truncated.
fn below<'p>(path: &'p Path, (dir, truncated): (&Path, bool)) -> Option<&'p Path> {
    path.strip_prefix(dir)
        .ok()
        .filter(|rest| !truncated && !rest.as_os_str().is_empty())
}

impl<S: Sink> Engine<S> {
    /// An engine resolving paths through `roots`, stamping times with `clock`, and writing
    /// the changes `filter` admits to `sink`.
    pub fn new(roots: Roots, clock: Clock, filter: Filter, sink: S) -> Self {
        let start_clock = StartClock::BootNs {
            ticks_per_sec: clock::clock_ticks_per_sec(),
        };
        let cfg = Config {
            start_clock,
            ..Config::default()
        };
        Self {
            procs: ProcTable::new(ProcFs::new(), cfg),
            start_clock,
            clock,
            roots,
            filter,
            sink,
            bindings: HashMap::new(),
            windows: HashMap::new(),
            cwd: Vec::new(),
            env: Vec::new(),
            lineages: HashMap::new(),
            unknown: Rc::default(),
            last_expire_ns: 0,
            read_ns: 0,
            counts: Counts::default(),
        }
    }

    /// Run counters.
    pub fn counts(&self) -> Counts {
        self.counts
    }

    /// Converts the times of the lines reported from now on with `clock`, such as one
    /// resampled after the wall clock was set.
    pub fn set_clock(&mut self, clock: Clock) {
        self.clock = clock;
    }

    /// The sink, for lines that do not come from records (losses, the summary).
    pub fn sink_mut(&mut self) -> &mut S {
        &mut self.sink
    }

    /// Handles one ring buffer item.
    pub fn handle(&mut self, bytes: &[u8], totals: &mut impl Totals) -> io::Result<()> {
        let record = match record::decode(bytes) {
            Ok(record) => record,
            Err(malformed) => {
                log::debug!("{malformed}");
                self.counts.malformed += 1;
                return Ok(());
            }
        };
        self.read_ns = self.read_ns.max(match &record {
            Record::Fork(r) => r.hdr.ts_ns,
            Record::Exec(exec) => exec.rec.hdr.ts_ns,
            Record::Exit(r) => r.hdr.ts_ns,
            Record::Fs(fs) => fs.rec.hdr.ts_ns,
        });
        match record {
            Record::Fork(r) => {
                self.procs.on_fork(ForkEvent {
                    ts_ns: r.hdr.ts_ns,
                    parent: r.parent_tgid,
                    child: ProcKey {
                        pid: r.child_tgid,
                        start: r.child_start_ns,
                    },
                    is_thread: false,
                });
                Ok(())
            }
            Record::Exec(exec) => {
                let tgid = exec.rec.tgid;
                // Report the writes of the image being replaced while the table still
                // describes it: `sh -c 'echo x >> f; mkdir d'` execs mkdir in place, and its
                // pending window for `f` would otherwise carry mkdir's comm and argv.
                self.flush_process(tgid, exec.rec.hdr.ts_ns, totals)?;
                // Descriptors survive the exec: later writes through them are the new
                // program's (`sh -c 'echo building; exec make' >> build.log`).
                let comm = record::c_str(&exec.rec.comm);
                for binding in self.bindings.values_mut() {
                    if binding.actor.tgid == tgid {
                        binding.actor.comm.clone_from(&comm);
                    }
                }
                self.on_exec(&exec);
                Ok(())
            }
            Record::Exit(r) => {
                // Report the process's writes while its record is still live: the exit event
                // arrives while the task is still in do_exit, so a lookup after on_exit would
                // rebuild it from a half-torn-down /proc entry (no exe, argv, cwd or env).
                self.finish_process(r.tgid, totals)?;
                self.lineages.remove(&r.tgid);
                self.procs.on_exit(ExitEvent {
                    ts_ns: r.hdr.ts_ns,
                    key: ProcKey {
                        pid: r.tgid,
                        start: r.start_ns,
                    },
                    code: r.code,
                });
                Ok(())
            }
            Record::Fs(fs) => self.on_fs(&fs, totals),
        }
    }

    fn on_exec(&mut self, exec: &Exec<'_>) {
        let r = exec.rec;
        let key = ProcKey {
            pid: r.tgid,
            start: r.start_ns,
        };
        // The fork event named the parent that started this process. The exec record's
        // `real_parent` is the parent at exec time, which is the reaper when the parent exited
        // in between (`sh -c 'cmd & exit'`); it only fills in a process forked before the start.
        let forked_here = self
            .procs
            .get_key(key)
            .is_some_and(|info| info.ppid.is_some());
        self.procs.on_exec(ExecEvent {
            ts_ns: r.hdr.ts_ns,
            key,
            ppid: (!forked_here).then_some(r.ppid),
            comm: Some(record::trim_nul(&r.comm)),
            filename: Some(exec.filename),
            argv: Some(exec.argv),
            // Without one in the record, procctx reads /proc/<pid>/cwd when the lineage loads.
            cwd: exec.cwd(&mut self.cwd),
            env: Some(exec.env_entries(&mut self.env)),
            argv_truncated: flag(r.hdr.flags, abi::F_ARGV_TRUNC),
            cgroup_id: Some(r.cgroup_id),
            uid: Some(r.uid),
            gid: Some(r.gid),
        });
    }

    // One linear per-event pipeline: decode, scope, coalesce, resolve, emit. Splitting it would
    // scatter shared locals without clarifying the flow.
    #[allow(clippy::too_many_lines)]
    fn on_fs(&mut self, fs: &Fs<'_>, totals: &mut impl Totals) -> io::Result<()> {
        let r = fs.rec;
        let Some(op) = Op::from_code(r.hdr.op) else {
            self.counts.malformed += 1;
            return Ok(());
        };
        let mapped = if flag(r.hdr.flags, abi::F_MAPPED) {
            let Some(via) = MapVia::from_code(r.aux) else {
                self.counts.malformed += 1;
                return Ok(());
            };
            Some(via)
        } else {
            None
        };
        let path1 = self
            .roots
            .path(r.root, r.dev, fs.path, flag(r.hdr.flags, abi::F_PATH_TRUNC));
        let path2 = self.roots.path(
            r.root2,
            r.dev,
            fs.path2,
            flag(r.hdr.flags, abi::F_PATH2_TRUNC),
        );
        let Some(path) = path1 else {
            self.counts.malformed += 1;
            return Ok(());
        };
        let actor = Actor {
            tgid: r.tgid,
            tid: r.tid,
            ns_tgid: (r.ns_tgid != 0).then_some(r.ns_tgid),
            start_ns: r.start_ns,
            comm: record::c_str(&r.comm),
            uid: r.uid,
        };
        // An actor whose exec carried no cwd (it predates fsblame, or the kernel could not
        // capture it): read it from /proc while the actor is still alive.
        if self
            .procs
            .get(actor.tgid)
            .is_some_and(|info| info.cwd.is_none() && info.exit.is_none())
        {
            // A process that is already gone keeps its record as it is.
            let _ = self.procs.enrich(actor.tgid);
        }
        let file = FileId {
            dev: r.dev,
            ino: r.ino,
        };
        let truncated = flag(r.hdr.flags, abi::F_PATH_TRUNC | abi::F_PATH2_TRUNC);

        if op == Op::Write && mapped.is_none() {
            // Load the lineage while the processes are alive; the window is reported later.
            self.procs.ancestry(actor.tgid, Stop::Root);
            let key = (r.tgid, r.file);
            if let Some(mut old) = self.bindings.remove(&key) {
                // The kernel replaced the binding. When the struct file was reused, it handed
                // the old binding's final totals over; without them, the LRU had evicted it,
                // taking the totals since the last poll along. A superseded binding was
                // replaced by the one a poll saw: a record from after that replaced another
                // binding, and the record with this one's final totals was lost.
                if flag(r.hdr.flags, abi::F_REPLACED)
                    && old.superseded.is_none_or(|by| r.hdr.ts_ns <= by)
                {
                    old.seen = old.seen.max((r.aux, r.aux2));
                } else {
                    self.counts.evicted += 1;
                }
                self.credit(&mut old, r.hdr.ts_ns)?;
            }
            let now = r.hdr.ts_ns;
            let mut binding = Binding {
                first_ns: now,
                path,
                truncated,
                file,
                mode: r.mode,
                actor,
                seen: (r.bytes, 1),
                credited: (0, 0),
                last_ns: now,
                next_poll_ns: now + POLL_NS,
                superseded: None,
            };
            self.credit(&mut binding, now)?;
            self.bindings.insert(key, binding);
            return Ok(());
        }

        // Report pending writes to the inodes involved first, keeping causal order.
        self.flush_file(file, r.hdr.ts_ns, totals)?;
        if op == Op::Rename && r.aux2 != 0 {
            self.flush_file(
                FileId {
                    dev: r.dev,
                    ino: r.aux2,
                },
                r.hdr.ts_ns,
                totals,
            )?;
        }
        if op == Op::Rename
            && let Some(old) = &path2
        {
            let exchanged = (u32::try_from(r.aux).unwrap_or(0) & RENAME_EXCHANGE != 0
                && r.aux2 != 0)
                .then_some(FileId {
                    dev: r.dev,
                    ino: r.aux2,
                });
            self.renamed(
                file,
                exchanged,
                (old, flag(r.hdr.flags, abi::F_PATH2_TRUNC)),
                (&path, flag(r.hdr.flags, abi::F_PATH_TRUNC)),
            );
        }
        let change = match op {
            // Coalesced writes returned above: a write here is a mapping.
            Op::Write => mapped.map_or(Change::None, |via| Change::Mapped { via }),
            Op::Chmod => Change::Mode(u32::try_from(r.aux2).unwrap_or(0)),
            Op::Chown => Change::Owner {
                uid: (r.aux & ATTR_UID != 0).then(|| u32::try_from(r.aux2 >> 32).unwrap_or(0)),
                gid: (r.aux & ATTR_GID != 0)
                    .then(|| u32::try_from(r.aux2 & 0xffff_ffff).unwrap_or(0)),
            },
            Op::Truncate => Change::Size(r.aux2),
            Op::Rename => Change::Rename {
                flags: u32::try_from(r.aux).unwrap_or(0),
                replaced: r.aux2 != 0,
            },
            Op::Mknod => Change::Node(u32::try_from(r.aux).unwrap_or(0)),
            _ => Change::None,
        };
        let (old_path, target) = match op {
            Op::Rename => (path2, None),
            Op::Link | Op::Symlink => (None, path2),
            _ => (None, None),
        };
        let touch = Touch {
            ts_ns: r.hdr.ts_ns,
            op,
            path,
            truncated,
            old_path,
            target,
            file,
            mode: r.mode,
            change,
            actor,
        };
        self.emit(&touch)
    }

    /// Reads kernel totals for the bindings due and reports finished write windows.
    pub fn poll(&mut self, now_ns: u64, totals: &mut impl Totals) -> io::Result<()> {
        // A window due for a check has every binding feeding it refreshed first, so its
        // latest write is current when quiet is judged.
        let due: Vec<(u32, u64)> = self
            .bindings
            .iter()
            .filter(|(_, b)| {
                b.superseded.is_none()
                    && (b.next_poll_ns <= now_ns
                        || self
                            .windows
                            .get(&b.window_key())
                            .is_some_and(|w| w.next_poll_ns <= now_ns))
            })
            .map(|(key, _)| *key)
            .collect();
        for key in due {
            self.refresh(key, now_ns, totals)?;
        }
        let read_ns = self.read_ns;
        self.give_up(|_, by| read_ns > by.saturating_add(REPLACED_WAIT_NS));
        // A window fed by a superseded binding is not quiet before that binding's final
        // totals are in; the hold limit still cuts it.
        let waiting: Vec<WindowKey> = self
            .bindings
            .values()
            .filter(|b| b.superseded.is_some())
            .map(Binding::window_key)
            .collect();
        let due: Vec<WindowKey> = self
            .windows
            .iter()
            .filter(|(_, w)| w.next_poll_ns <= now_ns)
            .map(|(key, _)| *key)
            .collect();
        for key in due {
            let Some(window) = self.windows.get_mut(&key) else {
                continue;
            };
            let quiet =
                now_ns.saturating_sub(window.last_ns) >= QUIET_NS && !waiting.contains(&key);
            let held = now_ns.saturating_sub(window.opened_ns) >= HOLD_NS;
            if quiet || held {
                self.report_window(key)?;
            } else {
                window.next_poll_ns = now_ns + POLL_NS;
            }
        }
        if now_ns.saturating_sub(self.last_expire_ns) >= EXPIRE_EVERY_NS {
            self.procs.expire(now_ns);
            // Exits drop their process's lineage; this catches the exits that were lost.
            let procs = &self.procs;
            self.lineages
                .retain(|&tgid, _| procs.get(tgid).is_some_and(|info| info.exit.is_none()));
            self.last_expire_ns = now_ns;
        }
        self.sink.flush()
    }

    /// Reports every pending write window (shutdown). A superseded binding is reported as
    /// seen: the record with its final totals comes after the stop, as later changes do, or
    /// is counted unread.
    pub fn finish(&mut self, totals: &mut impl Totals) -> io::Result<()> {
        let now = clock::boot_now_ns();
        let keys: Vec<(u32, u64)> = self.bindings.keys().copied().collect();
        for key in keys {
            self.refresh(key, now, totals)?;
        }
        self.report_windows(|_| true)?;
        self.sink.flush()
    }

    /// The keys of process `tgid`'s bindings.
    fn process_keys(&self, tgid: u32) -> Vec<(u32, u64)> {
        self.bindings
            .keys()
            .filter(|k| k.0 == tgid)
            .copied()
            .collect()
    }

    /// Reports the pending write windows of process `tgid` as of `now`, keeping its bindings.
    fn flush_process(&mut self, tgid: u32, now: u64, totals: &mut impl Totals) -> io::Result<()> {
        for key in self.process_keys(tgid) {
            self.refresh(key, now, totals)?;
        }
        self.report_windows(|key| key.tgid == tgid)
    }

    /// A process exited: report and forget its bindings. The records of its writes all came
    /// before its exit, so a superseded binding's final totals never will.
    fn finish_process(&mut self, tgid: u32, totals: &mut impl Totals) -> io::Result<()> {
        let now = clock::boot_now_ns();
        for key in self.process_keys(tgid) {
            self.refresh(key, now, totals)?;
            totals.remove(&write_key(key));
        }
        self.give_up(|key, _| key.0 == tgid);
        self.bindings.retain(|key, _| key.0 != tgid);
        self.report_windows(|key| key.tgid == tgid)
    }

    /// Drops the superseded bindings that `which` selects by key and `superseded` time,
    /// counting each as evicted: the record with its final totals is lost, and with them the
    /// writes since it was last polled.
    fn give_up(&mut self, which: impl Fn((u32, u64), u64) -> bool) {
        let mut lost = 0;
        self.bindings.retain(|&key, b| match b.superseded {
            Some(by) if which(key, by) => {
                lost += 1;
                false
            }
            _ => true,
        });
        self.counts.evicted += lost;
    }

    /// A rename moved inode `file` from `old` to `new` and, exchanging them, inode
    /// `exchanged` from `new` to `old` (each a path and whether it is truncated). The open
    /// files of those inodes, and below them when they are directories, write at their new
    /// names from now on; pending windows keep the writes before.
    fn renamed(
        &mut self,
        file: FileId,
        exchanged: Option<FileId>,
        old: (&Path, bool),
        new: (&Path, bool),
    ) {
        for binding in self.bindings.values_mut() {
            let (path, truncated) = if binding.file == file {
                (new.0.to_path_buf(), new.1)
            } else if exchanged == Some(binding.file) {
                (old.0.to_path_buf(), old.1)
            } else if binding.file.dev != file.dev {
                continue;
            } else if let Some(rest) = below(&binding.path, old) {
                (new.0.join(rest), new.1)
            } else if exchanged.is_some()
                && let Some(rest) = below(&binding.path, new)
            {
                (old.0.join(rest), old.1)
            } else {
                continue;
            };
            binding.path = path;
            binding.truncated = truncated;
        }
    }

    /// Reports pending writes to `file` as of `now`.
    fn flush_file(&mut self, file: FileId, now: u64, totals: &mut impl Totals) -> io::Result<()> {
        if file.ino == 0 {
            return Ok(());
        }
        let keys: Vec<(u32, u64)> = self
            .bindings
            .iter()
            .filter(|(_, b)| b.file == file)
            .map(|(key, _)| *key)
            .collect();
        for key in keys {
            self.refresh(key, now, totals)?;
        }
        self.report_windows(|key| key.file == file)
    }

    /// Updates a binding from the kernel and adds its new writes to its window; `now` opens
    /// the window if there is none.
    fn refresh(&mut self, key: (u32, u64), now: u64, totals: &mut impl Totals) -> io::Result<()> {
        let Some(mut binding) = self.bindings.remove(&key) else {
            return Ok(());
        };
        if binding.superseded.is_none() {
            match totals.get(&write_key(key)) {
                Some(v) if v.first_ns == binding.first_ns => {
                    if v.calls != binding.seen.1 {
                        binding.seen = (v.bytes, v.calls);
                        binding.last_ns = v.last_ns;
                    }
                    let idle = now.saturating_sub(binding.last_ns) >= IDLE_NS;
                    binding.next_poll_ns = now + if idle { IDLE_POLL_NS } else { POLL_NS };
                }
                // Replaced by a newer binding for a reused struct file. The record of that
                // one, still in the ring, hands this one's final totals over: wait for it.
                Some(v) => binding.superseded = Some(v.first_ns),
                // Evicted from the LRU: the writes since the last poll are lost.
                None => {
                    self.counts.evicted += 1;
                    return self.credit(&mut binding, now);
                }
            }
        }
        self.credit(&mut binding, now)?;
        self.bindings.insert(key, binding);
        Ok(())
    }

    /// Adds the writes of `binding` not yet credited to its window, opening one at `now` if
    /// there is none. A pending window of the same file under another path (the inode number
    /// was reused, or the file renamed) is reported first.
    fn credit(&mut self, binding: &mut Binding, now: u64) -> io::Result<()> {
        if binding.seen.1 <= binding.credited.1 {
            return Ok(());
        }
        let (bytes, calls) = (
            binding.seen.0.saturating_sub(binding.credited.0),
            binding.seen.1 - binding.credited.1,
        );
        binding.credited = binding.seen;
        let key = binding.window_key();
        if self
            .windows
            .get(&key)
            .is_some_and(|w| w.path != binding.path)
        {
            self.report_window(key)?;
        }
        let window = self
            .windows
            .entry(key)
            .or_insert_with(|| Window::new(binding, now));
        window.bytes += bytes;
        window.calls += calls;
        window.last_ns = window.last_ns.max(binding.last_ns);
        Ok(())
    }

    /// Reports the pending windows whose key `which` selects.
    fn report_windows(&mut self, which: impl Fn(&WindowKey) -> bool) -> io::Result<()> {
        let keys: Vec<WindowKey> = self.windows.keys().copied().filter(which).collect();
        for key in keys {
            self.report_window(key)?;
        }
        Ok(())
    }

    fn report_window(&mut self, key: WindowKey) -> io::Result<()> {
        match self.windows.remove(&key) {
            Some(window) => self.emit(&window.into_touch(key.file)),
            None => Ok(()),
        }
    }

    /// Reports `touch` if the filter admits it. The lineage is resolved only for admitted
    /// changes, unless a `unit` criterion needs it to decide.
    fn emit(&mut self, touch: &Touch) -> io::Result<()> {
        let lineage = if self.filter.is_empty() {
            self.lineage(&touch.actor)
        } else if self.filter.needs_unit() {
            let lineage = self.lineage(&touch.actor);
            let unit = lineage.context.unit.as_ref().map(|u| &*u.name);
            if !self.filter.matches(&touch.candidate(unit)) {
                return Ok(());
            }
            lineage
        } else {
            if !self.filter.matches(&touch.candidate(None)) {
                return Ok(());
            }
            self.lineage(&touch.actor)
        };
        self.counts.touches += 1;
        let report = ChangeReport::new(touch, &lineage, self.clock);
        self.sink.line(&Line::Touch(report))
    }

    /// The actor's ancestry, if the table's record for its pid is the same process. The
    /// lineage last made for the process is reused while its chain holds the same records:
    /// procctx replaces a record it changes (copy on write, as the lineage holds it), so equal
    /// pointers mean equal contents.
    fn lineage(&mut self, actor: &Actor) -> Rc<Lineage> {
        let ancestry = self.procs.ancestry(actor.tgid, Stop::Root);
        let ticks = |start| self.start_clock.start_to_ticks(start);
        let same = ancestry
            .chain
            .first()
            .is_some_and(|info| ticks(info.key.start) == ticks(actor.start_ns));
        if !same {
            return Rc::clone(&self.unknown);
        }
        if let Some(known) = self.lineages.get(&actor.tgid)
            && known.complete == ancestry.complete
            && known.chain.len() == ancestry.chain.len()
            && known
                .chain
                .iter()
                .zip(&ancestry.chain)
                .all(|(known, now)| Arc::ptr_eq(known, now))
        {
            return Rc::clone(known);
        }
        let chain = ancestry.chain;
        let context = Context {
            cgroup: chain.iter().find_map(|info| info.cgroup.clone()),
            unit: chain
                .iter()
                .find_map(|info| info.cgroup.as_ref()?.unit.clone()),
            container: chain
                .iter()
                .find_map(|info| info.cgroup.as_ref()?.container.clone()),
            tmux: chain
                .iter()
                .find_map(|info| info.env.as_ref()?.tmux.clone()),
        };
        let lineage = Rc::new(Lineage {
            origin: classify_origin(&chain),
            complete: ancestry.complete,
            context,
            chain,
            id: Some(LineageId::fresh()),
        });
        self.lineages.insert(actor.tgid, Rc::clone(&lineage));
        lineage
    }
}

#[cfg(test)]
#[path = "engine_tests.rs"]
mod tests;
