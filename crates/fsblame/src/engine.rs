//! Event processing: feeds process events to procctx, coalesces writes, selects changes and
//! emits them, with their lineage, as report lines.

use std::{collections::HashMap, io, path::PathBuf, sync::Arc};

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
    report::{ChangeReport, Line, Sink},
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
    /// Inode number; 0 for a name being created.
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
    /// `i_mode`, or the requested mode for creations.
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
}

/// One open file of one process, being coalesced.
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
    /// Totals already reported.
    reported: (u64, u64),
    /// Latest write as last read from the kernel.
    last_ns: u64,
    /// When the unreported window opened.
    window_ns: u64,
    next_poll_ns: u64,
}

impl Binding {
    fn delta(&self) -> Touch {
        Touch {
            ts_ns: self.last_ns,
            op: Op::Write,
            path: self.path.clone(),
            truncated: self.truncated,
            old_path: None,
            target: None,
            file: self.file,
            mode: self.mode,
            change: Change::Write {
                bytes: self.seen.0.saturating_sub(self.reported.0),
                calls: self.seen.1.saturating_sub(self.reported.1),
            },
            actor: self.actor.clone(),
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
    /// Write bindings the kernel's `writes` LRU evicted before their latest totals were
    /// read: the bytes and calls since the previous poll are missing from the reports.
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
    /// Scratch for the cwd of an exec record, reused across execs.
    cwd: Vec<u8>,
    last_expire_ns: u64,
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
            cwd: Vec::new(),
            last_expire_ns: 0,
            counts: Counts::default(),
        }
    }

    /// Run counters.
    pub fn counts(&self) -> Counts {
        self.counts
    }

    /// The sink, for lines that do not come from records (losses, the summary).
    pub fn sink_mut(&mut self) -> &mut S {
        &mut self.sink
    }

    /// Handles one ring buffer item.
    pub fn handle(&mut self, bytes: &[u8], totals: &mut impl Totals) -> io::Result<()> {
        match record::decode(bytes) {
            Ok(Record::Fork(r)) => {
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
            Ok(Record::Exec(exec)) => {
                self.on_exec(&exec);
                Ok(())
            }
            Ok(Record::Exit(r)) => {
                // Report the process's writes while its record is still live: the exit event
                // arrives while the task is still in do_exit, so a lookup after on_exit would
                // rebuild it from a half-torn-down /proc entry (no exe, argv, cwd or env).
                self.finish_process(r.tgid, totals)?;
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
            Ok(Record::Fs(fs)) => self.on_fs(&fs, totals),
            Err(malformed) => {
                log::debug!("{malformed}");
                self.counts.malformed += 1;
                Ok(())
            }
        }
    }

    fn on_exec(&mut self, exec: &Exec<'_>) {
        let r = exec.rec;
        let env = exec.env_entries();
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
            env: Some(&env),
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
        // Load the lineage while the processes are alive; it is rendered later.
        self.procs.ancestry(actor.tgid, Stop::Root);
        let file = FileId {
            dev: r.dev,
            ino: r.ino,
        };
        let truncated = flag(r.hdr.flags, abi::F_PATH_TRUNC | abi::F_PATH2_TRUNC);

        if op == Op::Write && mapped.is_none() {
            let key = (r.tgid, r.file);
            if let Some(mut old) = self.bindings.remove(&key) {
                if flag(r.hdr.flags, abi::F_REPLACED) {
                    // The struct file was reused: the kernel handed over the old binding's
                    // final totals with the new one.
                    old.seen = old.seen.max((r.aux, r.aux2));
                } else {
                    // The kernel had no binding left to replace: the LRU evicted it, taking
                    // the totals since the last poll along.
                    self.counts.evicted += 1;
                }
                self.report_binding(&mut old)?;
            }
            let now = r.hdr.ts_ns;
            self.bindings.insert(
                key,
                Binding {
                    first_ns: now,
                    path,
                    truncated,
                    file,
                    mode: r.mode,
                    actor,
                    seen: (r.bytes, 1),
                    reported: (0, 0),
                    last_ns: now,
                    window_ns: now,
                    next_poll_ns: now + POLL_NS,
                },
            );
            return Ok(());
        }

        // Report pending writes to the inodes involved first, keeping causal order.
        self.flush_file(file, totals)?;
        if op == Op::Rename && r.aux2 != 0 {
            self.flush_file(
                FileId {
                    dev: r.dev,
                    ino: r.aux2,
                },
                totals,
            )?;
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
        let due: Vec<(u32, u64)> = self
            .bindings
            .iter()
            .filter(|(_, b)| b.next_poll_ns <= now_ns)
            .map(|(key, _)| *key)
            .collect();
        for key in due {
            self.refresh(key, now_ns, totals, false)?;
        }
        if now_ns.saturating_sub(self.last_expire_ns) >= EXPIRE_EVERY_NS {
            self.procs.expire(now_ns);
            self.last_expire_ns = now_ns;
        }
        self.sink.flush()
    }

    /// Reports every pending write window (shutdown).
    pub fn finish(&mut self, totals: &mut impl Totals) -> io::Result<()> {
        let now = clock::boot_now_ns();
        let keys: Vec<(u32, u64)> = self.bindings.keys().copied().collect();
        for key in keys {
            self.refresh(key, now, totals, true)?;
        }
        self.sink.flush()
    }

    /// A process exited: report and forget its bindings.
    fn finish_process(&mut self, tgid: u32, totals: &mut impl Totals) -> io::Result<()> {
        let keys: Vec<(u32, u64)> = self
            .bindings
            .keys()
            .filter(|k| k.0 == tgid)
            .copied()
            .collect();
        let now = clock::boot_now_ns();
        for key in keys {
            self.refresh(key, now, totals, true)?;
            self.bindings.remove(&key);
            totals.remove(&write_key(key));
        }
        Ok(())
    }

    /// Reports pending writes to `file`.
    fn flush_file(&mut self, file: FileId, totals: &mut impl Totals) -> io::Result<()> {
        if file.ino == 0 {
            return Ok(());
        }
        let keys: Vec<(u32, u64)> = self
            .bindings
            .iter()
            .filter(|(_, b)| b.file == file)
            .map(|(key, _)| *key)
            .collect();
        let now = clock::boot_now_ns();
        for key in keys {
            self.refresh(key, now, totals, true)?;
        }
        Ok(())
    }

    /// Updates a binding from the kernel and reports its window when finished, quiet, held
    /// long enough, or `force`d.
    fn refresh(
        &mut self,
        key: (u32, u64),
        now: u64,
        totals: &mut impl Totals,
        force: bool,
    ) -> io::Result<()> {
        let Some(mut binding) = self.bindings.remove(&key) else {
            return Ok(());
        };
        let gone = match totals.get(&write_key(key)) {
            Some(v) if v.first_ns == binding.first_ns => {
                if v.calls != binding.seen.1 {
                    if binding.seen == binding.reported {
                        binding.window_ns = now;
                    }
                    binding.seen = (v.bytes, v.calls);
                    binding.last_ns = v.last_ns;
                }
                false
            }
            // Superseded by a newer binding for a reused struct file (its record follows):
            // report what was seen of this one.
            Some(_) => true,
            // Evicted from the LRU: the writes since the last poll are lost.
            None => {
                self.counts.evicted += 1;
                true
            }
        };
        let quiet = now.saturating_sub(binding.last_ns) >= QUIET_NS;
        let held = now.saturating_sub(binding.window_ns) >= HOLD_NS;
        if force || gone || quiet || held {
            self.report_binding(&mut binding)?;
        }
        if !gone {
            let idle = now.saturating_sub(binding.last_ns) >= IDLE_NS;
            binding.next_poll_ns = now + if idle { IDLE_POLL_NS } else { POLL_NS };
            self.bindings.insert(key, binding);
        }
        Ok(())
    }

    fn report_binding(&mut self, binding: &mut Binding) -> io::Result<()> {
        if binding.seen.1 > binding.reported.1 {
            let touch = binding.delta();
            binding.reported = binding.seen;
            self.emit(&touch)?;
        }
        Ok(())
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

    /// The actor's ancestry, if the table's record for its pid is the same process.
    fn lineage(&mut self, actor: &Actor) -> Lineage {
        let ancestry = self.procs.ancestry(actor.tgid, Stop::Root);
        let ticks = |start| self.start_clock.start_to_ticks(start);
        let same = ancestry
            .chain
            .first()
            .is_some_and(|info| ticks(info.key.start) == ticks(actor.start_ns));
        if !same {
            return Lineage::default();
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
        Lineage {
            origin: classify_origin(&chain),
            complete: ancestry.complete,
            context,
            chain,
        }
    }
}
