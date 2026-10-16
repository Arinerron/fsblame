//! Loading the BPF object, filling the roots map and attaching programs.

use std::fmt;

use aya::{
    Btf, BtfError, Ebpf, EbpfLoader, VerifierLogLevel,
    maps::{Array, HashMap, MapData, MapError, PerCpuArray, RingBuf},
    programs::{BtfTracePoint, FEntry, Program, ProgramError},
};
use fsblame_abi::{self as abi, DevFilter, RootKey, RootVal, WriteKey, WriteVal};

use crate::{
    fail::errno_of,
    ops::{EXEC_CWD_HOOK, FS_HOOKS, Hook, Op, OpSet, Role, SCHED_HOOKS},
    roots::Roots,
};

/// Kernel-internal "operation not supported", which leaks from some attach paths.
const ENOTSUPP: i32 = 524;

/// The map of the tracer's `armed` flag (its own data section).
const ARMED: &str = ".data.armed";

/// How a load failure should be reported.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    /// The kernel refused for lack of privilege.
    Privileges,
    /// The kernel lacks a function, BTF, or attach support, or rejected the program.
    Unsupported,
    /// Anything else.
    Runtime,
}

/// Why a program could not be loaded or attached.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cause {
    /// The verifier gave up at its complexity limit (`E2BIG`, or `ENOSPC` for a log that
    /// outgrew its buffer): the program is valid but too costly to verify on this kernel.
    TooComplex {
        /// Instructions the verifier processed before it stopped, if it logged them.
        insns: Option<u64>,
        /// The verifier's instruction limit, if it logged it.
        limit: Option<u64>,
    },
    /// The kernel function is not in BTF, or cannot carry an fentry trampoline.
    Missing,
    /// Refused for lack of privilege, or by lockdown (`EPERM`, `EACCES` before verification).
    Denied,
    /// The verifier rejected the program for a reason other than complexity.
    Rejected,
    /// Anything else.
    Other,
}

impl Cause {
    /// Stable name for JSON output.
    pub const fn name(self) -> &'static str {
        match self {
            Self::TooComplex { .. } => "verifier-limit",
            Self::Missing => "missing-hook",
            Self::Denied => "permission",
            Self::Rejected => "verifier-rejected",
            Self::Other => "error",
        }
    }
}

/// The kernel's `BPF_COMPLEXITY_LIMIT_INSNS`, for logs that do not state it.
const VERIFIER_INSN_LIMIT: u64 = 1_000_000;

/// `1234567` as `1,234,567`.
pub fn grouped(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// The number after `marker` on the last log line that has it, such as `processed 123 insns`.
fn logged_number(log: &str, marker: &str) -> Option<u64> {
    log.lines().rev().find_map(|line| {
        let rest = &line[line.find(marker)? + marker.len()..];
        let end = rest
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(rest.len());
        rest[..end].parse().ok()
    })
}

/// The verifier's verdict: the line before its statistics, else the last line.
pub fn verdict(log: &str) -> Option<&str> {
    let lines: Vec<&str> = log
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    lines
        .iter()
        .position(|l| l.starts_with("verification time") || l.starts_with("processed "))
        .and_then(|at| at.checked_sub(1))
        .and_then(|at| lines.get(at))
        .or(lines.last())
        .copied()
}

/// A failed load or attach step.
#[derive(Debug)]
pub struct LoadError {
    /// The step, such as `attaching on_exec to sched_process_exec`.
    pub what: String,
    /// OS error code, if any.
    pub errno: Option<i32>,
    /// The target function or type is not in the kernel's BTF.
    pub missing_symbol: bool,
    /// Verifier output, when the verifier rejected a program.
    pub verifier_log: Option<String>,
    source: anyhow::Error,
}

impl LoadError {
    fn new<E: std::error::Error + Send + Sync + 'static>(what: impl Into<String>, e: E) -> Self {
        let mut verifier_log = None;
        let mut missing_symbol = false;
        let mut next: Option<&(dyn std::error::Error + 'static)> = Some(&e);
        while let Some(err) = next {
            if let Some(ProgramError::LoadError {
                verifier_log: log, ..
            }) = err.downcast_ref()
            {
                let log = format!("{log:?}");
                verifier_log = (!log.trim().is_empty()).then_some(log);
            }
            // `ProgramError::Btf` is transparent: the chain never yields its `BtfError` itself.
            missing_symbol |= matches!(
                err.downcast_ref(),
                Some(BtfError::UnknownBtfTypeName { .. })
            ) || matches!(
                err.downcast_ref(),
                Some(ProgramError::Btf(BtfError::UnknownBtfTypeName { .. }))
            );
            next = err.source();
        }
        Self {
            what: what.into(),
            errno: errno_of(&e),
            missing_symbol,
            verifier_log,
            source: anyhow::Error::new(e),
        }
    }

    /// Why the step failed.
    pub fn cause(&self) -> Cause {
        if let Some(log) = &self.verifier_log {
            return match self.errno {
                Some(libc::E2BIG | libc::ENOSPC) => Cause::TooComplex {
                    // "processed N insns (limit M)", or "Processed N insn" when it stopped.
                    insns: logged_number(log, "rocessed "),
                    limit: logged_number(log, "(limit "),
                },
                _ => Cause::Rejected,
            };
        }
        if self.missing_symbol {
            return Cause::Missing;
        }
        match self.errno {
            Some(libc::EPERM | libc::EACCES) => Cause::Denied,
            Some(
                libc::ENOENT
                | libc::EINVAL
                | libc::E2BIG
                | libc::ENOSYS
                | libc::EOPNOTSUPP
                | ENOTSUPP,
            ) => Cause::Missing,
            _ => Cause::Other,
        }
    }

    /// How to report this failure.
    pub fn class(&self) -> Class {
        match self.cause() {
            Cause::TooComplex { .. } | Cause::Missing | Cause::Rejected => Class::Unsupported,
            Cause::Denied => Class::Privileges,
            Cause::Other => Class::Runtime,
        }
    }

    /// One line on why `hook` is unusable, distinguishing the verifier's complexity limit, a
    /// missing hook and a refusal; for a hook that supplements another, also what is lost.
    pub fn describe(&self, hook: &Hook) -> String {
        let why = match self.cause() {
            Cause::TooComplex { insns, limit } => {
                let limit = grouped(limit.unwrap_or(VERIFIER_INSN_LIMIT));
                match insns {
                    Some(n) => format!(
                        "{} exceeded the BPF verifier instruction limit ({} insns > {limit})",
                        hook.program,
                        grouped(n)
                    ),
                    None => format!(
                        "{} exceeded the BPF verifier complexity limit ({limit} insns)",
                        hook.program
                    ),
                }
            }
            Cause::Missing => format!(
                "{} is not traceable on this kernel (not in BTF, or not ftrace-attachable)",
                hook.function
            ),
            Cause::Denied => format!(
                "loading {} was refused ({}): privileges or kernel lockdown",
                hook.program,
                self.errno
                    .and_then(bpfdoctor::errno_name)
                    .unwrap_or("EPERM")
            ),
            Cause::Rejected => format!(
                "the verifier rejected {}: {}",
                hook.program,
                self.verifier_log
                    .as_deref()
                    .and_then(verdict)
                    .unwrap_or("no verdict logged")
            ),
            Cause::Other => format!("{}: {:#}", self.what, self.source),
        };
        match hook.role {
            Role::Reports => why,
            Role::Supplements(lost) => format!("{why}; {lost}"),
        }
    }
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {:#}", self.what, self.source)?;
        if let Some(log) = &self.verifier_log {
            // The verdict is at the end of the log.
            let lines: Vec<&str> = log.lines().collect();
            write!(f, "\nverifier log (last lines):")?;
            for line in &lines[lines.len().saturating_sub(20)..] {
                write!(f, "\n  {line}")?;
            }
        }
        Ok(())
    }
}

impl std::error::Error for LoadError {}

/// An optional program that could not be attached: its ops are not reported, or for a
/// supplementing one, what it adds is lost.
#[derive(Debug)]
pub struct Missing {
    /// The hook.
    pub hook: Hook,
    /// Why.
    pub error: LoadError,
}

/// Outcome of loading and attaching one optional program of the tracer.
#[derive(Debug)]
pub struct HookOutcome {
    /// The hook.
    pub hook: Hook,
    /// Instructions the verifier processed for it, or why it is unusable.
    pub result: Result<Option<u32>, LoadError>,
}

/// Most processes tracked at once (entries of the `tracked` map) when following processes.
pub const TRACKED_MAX: u32 = 65_536;

/// Whose changes the file hooks report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Processes {
    /// Every process but fsblame.
    All,
    /// The processes added with [`Tracer::track`] and every process they start once added
    /// (the kernel adds those itself).
    Tracked,
}

/// The loaded, attached tracer.
pub struct Tracer {
    /// Keeps the programs and their links alive.
    _ebpf: Ebpf,
    /// Event records.
    pub ring: RingBuf<MapData>,
    /// Write coalescing totals.
    pub writes: HashMap<MapData, WriteKey, WriteVal>,
    tracked: HashMap<MapData, u32, u8>,
    stats: PerCpuArray<MapData, u64>,
    /// Hooks that are unavailable on this kernel.
    pub missing: Vec<Missing>,
    /// Selected ops that no attached hook reports.
    pub unavailable: Vec<Op>,
}

impl fmt::Debug for Tracer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tracer")
            .field("missing", &self.missing)
            .field("unavailable", &self.unavailable)
            .finish_non_exhaustive()
    }
}

fn program<'a>(ebpf: &'a mut Ebpf, name: &str) -> Result<&'a mut Program, LoadError> {
    ebpf.program_mut(name).ok_or_else(|| {
        LoadError::new(
            format!("finding program {name}"),
            std::io::Error::other("not in the BPF object"),
        )
    })
}

/// Verifier logging: statistics and errors only, unless `FSBLAME_LOG=debug` asks for the
/// instruction trace. The trace of a program that hits the instruction limit runs to hundreds
/// of megabytes, and aya re-verifies with ever larger buffers until it fits: minutes per
/// program instead of a second.
fn log_level() -> VerifierLogLevel {
    if log::log_enabled!(log::Level::Debug) {
        VerifierLogLevel::DEBUG | VerifierLogLevel::STATS
    } else {
        VerifierLogLevel::STATS
    }
}

/// The tracer object for `ops`, with its maps created (the `events` ring buffer of
/// `ring_bytes`) and no program loaded yet. `scope` is the `SCOPE_*` of the roots; the
/// `tracked` map has room only when following `processes`.
fn open(
    btf: &Btf,
    ops: OpSet,
    dev_filter: &DevFilter,
    root_slots: u32,
    ring_bytes: u32,
    scope: u32,
    processes: Processes,
) -> Result<Ebpf, LoadError> {
    let self_tgid = std::process::id();
    let op_mask = ops.mask();
    let track = u32::from(processes == Processes::Tracked);
    // security_inode_setattr gained a leading idmap in 6.0 and distributions backport it, so
    // its arity comes from the prototype, not the kernel version.
    let setattr_idmap = u32::from(
        crate::btf::kernel_func_params("security_inode_setattr")
            .map_err(|e| LoadError::new("reading kernel BTF", e))?
            != Some(2),
    );
    EbpfLoader::new()
        .btf(Some(btf))
        .verifier_log_level(log_level())
        .override_global("self_tgid", &self_tgid, true)
        .override_global("op_mask", &op_mask, true)
        .override_global("dev_filter", dev_filter, true)
        .override_global("scope", &scope, true)
        .override_global("track", &track, true)
        .override_global("setattr_idmap", &setattr_idmap, true)
        .map_max_entries("roots", root_slots)
        .map_max_entries("tracked", if track == 0 { 1 } else { TRACKED_MAX })
        .map_max_entries("events", ring_bytes)
        .load(fsblame_bpf::OBJECT)
        .map_err(|e| LoadError::new("loading the BPF object", e))
}

/// Logs how many instructions the verifier processed for `program` on `target`.
fn log_insns(program: &str, target: &str, insns: Option<u32>) {
    log::debug!(
        "{program} on {target}: {} verifier insns",
        insns.map_or_else(|| "?".to_owned(), |n| grouped(n.into()))
    );
}

/// Loads and attaches the fentry program of `hook`; returns the instructions the verifier
/// processed.
fn attach_fentry(ebpf: &mut Ebpf, btf: &Btf, hook: &Hook) -> Result<Option<u32>, LoadError> {
    let what = |step: &str| format!("{step} {} on {}", hook.program, hook.function);
    let prog: &mut FEntry = program(ebpf, hook.program)?
        .try_into()
        .map_err(|e| LoadError::new(what("typing"), e))?;
    prog.load(hook.function, btf)
        .map_err(|e| LoadError::new(what("loading"), e))?;
    let insns = prog
        .info()
        .ok()
        .and_then(|info| info.verified_instruction_count());
    prog.attach()
        .map_err(|e| LoadError::new(what("attaching"), e))?;
    log_insns(hook.program, hook.function, insns);
    Ok(insns)
}

/// Loads and attaches the `tp_btf` program `name` to `tracepoint`; returns the instructions
/// the verifier processed.
fn attach_tp(
    ebpf: &mut Ebpf,
    btf: &Btf,
    name: &str,
    tracepoint: &str,
) -> Result<Option<u32>, LoadError> {
    let what = |step: &str| format!("{step} {name} on tp_btf/{tracepoint}");
    let prog: &mut BtfTracePoint = program(ebpf, name)?
        .try_into()
        .map_err(|e| LoadError::new(what("typing"), e))?;
    prog.load(tracepoint, btf)
        .map_err(|e| LoadError::new(what("loading"), e))?;
    let insns = prog
        .info()
        .ok()
        .and_then(|info| info.verified_instruction_count());
    prog.attach()
        .map_err(|e| LoadError::new(what("attaching"), e))?;
    log_insns(name, tracepoint, insns);
    Ok(insns)
}

/// Loads every optional program of the tracer (the fentry hooks and [`EXEC_CWD_HOOK`]),
/// configured for watch roots on the devices of `dev_filter` and every process, and reports
/// how each fared. The programs detach when this returns.
pub fn probe_hooks(dev_filter: &DevFilter) -> Result<Vec<HookOutcome>, LoadError> {
    let btf = Btf::from_sys_fs().map_err(|e| LoadError::new("reading kernel BTF", e))?;
    let mut ebpf = open(
        &btf,
        OpSet::new(&[]),
        dev_filter,
        1,
        abi::RINGBUF_BYTES,
        abi::SCOPE_ROOTS,
        Processes::All,
    )?;
    let mut outcomes: Vec<HookOutcome> = FS_HOOKS
        .iter()
        .map(|hook| HookOutcome {
            hook: *hook,
            result: attach_fentry(&mut ebpf, &btf, hook),
        })
        .collect();
    outcomes.push(HookOutcome {
        hook: EXEC_CWD_HOOK,
        result: attach_tp(
            &mut ebpf,
            &btf,
            EXEC_CWD_HOOK.program,
            EXEC_CWD_HOOK.function,
        ),
    });
    Ok(outcomes)
}

/// Fills the `roots` map of `ebpf` with `roots`, each under its id.
fn fill_roots(ebpf: &mut Ebpf, roots: &Roots) -> Result<(), LoadError> {
    let map = ebpf.map_mut("roots").ok_or_else(|| {
        LoadError::new(
            "finding map roots",
            std::io::Error::other("not in the BPF object"),
        )
    })?;
    let mut map: HashMap<_, RootKey, RootVal> =
        HashMap::try_from(map).map_err(|e| LoadError::new("opening map roots", e))?;
    for (id, root) in roots.iter() {
        let key = RootKey {
            dev: root.dev,
            _pad: 0,
            ino: root.ino,
        };
        let flags = if root.exclude { abi::ROOT_F_EXCLUDE } else { 0 };
        map.insert(key, RootVal { id, flags }, 0)
            .map_err(|e| LoadError::new(format!("adding {} to roots", root.path.display()), e))?;
    }
    Ok(())
}

impl Tracer {
    /// Loads the tracer for `roots`, reporting `ops` of `processes` through a ring buffer of
    /// `ring_bytes` (a power of two and a multiple of the page size). The sched tracepoints
    /// are required; an optional program (fentry hook, cwd capture) whose kernel function is
    /// missing or unattachable is skipped and listed in [`missing`](Self::missing), unless no
    /// file hook attaches at all.
    pub fn load(
        roots: &Roots,
        ops: OpSet,
        ring_bytes: u32,
        processes: Processes,
    ) -> Result<Self, LoadError> {
        let btf = Btf::from_sys_fs().map_err(|e| LoadError::new("reading kernel BTF", e))?;
        let root_slots = u32::try_from(roots.len()).unwrap_or(u32::MAX).max(1);
        let scope = match (roots.everywhere(), roots.len()) {
            (false, _) => abi::SCOPE_ROOTS,
            (true, 0) => abi::SCOPE_ALL,
            (true, _) => abi::SCOPE_ALL_EXCLUDES,
        };
        let mut ebpf = open(
            &btf,
            ops,
            &roots.dev_filter(),
            root_slots,
            ring_bytes,
            scope,
            processes,
        )?;
        fill_roots(&mut ebpf, roots)?;

        // on_exec reads what on_exec_cwd leaves on its CPU, and programs on one tracepoint run
        // in attach order: the cwd capture goes first.
        let mut missing = Vec::new();
        match attach_tp(
            &mut ebpf,
            &btf,
            EXEC_CWD_HOOK.program,
            EXEC_CWD_HOOK.function,
        ) {
            Ok(_) => {}
            Err(error) if error.class() == Class::Unsupported => missing.push(Missing {
                hook: EXEC_CWD_HOOK,
                error,
            }),
            Err(error) => return Err(error),
        }
        // Process tracking before file hooks, so lineage is complete before the first file
        // event.
        for (name, tracepoint) in SCHED_HOOKS {
            attach_tp(&mut ebpf, &btf, name, tracepoint)?;
        }

        let mut attached = Vec::new();
        for hook in FS_HOOKS.iter().filter(|hook| hook.wanted(ops)) {
            match attach_fentry(&mut ebpf, &btf, hook) {
                Ok(_) => attached.push(*hook),
                Err(error) if error.class() == Class::Unsupported => {
                    missing.push(Missing { hook: *hook, error });
                }
                Err(error) => return Err(error),
            }
        }
        let reportable = |op| {
            attached
                .iter()
                .any(|h| h.role == Role::Reports && h.ops.contains(&op))
        };
        let unavailable: Vec<Op> = ops.iter().filter(|&op| !reportable(op)).collect();
        if unavailable.len() == ops.iter().count() {
            // Nothing selected can be traced; `wanted` hooks always include one reporting hook
            // per op, so one of them is missing: fail with its error.
            let first = missing
                .iter()
                .position(|m| m.hook.role == Role::Reports)
                .unwrap_or(0);
            let Missing { error, .. } = missing.swap_remove(first);
            return Err(error);
        }

        // Every hook is attached: report file events from now on, for all of them at once.
        let armed = ebpf.map_mut(ARMED).ok_or_else(|| {
            LoadError::new(
                format!("finding map {ARMED}"),
                std::io::Error::other("not in the BPF object"),
            )
        })?;
        Array::<_, u32>::try_from(armed)
            .and_then(|mut armed| armed.set(0, 1, 0))
            .map_err(|e| LoadError::new("arming the file hooks", e))?;

        let mut take = |name: &str| {
            ebpf.take_map(name).ok_or_else(|| {
                LoadError::new(
                    format!("finding map {name}"),
                    std::io::Error::other("not in the BPF object"),
                )
            })
        };
        let ring = RingBuf::try_from(take("events")?)
            .map_err(|e| LoadError::new("opening map events", e))?;
        let writes = HashMap::try_from(take("writes")?)
            .map_err(|e| LoadError::new("opening map writes", e))?;
        let tracked = HashMap::try_from(take("tracked")?)
            .map_err(|e| LoadError::new("opening map tracked", e))?;
        let stats = PerCpuArray::try_from(take("stats")?)
            .map_err(|e| LoadError::new("opening map stats", e))?;
        Ok(Self {
            _ebpf: ebpf,
            ring,
            writes,
            tracked,
            stats,
            missing,
            unavailable,
        })
    }

    /// Adds process `pid` to the tracked set of a tracer loaded for
    /// [`Processes::Tracked`]; from now on the kernel adds every process it starts. Fails
    /// when [`TRACKED_MAX`] processes are tracked.
    pub fn track(&mut self, pid: u32) -> Result<(), MapError> {
        self.tracked.insert(pid, 1, 0)
    }

    /// The sum over all CPUs of a `stats` slot.
    fn stat(&self, slot: u32) -> u64 {
        self.stats
            .get(&slot, 0)
            .map_or(0, |per_cpu| per_cpu.iter().sum())
    }

    /// Records the kernel could not put in the ring buffer because it was full.
    pub fn ring_drops(&self) -> u64 {
        self.stat(abi::STAT_RING_DROPS)
    }

    /// New processes of tracked ones that were left untracked because [`TRACKED_MAX`]
    /// processes were tracked; their changes are not reported.
    pub fn track_full(&self) -> u64 {
        self.stat(abi::STAT_TRACK_FULL)
    }
}
