//! `fsblame doctor`: bpfdoctor's shared checks plus fsblame's own probes.

use std::{
    io::{self, IsTerminal},
    path::{Path, PathBuf},
    sync::{Arc, OnceLock},
};

use anyhow::anyhow;
use aya::{
    Btf, Ebpf, EbpfLoader,
    programs::{BtfTracePoint, FEntry},
};
use bpfdoctor::{
    Cap, Check, Diagnostic, Doctor, Env, Fix, RealEnv, Report, Status, Tool, errno_name,
    ids_for_errno,
};
use fsblame_abi::{self as abi, DevFilter};
use serde::Serialize;

use crate::{
    cli::DoctorArgs,
    fail::{Failure, errno_of},
    ops::{FS_HOOKS, Hook, Op, Role, SCHED_HOOKS},
    roots::{self, Mount, Overlay, Roots},
    tracer::{self, Cause, Class, HookOutcome, LoadError},
};

/// fsblame as bpfdoctor sees it.
pub fn tool() -> Tool {
    Tool {
        name: "fsblame",
        exe: std::env::current_exe().unwrap_or_else(|_| PathBuf::from("fsblame")),
        required_caps: &[Cap::Bpf, Cap::Perfmon],
        optional_caps: &[(
            Cap::SysPtrace,
            "argv, cwd and environment of other users' processes that started before fsblame",
        )],
        // bpf_loop.
        min_kernel: (5, 17),
        // 16 MiB ring buffer, LRU maps and per-CPU scratch.
        memlock_bytes: 48 << 20,
    }
}

fn privileged(env: &dyn Env, tool: &Tool) -> bool {
    let effective = env.caps().effective;
    tool.required_caps
        .iter()
        .all(|cap| cap.granted_by(effective))
}

const SKIPPED: &str = "skipped: required capabilities not effective";

/// `EINVAL`, plus the verifier's verdict when it rejected a program, in one line.
fn brief(e: &(dyn std::error::Error + 'static)) -> String {
    let label = errno_of(e).map_or_else(
        || "no errno".to_owned(),
        |errno| errno_name(errno).map_or_else(|| format!("errno {errno}"), str::to_owned),
    );
    let mut next = Some(e);
    while let Some(err) = next {
        if let Some(aya::programs::ProgramError::LoadError { verifier_log, .. }) =
            err.downcast_ref()
            && let Some(verdict) = tracer::verdict(&format!("{verifier_log:?}"))
        {
            return format!("{label}, verifier: {verdict}");
        }
        next = err.source();
    }
    format!("{label}: {e}")
}

fn load_probes() -> Result<(Btf, Ebpf), String> {
    let btf = Btf::from_sys_fs().map_err(|e| format!("kernel BTF unreadable: {e}"))?;
    let ebpf = EbpfLoader::new()
        .btf(Some(&btf))
        .load(fsblame_bpf::PROBE_OBJECT)
        .map_err(|e| format!("probe object did not load: {}", brief(&e)))?;
    Ok((btf, ebpf))
}

/// Loads and attaches `probe_<function>`; the link is dropped with `ebpf`.
fn probe_fentry(ebpf: &mut Ebpf, btf: &Btf, function: &str) -> Result<(), String> {
    let name = format!("probe_{function}");
    let prog: &mut FEntry = ebpf
        .program_mut(&name)
        .ok_or_else(|| format!("{name} missing from the probe object"))?
        .try_into()
        .map_err(|e| format!("{e}"))?;
    prog.load(function, btf).map_err(|e| brief(&e))?;
    prog.attach().map_err(|e| brief(&e))?;
    Ok(())
}

/// `probe.fentry_security`: fentry trampolines on the security hooks.
#[derive(Debug)]
pub struct FentryProbe;

impl Check for FentryProbe {
    fn id(&self) -> &'static str {
        "probe.fentry_security"
    }

    fn run(&self, env: &dyn Env, tool: &Tool) -> Diagnostic {
        const CANONICAL: &str = "security_inode_unlink";
        let diag = |status, observed: String| {
            Diagnostic::new(
                self.id(),
                "fentry on VFS security hooks",
                true,
                status,
                observed,
            )
        };
        let explain = "fsblame attaches BPF trampolines (fentry) to the security_* hooks that every \
                       modifying VFS operation calls; that needs the function in kernel BTF, \
                       ftrace direct calls and the BPF JIT";
        if !privileged(env, tool) {
            return diag(Status::Skip, SKIPPED.to_owned());
        }
        let (btf, mut ebpf) = match load_probes() {
            Ok(loaded) => loaded,
            Err(why) => {
                return diag(Status::Fail, why)
                    .with_impact("fsblame cannot load its BPF programs")
                    .with_explain(explain);
            }
        };
        if let Err(why) = probe_fentry(&mut ebpf, &btf, CANONICAL) {
            return diag(Status::Fail, format!("fentry on {CANONICAL} failed: {why}"))
                .with_impact("fsblame sees no file operations")
                .with_fix(Fix::new(
                    "zgrep -E 'CONFIG_(DEBUG_INFO_BTF|FUNCTION_TRACER|DYNAMIC_FTRACE_WITH_DIRECT_CALLS|BPF_JIT)=' /proc/config.gz",
                    "each must be =y; otherwise boot a distribution kernel that has them",
                ))
                .with_explain(explain);
        }
        let mut failed = Vec::new();
        let mut impact =
            String::from("operations reported only by the unavailable hooks are not seen");
        for hook in FS_HOOKS.iter().filter(|hook| hook.function != CANONICAL) {
            if let Err(why) = probe_fentry(&mut ebpf, &btf, hook.function) {
                failed.push(format!("{} ({why})", hook.function));
                if let Role::Supplements(lost) = hook.role {
                    impact.push_str("; ");
                    impact.push_str(lost);
                }
            }
        }
        if failed.is_empty() {
            return diag(
                Status::Pass,
                format!(
                    "fentry attached to {CANONICAL} and all {} tracer hooks",
                    FS_HOOKS.len()
                ),
            );
        }
        diag(
            Status::Warn,
            format!("fentry attached to {CANONICAL}; unavailable: {}", failed.join(", ")),
        )
        .with_impact(impact)
        .with_fix(Fix::new(
            "grep -wE 'security_[a-z_]+|rw_verify_area' /sys/kernel/tracing/available_filter_functions",
            "a hook missing here is inlined or not traceable on this kernel",
        ))
        .with_explain(explain)
    }
}

/// `probe.sched_tp`: the three sched `tp_btf` tracepoints that feed lineage.
#[derive(Debug)]
pub struct SchedProbe;

impl Check for SchedProbe {
    fn id(&self) -> &'static str {
        "probe.sched_tp"
    }

    fn run(&self, env: &dyn Env, tool: &Tool) -> Diagnostic {
        let diag = |status, observed: String| {
            Diagnostic::new(
                self.id(),
                "sched tracepoints (tp_btf)",
                true,
                status,
                observed,
            )
        };
        if !privileged(env, tool) {
            return diag(Status::Skip, SKIPPED.to_owned());
        }
        let (btf, mut ebpf) = match load_probes() {
            Ok(loaded) => loaded,
            Err(why) => {
                return diag(Status::Fail, why).with_impact("fsblame cannot load its BPF programs");
            }
        };
        let mut failed = Vec::new();
        for (_, tracepoint) in SCHED_HOOKS {
            let name = format!("probe_{tracepoint}");
            let result = (|| -> Result<(), String> {
                let prog: &mut BtfTracePoint = ebpf
                    .program_mut(&name)
                    .ok_or_else(|| format!("{name} missing from the probe object"))?
                    .try_into()
                    .map_err(|e| format!("{e}"))?;
                prog.load(tracepoint, &btf).map_err(|e| brief(&e))?;
                prog.attach().map_err(|e| brief(&e))?;
                Ok(())
            })();
            if let Err(why) = result {
                failed.push(format!("{tracepoint}: {why}"));
            }
        }
        if failed.is_empty() {
            return diag(
                Status::Pass,
                "tp_btf attached to sched_process_fork, sched_process_exec and sched_process_exit"
                    .to_owned(),
            );
        }
        diag(
            Status::Fail,
            format!("tp_btf failed: {}", failed.join("; ")),
        )
        .with_impact("no process lineage: fsblame cannot tell which command made a change")
        .with_fix(Fix::new(
            "ls -l /sys/kernel/btf/vmlinux && zgrep CONFIG_DEBUG_INFO_BTF= /proc/config.gz",
            "tp_btf needs kernel BTF (CONFIG_DEBUG_INFO_BTF=y, 5.5+)",
        ))
        .with_explain(
            "fork, exec and exit events let fsblame keep the argv, cwd and environment of \
                 processes that exit before their file changes are reported",
        )
    }
}

/// Whether one op can be reported here, for `doctor --json`.
#[derive(Clone, Debug, Serialize)]
pub struct OpStatus {
    /// Op name, as in `--op`.
    pub name: &'static str,
    /// `available`, `disabled`, or `unknown` (not probed: no privileges).
    pub status: &'static str,
    /// Why it is disabled: `verifier-limit`, `missing-hook`, `permission`,
    /// `verifier-rejected` or `error`; `not-probed` when unknown.
    pub reason: Option<&'static str>,
    /// The tracer program that reports it.
    pub program: &'static str,
    /// Instructions the verifier processed for that program, when it loaded.
    pub insns: Option<u32>,
    /// One line on why it is disabled.
    pub detail: Option<String>,
}

/// `probe.ops`: loads every optional program of the real tracer (the fentry hooks and the cwd
/// capture), so each op is known to be reportable here, or disabled with its cause.
#[derive(Debug)]
pub struct OpsProbe {
    /// Paths the user plans to watch; they shape the program like a real run.
    pub paths: Vec<PathBuf>,
    /// Per-op results of the last run, for `--json`.
    pub ops: Arc<OnceLock<Vec<OpStatus>>>,
}

/// The program that reports `op`.
fn reporting_hook(op: Op) -> &'static Hook {
    FS_HOOKS
        .iter()
        .find(|hook| hook.role == Role::Reports && hook.ops.contains(&op))
        .expect("every op has a reporting hook")
}

fn op_statuses(outcomes: &[HookOutcome]) -> Vec<OpStatus> {
    Op::ALL
        .iter()
        .map(|&op| {
            let hook = reporting_hook(op);
            let outcome = outcomes.iter().find(|o| o.hook.program == hook.program);
            match outcome.map(|o| &o.result) {
                Some(Ok(insns)) => OpStatus {
                    name: op.name(),
                    status: "available",
                    reason: None,
                    program: hook.program,
                    insns: *insns,
                    detail: None,
                },
                Some(Err(error)) => OpStatus {
                    name: op.name(),
                    status: "disabled",
                    reason: Some(error.cause().name()),
                    program: hook.program,
                    insns: None,
                    detail: Some(error.describe(hook)),
                },
                None => OpStatus {
                    name: op.name(),
                    status: "unknown",
                    reason: Some("not-probed"),
                    program: hook.program,
                    insns: None,
                    detail: None,
                },
            }
        })
        .collect()
}

fn unprobed() -> Vec<OpStatus> {
    op_statuses(&[])
}

impl Check for OpsProbe {
    fn id(&self) -> &'static str {
        "probe.ops"
    }

    fn run(&self, env: &dyn Env, tool: &Tool) -> Diagnostic {
        let diag = |status, observed: String| {
            Diagnostic::new(
                self.id(),
                "Operations the tracer can report",
                false,
                status,
                observed,
            )
        };
        if !privileged(env, tool) {
            let _ = self.ops.set(unprobed());
            return diag(Status::Skip, SKIPPED.to_owned());
        }
        // Shape the programs like a real run on these paths; the device filter changes them.
        let filter = Roots::resolve(&self.paths, &[]).map_or(
            DevFilter {
                count: 0,
                _pad: 0,
                devs: [0; abi::MAX_DEVS as usize],
            },
            |roots| roots.dev_filter(),
        );
        let outcomes = match tracer::probe_hooks(&filter) {
            Ok(outcomes) => outcomes,
            Err(error) => {
                let _ = self.ops.set(unprobed());
                return diag(
                    Status::Fail,
                    format!("the tracer object did not load: {error}"),
                )
                .with_impact("fsblame cannot run its file programs");
            }
        };
        let ops = op_statuses(&outcomes);
        let report = ops_diagnostic(diag, &outcomes, &ops, tool);
        let _ = self.ops.set(ops);
        report
    }
}

/// The `probe.ops` verdict: pass, or one finding per cause, each with its own explanation.
// One cohesive verdict builder: one finding per distinct cause, each with tailored text.
#[allow(clippy::too_many_lines)]
fn ops_diagnostic(
    diag: impl Fn(Status, String) -> Diagnostic,
    outcomes: &[HookOutcome],
    ops: &[OpStatus],
    tool: &Tool,
) -> Diagnostic {
    let failed: Vec<(&HookOutcome, &LoadError)> = outcomes
        .iter()
        .filter_map(|o| o.result.as_ref().err().map(|e| (o, e)))
        .collect();
    let disabled: Vec<&str> = ops
        .iter()
        .filter(|o| o.status != "available")
        .map(|o| o.name)
        .collect();
    if failed.is_empty() {
        let largest = outcomes
            .iter()
            .filter_map(|o| Some((o.hook.program, o.result.as_ref().ok().copied().flatten()?)))
            .max_by_key(|&(_, insns)| insns);
        let observed = match largest {
            Some((program, insns)) => format!(
                "all {} operations available; largest program {program} verified in {} of 1,000,000 instructions",
                ops.len(),
                tracer::grouped(insns.into())
            ),
            None => format!("all {} operations available", ops.len()),
        };
        return diag(Status::Pass, observed);
    }

    let observed: Vec<String> = failed.iter().map(|(o, e)| e.describe(&o.hook)).collect();
    let status = if disabled.len() == ops.len() {
        Status::Fail
    } else {
        Status::Warn
    };
    let mut impact = if disabled.is_empty() {
        String::from("all operations are still reported")
    } else {
        format!("{} operations will not be reported", disabled.join(", "))
    };
    // What a failed supplementing hook loses is in its `describe` line.
    if failed.iter().any(|(o, _)| o.hook.ops.contains(&Op::Rename)) {
        impact.push_str(
            "; directory renames no longer refresh the scope cache, so files moved into or out of \
             a watch root may be misjudged",
        );
    }
    let mut d = diag(status, observed.join("; ")).with_impact(impact);
    let causes: Vec<Cause> = failed.iter().map(|(_, e)| e.cause()).collect();
    let has = |want: fn(Cause) -> bool| causes.iter().any(|&c| want(c));
    let mut explain = Vec::new();
    if has(|c| matches!(c, Cause::TooComplex { .. })) {
        let available: Vec<&str> = ops
            .iter()
            .filter(|o| o.status == "available")
            .map(|o| o.name)
            .collect();
        let rename = failed.iter().any(|(o, e)| {
            o.hook.ops.contains(&Op::Rename) && matches!(e.cause(), Cause::TooComplex { .. })
        });
        let note = if rename {
            "known limitation on this kernel, there is no reduced-complexity mode beyond this: \
             without rename in --op, on_rename loads reduced to scope-cache upkeep, which fits, \
             and start-up skips the failing verification"
        } else {
            "known limitation on this kernel, there is no reduced-complexity mode: leaving the op \
             out of --op skips the failing program and its slow verification at start-up"
        };
        // Leaving ops out cannot skip a program that serves none (the cwd capture).
        if failed
            .iter()
            .any(|(o, e)| !o.hook.ops.is_empty() && matches!(e.cause(), Cause::TooComplex { .. }))
        {
            d = d.with_fix(Fix::new(
                format!("{} watch --op {} <PATH>", tool.name, available.join(",")),
                note,
            ));
        }
        explain.push(
            "verifier limit: the kernel's BPF verifier proves a program safe by walking every \
             path through it and gives up after 1,000,000 instructions; this program's dentry \
             walks exceed that budget on this kernel. It is a complexity limit of the verifier for \
             that program here, not a missing kernel feature or a privilege problem",
        );
    }
    if has(|c| c == Cause::Missing) {
        d = d.with_fix(Fix::new(
            "grep -wE 'security_[a-z_]+|rw_verify_area' /sys/kernel/tracing/available_filter_functions",
            "a hook missing here is inlined or not traceable on this kernel; no workaround",
        ));
        explain.push(
            "missing hook: the kernel function is not in BTF or cannot carry an fentry \
             trampoline (inlined, or excluded from ftrace)",
        );
    }
    if has(|c| c == Cause::Denied) {
        d = d.with_fix(Fix::new(
            tool.setcap_command(&[], &tool.exe),
            "or run with sudo; with lockdown=confidentiality BPF tracing stays blocked",
        ));
        explain.push(
            "permission: the kernel refused BPF_PROG_LOAD (EPERM/EACCES) before verifying: \
             CAP_BPF and CAP_PERFMON are missing, or kernel lockdown forbids it",
        );
    }
    if has(|c| matches!(c, Cause::Rejected | Cause::Other)) {
        d = d.with_fix(Fix::new(
            format!("FSBLAME_LOG=debug {} doctor", tool.name),
            "prints the full verifier log; please report it, this is a fsblame bug on this kernel",
        ));
        explain.push("rejected: the verifier refused the program for a reason other than its size");
    }
    d.with_explain(explain.join(". "))
}

/// `fsblame.watchfs`: how the filesystems of the watch paths shape what is reported.
/// Overlays are watched through their merged view (see [`roots`]); network and FUSE
/// filesystems hide or misattribute changes.
#[derive(Debug)]
pub struct WatchFs {
    /// Paths to inspect.
    pub paths: Vec<PathBuf>,
}

/// What limits reporting on a watch path's filesystem.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Concern {
    /// The overlay (named) involved has repeating inode numbers (see [`roots`]).
    OverlayInodes(String),
    /// The overlay's upper layer, `upperdir=` as given, is not found in this mount namespace.
    OverlayUpper(PathBuf),
    Network,
    Fuse,
}

fn fs_concern(fstype: &str) -> Option<Concern> {
    match fstype {
        "nfs" | "nfs4" | "cifs" | "smb3" | "9p" | "ceph" | "glusterfs" | "afs" => {
            Some(Concern::Network)
        }
        t if t == "fuse" || t == "fuseblk" || t == "virtiofs" || t.starts_with("fuse.") => {
            Some(Concern::Fuse)
        }
        _ => None,
    }
}

/// What `fsblame.watchfs` finds for one watch path.
struct Finding {
    /// Its part of the observed text.
    note: String,
    /// Whether the overlay rules of [`roots`] apply to it.
    overlay: bool,
    /// What limits reporting there.
    concern: Option<Concern>,
}

/// How an overlay is named in diagnostics.
fn overlay_name(overlay: &Overlay) -> String {
    overlay.point.as_ref().map_or_else(
        || format!("the overlay on device {}", roots::dev_string(overlay.dev)),
        |point| format!("the overlay at {}", point.display()),
    )
}

/// The upper layer of `overlay`, when found.
fn upper_layer(overlay: &Overlay) -> Option<&Path> {
    overlay.writable.as_ref().map(|w| w.upper.path.as_path())
}

/// Inspects the canonical watch path `path`, held by `mount`.
fn inspect(path: &Path, mount: &Mount, overlays: &[Overlay], mounts: &[Mount]) -> Finding {
    let shown = path.display();
    let inodes = |overlay: &Overlay| {
        (!overlay.unique_inodes(mounts)).then(|| Concern::OverlayInodes(overlay_name(overlay)))
    };
    if let Some(overlay) = overlays.iter().find(|o| o.dev == mount.dev) {
        let note = match (&overlay.writable, &overlay.upperdir) {
            (Some(writable), _) => format!(
                "{shown} is in the merged view of an overlay: each change made through it is \
                 reported once, at its path there; copy-ups and whiteouts in the upper layer {} \
                 are not reported",
                writable.upper.path.display()
            ),
            (None, Some(_)) => format!(
                "{shown} is in the merged view of an overlay: each change made through it is \
                 reported once, at its path there"
            ),
            (None, None) => format!("{shown} is in the merged view of a read-only overlay"),
        };
        let lost = overlay
            .upperdir
            .clone()
            .filter(|_| overlay.writable.is_none())
            .map(Concern::OverlayUpper);
        return Finding {
            note,
            overlay: true,
            concern: inodes(overlay).or(lost),
        };
    }
    if let Some(overlay) = overlays
        .iter()
        .find(|o| upper_layer(o).is_some_and(|u| path.starts_with(u)))
    {
        return Finding {
            note: format!(
                "{shown} is in the upper layer of {}: it is watched through the merged view, \
                 where each change made through the overlay is reported once",
                overlay_name(overlay)
            ),
            overlay: true,
            concern: inodes(overlay),
        };
    }
    let held: Vec<&Overlay> = overlays
        .iter()
        .filter(|o| upper_layer(o).is_some_and(|u| u.starts_with(path)))
        .collect();
    let concern = fs_concern(&mount.fstype);
    let Some(first) = held.first() else {
        return Finding {
            note: format!("{shown} on {}", mount.fstype),
            overlay: false,
            concern,
        };
    };
    let layers = if held.len() == 1 {
        format!("the upper layer of {}", overlay_name(first))
    } else {
        format!(
            "the upper layers of {} overlays, such as {}",
            held.len(),
            overlay_name(first)
        )
    };
    Finding {
        note: format!(
            "{shown} on {} holds {layers}: each change made through an overlay is reported \
             once, at its merged path",
            mount.fstype
        ),
        overlay: true,
        concern: concern.or_else(|| held.iter().find_map(|&o| inodes(o))),
    }
}

/// Id of the [`WatchFs`] check.
const WATCHFS: &str = "fsblame.watchfs";

/// The [`WatchFs`] diagnostic.
fn watchfs(status: Status, observed: String) -> Diagnostic {
    Diagnostic::new(WATCHFS, "Watch path filesystems", false, status, observed)
}

/// How fsblame watches an overlay.
const OVERLAY_EXPLAIN: &str = "overlayfs repeats every change made through the merged view on \
     its upper layer, in the same process, and first copies a lower file up into that layer; \
     fsblame reports the overlay's own operation and leaves out the upper layer and work \
     directory, so a change shows once, at its merged path. On an overlay, writes through a \
     shared mapping that mprotect(2) makes writable are not seen: the kernel names the upper \
     layer's file to that hook, not the overlay's";

/// Why network and FUSE filesystems are flagged.
const LOCAL_ONLY: &str = "fsblame sees the operations made through this kernel's VFS and \
     attributes each to the process that made it, so it is exact only on local filesystems";

/// The warning for the first `concern`, found at the canonical watch path `path` on `mount`.
fn concern_diagnostic(concern: &Concern, path: &Path, mount: &Mount, tool: &Tool) -> Diagnostic {
    let at = format!("{} is on {}", path.display(), mount.fstype);
    match concern {
        Concern::OverlayInodes(overlay) => watchfs(
            Status::Warn,
            format!(
                "{} involves {overlay}, whose layers are on different filesystems with xino \
                 off, so its inode numbers repeat",
                path.display()
            ),
        )
        .with_impact(
            "a file whose inode number equals a watched or excluded directory's on that overlay \
             is reported as that directory; watched directories below its root are kept open \
             while fsblame runs, which keeps the overlay busy",
        )
        .with_fix(Fix::new(
            "mount -t overlay overlay -o xino=on,lowerdir=...,upperdir=...,workdir=... <merged>",
            "xino=on gives every file of the overlay its own number; so do layers on one \
             filesystem",
        ))
        .with_explain(
            "fsblame matches watch roots by (superblock device, inode number); with layers on \
             several filesystems and xino off, overlayfs numbers each directory inode from a \
             counter whenever it loads it, while a file keeps the number it has on its layer",
        ),
        Concern::OverlayUpper(upperdir) => watchfs(
            Status::Warn,
            format!(
                "{at}, whose upper layer (upperdir={}) is not found in this mount namespace",
                upperdir.display()
            ),
        )
        .with_impact(
            "if another watch path contains that layer, overlayfs's copy-ups, whiteouts and \
             repeated changes there are reported as well",
        )
        .with_fix(Fix::new(
            format!("{} watch {}", tool.name, path.display()),
            "watch only the merged view",
        ))
        .with_explain(OVERLAY_EXPLAIN),
        Concern::Network => watchfs(Status::Warn, format!("{at}, a network filesystem"))
            .with_impact("changes made by other clients or by the server are never seen")
            .with_fix(Fix::new(
                format!("{} watch <export path>  # on the server", tool.name),
                "only operations made through this kernel are visible",
            ))
            .with_explain(LOCAL_ONLY),
        Concern::Fuse => watchfs(Status::Warn, format!("{at}, a FUSE filesystem"))
            .with_impact(
                "the FUSE daemon's writes to its backing store are attributed to the daemon, \
                 not the client",
            )
            .with_fix(Fix::new(
                format!("{} watch <backing directory>", tool.name),
                "if the daemon has one, watch it as well",
            ))
            .with_explain(LOCAL_ONLY),
    }
}

impl Check for WatchFs {
    fn id(&self) -> &'static str {
        WATCHFS
    }

    fn run(&self, _env: &dyn Env, tool: &Tool) -> Diagnostic {
        let mounts = match roots::mounts() {
            Ok(mounts) => mounts,
            Err(e) => {
                return watchfs(
                    Status::Skip,
                    format!("cannot read /proc/self/mountinfo: {e}"),
                );
            }
        };
        let overlays = roots::overlays(&mounts);
        let mut notes = Vec::new();
        let mut overlaid = false;
        let mut warned = None;
        for path in &self.paths {
            let located = roots::canonical(path, &mounts).and_then(|p| {
                let (mount, _) = roots::locate(&p, &mounts)?;
                Ok((p, mount))
            });
            let (canonical, mount) = match located {
                Ok(found) => found,
                Err(e) => {
                    return watchfs(
                        Status::Warn,
                        format!("cannot inspect {}: {e:#}", path.display()),
                    );
                }
            };
            let finding = inspect(&canonical, mount, &overlays, &mounts);
            overlaid |= finding.overlay;
            if let Some(concern) = finding.concern {
                warned.get_or_insert((canonical, mount, concern));
            }
            notes.push(finding.note);
        }
        match warned {
            Some((path, mount, concern)) => concern_diagnostic(&concern, &path, mount, tool),
            None if overlaid => {
                watchfs(Status::Info, notes.join("; ")).with_explain(OVERLAY_EXPLAIN)
            }
            None => watchfs(Status::Pass, notes.join(", ")),
        }
    }
}

/// Every check, in display order. `ops` receives the per-op results of `probe.ops`.
pub fn full(paths: Vec<PathBuf>, ops: Arc<OnceLock<Vec<OpStatus>>>) -> Doctor {
    let mut doctor = Doctor::with_shared();
    doctor
        .add(Box::new(FentryProbe))
        .add(Box::new(SchedProbe))
        .add(Box::new(OpsProbe {
            paths: paths.clone(),
            ops,
        }))
        .add(Box::new(WatchFs { paths }));
    doctor
}

/// The fast checks run before `watch` attaches.
pub fn preflight(paths: Vec<PathBuf>) -> Doctor {
    let mut doctor = Doctor::preflight();
    doctor.add(Box::new(WatchFs { paths }));
    doctor
}

/// The failure for a report with required failures: privileges unless only the kernel or
/// platform is at fault.
pub fn failure(report: &Report, message: &str) -> Failure {
    let unsupported = report
        .checks
        .iter()
        .filter(|c| c.status == Status::Fail && c.required)
        .all(|c| {
            ["kernel.", "platform.", "probe."]
                .iter()
                .any(|p| c.id.starts_with(p))
        });
    let error = anyhow!("{message}");
    if unsupported {
        Failure::Unsupported(error)
    } else {
        Failure::Privileges(error)
    }
}

fn color(stream: &impl IsTerminal) -> bool {
    stream.is_terminal() && std::env::var_os("NO_COLOR").is_none()
}

/// Prints the checks relevant to a failed load or attach to stderr.
pub fn explain_load_failure(error: &LoadError, paths: &[PathBuf]) -> io::Result<()> {
    let tool = tool();
    let mut ids: Vec<&str> = error.errno.map_or(&[][..], ids_for_errno).to_vec();
    if error.class() == Class::Unsupported {
        ids.extend([
            "kernel.version",
            "kernel.btf",
            "probe.fentry_security",
            "probe.sched_tp",
        ]);
    }
    let report = full(paths.to_vec(), Arc::default()).run_ids(&RealEnv, &tool, &ids);
    report.render_human(&mut io::stderr(), color(&io::stderr()))
}

/// Prints the non-passing checks of a report to stderr.
pub fn print_problems(report: &Report) -> io::Result<()> {
    let problems: Vec<Diagnostic> = report
        .checks
        .iter()
        .filter(|c| matches!(c.status, Status::Warn | Status::Fail))
        .cloned()
        .collect();
    if problems.is_empty() {
        return Ok(());
    }
    let uname = bpfdoctor::Uname {
        sysname: String::new(),
        release: report.kernel.clone(),
        machine: report.arch.clone(),
    };
    Report::new(report.tool, uname, problems).render_human(&mut io::stderr(), color(&io::stderr()))
}

/// The report as JSON, with the per-op results of `probe.ops` as `ops`.
fn render_json(report: &Report, ops: &[OpStatus], out: &mut impl io::Write) -> io::Result<()> {
    let mut value = serde_json::to_value(report)?;
    if let Some(object) = value.as_object_mut() {
        object.insert("ops".to_owned(), serde_json::to_value(ops)?);
    }
    serde_json::to_writer_pretty(&mut *out, &value)?;
    writeln!(out)
}

/// `fsblame doctor`.
pub fn run(args: &DoctorArgs) -> Result<(), Failure> {
    let paths = if args.paths.is_empty() {
        vec![std::env::current_dir().map_err(|e| Failure::Runtime(e.into()))?]
    } else {
        args.paths.clone()
    };
    let tool = tool();
    let ops = Arc::<OnceLock<Vec<OpStatus>>>::default();
    let report = full(paths, Arc::clone(&ops)).run(&RealEnv, &tool);
    let mut out = io::stdout();
    let rendered = if args.json {
        render_json(&report, ops.get().map_or(&[][..], Vec::as_slice), &mut out)
    } else {
        let color = color(&out);
        report.render_human(&mut out, color)
    };
    rendered.map_err(|e| Failure::Runtime(e.into()))?;
    if report.has_fail() {
        return Err(failure(
            &report,
            "fsblame cannot run here; see the FAIL lines above",
        ));
    }
    Ok(())
}
