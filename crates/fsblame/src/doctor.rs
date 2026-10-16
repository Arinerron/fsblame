//! `fsblame doctor`: bpfdoctor's shared checks plus fsblame's own probes.

use std::{
    cell::OnceCell,
    fs,
    io::{self, IsTerminal},
    path::PathBuf,
    rc::Rc,
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
    ops::{FS_HOOKS, Hook, Op, SCHED_HOOKS},
    roots::{self, Roots},
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
        for hook in FS_HOOKS.iter().filter(|hook| hook.function != CANONICAL) {
            if let Err(why) = probe_fentry(&mut ebpf, &btf, hook.function) {
                failed.push(format!("{} ({why})", hook.function));
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
        .with_impact("operations reported only by the unavailable hooks are not seen (rw_verify_area: write byte counts)")
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

/// `probe.ops`: loads every fentry program of the real tracer, so each op is known to be
/// reportable here, or disabled with its cause.
#[derive(Debug)]
pub struct OpsProbe {
    /// Paths the user plans to watch; they shape the program like a real run.
    pub paths: Vec<PathBuf>,
    /// Per-op results of the last run, for `--json`.
    pub ops: Rc<OnceCell<Vec<OpStatus>>>,
}

/// The program that reports `op`.
fn reporting_hook(op: Op) -> &'static Hook {
    FS_HOOKS
        .iter()
        .find(|hook| hook.reports && hook.ops.contains(&op))
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
    if failed
        .iter()
        .any(|(o, _)| o.hook.program == "on_rw_verify_area")
    {
        impact.push_str("; writes are reported without byte counts");
    }
    if failed.iter().any(|(o, _)| o.hook.always) {
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
        let rename = failed
            .iter()
            .any(|(o, e)| o.hook.always && matches!(e.cause(), Cause::TooComplex { .. }));
        let note = if rename {
            "known limitation on this kernel, there is no reduced-complexity mode beyond this: \
             without rename in --op, on_rename loads reduced to scope-cache upkeep, which fits, \
             and start-up skips the failing verification"
        } else {
            "known limitation on this kernel, there is no reduced-complexity mode: leaving the op \
             out of --op skips the failing program and its slow verification at start-up"
        };
        d = d.with_fix(Fix::new(
            format!("{} watch --op {} <PATH>", tool.name, available.join(",")),
            note,
        ));
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

/// `fsblame.watchfs`: watch paths on filesystems where dentry identity or paths mislead.
#[derive(Debug)]
pub struct WatchFs {
    /// Paths to inspect.
    pub paths: Vec<PathBuf>,
}

/// Filesystems on which dentry identity or paths mislead.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Concern {
    Overlay,
    Network,
    Fuse,
}

fn fs_concern(fstype: &str) -> Option<Concern> {
    match fstype {
        "overlay" => Some(Concern::Overlay),
        "nfs" | "nfs4" | "cifs" | "smb3" | "9p" | "ceph" | "glusterfs" | "afs" => {
            Some(Concern::Network)
        }
        t if t == "fuse" || t == "fuseblk" || t == "virtiofs" || t.starts_with("fuse.") => {
            Some(Concern::Fuse)
        }
        _ => None,
    }
}

impl Check for WatchFs {
    fn id(&self) -> &'static str {
        "fsblame.watchfs"
    }

    fn run(&self, _env: &dyn Env, tool: &Tool) -> Diagnostic {
        let diag = |status, observed: String| {
            Diagnostic::new(self.id(), "Watch path filesystems", false, status, observed)
        };
        let mounts = match roots::mounts() {
            Ok(mounts) => mounts,
            Err(e) => {
                return diag(
                    Status::Skip,
                    format!("cannot read /proc/self/mountinfo: {e}"),
                );
            }
        };
        let mut fine = Vec::new();
        let mut warned = None;
        for path in &self.paths {
            let located = fs::canonicalize(path).and_then(|p| {
                let (mount, _) = roots::locate(&p, &mounts)?;
                Ok((p, mount.clone()))
            });
            let (canonical, mount) = match located {
                Ok(found) => found,
                Err(e) => {
                    return diag(
                        Status::Warn,
                        format!("cannot inspect {}: {e}", path.display()),
                    );
                }
            };
            match fs_concern(&mount.fstype) {
                None => fine.push(format!("{} on {}", canonical.display(), mount.fstype)),
                Some(concern) => {
                    warned.get_or_insert((canonical, mount, concern));
                }
            }
        }
        let Some((path, mount, concern)) = warned else {
            return diag(Status::Pass, fine.join(", "));
        };
        let at = format!("{} is on {}", path.display(), mount.fstype);
        let d = match concern {
            Concern::Overlay => {
                let upper = mount
                    .super_opts
                    .split(',')
                    .find_map(|opt| opt.strip_prefix("upperdir="))
                    .unwrap_or("<upperdir>");
                diag(Status::Warn, format!("{at}: one file has a merged and an upper-layer identity"))
                    .with_impact("changes may be reported twice, or under the upper-layer path; copy-up shows as a create")
                    .with_fix(Fix::new(format!("{} watch {upper}", tool.name), "watch the writable layer directly"))
            }
            Concern::Network => diag(Status::Warn, format!("{at}, a network filesystem"))
                .with_impact("changes made by other clients or by the server are never seen")
                .with_fix(Fix::new(
                    format!("{} watch <export path>  # on the server", tool.name),
                    "only operations made through this kernel are visible",
                )),
            Concern::Fuse => diag(Status::Warn, format!("{at}, a FUSE filesystem"))
                .with_impact("the FUSE daemon's writes to its backing store are attributed to the daemon, not the client")
                .with_fix(Fix::new(
                    format!("{} watch <backing directory>", tool.name),
                    "if the daemon has one, watch it as well",
                )),
        };
        d.with_explain(
            "fsblame matches watch roots by (superblock device, inode) and rebuilds paths from the \
             kernel's dentries, so it is exact only on local, non-stacked filesystems",
        )
    }
}

/// Every check, in display order. `ops` receives the per-op results of `probe.ops`.
pub fn full(paths: Vec<PathBuf>, ops: Rc<OnceCell<Vec<OpStatus>>>) -> Doctor {
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
    let report = full(paths.to_vec(), Rc::default()).run_ids(&RealEnv, &tool, &ids);
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
    let ops = Rc::<OnceCell<Vec<OpStatus>>>::default();
    let report = full(paths, Rc::clone(&ops)).run(&RealEnv, &tool);
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
