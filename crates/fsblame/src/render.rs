//! Output: the human tree view and NDJSON.

use std::{
    ffi::OsStr,
    io::{self, Write},
    path::{Path, PathBuf},
};

use procctx::{Confidence, OriginKind, ProcInfo};
use serde::Serialize;

use crate::{
    clock::Clock,
    engine::{Change, Lineage, RENAME_EXCHANGE, RENAME_NOREPLACE, Sink, Touch},
    ops::Op,
    roots::dev_string,
};

const S_IFMT: u32 = 0o170_000;
/// Widest command shown before it is cut with `…`.
const MAX_COMMAND: usize = 60;
/// Column cap for aligning the process details.
const MAX_COLUMN: usize = 56;

/// Programs that run a script named by their first argument.
fn is_interpreter(name: &str) -> bool {
    matches!(
        name,
        "node"
            | "nodejs"
            | "python"
            | "python2"
            | "python3"
            | "perl"
            | "ruby"
            | "bun"
            | "deno"
            | "php"
    ) || name
        .strip_prefix("python3.")
        .is_some_and(|minor| minor.bytes().all(|b| b.is_ascii_digit()))
}

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// `npm` for `/usr/lib/node_modules/npm/bin/npm-cli.js`, `pip` for `/usr/bin/pip`.
fn script_name(path: &str) -> &str {
    let base = basename(path);
    let stem = [".js", ".cjs", ".mjs", ".py"]
        .iter()
        .find_map(|ext| base.strip_suffix(ext))
        .unwrap_or(base);
    stem.strip_suffix("-cli").unwrap_or(stem)
}

/// Quotes an argument for display when a shell would need it.
fn quote(arg: &str) -> String {
    let safe = |c: char| c.is_alphanumeric() || "-_./=:,+@%^~".contains(c);
    if !arg.is_empty() && arg.chars().all(safe) {
        arg.to_owned()
    } else {
        format!("'{}'", arg.replace('\'', r"'\''"))
    }
}

fn ellipsize(mut text: String, max: usize) -> String {
    if text.chars().count() > max {
        text = text.chars().take(max - 1).collect();
        text.push('…');
    }
    text
}

/// Replaces a leading home directory with `~`.
fn tilde(path: &str, home: Option<&Path>) -> String {
    let Some(home) = home.and_then(Path::to_str).filter(|h| h.len() > 1) else {
        return path.to_owned();
    };
    match path.strip_prefix(home) {
        Some("") => "~".to_owned(),
        Some(rest) if rest.starts_with('/') => format!("~{rest}"),
        _ => path.to_owned(),
    }
}

/// A process as a short command line: the program's basename and its arguments, with
/// `interpreter /abs/path/to/tool args` collapsed to `tool args`.
pub fn command_line(argv: &[Box<OsStr>], comm: &str, home: Option<&Path>) -> String {
    let cmd_parts: Vec<String> = argv
        .iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    let Some(first) = cmd_parts.first() else {
        return comm.to_owned();
    };
    let program = basename(first);
    let (head, rest) = match cmd_parts.get(1) {
        Some(script) if is_interpreter(program) && script.starts_with('/') => {
            (script_name(script), &cmd_parts[2..])
        }
        _ => (program, &cmd_parts[1..]),
    };
    let mut line = head.to_owned();
    for arg in rest {
        line.push(' ');
        line.push_str(&quote(&tilde(arg, home)));
    }
    ellipsize(line, MAX_COMMAND)
}

/// `118 B`, `4.0 KiB`, `1.5 MiB`.
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["KiB", "MiB", "GiB", "TiB", "PiB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    #[allow(clippy::cast_precision_loss, reason = "one decimal is shown")]
    let mut value = bytes as f64 / 1024.0;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

fn perms(mode: u32) -> String {
    format!("{:04o}", mode & 0o7777)
}

fn file_type(mode: u32) -> &'static str {
    match mode & S_IFMT {
        0o010_000 => "fifo",
        0o020_000 => "char device",
        0o060_000 => "block device",
        0o140_000 => "socket",
        0o040_000 => "dir",
        0o120_000 => "symlink",
        _ => "file",
    }
}

fn kind_label(kind: OriginKind) -> &'static str {
    match kind {
        OriginKind::NpmLifecycle => "npm lifecycle",
        OriginKind::PnpmLifecycle => "pnpm lifecycle",
        OriginKind::YarnLifecycle => "yarn lifecycle",
        OriginKind::BunLifecycle => "bun lifecycle",
        OriginKind::CargoBuildScript => "cargo build script",
        OriginKind::PipBuild => "pip build",
        OriginKind::Make => "make",
    }
}

fn kind_id(kind: OriginKind) -> &'static str {
    match kind {
        OriginKind::NpmLifecycle => "npm-lifecycle",
        OriginKind::PnpmLifecycle => "pnpm-lifecycle",
        OriginKind::YarnLifecycle => "yarn-lifecycle",
        OriginKind::BunLifecycle => "bun-lifecycle",
        OriginKind::CargoBuildScript => "cargo-build-script",
        OriginKind::PipBuild => "pip-build",
        OriginKind::Make => "make",
    }
}

fn confidence_id(confidence: Confidence) -> &'static str {
    match confidence {
        Confidence::High => "high",
        Confidence::Medium => "medium",
        Confidence::Low => "low",
    }
}

/// The aligned tree view.
#[derive(Debug)]
pub struct Human<W> {
    out: W,
    clock: Clock,
    home: Option<PathBuf>,
    depth: usize,
}

impl<W: Write> Human<W> {
    /// Writes to `out`, shortening paths below `home` and showing `depth` ancestors.
    pub fn new(out: W, clock: Clock, home: Option<PathBuf>, depth: usize) -> Self {
        Self {
            out,
            clock,
            home,
            depth,
        }
    }

    fn path(&self, path: &Path) -> String {
        tilde(&path.to_string_lossy(), self.home.as_deref())
    }

    fn detail(&self, touch: &Touch) -> Option<String> {
        Some(match touch.change {
            Change::Write { bytes, calls } => {
                let plural = if calls == 1 { "" } else { "s" };
                format!("(+{}, {calls} write{plural})", format_bytes(bytes))
            }
            Change::Mode(mode) => format!("({} → {})", perms(touch.mode), perms(mode)),
            Change::Owner { uid, gid } => {
                let parts: Vec<String> = [
                    uid.map(|u| format!("uid {u}")),
                    gid.map(|g| format!("gid {g}")),
                ]
                .into_iter()
                .flatten()
                .collect();
                format!("(→ {})", parts.join(", "))
            }
            Change::Size(size) => format!("(→ {})", format_bytes(size)),
            Change::Rename { flags, replaced } => {
                if flags & RENAME_EXCHANGE != 0 {
                    "(exchanged)".to_owned()
                } else if replaced {
                    "(replaced existing)".to_owned()
                } else {
                    return None;
                }
            }
            Change::Node(rdev) => format!("({} {})", file_type(touch.mode), dev_string(rdev)),
            Change::None => match touch.op {
                Op::Create | Op::Mkdir => format!("({})", perms(touch.mode)),
                Op::Symlink => format!("(→ {})", touch.target.as_deref()?.display()),
                Op::Link => format!("(= {})", self.path(touch.target.as_deref()?)),
                _ => return None,
            },
        })
    }

    fn proc_line(&self, info: &ProcInfo, cwd_shown: Option<&Path>) -> (String, String) {
        let command = command_line(&info.argv, &info.comm, self.home.as_deref());
        let mut facts = vec![format!("pid {}", info.key.pid)];
        if let Some(exit) = info.exit {
            if exit.ts_ns > 0 {
                facts.push(format!("exited {}", self.clock.local_hms(exit.ts_ns)));
            } else {
                facts.push("exited".to_owned());
            }
        }
        if let Some(cwd) = info.cwd.as_deref().filter(|cwd| Some(*cwd) != cwd_shown) {
            facts.push(format!("cwd {}", self.path(cwd)));
        }
        (command, format!("({})", facts.join(", ")))
    }
}

impl<W: Write> Sink for Human<W> {
    fn touch(&mut self, touch: &Touch, lineage: &Lineage) -> io::Result<()> {
        let path = match &touch.old_path {
            Some(old) => format!("{} → {}", self.path(old), self.path(&touch.path)),
            None => self.path(&touch.path),
        };
        write!(
            self.out,
            "{path}  {}  {}",
            touch.op.verb(),
            self.clock.local_hms(touch.ts_ns)
        )?;
        if let Some(detail) = self.detail(touch) {
            write!(self.out, "  {detail}")?;
        }
        writeln!(self.out)?;

        // (left column, details, annotations) per displayed process, leaf first.
        let mut rows: Vec<(String, String, Vec<String>)> = Vec::new();
        let chain = &lineage.chain;
        if chain.is_empty() {
            rows.push((
                touch.actor.comm.clone(),
                format!("(pid {}, not tracked)", touch.actor.tgid),
                Vec::new(),
            ));
        } else {
            let via = lineage.origin.as_ref().map(|o| o.via);
            let via_at = via.and_then(|via| chain.iter().position(|info| info.key == via));
            let shown = chain
                .len()
                .min(self.depth + 1)
                .max(via_at.map_or(0, |at| at + 1));
            let mut cwd_below: Option<&Path> = None;
            for (level, info) in chain[..shown].iter().enumerate() {
                let (command, facts) = self.proc_line(info, cwd_below);
                cwd_below = info.cwd.as_deref();
                let mut notes = Vec::new();
                if level == 0 {
                    let ctx = &lineage.context;
                    let mut parts = Vec::new();
                    if let Some(tmux) = &ctx.tmux {
                        parts.push(format!("tmux {}", tmux.pane));
                    }
                    if let Some(unit) = &ctx.unit {
                        parts.push(format!("unit {}", unit.name));
                    }
                    if let Some(container) = &ctx.container {
                        parts.push(format!(
                            "{} {}",
                            container.runtime.as_str(),
                            container.short_id()
                        ));
                    }
                    if !parts.is_empty() {
                        notes.push(format!("[{}]", parts.join(" · ")));
                    }
                }
                if let Some(origin) = lineage.origin.as_ref().filter(|o| o.via == info.key) {
                    let mut label = kind_label(origin.kind).to_owned();
                    let mut what = Vec::new();
                    if let Some(phase) = &origin.phase {
                        what.push(phase.to_string());
                    }
                    match (&origin.package, &origin.version) {
                        (Some(p), Some(v)) => what.push(format!("{p}@{v}")),
                        (Some(p), None) => what.push(p.to_string()),
                        _ => {}
                    }
                    if !what.is_empty() {
                        label.push_str(": ");
                        label.push_str(&what.join(" "));
                    }
                    notes.push(format!("[{label} · {}]", confidence_id(origin.confidence)));
                }
                rows.push((command, facts, notes));
            }
            let hidden = chain.len() - shown;
            if hidden > 0 {
                let plural = if hidden == 1 { "" } else { "s" };
                rows.push((
                    format!("… {hidden} more ancestor{plural}"),
                    String::new(),
                    Vec::new(),
                ));
            }
        }
        let lefts: Vec<String> = rows
            .iter()
            .enumerate()
            .map(|(level, (command, _, _))| format!("{}└─ {command}", " ".repeat(2 + 3 * level)))
            .collect();
        let column = lefts
            .iter()
            .map(|l| l.chars().count())
            .max()
            .unwrap_or(0)
            .min(MAX_COLUMN)
            + 2;
        for (left, (_, facts, notes)) in lefts.iter().zip(&rows) {
            let mut line = left.clone();
            if !facts.is_empty() {
                let pad = column.saturating_sub(left.chars().count()).max(2);
                line.push_str(&" ".repeat(pad));
                line.push_str(facts);
            }
            for note in notes {
                line.push_str("   ");
                line.push_str(note);
            }
            writeln!(self.out, "{line}")?;
        }
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }
}

#[derive(Serialize)]
struct FileJson {
    dev: String,
    ino: u64,
    mode: String,
}

#[derive(Serialize)]
struct ProcJson {
    pid: u32,
    comm: String,
    exe: Option<String>,
    argv: Vec<String>,
    argv_truncated: bool,
    cwd: Option<String>,
    uid: Option<u32>,
    exited: Option<bool>,
    exit_ts: Option<String>,
}

#[derive(Serialize, Default)]
struct ChangeJson {
    #[serde(skip_serializing_if = "Option::is_none")]
    mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    old_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    uid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    gid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rdev: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    exchange: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    noreplace: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    replaced: Option<bool>,
}

#[derive(Serialize)]
struct ContextJson {
    unit: Option<String>,
    container: Option<String>,
    tmux: Option<String>,
    cgroup: Option<String>,
}

#[derive(Serialize)]
struct OriginJson {
    kind: &'static str,
    package: Option<String>,
    version: Option<String>,
    phase: Option<String>,
    confidence: &'static str,
    via_pid: u32,
    evidence: Vec<String>,
}

#[derive(Serialize)]
struct TouchJson<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    ts: String,
    op: &'static str,
    path: String,
    old_path: Option<String>,
    target: Option<String>,
    truncated: bool,
    bytes: Option<u64>,
    calls: Option<u64>,
    file: FileJson,
    change: Option<ChangeJson>,
    tid: u32,
    proc: ProcJson,
    ancestry: &'a [ProcJson],
    ancestry_complete: bool,
    context: ContextJson,
    origin: Option<OriginJson>,
}

/// NDJSON: one `{"type":"touch",...}` object per line.
#[derive(Debug)]
pub struct Json<W> {
    out: W,
    clock: Clock,
}

impl<W: Write> Json<W> {
    /// Writes to `out`.
    pub fn new(out: W, clock: Clock) -> Self {
        Self { out, clock }
    }

    fn proc(&self, info: &ProcInfo) -> ProcJson {
        let text = |p: &Path| p.to_string_lossy().into_owned();
        ProcJson {
            pid: info.key.pid,
            comm: info.comm.to_string(),
            exe: info.exe.as_deref().map(text),
            argv: info
                .argv
                .iter()
                .map(|a| a.to_string_lossy().into_owned())
                .collect(),
            argv_truncated: info.argv_truncated,
            cwd: info.cwd.as_deref().map(text),
            uid: info.uid,
            exited: Some(info.exit.is_some()),
            exit_ts: info
                .exit
                .filter(|exit| exit.ts_ns > 0)
                .map(|exit| self.clock.rfc3339(exit.ts_ns)),
        }
    }
}

fn change_json(touch: &Touch) -> Option<ChangeJson> {
    let mut c = ChangeJson::default();
    match touch.change {
        Change::None | Change::Write { .. } => return None,
        Change::Mode(mode) => {
            c.mode = Some(perms(mode));
            c.old_mode = Some(perms(touch.mode));
        }
        Change::Owner { uid, gid } => {
            c.uid = uid;
            c.gid = gid;
        }
        Change::Size(size) => c.size = Some(size),
        Change::Rename { flags, replaced } => {
            c.exchange = Some(flags & RENAME_EXCHANGE != 0);
            c.noreplace = Some(flags & RENAME_NOREPLACE != 0);
            c.replaced = Some(replaced);
        }
        Change::Node(rdev) => c.rdev = Some(dev_string(rdev)),
    }
    Some(c)
}

impl<W: Write> Sink for Json<W> {
    fn touch(&mut self, touch: &Touch, lineage: &Lineage) -> io::Result<()> {
        let text = |p: &Path| p.to_string_lossy().into_owned();
        let (bytes, calls) = match touch.change {
            Change::Write { bytes, calls } => (Some(bytes), Some(calls)),
            _ => (None, None),
        };
        let proc = lineage.chain.first().map_or_else(
            || ProcJson {
                pid: touch.actor.tgid,
                comm: touch.actor.comm.clone(),
                exe: None,
                argv: Vec::new(),
                argv_truncated: false,
                cwd: None,
                uid: Some(touch.actor.uid),
                exited: None,
                exit_ts: None,
            },
            |info| self.proc(info),
        );
        let ancestry: Vec<ProcJson> = lineage
            .chain
            .iter()
            .skip(1)
            .map(|info| self.proc(info))
            .collect();
        let ctx = &lineage.context;
        let record = TouchJson {
            kind: "touch",
            ts: self.clock.rfc3339(touch.ts_ns),
            op: touch.op.name(),
            path: text(&touch.path),
            old_path: touch.old_path.as_deref().map(text),
            target: touch.target.as_deref().map(text),
            truncated: touch.truncated,
            bytes,
            calls,
            file: FileJson {
                dev: dev_string(touch.file.dev),
                ino: touch.file.ino,
                mode: format!("{:o}", touch.mode),
            },
            change: change_json(touch),
            tid: touch.actor.tid,
            proc,
            ancestry: &ancestry,
            ancestry_complete: lineage.complete,
            context: ContextJson {
                unit: ctx.unit.as_ref().map(|u| u.name.to_string()),
                container: ctx
                    .container
                    .as_ref()
                    .map(|c| format!("{}:{}", c.runtime.as_str(), c.id)),
                tmux: ctx.tmux.as_ref().map(|t| t.pane.to_string()),
                cgroup: ctx.cgroup.as_ref().map(|c| c.path.to_string()),
            },
            origin: lineage.origin.as_ref().map(|o| OriginJson {
                kind: kind_id(o.kind),
                package: o.package.as_deref().map(str::to_owned),
                version: o.version.as_deref().map(str::to_owned),
                phase: o.phase.as_deref().map(str::to_owned),
                confidence: confidence_id(o.confidence),
                via_pid: o.via.pid,
                evidence: o.evidence.iter().map(ToString::to_string).collect(),
            }),
        };
        serde_json::to_writer(&mut self.out, &record)?;
        writeln!(self.out)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(args: &[&str]) -> Vec<Box<OsStr>> {
        args.iter().map(|a| Box::from(OsStr::new(a))).collect()
    }

    #[test]
    fn interpreter_running_an_installed_tool_collapses_to_the_tool() {
        let home = Some(Path::new("/home/u"));
        assert_eq!(
            command_line(&argv(&["node", "/usr/bin/npm", "install"]), "node", home),
            "npm install"
        );
        assert_eq!(
            command_line(
                &argv(&[
                    "/usr/bin/node",
                    "/usr/lib/node_modules/npm/bin/npm-cli.js",
                    "run",
                    "build"
                ]),
                "node",
                home
            ),
            "npm run build"
        );
        assert_eq!(
            command_line(
                &argv(&["python3.12", "/usr/bin/pip", "install", "x"]),
                "python3",
                home
            ),
            "pip install x"
        );
        // A relative script is the program the user named: keep it.
        assert_eq!(
            command_line(&argv(&["node", "install.js"]), "node", home),
            "node install.js"
        );
        assert_eq!(
            command_line(&argv(&["/usr/bin/make", "-j8"]), "make", home),
            "make -j8"
        );
    }

    #[test]
    fn arguments_are_quoted_and_home_shortened() {
        let home = Some(Path::new("/home/u"));
        assert_eq!(
            command_line(&argv(&["sh", "-c", "echo hi > /home/u/x"]), "sh", home),
            "sh -c 'echo hi > /home/u/x'"
        );
        assert_eq!(
            command_line(&argv(&["cp", "/home/u/a", "/tmp/b"]), "cp", home),
            "cp ~/a /tmp/b"
        );
        assert_eq!(
            command_line(&argv(&["echo", "it's", ""]), "echo", home),
            r"echo 'it'\''s' ''"
        );
        assert_eq!(command_line(&[], "kworker/0:1", home), "kworker/0:1");
        let long = "x".repeat(100);
        assert_eq!(
            command_line(&argv(&["echo", &long]), "echo", home)
                .chars()
                .count(),
            MAX_COMMAND
        );
    }

    #[test]
    fn byte_counts_use_binary_units() {
        assert_eq!(format_bytes(118), "118 B");
        assert_eq!(format_bytes(1024), "1.0 KiB");
        assert_eq!(format_bytes(16 << 10), "16.0 KiB");
        assert_eq!(format_bytes(3 << 29), "1.5 GiB");
    }

    #[test]
    fn tilde_only_replaces_a_whole_leading_component() {
        let home = Some(Path::new("/home/u"));
        assert_eq!(tilde("/home/u", home), "~");
        assert_eq!(tilde("/home/u/x", home), "~/x");
        assert_eq!(tilde("/home/user2/x", home), "/home/user2/x");
        assert_eq!(tilde("/home/u/x", Some(Path::new("/"))), "/home/u/x");
    }
}
