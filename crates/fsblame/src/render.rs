//! Output sinks for [`Line`]s: the human tree view and NDJSON.

use std::{
    borrow::Cow,
    fmt::Write as _,
    io::{self, Write},
    path::{Path, PathBuf},
};

use crate::{
    ops::Op,
    report::{
        ChangeReport, Group, GroupReport, Line, LineEncoder, LossReason, LostReport, Perms,
        ProcReport, Sink, SummaryReport,
    },
};

const S_IFMT: u32 = 0o170_000;
/// Widest command shown before it is cut with `…`.
const MAX_COMMAND: usize = 60;
/// Column cap for aligning the process details.
const MAX_COLUMN: usize = 56;
/// Widest group label in the summary table.
const MAX_GROUP: usize = 40;
/// Widest list of first paths in the summary table.
const MAX_FIRST_PATHS: usize = 100;

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

/// Whether a terminal could act on `c` instead of showing it: C0 controls, DEL, C1
/// controls, the Unicode bidirectional controls, and the line and paragraph separators.
fn is_control(c: char) -> bool {
    matches!(
        c,
        '\0'..='\x1f'
            | '\x7f'..='\u{9f}'
            | '\u{61c}'
            | '\u{200e}'
            | '\u{200f}'
            | '\u{2028}'..='\u{202e}'
            | '\u{2066}'..='\u{2069}'
    )
}

/// Appends `c` to `out`, as an escape if it [`is_control`]: `\n`, `\r` and `\t` by name,
/// other ASCII controls as `\x1b`, the rest as `\u{9b}`, or as `\u009b` in bash's ANSI-C
/// form if `ansi_c`.
fn push_escaped(out: &mut String, c: char, ansi_c: bool) {
    match c {
        '\n' => out.push_str(r"\n"),
        '\r' => out.push_str(r"\r"),
        '\t' => out.push_str(r"\t"),
        // Writing to a `String` cannot fail.
        '\0'..='\x1f' | '\x7f' => {
            let _ = write!(out, r"\x{:02x}", u32::from(c));
        }
        c if is_control(c) && ansi_c => {
            let _ = write!(out, r"\u{:04x}", u32::from(c));
        }
        c if is_control(c) => {
            let _ = write!(out, r"\u{{{:x}}}", u32::from(c));
        }
        c => out.push(c),
    }
}

/// `text` safe to print on a terminal: every character a terminal could act on
/// ([`is_control`]) is shown as an escape instead ([`push_escaped`]). Borrows `text` when it
/// has none. Backslashes are not escaped, so the escapes are for reading only; NDJSON
/// keeps the exact text.
fn escape(text: &str) -> Cow<'_, str> {
    let Some(at) = text.find(is_control) else {
        return Cow::Borrowed(text);
    };
    let mut out = String::with_capacity(text.len() + 8);
    out.push_str(&text[..at]);
    for c in text[at..].chars() {
        push_escaped(&mut out, c, false);
    }
    Cow::Owned(out)
}

/// [`escape`] for owned text, keeping its allocation when nothing needs escaping.
fn escape_owned(text: String) -> String {
    match escape(&text) {
        Cow::Owned(escaped) => escaped,
        Cow::Borrowed(_) => text,
    }
}

/// Quotes an argument for display when a shell would need it: as `'…'`, or, if it holds
/// characters a terminal could act on ([`is_control`]), with bash's ANSI-C quoting
/// `$'…'`, where they are `\n`, `\r`, `\t`, `\xHH` or `\uHHHH` escapes. Either way a shell
/// reads the quoted text back as the same word.
fn quote(arg: &str) -> Cow<'_, str> {
    let safe = |c: char| c.is_alphanumeric() || "-_./=:,+@%^~".contains(c);
    if !arg.is_empty() && arg.chars().all(safe) {
        return Cow::Borrowed(arg);
    }
    if !arg.contains(is_control) {
        return Cow::Owned(format!("'{}'", arg.replace('\'', r"'\''")));
    }
    let mut out = String::with_capacity(arg.len() + 8);
    out.push_str("$'");
    for c in arg.chars() {
        if matches!(c, '\\' | '\'') {
            out.push('\\');
        }
        push_escaped(&mut out, c, true);
    }
    out.push('\'');
    Cow::Owned(out)
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
/// `interpreter /abs/path/to/tool args` collapsed to `tool args`. Terminal controls in the
/// program name show as escapes such as `\x1b`; arguments holding them are quoted as
/// `$'…'`, so the line holds none.
pub fn command_line<S: AsRef<str>>(argv: &[S], comm: &str, home: Option<&Path>) -> String {
    let Some(first) = argv.first() else {
        return escape(comm).into_owned();
    };
    let program = basename(first.as_ref());
    let (head, rest) = match argv.get(1).map(AsRef::as_ref) {
        Some(script) if is_interpreter(program) && script.starts_with('/') => {
            (script_name(script), &argv[2..])
        }
        _ => (program, &argv[1..]),
    };
    let mut line = escape(head).into_owned();
    for arg in rest {
        line.push(' ');
        line.push_str(&quote(&tilde(arg.as_ref(), home)));
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

/// `1 change`, `2 changes`.
pub(crate) fn counted(n: u64, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
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

/// Display name of a build step kind, by its JSON id.
fn kind_label(kind: &str) -> &str {
    match kind {
        "npm-lifecycle" => "npm lifecycle",
        "pnpm-lifecycle" => "pnpm lifecycle",
        "yarn-lifecycle" => "yarn lifecycle",
        "bun-lifecycle" => "bun lifecycle",
        "cargo-build-script" => "cargo build script",
        "pip-build" => "pip build",
        "make" => "make",
        // procctx may learn new kinds; label them generically until fsblame names them.
        _ => "build step",
    }
}

/// `npm lifecycle: postinstall demo@1.0.0`, with the phase, package and version escaped.
fn origin_label(
    kind: &str,
    phase: Option<&str>,
    package: Option<&str>,
    version: Option<&str>,
) -> String {
    let mut label = kind_label(kind).to_owned();
    let mut separator = ": ";
    if let Some(phase) = phase {
        label.push_str(separator);
        label.push_str(&escape(phase));
        separator = " ";
    }
    if let Some(package) = package {
        label.push_str(separator);
        label.push_str(&escape(package));
        if let Some(version) = version {
            label.push('@');
            label.push_str(&escape(version));
        }
    }
    label
}

/// ANSI SGR sequences of the human view, all empty when color is off.
#[derive(Clone, Copy, Debug)]
struct Palette {
    on: bool,
}

impl Palette {
    const fn sgr(self, code: &'static str) -> &'static str {
        if self.on { code } else { "" }
    }

    const fn bold(self) -> &'static str {
        self.sgr("\x1b[1m")
    }

    const fn dim(self) -> &'static str {
        self.sgr("\x1b[2m")
    }

    const fn reset(self) -> &'static str {
        self.sgr("\x1b[0m")
    }

    /// The color of an op's class: creations green, removals red, writes yellow, renames
    /// cyan, attribute changes magenta.
    const fn op(self, op: Op) -> &'static str {
        self.sgr(match op {
            Op::Create | Op::Mkdir | Op::Link | Op::Symlink | Op::Mknod => "\x1b[32m",
            Op::Unlink | Op::Rmdir => "\x1b[31m",
            Op::Write => "\x1b[33m",
            Op::Rename => "\x1b[36m",
            Op::Chmod | Op::Chown | Op::Truncate | Op::Utimes | Op::Setattr => "\x1b[35m",
        })
    }
}

/// The aligned tree view. Changes and the summary go to `out`; losses are warnings on
/// stderr.
#[derive(Debug)]
pub struct Human<W> {
    out: W,
    home: Option<PathBuf>,
    depth: usize,
    palette: Palette,
}

impl<W: Write> Human<W> {
    /// Writes to `out`, shortening paths below `home`, showing `depth` ancestors, with ANSI
    /// colors if `color`.
    pub fn new(out: W, home: Option<PathBuf>, depth: usize, color: bool) -> Self {
        Self {
            out,
            home,
            depth,
            palette: Palette { on: color },
        }
    }

    /// `path` as shown: below `home` shortened, terminal controls escaped.
    fn path(&self, path: &str) -> String {
        escape_owned(tilde(path, self.home.as_deref()))
    }

    fn detail(&self, c: &ChangeReport<'_>) -> Option<String> {
        if let (Some(bytes), Some(calls)) = (c.bytes, c.calls) {
            let plural = if calls == 1 { "" } else { "s" };
            return Some(format!("(+{}, {calls} write{plural})", format_bytes(bytes)));
        }
        let d = c.change.unwrap_or_default();
        if let Some(via) = d.mapped {
            return Some(format!("(shared writable mapping, {})", via.name()));
        }
        if let Some(mode) = d.mode {
            let old = d.old_mode.unwrap_or(Perms(c.file.mode.0));
            return Some(format!("({old} → {mode})"));
        }
        if d.uid.is_some() || d.gid.is_some() {
            let parts: Vec<String> = [
                d.uid.map(|u| format!("uid {u}")),
                d.gid.map(|g| format!("gid {g}")),
            ]
            .into_iter()
            .flatten()
            .collect();
            return Some(format!("(→ {})", parts.join(", ")));
        }
        if let Some(size) = d.size {
            return Some(format!("(→ {})", format_bytes(size)));
        }
        if let Some(rdev) = d.rdev {
            return Some(format!("({} {rdev})", file_type(c.file.mode.0)));
        }
        if d.exchange == Some(true) {
            return Some("(exchanged)".to_owned());
        }
        if d.replaced == Some(true) {
            return Some("(replaced existing)".to_owned());
        }
        match c.op {
            Op::Create | Op::Mkdir => Some(format!("({})", Perms(c.file.mode.0))),
            Op::Symlink => Some(format!("(→ {})", escape(c.target.as_deref()?))),
            Op::Link => Some(format!("(= {})", self.path(c.target.as_deref()?))),
            _ => None,
        }
    }

    fn proc_line(
        &self,
        info: &ProcReport<'_>,
        ns_pid: Option<u32>,
        cwd_shown: Option<&str>,
    ) -> (String, String) {
        let command = command_line(&info.argv, &info.comm, self.home.as_deref());
        let mut facts = vec![format!("pid {}", info.pid)];
        if let Some(ns_pid) = ns_pid {
            facts.push(format!("ns pid {ns_pid}"));
        }
        if info.exited == Some(true) {
            facts.push(info.exit_ts.map_or_else(
                || "exited".to_owned(),
                |ts| format!("exited {}", ts.local_hms()),
            ));
        }
        if let Some(cwd) = info.cwd.as_deref().filter(|cwd| Some(*cwd) != cwd_shown) {
            facts.push(format!("cwd {}", self.path(cwd)));
        }
        (command, format!("({})", facts.join(", ")))
    }

    /// The path header plus the indented ancestry tree and its tags.
    // One linear renderer: splitting it would scatter the row state without clarifying it.
    #[allow(clippy::too_many_lines)]
    fn touch(&mut self, c: &ChangeReport<'_>) -> io::Result<()> {
        let p = self.palette;
        let path = match &c.old_path {
            Some(old) => format!("{} → {}", self.path(old), self.path(&c.path)),
            None => self.path(&c.path),
        };
        write!(
            self.out,
            "{}{path}{}  {}{}{}  {}{}{}",
            p.bold(),
            p.reset(),
            p.op(c.op),
            c.op.verb(),
            p.reset(),
            p.dim(),
            c.ts.local_hms(),
            p.reset()
        )?;
        if let Some(detail) = self.detail(c) {
            write!(self.out, "  {detail}")?;
        }
        writeln!(self.out)?;

        // (left column, details, annotations) per displayed process, leaf first.
        let mut rows: Vec<(String, String, Vec<String>)> = Vec::new();
        if c.proc.tracked() {
            let via_at = c
                .origin
                .as_ref()
                .and_then(|o| c.chain().position(|info| info.pid == o.via_pid));
            let shown = (1 + c.ancestry.len())
                .min(self.depth + 1)
                .max(via_at.map_or(0, |at| at + 1));
            let mut cwd_below: Option<&str> = None;
            for (level, info) in c.chain().take(shown).enumerate() {
                let ns_pid = if level == 0 { c.ns_pid } else { None };
                let (command, facts) = self.proc_line(info, ns_pid, cwd_below);
                cwd_below = info.cwd.as_deref();
                let mut notes = Vec::new();
                if level == 0 {
                    let ctx = &c.context;
                    let mut parts = Vec::new();
                    if let Some(tmux) = &ctx.tmux {
                        parts.push(format!("tmux {}", escape(tmux)));
                    }
                    if let Some(unit) = &ctx.unit {
                        parts.push(format!("unit {}", escape(unit)));
                    }
                    if let Some(container) = &ctx.container {
                        parts.push(format!(
                            "{} {}",
                            escape(&container.runtime),
                            escape(container.short_id())
                        ));
                    }
                    if !parts.is_empty() {
                        notes.push(format!("[{}]", parts.join(" · ")));
                    }
                }
                if let Some(origin) = c.origin.as_ref().filter(|_| via_at == Some(level)) {
                    let label = origin_label(
                        &origin.kind,
                        origin.phase.as_deref(),
                        origin.package.as_deref(),
                        origin.version.as_deref(),
                    );
                    notes.push(format!("[{label} · {}]", escape(&origin.confidence)));
                }
                rows.push((command, facts, notes));
            }
            let hidden = 1 + c.ancestry.len() - shown;
            if hidden > 0 {
                let plural = if hidden == 1 { "" } else { "s" };
                rows.push((
                    format!("… {hidden} more ancestor{plural}"),
                    String::new(),
                    Vec::new(),
                ));
            }
        } else {
            let ns = c
                .ns_pid
                .map(|n| format!(", ns pid {n}"))
                .unwrap_or_default();
            rows.push((
                escape(&c.proc.comm).into_owned(),
                format!("(pid {}{ns}, not tracked)", c.proc.pid),
                Vec::new(),
            ));
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
        for (level, (left, (_, facts, notes))) in lefts.iter().zip(&rows).enumerate() {
            // Ancestor lines are dim as a whole; on the actor's line only its facts are.
            let (line_dim, facts_dim) = if level == 0 {
                ("", p.dim())
            } else {
                (p.dim(), "")
            };
            let mut line = format!("{line_dim}{left}");
            if !facts.is_empty() {
                let pad = column.saturating_sub(left.chars().count()).max(2);
                line.push_str(&" ".repeat(pad));
                line.push_str(facts_dim);
                line.push_str(facts);
                if level == 0 {
                    line.push_str(p.reset());
                }
            }
            for note in notes {
                line.push_str("   ");
                line.push_str(note);
            }
            if level > 0 {
                line.push_str(p.reset());
            }
            writeln!(self.out, "{line}")?;
        }
        Ok(())
    }

    /// A loss, as a warning on stderr.
    fn lost(&mut self, lost: &LostReport) -> io::Result<()> {
        // What was printed before the loss stays before the warning on a shared terminal.
        self.out.flush()?;
        let what = match lost.reason {
            LossReason::RingFull => format!(
                "{} lost (ring buffer full; a larger --ring-size helps)",
                counted(lost.count, "kernel record", "kernel records")
            ),
            LossReason::WriteEvicted => format!(
                "latest byte counts of {} lost (kernel write table or ring buffer full)",
                counted(lost.count, "open file", "open files")
            ),
            LossReason::TrackFull => format!(
                "changes of {} lost (tracked-process table full)",
                counted(lost.count, "new process", "new processes")
            ),
            LossReason::Unread => format!(
                "{} lost (still unread when fsblame stopped)",
                counted(lost.count, "kernel record", "kernel records")
            ),
            LossReason::Skipped => format!(
                "{} of fsblame's hooks skipped by the kernel (the hook was already running on \
                 that CPU; changes may be missing)",
                counted(lost.count, "run", "runs")
            ),
            LossReason::Other => format!(
                "{} lost (a reason this version of fsblame does not know)",
                counted(lost.count, "item", "items")
            ),
        };
        writeln!(
            io::stderr().lock(),
            "fsblame: warning: {what} at {}",
            lost.ts.local_hms()
        )
    }

    /// One row of the summary table: group, changes, paths, ops, first paths.
    fn group_row(&self, g: &GroupReport<'_>) -> [String; 5] {
        let label = match &g.group {
            Group::Origin(k) => origin_label(
                &k.kind,
                k.phase.as_deref(),
                k.package.as_deref(),
                k.version.as_deref(),
            ),
            Group::Comm(comm) => escape(comm).into_owned(),
            Group::Other => "(other)".to_owned(),
        };
        let paths = if g.paths_untracked > 0 {
            format!("{}+", g.paths)
        } else {
            g.paths.to_string()
        };
        let ops: Vec<String> = g
            .ops
            .iter()
            .map(|(op, n)| format!("{} {n}", op.name()))
            .collect();
        let mut first: Vec<String> = g.first_paths.iter().map(|p| self.path(p)).collect();
        if g.paths_untracked > 0 || g.paths > first.len() as u64 {
            first.push("…".to_owned());
        }
        [
            ellipsize(label, MAX_GROUP),
            g.changes.to_string(),
            paths,
            ops.join(", "),
            ellipsize(first.join(", "), MAX_FIRST_PATHS),
        ]
    }

    /// The summary as an aligned table.
    fn summary(&mut self, s: &SummaryReport<'_>) -> io::Result<()> {
        let p = self.palette;
        writeln!(
            self.out,
            "\n{}summary{}: {}",
            p.bold(),
            p.reset(),
            counted(s.changes, "change", "changes")
        )?;
        let header = ["GROUP", "CHANGES", "PATHS", "OPS", "FIRST PATHS"].map(str::to_owned);
        let rows: Vec<[String; 5]> = s.groups.iter().map(|g| self.group_row(g)).collect();
        let mut widths = [0; 5];
        for row in std::iter::once(&header).chain(&rows) {
            for (width, cell) in widths.iter_mut().zip(row) {
                *width = (*width).max(cell.chars().count());
            }
        }
        if !rows.is_empty() {
            for (at, row) in std::iter::once(&header).chain(&rows).enumerate() {
                let line = format!(
                    "  {:<w0$}  {:>w1$}  {:>w2$}  {:<w3$}  {}",
                    row[0],
                    row[1],
                    row[2],
                    row[3],
                    row[4],
                    w0 = widths[0],
                    w1 = widths[1],
                    w2 = widths[2],
                    w3 = widths[3],
                );
                let (on, off) = if at == 0 {
                    (p.dim(), p.reset())
                } else {
                    ("", "")
                };
                writeln!(self.out, "{on}{}{off}", line.trim_end())?;
            }
        }
        if !s.lost.is_empty() {
            let mut parts = Vec::new();
            if s.lost.ring_full > 0 {
                parts.push(format!(
                    "{} (ring buffer full)",
                    counted(s.lost.ring_full, "kernel record", "kernel records")
                ));
            }
            if s.lost.write_evicted > 0 {
                parts.push(format!(
                    "latest byte counts of {} (kernel write table or ring buffer full)",
                    counted(s.lost.write_evicted, "open file", "open files")
                ));
            }
            if s.lost.track_full > 0 {
                parts.push(format!(
                    "changes of {} (tracked-process table full)",
                    counted(s.lost.track_full, "new process", "new processes")
                ));
            }
            if s.lost.unread > 0 {
                parts.push(format!(
                    "{} (unread at the stop)",
                    counted(s.lost.unread, "kernel record", "kernel records")
                ));
            }
            if s.lost.skipped > 0 {
                parts.push(format!(
                    "{} (skipped by the kernel: already running on that CPU)",
                    counted(s.lost.skipped, "hook run", "hook runs")
                ));
            }
            writeln!(self.out, "  lost: {}", parts.join(", "))?;
        }
        Ok(())
    }
}

impl<W: Write> Sink for Human<W> {
    fn line(&mut self, line: &Line<'_>) -> io::Result<()> {
        match line {
            Line::Touch(change) => self.touch(change),
            Line::Lost(lost) => self.lost(lost),
            Line::Summary(summary) => self.summary(summary),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }
}

/// NDJSON: one JSON object per line.
#[derive(Debug)]
pub struct Json<W> {
    out: W,
    encoder: LineEncoder,
}

impl<W: Write> Json<W> {
    /// Writes to `out`.
    pub fn new(out: W) -> Self {
        Self {
            out,
            encoder: LineEncoder::default(),
        }
    }
}

impl<W: Write> Sink for Json<W> {
    fn line(&mut self, line: &Line<'_>) -> io::Result<()> {
        let line = self.encoder.encode(line)?;
        self.out.write_all(line)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use super::*;
    use crate::{
        engine::MapVia,
        report::{ChangeDetail, tests::chmod},
    };

    #[test]
    fn interpreter_running_an_installed_tool_collapses_to_the_tool() {
        let home = Some(Path::new("/home/u"));
        assert_eq!(
            command_line(&["node", "/usr/bin/npm", "install"], "node", home),
            "npm install"
        );
        assert_eq!(
            command_line(
                &[
                    "/usr/bin/node",
                    "/usr/lib/node_modules/npm/bin/npm-cli.js",
                    "run",
                    "build"
                ],
                "node",
                home
            ),
            "npm run build"
        );
        assert_eq!(
            command_line(
                &["python3.12", "/usr/bin/pip", "install", "x"],
                "python3",
                home
            ),
            "pip install x"
        );
        // A relative script is the program the user named: keep it.
        assert_eq!(
            command_line(&["node", "install.js"], "node", home),
            "node install.js"
        );
        assert_eq!(
            command_line(&["/usr/bin/make", "-j8"], "make", home),
            "make -j8"
        );
    }

    #[test]
    fn arguments_are_quoted_and_home_shortened() {
        let home = Some(Path::new("/home/u"));
        assert_eq!(
            command_line(&["sh", "-c", "echo hi > /home/u/x"], "sh", home),
            "sh -c 'echo hi > /home/u/x'"
        );
        assert_eq!(
            command_line(&["cp", "/home/u/a", "/tmp/b"], "cp", home),
            "cp ~/a /tmp/b"
        );
        assert_eq!(
            command_line(&["echo", "it's", ""], "echo", home),
            r"echo 'it'\''s' ''"
        );
        assert_eq!(
            command_line::<&str>(&[], "kworker/0:1", home),
            "kworker/0:1"
        );
        let long = "x".repeat(100);
        assert_eq!(
            command_line(&["echo", &long], "echo", home).chars().count(),
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

    fn human(line: &Line<'_>, color: bool) -> String {
        let mut out = Vec::new();
        Human::new(&mut out, Some(PathBuf::from("/home/u")), 4, color)
            .line(line)
            .unwrap();
        String::from_utf8(out).unwrap()
    }

    /// `text` without ANSI SGR sequences.
    fn plain(text: &str) -> String {
        let mut out = String::new();
        let mut rest = text;
        while let Some(at) = rest.find('\x1b') {
            out.push_str(&rest[..at]);
            rest = &rest[at + rest[at..].find('m').unwrap() + 1..];
        }
        out.push_str(rest);
        out
    }

    #[test]
    fn replayed_json_renders_the_same_tree() {
        let mut mapped = chmod();
        mapped.op = Op::Write;
        mapped.change = Some(ChangeDetail {
            mapped: Some(MapVia::Mmap),
            ..ChangeDetail::default()
        });
        for change in [chmod(), mapped] {
            let line = Line::Touch(change);
            let mut json = Vec::new();
            Json::new(&mut json).line(&line).unwrap();
            let replayed = Line::parse(std::str::from_utf8(&json).unwrap()).unwrap();
            assert_eq!(human(&replayed, false), human(&line, false));
        }
    }

    #[test]
    fn tree_shows_kernel_facts_and_tags() {
        let text = human(&Line::Touch(chmod()), false);
        let mut lines = text.lines();
        let header = lines.next().unwrap();
        assert!(header.starts_with("~/proj/run.sh  chmod  "), "{header}");
        assert!(header.ends_with("  (0644 → 0755)"), "{header}");
        let actor = lines.next().unwrap();
        assert!(actor.starts_with("  └─ chmod +x run.sh"), "{actor}");
        assert!(actor.contains("(pid 4242, ns pid 7, exited "), "{actor}");
        assert!(
            actor.contains("[tmux %3 · unit session-2.scope · docker 3f4e5d6c7b8a]"),
            "{actor}"
        );
        let parent = lines.next().unwrap();
        assert!(parent.starts_with("     └─ npm install"), "{parent}");
        // The parent's cwd is the child's: shown once, on the child.
        assert!(actor.contains(", cwd ~/proj)"), "{actor}");
        assert!(parent.contains("(pid 4000)"), "{parent}");
        assert!(
            parent.ends_with("[npm lifecycle: postinstall demo@1.0.0 · high]"),
            "{parent}"
        );

        let mut mapped = chmod();
        mapped.op = Op::Write;
        mapped.change = Some(ChangeDetail {
            mapped: Some(MapVia::Mprotect),
            ..ChangeDetail::default()
        });
        mapped.proc.exited = None;
        mapped.ancestry.clear();
        let text = human(&Line::Touch(mapped), false);
        let mut lines = text.lines();
        let header = lines.next().unwrap();
        assert!(
            header.ends_with("  (shared writable mapping, mprotect)"),
            "{header}"
        );
        assert!(header.contains("  modified  "), "{header}");
        let actor = lines.next().unwrap();
        assert!(
            actor.ends_with("(pid 4242, ns pid 7, not tracked)"),
            "{actor}"
        );
    }

    #[test]
    fn color_only_adds_sgr_sequences() {
        let line = Line::Touch(chmod());
        let colored = human(&line, true);
        assert!(colored.contains("\x1b[35mchmod\x1b[0m"), "{colored:?}");
        assert_eq!(plain(&colored), human(&line, false));
    }

    #[test]
    fn summary_table_aligns_groups() {
        let mut summary = crate::report::Summary::new();
        let mut vim = chmod();
        vim.origin = None;
        vim.proc.comm = Cow::Borrowed("vim");
        summary.add(&vim);
        summary.add(&chmod());
        summary.add(&chmod());
        let report = summary.report(
            crate::report::Timestamp::from_unix_ns(0),
            crate::report::LossTotals {
                ring_full: 3,
                ..Default::default()
            },
        );
        let text = human(&Line::Summary(report), false);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[1], "summary: 3 changes");
        assert!(lines[2].starts_with("  GROUP "), "{text}");
        assert!(
            lines[3].starts_with(
                "  npm lifecycle: postinstall demo@1.0.0        2      1  chmod 2  ~/proj/run.sh"
            ),
            "{text}"
        );
        assert!(lines[4].starts_with("  vim "), "{text}");
        assert_eq!(lines[5], "  lost: 3 kernel records (ring buffer full)");
    }

    /// Asserts that `text` is `lines` lines holding no character a terminal acts on.
    fn assert_inert(text: &str, lines: usize) {
        assert_eq!(text.matches('\n').count(), lines, "{text:?}");
        assert!(text.ends_with('\n'), "{text:?}");
        assert!(
            !text.chars().any(|c| c != '\n' && is_control(c)),
            "{text:?}"
        );
    }

    #[test]
    fn escape_shows_terminal_controls_and_borrows_plain_text() {
        let plain = "/home/u/naïve file's.txt";
        assert!(matches!(escape(plain), Cow::Borrowed(p) if p.as_ptr() == plain.as_ptr()));
        let owned = plain.to_owned();
        let at = owned.as_ptr();
        let kept = escape_owned(owned);
        assert_eq!(kept.as_ptr(), at);
        assert_eq!(
            escape("a\nb\x1b[2K\r\t\x7f\u{9b}\u{202e}\u{2066}\u{200f}c\\n"),
            r"a\nb\x1b[2K\r\t\x7f\u{9b}\u{202e}\u{2066}\u{200f}c\n"
        );
    }

    #[test]
    fn arguments_with_terminal_controls_use_ansi_c_quoting() {
        assert_eq!(quote("\x1b[31mred"), r"$'\x1b[31mred'");
        assert_eq!(quote("it's\\\n"), r"$'it\'s\\\n'");
        assert_eq!(quote("\u{202e}gpj.sh"), r"$'\u202egpj.sh'");
        assert_eq!(quote("a b"), "'a b'");
        assert_eq!(
            command_line(&["\x1bsh", "-c", "\r"], "sh", None),
            r"\x1bsh -c $'\r'"
        );
        assert_eq!(command_line::<&str>(&[], "kw\x1b", None), r"kw\x1b");
    }

    #[test]
    fn hostile_names_render_on_their_own_lines() {
        let mut c = chmod();
        c.op = Op::Rename;
        c.change = None;
        c.path = Cow::Borrowed("/home/u/a\nb\x1b[2K");
        c.old_path = Some(Cow::Borrowed("/home/u/\u{202e}hs.txt"));
        c.proc.argv = ["chmod", "+x", "\x1b[31mrun.sh"].map(Cow::Borrowed).into();
        c.proc.cwd = Some(Cow::Borrowed("/home/u/\rproj"));
        c.context.unit = Some(Cow::Borrowed("evil\n.scope"));
        c.context.tmux = Some(Cow::Borrowed("%3\x07"));
        c.origin.as_mut().unwrap().package = Some(Cow::Borrowed("demo\u{9b}2K"));
        let line = Line::Touch(c);
        let text = human(&line, false);
        assert_inert(&text, 3);
        let mut lines = text.lines();
        let header = lines.next().unwrap();
        assert!(
            header.starts_with(r"~/\u{202e}hs.txt → ~/a\nb\x1b[2K  renamed  "),
            "{header}"
        );
        let actor = lines.next().unwrap();
        assert!(
            actor.starts_with(r"  └─ chmod +x $'\x1b[31mrun.sh'  "),
            "{actor}"
        );
        assert!(actor.contains(r", cwd ~/\rproj)"), "{actor}");
        assert!(
            actor.contains(r"[tmux %3\x07 · unit evil\n.scope · docker "),
            "{actor}"
        );
        let parent = lines.next().unwrap();
        assert!(
            parent.ends_with(r"[npm lifecycle: postinstall demo\u{9b}2K@1.0.0 · high]"),
            "{parent}"
        );
        // The left column is padded to the escaped command's width.
        let facts_at = |l: &str| l.chars().position(|c| c == '(').unwrap();
        assert_eq!(facts_at(actor), facts_at(parent), "{text}");
        let colored = human(&line, true);
        assert_eq!(plain(&colored), text);

        let mut symlink = chmod();
        symlink.op = Op::Symlink;
        symlink.change = None;
        symlink.target = Some(Cow::Borrowed("../x\ny"));
        let text = human(&Line::Touch(symlink), false);
        assert_inert(&text, 3);
        assert!(
            text.lines().next().unwrap().ends_with(r"  (→ ../x\ny)"),
            "{text}"
        );

        let mut untracked = chmod();
        untracked.proc.exited = None;
        untracked.proc.comm = Cow::Borrowed("vim\r");
        untracked.ancestry.clear();
        let text = human(&Line::Touch(untracked), false);
        assert_inert(&text, 2);
        assert!(
            text.lines()
                .nth(1)
                .unwrap()
                .starts_with(r"  └─ vim\r  (pid 4242"),
            "{text}"
        );
    }

    #[test]
    fn summary_aligns_escaped_groups() {
        let mut summary = crate::report::Summary::new();
        let mut vim = chmod();
        vim.origin = None;
        vim.proc.comm = Cow::Borrowed("vim\r\x1b[2K");
        vim.path = Cow::Borrowed("/home/u/a\nb");
        summary.add(&vim);
        let report = summary.report(
            crate::report::Timestamp::from_unix_ns(0),
            crate::report::LossTotals::default(),
        );
        let text = human(&Line::Summary(report), false);
        assert_inert(&text, 4);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(
            lines[2..],
            [
                "  GROUP         CHANGES  PATHS  OPS      FIRST PATHS",
                r"  vim\r\x1b[2K        1      1  chmod 1  ~/a\nb",
            ]
        );
    }
}
