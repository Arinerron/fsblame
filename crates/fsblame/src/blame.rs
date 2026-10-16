//! `fsblame blame`: who changed a path, from the journal `fsblame record` writes.
//!
//! The journal files are read in the order they were started, line by line through one
//! reused buffer. Two cheap checks skip most lines before they are parsed: the timestamp at
//! the start of each line against `--since`/`--until`, and the queried paths, which a
//! matching change holds as the start of a JSON string. Matching changes go to the sinks
//! `watch` writes to, so a recorded change shows as the tree `watch` printed live. Malformed
//! lines, such as the torn last line of a recorder that crashed, are counted and skipped.

use std::{
    collections::VecDeque,
    fs::File,
    io::{self, BufRead as _, BufReader, BufWriter, Write as _},
    path::{Component, Path, PathBuf},
};

use anyhow::anyhow;

use crate::{
    cli::BlameArgs,
    clock,
    fail::Failure,
    filter::{Filter, FilterSpec},
    journal,
    ops::OpSet,
    render::{Human, Json},
    report::{ChangeReport, Line, LossReason, LostReport, Sink},
    watch,
};

/// Read buffer per journal file.
const READ_BUF: usize = 64 << 10;
/// Bytes at the start of a line that hold its timestamp: only `type` and `v` come before.
const TS_WITHIN: usize = 64;
/// Longest timestamp text looked at.
const TS_MAX: usize = 40;
/// How every change line starts.
const TOUCH_START: &str = r#"{"type":"touch","#;

/// Which journal lines a query selects.
#[derive(Debug)]
pub struct Query {
    /// Absolute paths; a change matches if one of its paths equals or lies below one of
    /// them. Empty for every change.
    paths: Vec<String>,
    /// For each path, `"` and the path: how a JSON string of that path or a path below it
    /// starts. `None` if a path would be escaped in JSON; then every line is parsed.
    needles: Option<Vec<String>>,
    /// Earliest time, Unix nanoseconds.
    since: Option<i128>,
    /// Latest time, Unix nanoseconds.
    until: Option<i128>,
    /// Operations.
    ops: OpSet,
    /// The other criteria.
    filter: Filter,
    /// Most changes kept, the most recent ones.
    limit: Option<usize>,
}

impl Query {
    /// The query of `args`, resolving relative paths below `cwd` and times relative to
    /// `now_ns` (Unix nanoseconds).
    pub fn new(args: &BlameArgs, cwd: Option<&Path>, now_ns: i128) -> Result<Self, Failure> {
        let mut paths = Vec::new();
        for path in &args.paths {
            let lexical = match (path.is_absolute(), cwd) {
                (true, _) => lexical(path),
                (false, Some(cwd)) => lexical(&cwd.join(path)),
                (false, None) => {
                    return Err(Failure::Usage(anyhow!(
                        "cannot resolve {} without a current directory",
                        path.display()
                    )));
                }
            };
            // As given, through the real directories that hold it, and, if it is a link, at
            // what it points to: the recorder reports paths without symbolic links.
            let resolved = lexical.canonicalize().ok();
            for form in [Some(physical(&lexical)), resolved, Some(lexical)]
                .into_iter()
                .flatten()
            {
                let text = form.to_string_lossy().into_owned();
                if !paths.contains(&text) {
                    paths.push(text);
                }
            }
        }
        let needles = paths
            .iter()
            .all(|path| path.chars().all(|c| c >= ' ' && c != '"' && c != '\\'))
            .then(|| paths.iter().map(|path| format!("\"{path}")).collect());
        Ok(Self {
            paths,
            needles,
            since: args.since.map(|t| t.unix_ns(now_ns)),
            until: args.until.map(|t| t.unix_ns(now_ns)),
            ops: OpSet::new(&args.filter.op),
            filter: Filter::new(FilterSpec::from(&args.filter)),
            limit: args.limit.map(|n| usize::try_from(n).unwrap_or(usize::MAX)),
        })
    }

    /// Whether `unix_ns` lies in the queried time window.
    fn in_window(&self, unix_ns: i128) -> bool {
        self.since.is_none_or(|since| unix_ns >= since)
            && self.until.is_none_or(|until| unix_ns <= until)
    }

    /// Whether the line `text` may be selected, by its timestamp and, for a change, by the
    /// queried paths, without parsing it.
    fn may_select(&self, text: &str) -> bool {
        if line_ts(text).is_some_and(|ts| !self.in_window(ts)) {
            return false;
        }
        match &self.needles {
            Some(needles) if !needles.is_empty() && text.starts_with(TOUCH_START) => {
                needles.iter().any(|needle| text.contains(needle.as_str()))
            }
            _ => true,
        }
    }

    /// Whether `change` matches.
    fn matches(&self, change: &ChangeReport<'_>) -> bool {
        self.in_window(change.ts.unix_ns())
            && self.ops.contains(change.op)
            && (self.paths.is_empty()
                || [
                    Some(&*change.path),
                    change.old_path.as_deref(),
                    change.target.as_deref(),
                ]
                .into_iter()
                .flatten()
                .any(|path| self.paths.iter().any(|query| covers(query, path))))
            && self.filter.matches(&change.candidate())
    }

    /// The line of the journal text `raw` (one line, with or without its newline) if the
    /// query selects it: a matching change, or a loss or summary in the time window.
    /// `Err(())` for a line that is not a report line. A last line without its newline was
    /// cut short unless it parses, so it skips the checks before parsing.
    fn select(&self, raw: &[u8]) -> Result<Option<Line<'static>>, ()> {
        let (raw, whole) = match raw.strip_suffix(b"\n") {
            Some(line) => (line, true),
            None => (raw, false),
        };
        if raw.iter().all(u8::is_ascii_whitespace) {
            return Ok(None);
        }
        let text = std::str::from_utf8(raw).map_err(drop)?;
        if whole && !self.may_select(text) {
            return Ok(None);
        }
        let line = Line::parse(text).map_err(drop)?;
        let selected = match &line {
            Line::Touch(change) => self.matches(change),
            Line::Lost(lost) => self.in_window(lost.ts.unix_ns()),
            Line::Summary(summary) => self.in_window(summary.ts.unix_ns()),
        };
        Ok(selected.then_some(line))
    }
}

/// The absolute `path` normalised without touching the filesystem: `.` dropped, `..`
/// removing the component before it, repeated and trailing separators removed.
fn lexical(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir => out.push("/"),
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(name) => out.push(name),
        }
    }
    out
}

/// `path` (absolute and lexical) with the symbolic links of its existing ancestor
/// directories resolved, as the recorder saw it; its last component is kept as it is, since
/// a change may concern the link itself. `path` unchanged if no ancestor resolves.
fn physical(path: &Path) -> PathBuf {
    let Some(name) = path.file_name() else {
        return path.to_owned();
    };
    let mut base = path.parent();
    let mut below = Vec::new();
    while let Some(dir) = base {
        if let Ok(real) = dir.canonicalize() {
            let mut out = real;
            out.extend(below.iter().rev());
            out.push(name);
            return out;
        }
        below.extend(dir.file_name());
        base = dir.parent();
    }
    path.to_owned()
}

/// Whether `path` is `query` or lies below it, component-wise.
fn covers(query: &str, path: &str) -> bool {
    path.strip_prefix(query)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('/') || query.ends_with('/'))
}

/// The timestamp of a journal line, read from the `ts` field near its start without parsing
/// the line; `None` if it is not there.
fn line_ts(text: &str) -> Option<i128> {
    const KEY: &str = r#""ts":""#;
    let head = &text.as_bytes()[..text.len().min(TS_WITHIN)];
    let start = head.windows(KEY.len()).position(|w| w == KEY.as_bytes())? + KEY.len();
    let rest = &text.as_bytes()[start..];
    let end = rest.iter().take(TS_MAX).position(|&b| b == b'"')?;
    clock::parse_rfc3339(std::str::from_utf8(&rest[..end]).ok()?)
}

/// `1 kernel record was`, `2 kernel records were`.
fn counted(n: u64, one: &str, many: &str) -> String {
    if n == 1 {
        format!("1 {one} was")
    } else {
        format!("{n} {many} were")
    }
}

/// The note on a loss that overlaps the queried time window.
fn loss_note(lost: &LostReport) -> String {
    let when = lost.ts.local_hms();
    match lost.reason {
        LossReason::RingFull => format!(
            "{} lost around {when}; the history may be incomplete",
            counted(lost.count, "kernel record", "kernel records")
        ),
        LossReason::WriteEvicted => format!(
            "the latest byte counts of {} lost around {when}",
            counted(lost.count, "open file", "open files")
        ),
        LossReason::TrackFull => format!(
            "{} left untracked around {when}; their changes are missing",
            counted(lost.count, "new process", "new processes")
        ),
        LossReason::Unread => format!(
            "{} left unread when recording stopped around {when}; the history may be incomplete",
            counted(lost.count, "kernel record", "kernel records")
        ),
        LossReason::Other => format!(
            "{} lost around {when}, for a reason this version of fsblame does not know; the \
             history may be incomplete",
            counted(lost.count, "item", "items")
        ),
    }
}

/// Where selected lines go: changes to the sink; losses and summaries to the sink as well
/// for NDJSON, else losses as notes on stderr.
struct Output<'s> {
    sink: &'s mut dyn Sink,
    json: bool,
}

impl Output<'_> {
    fn line(&mut self, line: &Line<'_>) -> io::Result<()> {
        match line {
            Line::Touch(_) => self.sink.line(line),
            _ if self.json => self.sink.line(line),
            Line::Lost(lost) => {
                // What was printed before the loss stays before the note on a shared terminal.
                self.sink.flush()?;
                writeln!(io::stderr().lock(), "fsblame: note: {}", loss_note(lost))
            }
            Line::Summary(_) => Ok(()),
        }
    }
}

/// The most recent selected lines: at most `limit` changes, and the losses and summaries
/// from the oldest of them on.
#[derive(Debug)]
struct Latest {
    lines: VecDeque<Line<'static>>,
    changes: usize,
    limit: usize,
}

impl Latest {
    fn new(limit: usize) -> Self {
        Self {
            lines: VecDeque::new(),
            changes: 0,
            limit,
        }
    }

    fn push(&mut self, line: Line<'static>) {
        let change = matches!(line, Line::Touch(_));
        self.lines.push_back(line);
        if !change {
            return;
        }
        self.changes += 1;
        if self.changes > self.limit {
            // Drop up to and including the oldest change, then what precedes the next one.
            while let Some(old) = self.lines.pop_front() {
                if matches!(old, Line::Touch(_)) {
                    break;
                }
            }
            while self
                .lines
                .front()
                .is_some_and(|line| !matches!(line, Line::Touch(_)))
            {
                self.lines.pop_front();
            }
            self.changes -= 1;
        }
    }
}

/// What a search found.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Found {
    /// Changes written.
    pub changes: u64,
    /// Lines that were not report lines and were skipped.
    pub malformed: u64,
}

/// A journal file that cannot be read: exit 4 with a `sudo` hint when it is a permission
/// problem.
fn unreadable(path: &Path, e: &io::Error) -> Failure {
    if e.kind() == io::ErrorKind::PermissionDenied {
        Failure::Privileges(anyhow!(
            "cannot read the journal at {}: {e}; journals are readable by root only, so \
             run fsblame blame with sudo",
            path.display()
        ))
    } else {
        Failure::Runtime(anyhow!(
            "cannot read the journal at {}: {e}",
            path.display()
        ))
    }
}

/// Writes the lines of the journal `files` that `query` selects to `sink`, oldest first;
/// with `json`, losses and summaries too, else losses as notes on stderr. A closed output
/// (broken pipe) ends the search early without an error.
pub fn search(
    query: &Query,
    files: &[PathBuf],
    sink: &mut dyn Sink,
    json: bool,
) -> Result<Found, Failure> {
    let mut out = Output { sink, json };
    let mut found = Found::default();
    let mut latest = query.limit.map(Latest::new);
    let mut raw = Vec::new();
    for path in files {
        let file = match File::open(path) {
            Ok(file) => file,
            // Deleted by the recorder's rotation since it was listed.
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(unreadable(path, &e)),
        };
        let mut reader = BufReader::with_capacity(READ_BUF, file);
        loop {
            raw.clear();
            if reader
                .read_until(b'\n', &mut raw)
                .map_err(|e| unreadable(path, &e))?
                == 0
            {
                break;
            }
            let line = match query.select(&raw) {
                Ok(Some(line)) => line,
                Ok(None) => continue,
                Err(()) => {
                    found.malformed += 1;
                    continue;
                }
            };
            if let Some(latest) = &mut latest {
                latest.push(line);
            } else {
                found.changes += u64::from(matches!(line, Line::Touch(_)));
                if !watch::output_result(out.line(&line))? {
                    return Ok(found);
                }
            }
        }
    }
    for line in latest.iter().flat_map(|latest| &latest.lines) {
        found.changes += u64::from(matches!(line, Line::Touch(_)));
        if !watch::output_result(out.line(line))? {
            return Ok(found);
        }
    }
    watch::output_result(out.sink.flush())?;
    Ok(found)
}

/// `fsblame blame`: the tree view or NDJSON of the recorded changes to the given paths.
pub fn command(args: &BlameArgs) -> Result<(), Failure> {
    let cwd = std::env::current_dir().ok();
    let query = Query::new(args, cwd.as_deref(), journal::now_unix_ns())?;
    let files = journal::files(&args.journal).map_err(|e| {
        if e.kind() == io::ErrorKind::NotFound {
            Failure::Usage(anyhow!(
                "no journal at {}; fsblame record writes one (pass --journal DIR for another)",
                args.journal.display()
            ))
        } else {
            unreadable(&args.journal, &e)
        }
    })?;
    if files.is_empty() {
        eprintln!(
            "fsblame: the journal at {} has no files yet",
            args.journal.display()
        );
        return Ok(());
    }
    let view = &args.view;
    let out = BufWriter::new(io::stdout().lock());
    let found = if view.json {
        search(&query, &files, &mut Json::new(out), true)?
    } else {
        let color = watch::use_color(view.color, &io::stdout());
        let mut sink = Human::new(out, watch::home_dir(), view.depth, color);
        search(&query, &files, &mut sink, false)?
    };
    if found.malformed > 0 {
        eprintln!(
            "fsblame: warning: {} journal lines were not report lines (such as a line cut \
             short by a crash) and were skipped",
            found.malformed
        );
    }
    if found.changes == 0 && !view.json {
        eprintln!("fsblame: no recorded change matches");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{borrow::Cow, fs};

    use clap::Parser as _;

    use super::*;
    use crate::{
        cli::{Cli, Command},
        journal::tests::TestDir,
        ops::Op,
        report::{Timestamp, tests::chmod},
    };

    const T0: i128 = 1_791_986_531_000_000_000;
    const SEC: i128 = 1_000_000_000;

    fn query(args: &[&str]) -> Query {
        let cli = Cli::try_parse_from(["fsblame", "blame"].iter().chain(args)).unwrap();
        let Some(Command::Blame(args)) = cli.command else {
            panic!("not blame");
        };
        Query::new(&args, Some(Path::new("/home/u/proj")), T0 + 3600 * SEC).unwrap()
    }

    fn change(op: Op, path: &str, at_s: i128) -> Line<'static> {
        let mut change = chmod();
        change.op = op;
        change.path = Cow::Owned(path.to_owned());
        change.old_path = None;
        change.target = None;
        change.ts = Timestamp::from_unix_ns(T0 + at_s * SEC);
        Line::Touch(change)
    }

    fn lost(at_s: i128) -> Line<'static> {
        Line::Lost(LostReport {
            v: crate::report::Version,
            ts: Timestamp::from_unix_ns(T0 + at_s * SEC),
            reason: LossReason::RingFull,
            count: 3,
        })
    }

    fn json(line: &Line<'_>) -> String {
        serde_json::to_string(line).unwrap()
    }

    fn selects(query: &Query, line: &Line<'_>) -> bool {
        let selected = query.select((json(line) + "\n").as_bytes()).unwrap();
        assert_eq!(
            query.select(json(line).as_bytes()).unwrap(),
            selected,
            "the checks before parsing change nothing"
        );
        selected.is_some()
    }

    /// Collects lines as parsed back from NDJSON.
    #[derive(Default)]
    struct Collect(Vec<Line<'static>>);

    impl Sink for Collect {
        fn line(&mut self, line: &Line<'_>) -> io::Result<()> {
            self.0.push(Line::parse(&json(line)).unwrap());
            Ok(())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn paths_are_made_absolute_lexically() {
        assert_eq!(lexical(Path::new("/a/./b//c/../d/")), Path::new("/a/b/d"));
        assert_eq!(lexical(Path::new("/../a/..")), Path::new("/"));
        let q = query(&["src/../Cargo.toml", "/nonexistent-fsblame/x/./y"]);
        assert!(q.paths.contains(&"/home/u/proj/Cargo.toml".to_owned()));
        assert!(q.paths.contains(&"/nonexistent-fsblame/x/y".to_owned()));
    }

    #[test]
    fn links_in_the_query_also_match_the_paths_they_lead_to() {
        let dir = TestDir::new("blame-links");
        let real = dir.0.join("real");
        fs::create_dir_all(&real).unwrap();
        std::os::unix::fs::symlink(&real, dir.0.join("link")).unwrap();
        let real = real.canonicalize().unwrap();
        let real = real.to_str().unwrap();
        let link = dir.0.join("link");
        let link = link.to_str().unwrap();
        // A directory through a link: the link and its target.
        let q = query(&[link]);
        assert!(selects(&q, &change(Op::Write, &format!("{real}/x"), 0)));
        assert!(selects(&q, &change(Op::Unlink, link, 0)));
        // A file that no longer exists, below the link.
        let q = query(&[&format!("{link}/gone")]);
        assert!(selects(&q, &change(Op::Write, &format!("{real}/gone"), 0)));
        assert!(!selects(
            &q,
            &change(Op::Write, &format!("{real}/other"), 0)
        ));
    }

    #[test]
    fn a_change_matches_by_any_of_its_paths_at_or_below_the_query() {
        let q = query(&["/w/dir"]);
        assert!(selects(&q, &change(Op::Write, "/w/dir", 0)));
        assert!(selects(&q, &change(Op::Write, "/w/dir/a/b", 0)));
        assert!(!selects(&q, &change(Op::Write, "/w/dirt", 0)));
        assert!(!selects(&q, &change(Op::Write, "/w", 0)));

        let Line::Touch(mut rename) = change(Op::Rename, "/elsewhere/x", 0) else {
            unreachable!()
        };
        rename.old_path = Some(Cow::Borrowed("/w/dir/x"));
        assert!(selects(&q, &Line::Touch(rename.clone())));
        rename.old_path = Some(Cow::Borrowed("/w/dirx"));
        assert!(!selects(&q, &Line::Touch(rename.clone())));
        rename.old_path = None;
        rename.target = Some(Cow::Borrowed("/w/dir"));
        assert!(selects(&q, &Line::Touch(rename)));

        assert!(selects(&query(&["/"]), &change(Op::Write, "/w/x", 0)));
        assert!(selects(&query(&[]), &change(Op::Write, "/w/x", 0)));
    }

    #[test]
    fn paths_that_json_escapes_are_matched_without_the_prefilter() {
        let q = query(&["/w/a\"b"]);
        assert!(q.needles.is_none());
        assert!(selects(&q, &change(Op::Write, "/w/a\"b/c", 0)));
        assert!(!selects(&q, &change(Op::Write, "/w/a", 0)));
    }

    #[test]
    fn ops_filters_and_the_time_window_apply() {
        let q = query(&["--op", "chmod,rename"]);
        assert!(!selects(&q, &change(Op::Write, "/w/x", 0)));
        assert!(selects(&q, &change(Op::Chmod, "/w/x", 0)));
        assert!(!selects(
            &query(&["--ignore-comm", "chmod"]),
            &change(Op::Write, "/w/x", 0)
        ));
        assert!(selects(
            &query(&["--uid", "1000"]),
            &change(Op::Write, "/w/x", 0)
        ));

        // Now is T0 + 1h: --since 30m starts at T0 + 30m.
        let q = query(&["--since", "30m", "--until", "2026-10-14T14:50:11Z"]);
        assert_eq!(q.since, Some(T0 + 1800 * SEC));
        assert_eq!(q.until, Some(T0 + 2880 * SEC));
        assert!(!selects(&q, &change(Op::Write, "/w/x", 1799)));
        assert!(selects(&q, &change(Op::Write, "/w/x", 1800)));
        assert!(selects(&q, &change(Op::Write, "/w/x", 2880)));
        assert!(!selects(&q, &change(Op::Write, "/w/x", 2881)));
        assert!(!selects(&q, &lost(0)));
        assert!(selects(&q, &lost(2000)));
    }

    #[test]
    fn line_timestamps_are_read_without_parsing() {
        let line = json(&change(Op::Write, "/w/x", 5));
        assert_eq!(line_ts(&line), Some(T0 + 5 * SEC));
        assert_eq!(line_ts(&json(&lost(7))), Some(T0 + 7 * SEC));
        assert_eq!(line_ts(r#"{"type":"touch","v":1"#), None);
        assert_eq!(line_ts(r#"{"type":"touch","v":1,"ts":"20"#), None);
    }

    /// Writes `lines` as journal files, one file per inner slice, and searches them.
    fn search_files(
        files: &[&[Line<'_>]],
        torn: &str,
        args: &[&str],
    ) -> (Vec<Line<'static>>, Found) {
        let dir = TestDir::new(&format!("blame-{}", args.join("-").replace('/', "_")));
        fs::create_dir_all(&dir.0).unwrap();
        let mut paths = Vec::new();
        for (i, lines) in files.iter().enumerate() {
            let mut text: String = lines.iter().map(|l| json(l) + "\n").collect();
            if i + 1 == files.len() {
                text.push_str(torn);
            }
            let path = dir.0.join(format!("fsblame-{i}.ndjson"));
            fs::write(&path, text).unwrap();
            paths.push(path);
        }
        let mut sink = Collect::default();
        let found = search(&query(args), &paths, &mut sink, true).unwrap();
        (sink.0, found)
    }

    #[test]
    fn searches_files_in_order_and_skips_torn_lines() {
        let a = change(Op::Write, "/w/a", 1);
        let b = change(Op::Write, "/w/b", 2);
        let c = change(Op::Create, "/w/a", 3);
        let torn = &json(&change(Op::Write, "/w/a", 4))[..40];
        let (lines, found) =
            search_files(&[&[a.clone(), b], &[lost(2), c.clone()]], torn, &["/w/a"]);
        assert_eq!(lines, [a, lost(2), c]);
        assert_eq!(
            found,
            Found {
                changes: 2,
                malformed: 1
            }
        );
    }

    #[test]
    fn limit_keeps_the_most_recent_changes_and_the_losses_among_them() {
        let lines: Vec<Line<'_>> = (0..5)
            .flat_map(|i| [lost(i * 10), change(Op::Write, "/w/a", i * 10 + 1)])
            .collect();
        let (found_lines, found) = search_files(&[&lines[..4], &lines[4..]], "", &["--limit", "2"]);
        assert_eq!(found_lines, lines[7..]);
        assert_eq!(found.changes, 2);
        let (found_lines, _) = search_files(&[&lines], "", &["--limit", "1"]);
        assert_eq!(found_lines, [change(Op::Write, "/w/a", 41)]);
        let (found_lines, _) = search_files(&[&lines], "", &["--limit", "99"]);
        assert_eq!(found_lines, lines);
    }
}
