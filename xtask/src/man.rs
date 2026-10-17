//! `cargo xtask man [DIR]`: fsblame(1) and one fsblame-COMMAND(1) page per subcommand.
//!
//! `clap_mangen` renders each page's title line and option lists from the binary's own clap
//! definition, so they cannot drift from `--help`; the synopses and the command list are
//! derived from it as well. The prose (description, exit status, environment, files, examples)
//! is written here, from README.md and the code it describes.
//!
//! Prose uses two marks: `` `bold` `` for what is typed literally (commands, options, paths)
//! and `{italic}` for placeholders. Everything else is escaped, and the pages are pure ASCII
//! (other characters become `\[uXXXX]`), so `groff -man -ww` renders them without warnings and
//! without a preprocessor for the input encoding.

use std::{
    env,
    ffi::OsString,
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context as _, Result, bail};
use clap::{Arg, CommandFactory as _};
use clap_mangen::{Man, roff::Roff};

use crate::{USAGE, cli, clock::Rfc3339};

/// The version in every page's footer.
const VERSION: &str = env!("CARGO_PKG_VERSION");
/// The project page, with the README.
const REPO: &str = "https://github.com/Arinerron/fsblame";
/// Where bugs are reported.
const ISSUES: &str = "https://github.com/Arinerron/fsblame/issues";
/// Where vulnerabilities are reported, privately.
const ADVISORIES: &str = "https://github.com/Arinerron/fsblame/security/advisories/new";
/// Longest line of a code block: an 80-column terminal shows 71 at its indent.
const CODE_WIDTH: usize = 71;
/// The NDJSON schema.
const JSON_DOC: &str = "https://github.com/Arinerron/fsblame/blob/main/docs/json.md";

/// `cargo xtask man [DIR]`: writes the pages into DIR.
pub fn man(args: &[OsString]) -> Result<bool> {
    let dir = match args {
        [] => env::var_os("CARGO_TARGET_DIR")
            .map_or_else(
                || Path::new(env!("CARGO_MANIFEST_DIR")).join("../target"),
                PathBuf::from,
            )
            .join("man"),
        [dir] => PathBuf::from(dir),
        [_, extra, ..] => bail!("unexpected argument {}\n{USAGE}", extra.display()),
    };
    fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    for (file, text) in pages() {
        let path = dir.join(file);
        fs::write(&path, text).with_context(|| format!("writing {}", path.display()))?;
    }
    println!("{}", dir.display());
    Ok(true)
}

/// Every page: its file name and its roff source.
fn pages() -> Vec<(String, String)> {
    let date = date();
    let mut top = cli::Cli::command().disable_help_subcommand(true);
    top.build();
    let mut pages = vec![("fsblame.1".to_owned(), fsblame(&top, &date))];
    for sub in top.get_subcommands() {
        let name = sub.get_name();
        let mut page = Page::new(sub, &format!("fsblame-{name}"), &date);
        page.name(&format!("fsblame-{name}"), &summary(sub));
        page.synopsis(&[usage(sub)]);
        match name {
            "watch" => watch(&mut page),
            "run" => run(&mut page),
            "record" => record(&mut page),
            "blame" => blame(&mut page),
            "doctor" => doctor(&mut page),
            "completions" => completions(&mut page),
            other => panic!("no man page text for `fsblame {other}`"),
        }
        pages.push((format!("fsblame-{name}.1"), page.out));
    }
    pages
}

/// The date in the page footers, `YYYY-MM-DD`: that of `SOURCE_DATE_EPOCH` when set, for
/// reproducible builds, else today's (UTC).
fn date() -> String {
    let secs = env::var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        });
    let mut date = Rfc3339(i128::from(secs) * 1_000_000_000).to_string();
    date.truncate("YYYY-MM-DD".len());
    date
}

/// A page being written: roff source.
struct Page {
    man: Man,
    out: String,
    /// What every rendering by the roff crate starts with (the definition of the `Aq` string
    /// that apostrophes use); the title line brings it, the later renderings drop it.
    preamble: String,
}

impl Page {
    /// A page of `cmd` titled `title` and dated `date`, with its title line.
    fn new(cmd: &clap::Command, title: &str, date: &str) -> Self {
        let man = Man::new(cmd.clone())
            .title(title.to_ascii_uppercase())
            .section("1")
            .date(date)
            .source(format!("fsblame {VERSION}"))
            .manual("User Commands");
        let mut out = Vec::new();
        man.render_title(&mut out).expect("writing to a Vec");
        let mut page = Self {
            man,
            out: String::from_utf8(out).expect("clap_mangen writes UTF-8"),
            preamble: Roff::new().render(),
        };
        // "fsblame" in running text is never hyphenated (marked-up words are not either).
        page.raw(".hw fsblame");
        page
    }

    /// The NAME section.
    fn name(&mut self, name: &str, summary: &str) {
        self.sh("NAME");
        self.raw(&format!("{} \\- {}", escape(name), escape(summary)));
    }

    /// The SYNOPSIS section, one form per line (marked-up text).
    fn synopsis(&mut self, forms: &[String]) {
        self.sh("SYNOPSIS");
        for (i, form) in forms.iter().enumerate() {
            if i > 0 {
                self.raw(".br");
            }
            self.text(form);
        }
    }

    /// The OPTIONS section, and one section per help heading (such as FILTERS).
    fn options(&mut self) {
        let mut out = Vec::new();
        self.man
            .render_options_section(&mut out)
            .expect("writing to a Vec");
        let out = String::from_utf8(out).expect("clap_mangen writes UTF-8");
        for line in out.strip_prefix(&self.preamble).unwrap_or(&out).lines() {
            self.raw(&bold_quoted(line));
        }
    }

    /// A section heading.
    fn sh(&mut self, title: &str) {
        self.raw(&format!(".SH {}", quote(title)));
    }

    /// A subsection heading.
    fn ss(&mut self, title: &str) {
        self.raw(&format!(".SS {}", quote(title)));
    }

    /// A paragraph.
    fn p(&mut self, text: &str) {
        self.raw(".PP");
        self.text(text);
    }

    /// A tagged paragraph: `term` on its own line, `text` indented below it.
    fn tp(&mut self, term: &str, text: &str) {
        self.raw(".TP");
        self.text(term);
        self.text(text);
    }

    /// A tagged paragraph indented by `indent` ens, so a term that fits shares its line.
    fn tp_indent(&mut self, indent: u8, term: &str, text: &str) {
        self.raw(&format!(".TP {indent}"));
        self.text(term);
        self.text(text);
    }

    /// A bullet item.
    fn bullet(&mut self, text: &str) {
        self.raw(r".IP \(bu 2");
        self.text(text);
    }

    /// Indented lines shown as they are, such as commands or output.
    fn code(&mut self, lines: &[&str]) {
        self.raw(".PP");
        self.raw(".RS 4");
        self.raw(".nf");
        for line in lines {
            assert!(
                line.chars().count() <= CODE_WIDTH,
                "longer than {CODE_WIDTH} characters, wider than an 80-column terminal shows \
                 at that indent: {line:?}"
            );
            self.raw(&escape_line(line));
        }
        self.raw(".fi");
        self.raw(".RE");
    }

    /// An example: what it does, then the command.
    fn example(&mut self, text: &str, lines: &[&str]) {
        self.p(text);
        self.code(lines);
    }

    /// A text line of marked-up text.
    fn text(&mut self, text: &str) {
        self.raw(&markup(text));
    }

    /// A line of roff source.
    fn raw(&mut self, line: &str) {
        self.out.push_str(line);
        self.out.push('\n');
    }
}

/// `text` for a roff text line: `` `bold` `` and `{italic}` set in their fonts, the rest
/// escaped. Marked-up words, such as options, paths and URLs, are never hyphenated. Panics on
/// an unclosed mark: the texts are this file's.
fn markup(text: &str) -> String {
    assert!(!text.contains('\n'), "one line per text: {text:?}");
    let mut out = String::with_capacity(text.len() + 16);
    let mut rest = text;
    while let Some(at) = rest.find(['`', '{']) {
        out.push_str(&escape(&rest[..at]));
        let (close, font) = if rest[at..].starts_with('`') {
            ('`', 'B')
        } else {
            ('}', 'I')
        };
        let inner = &rest[at + 1..];
        let end = inner
            .find(close)
            .unwrap_or_else(|| panic!("unclosed {close:?} in {text:?}"));
        // `\%` keeps a word whole only at its start, which may be before roman text such as
        // the "(" of "(`--quiet`".
        let word_start = out.rfind(' ').map_or(0, |space| space + 1);
        if !out[word_start..].starts_with(r"\%") {
            out.insert_str(word_start, r"\%");
        }
        let words = escape(&inner[..end]).replace(' ', r" \%");
        let _ = write!(out, "\\f{font}{words}\\fR");
        rest = &inner[end + 1..];
    }
    out.push_str(&escape(rest));
    if out.starts_with('.') {
        out.insert_str(0, "\\&");
    }
    out
}

/// A text line of `clap_mangen`'s with the `` `code` `` of the help texts set in bold, as the
/// prose of the pages is, rather than between grave accents.
fn bold_quoted(line: &str) -> String {
    if line.starts_with('.') || !line.matches('`').count().is_multiple_of(2) {
        return line.to_owned();
    }
    let mut out = String::with_capacity(line.len() + 16);
    for (i, part) in line.split('`').enumerate() {
        if i > 0 {
            out.push_str(if i % 2 == 1 { r"\fB" } else { r"\fR" });
        }
        out.push_str(part);
    }
    out
}

/// `line` as a roff text line shown as it is.
fn escape_line(line: &str) -> String {
    let out = escape(line);
    if out.starts_with('.') || out.is_empty() {
        format!("\\&{out}")
    } else {
        out
    }
}

/// `text` with the characters roff would interpret escaped: backslashes, dashes (which
/// should stay minus signs, as in options), apostrophes and grave accents (which would be set
/// as curly quotes), and every non-ASCII character as its Unicode escape.
fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '\\' => out.push_str(r"\e"),
            '-' => out.push_str(r"\-"),
            '\'' => out.push_str(r"\*(Aq"),
            '`' => out.push_str(r"\(ga"),
            c if c.is_ascii() => out.push(c),
            c => {
                let _ = write!(out, "\\[u{:04X}]", u32::from(c));
            }
        }
    }
    out
}

/// A macro argument: quoted if it has spaces.
fn quote(arg: &str) -> String {
    if arg.contains(' ') {
        format!("\"{arg}\"")
    } else {
        arg.to_owned()
    }
}

/// The one-line summary of a subcommand for NAME: its clap `about`, lowercased and without
/// the final period.
fn summary(cmd: &clap::Command) -> String {
    let about = cmd.get_about().map(ToString::to_string).unwrap_or_default();
    let about = about.trim_end_matches('.').replace('`', "");
    let mut chars = about.chars();
    chars.next().map_or_else(String::new, |first| {
        first.to_lowercase().chain(chars).collect()
    })
}

/// The marked-up synopsis of `fsblame NAME`, from its arguments: `[OPTIONS]` when it has any
/// besides `--help` and `--version`, then its positionals.
fn usage(cmd: &clap::Command) -> String {
    let mut form = format!("`fsblame {}`", cmd.get_name());
    let options = cmd.get_arguments().any(|a| {
        !a.is_hide_set()
            && !a.is_positional()
            && !["help", "version"].contains(&a.get_id().as_str())
    });
    if options {
        form.push_str(" [{OPTIONS}]");
    }
    for arg in cmd.get_positionals().filter(|a| !a.is_hide_set()) {
        form.push(' ');
        form.push_str(&positional(arg));
    }
    form
}

/// A positional argument in a synopsis, such as `{PATH}...`, `[{PATH}...]` or `` `--` {CMD}... ``.
fn positional(arg: &Arg) -> String {
    let name = arg.get_value_names().map_or_else(
        || arg.get_id().as_str().to_ascii_uppercase(),
        |names| names.join(" "),
    );
    let many = arg
        .get_num_args()
        .is_some_and(|range| range.max_values() > 1);
    let mut text = format!("{{{name}}}{}", if many { "..." } else { "" });
    if arg.is_last_set() {
        text = format!("`--` {text}");
    }
    if arg.is_required_set() {
        text
    } else {
        format!("[{text}]")
    }
}

/// fsblame(1).
fn fsblame(top: &clap::Command, date: &str) -> String {
    let mut p = Page::new(top, "fsblame", date);
    p.name(
        "fsblame",
        "show which command changed a file, with the processes behind it",
    );
    let watch = top.find_subcommand("watch").expect("fsblame watch");
    let mut forms = vec![usage(watch).replacen("`fsblame watch`", "`fsblame`", 1)];
    forms.extend(top.get_subcommands().map(usage));
    forms.push("`fsblame` `--help` | `--version`".to_owned());
    p.synopsis(&forms);

    main_description(&mut p);

    p.sh("COMMANDS");
    for sub in top.get_subcommands() {
        let name = sub.get_name();
        let about = sub.get_about().map(ToString::to_string).unwrap_or_default();
        let about = about.trim_end_matches('.');
        p.tp_indent(
            14,
            &format!("`{name}`"),
            &format!("{about}. See `fsblame-{name}`(1)."),
        );
    }

    p.sh("OPTIONS");
    p.tp(
        "`-h`, `--help`",
        "Print help; `fsblame` {COMMAND} `--help` prints a command's options.",
    );
    p.tp(
        "`-V`, `--version`",
        "Print the version; `--version` adds the BPF ABI the binary was built for and the exit \
         codes.",
    );
    p.p("The short form `fsblame` {PATH}... takes every option of `fsblame watch`; see `fsblame-watch`(1).");

    privileges(&mut p);

    p.sh("EXIT STATUS");
    exit_codes(
        &mut p,
        "a watch stopped cleanly (Ctrl-C, SIGTERM, SIGHUP, `--duration`, or a \
         closed output pipe), or another command finished.",
    );
    p.p(
        "`fsblame run` exits with the status of the command it ran instead, unless fsblame \
         itself fails; see `fsblame-run`(1). fsblame explains every failure on stderr, in a \
         line that starts with its name.",
    );

    environment_and_files(&mut p);

    caveats_and_examples(&mut p);

    reporting(&mut p);
    p.sh("AUTHORS");
    p.p("Aaron Esau.");
    p.sh("COPYRIGHT");
    p.p("Copyright (c) 2026 Aaron Esau. fsblame is released under the MIT License.");

    p.sh("SEE ALSO");
    let mut refs: Vec<String> = top
        .get_subcommands()
        .map(|sub| format!("`fsblame-{}`(1)", sub.get_name()))
        .collect();
    refs.extend(
        [
            "`setcap`(8)",
            "`capabilities`(7)",
            "`bpf`(2)",
            "`inotify`(7)",
            "`fanotify`(7)",
        ]
        .map(str::to_owned),
    );
    p.p(&refs.join(", "));
    p.p("The README covers installation, the output and the design:");
    p.code(&[REPO]);
    p.out
}

/// The DESCRIPTION of fsblame(1).
fn main_description(p: &mut Page) {
    p.sh("DESCRIPTION");
    p.p(
        "fsblame answers the question: which command changed this file? It watches files and \
         directory trees and reports every change made to them (writes, creates, renames, links, \
         deletes, chmod, chown, truncation, timestamp and attribute changes) together with the \
         process that made it: its command line and working directory, every ancestor up to \
         init, its systemd unit or container, and the build step it ran under, such as an npm \
         `postinstall` script or a cargo build script.",
    );
    p.p(
        "inotify(7) reports that a file changed and nothing about the process; fanotify(7) adds \
         a pid, but the `cp`, `mv` or `sed -i` a script ran has usually exited by the time the \
         event is read, taking its command line, working directory and parent with it. fsblame \
         follows every fork and exec on the system from the moment it starts, so it still knows \
         a process after it exits.",
    );
    p.p(
        "It attaches BPF programs (fentry) to the kernel's VFS security hooks, which every create, \
         link, unlink, rename, attribute change and write passes through, and to the scheduler's \
         fork, exec and exit tracepoints. In the kernel, each hook decides whether the file is in \
         a watched tree, rebuilds its path and sends a record through a ring buffer; write calls \
         are only counted there. In userspace, fsblame rebuilds the process tree from those \
         records (and from `/proc` for processes that predate it), coalesces the write counts \
         into one change per process and file, recognizes the build step from the environment \
         npm, pnpm, yarn, bun, cargo, pip and make give their child processes, and prints each \
         change with its lineage.",
    );
    p.p(
        "Paths may be files or directories; a directory includes its whole subtree, including \
         the filesystems mounted below it when fsblame starts. Only changes made while fsblame \
         runs are reported: `fsblame record` keeps a journal so that `fsblame blame` can answer \
         later.",
    );
    p.p(
        "`fsblame` {PATH}... is short for `fsblame watch` {PATH}... and takes the same options. \
         A first argument that names a command runs that command: to watch a directory called \
         `run`, write `fsblame ./run` or `fsblame watch run`.",
    );
    p.p(
        "fsblame needs Linux 5.17 or newer with BTF (`/sys/kernel/btf/vmlinux`) and fentry \
         support, on x86_64 or aarch64, and runs on the host, in the initial pid namespace; it \
         sees containers' processes from there. `fsblame doctor` checks all of this.",
    );
}

/// The ENVIRONMENT and FILES of fsblame(1).
fn environment_and_files(p: &mut Page) {
    p.sh("ENVIRONMENT");
    p.tp(
        "`FSBLAME_LOG`",
        "fsblame's own diagnostics on stderr: `info`, `debug` or `trace`. By default only \
         warnings and errors are printed. `FSBLAME_LOG=debug fsblame doctor` prints the full \
         verifier log of a program the kernel rejects.",
    );
    p.tp(
        "`NO_COLOR`",
        "When set to a non-empty value, output is not colored unless `--color always` is given.",
    );
    p.tp(
        "`SUDO_UID`, `SUDO_GID`, `SUDO_USER`",
        "Set by sudo(8). Under sudo, paths below the invoking user's home directory are shown \
         with `~`, and `fsblame run` starts its command as that user, with that user's groups \
         and `HOME`, `USER`, `LOGNAME` and `SHELL` from the password database (`HOME` from \
         `SUDO_HOME` if the user has no entry there).",
    );
    p.tp("`HOME`", "Without sudo, the home directory shown as `~`.");

    p.sh("FILES");
    p.tp(
        "`/var/lib/fsblame`",
        "The default journal directory of `fsblame record` and `fsblame blame`, mode 0700; its \
         files have mode 0600, since they hold every user's command lines.",
    );
    p.tp(
        "`/etc/default/fsblame`",
        "Settings of `fsblame-record.service`: `FSBLAME_PATHS`, the files and directories to \
         record, separated by spaces (default `/etc /usr/local`), and `FSBLAME_ARGS`, further \
         `record` options.",
    );
    p.tp(
        "`/etc/systemd/system/fsblame-record.service`",
        "The systemd unit that runs `fsblame record` from boot (or the distribution's unit \
         directory, if a package installed it); see `fsblame-record`(1).",
    );
    p.tp(
        "`/sys/kernel/btf/vmlinux`",
        "The running kernel's BTF, which fsblame needs to load its programs \
         (`CONFIG_DEBUG_INFO_BTF`).",
    );
    p.tp(
        "`/proc/`{PID}`/`",
        "The command line, working directory and environment of processes that started before \
         fsblame.",
    );
}

/// The CAVEATS and EXAMPLES of fsblame(1).
fn caveats_and_examples(p: &mut Page) {
    p.sh("CAVEATS");
    p.bullet("Only changes made while fsblame runs are reported. For history, keep `fsblame record` running.");
    p.bullet(
        "On network filesystems, changes made by other machines are never seen; on FUSE \
         filesystems, the daemon's writes to its backing store are attributed to the daemon.",
    );
    p.bullet(
        "A filesystem mounted below a watched directory after fsblame started is not watched.",
    );
    p.bullet(
        "The working directory shown is the one at exec; a shell that runs `cd` later still \
         shows the old one. Command lines longer than 4 KiB are cut.",
    );
    p.bullet(
        "Byte counts are what each write call asked for. Stores through a shared writable \
         mapping are reported once, when the mapping becomes writable.",
    );
    p.bullet(
        "When changes arrive faster than fsblame reads them, the kernel drops records rather \
         than slow the system down. fsblame always says so on stderr; a larger `--ring-size` \
         helps.",
    );

    p.sh("EXAMPLES");
    p.example(
        "Check whether fsblame can run here, and what it would miss:",
        &["sudo fsblame doctor ~/proj"],
    );
    p.example(
        "Print each change below ~/proj as it happens, until Ctrl-C (the second form is the \
         same):",
        &["sudo fsblame watch ~/proj", "sudo fsblame ~/proj"],
    );
    p.example(
        "Show everything npm and the processes it starts change, anywhere:",
        &["sudo fsblame run -- npm install"],
    );
    p.example(
        "Keep a journal of the changes to /etc, then ask it later who changed a file:",
        &["sudo fsblame record /etc", "sudo fsblame blame /etc/hosts"],
    );
    p.example(
        "Run without sudo, once the binary has the capabilities:",
        &[
            "sudo setcap cap_bpf,cap_perfmon+ep /usr/local/bin/fsblame",
            "fsblame watch ~/proj",
        ],
    );
}

/// fsblame-watch(1).
fn watch(p: &mut Page) {
    p.sh("DESCRIPTION");
    p.p(
        "`fsblame watch` prints every change to the given files and directory trees as it \
         happens, each with the process that made it and that process's ancestors. A directory \
         includes its whole subtree, including the filesystems mounted below it when fsblame \
         starts. `fsblame` {PATH}... is the same command.",
    );
    p.p(
        "Once attached it prints `fsblame: watching` and what it watches on stderr; it stops at \
         Ctrl-C, SIGTERM or SIGHUP, after `--duration`, or when its output pipe is closed, and \
         then prints the number of changes reported (`--quiet` leaves out both lines). It \
         reports every change made before it was told to stop, including the write windows \
         still open, and nothing made after. If it is behind, it keeps reading for up to 10 \
         seconds before it exits; a second Ctrl-C ends that at once.",
    );
    p.p(
        "With `--tree`, only changes by the given processes and their descendants are reported: \
         those running at the start and those they start later. This needs \
         `CONFIG_PROC_CHILDREN` in the kernel, which lists the children of a process.",
    );
    human_output(p);
    p.ss("NDJSON output");
    p.p(
        "`--json` prints one JSON object per line: a `touch` object per change, `lost` when the \
         kernel side lost data, and a `summary` with `--summary`. Every line carries the schema \
         version `v` (currently 1); within a version, fields are only added. The schema, every \
         field, and jq(1) recipes are in docs/json.md in the source:",
    );
    p.code(&[JSON_DOC]);
    losses(p);
    filters(p);
    p.options();
    p.sh("EXIT STATUS");
    exit_codes(p, "stopped cleanly.");
    p.p("Status 5 also means `--tree` was given on a kernel without `CONFIG_PROC_CHILDREN`.");
    p.sh("EXAMPLES");
    p.example(
        "Watch several paths at once:",
        &["sudo fsblame watch ~/proj ~/.config"],
    );
    p.example(
        "Ignore a subtree, and report only writes, renames and deletions:",
        &[
            "sudo fsblame watch ~/proj --exclude ~/proj/target \\",
            "    --op write,rename,unlink",
        ],
    );
    p.example(
        "Stop after 10 minutes, then print the changes grouped by build step or command:",
        &["sudo fsblame watch ~/proj --duration 10m --summary"],
    );
    p.example(
        "Watch shell startup files and SSH settings in the home directory:",
        &[
            "sudo fsblame watch ~ --include .bashrc --include .profile \\",
            "    --include '.ssh/**'",
        ],
    );
    p.example(
        "Only process 4242 and its descendants:",
        &["sudo fsblame watch ~/proj --tree 4242"],
    );
    p.example(
        "One line per change, from the NDJSON:",
        &[
            "sudo fsblame watch ~/proj --json |",
            "  jq --unbuffered -r 'select(.type == \"touch\") | .op + \" \" + .path'",
        ],
    );
    see_also(p, &["run", "record", "doctor"], &["inotifywait(1)"]);
}

/// fsblame-run(1).
fn run(p: &mut Page) {
    p.sh("DESCRIPTION");
    p.p(
        "`fsblame run` starts {CMD} and reports every change made by it and by every process it \
         starts, until it exits. With {PATH} arguments, only changes below them are reported; \
         without, every filesystem but the pseudo ones (proc, sysfs, cgroup, debugfs and the \
         like) is watched. Paths on a filesystem mounted after the start are shown as \
         `<dev` {MAJOR}`:`{MINOR}`>/`{path}.",
    );
    p.p(
        "Under sudo, the command runs as the invoking user (`SUDO_UID`, `SUDO_GID`, \
         `SUDO_USER`), with that user's groups and `HOME`, `USER`, `LOGNAME` and `SHELL`, and \
         otherwise the environment sudo provides. When fsblame is not running as root under \
         sudo for another user, the command runs as fsblame does.",
    );
    p.p(
        "The report goes to stderr, or to the file given with `--output`, since the command owns \
         stdout. A new output file gets mode 0600 and, under sudo, the invoking user as owner: \
         it holds every command line the run saw. An existing one is truncated and must belong \
         to the invoking user; a symbolic link is refused.",
    );
    p.p(
        "fsblame ignores Ctrl-C, which the terminal sends to the command as well, passes SIGTERM \
         and SIGHUP on to the command, and stops when the command exits. `run` takes the \
         filters and output options of `fsblame watch`, but not `--duration`, `--tree` or \
         `--ready-fd`; its output is described in `fsblame-watch`(1).",
    );
    p.p(
        "`run` follows the process tree. Work the command causes outside it (a systemd unit it \
         starts, D-Bus activation, a container daemon) is not included, and descendants still \
         running after the command exits are not reported further.",
    );
    filters(p);
    p.options();
    p.sh("EXIT STATUS");
    p.p(
        "The command's exit status; 128 + {N} when signal {N} killed it, 127 when it was not \
         found and 126 when it could not be executed.",
    );
    p.p("fsblame's own failures end with an `fsblame:` line on stderr and these statuses:");
    p.tp("2", "Usage error, such as an unknown option, or an `--output` file that is a symbolic link or belongs to another user.");
    p.tp("4", "Missing privileges.");
    p.tp("5", "The kernel lacks something fsblame needs.");
    p.tp(
        "6",
        "Runtime error after the command started; fsblame waits for the command first.",
    );
    p.p("Statuses 2, 4 and 5 come before the command starts.");
    p.sh("EXAMPLES");
    p.example(
        "Everything an install changes, on every filesystem:",
        &["sudo fsblame run -- npm install"],
    );
    p.example(
        "Only changes below ~/proj:",
        &["sudo fsblame run ~/proj -- make"],
    );
    p.example(
        "The report as NDJSON in a file:",
        &["sudo fsblame run --json -o changes.ndjson -- ./install.sh"],
    );
    p.example(
        "Only what the command does to permissions, grouped at the end:",
        &["sudo fsblame run --op chmod,chown --summary -- ./setup.sh"],
    );
    see_also(p, &["watch", "doctor"], &["sudo(8)"]);
}

/// fsblame-record(1).
fn record(p: &mut Page) {
    p.sh("DESCRIPTION");
    p.p(
        "`fsblame record` watches like `fsblame watch` and appends each change to a journal of \
         NDJSON files, from which `fsblame blame` answers later: who changed a file while nobody \
         was watching. It prints `fsblame: recording to` {DIR} on stderr, unless `--quiet`, and \
         runs until Ctrl-C, SIGTERM, SIGHUP or `--duration` stops it. `--summary` ends each run \
         with a summary line in the journal.",
    );
    p.ss("The journal");
    p.p(
        "The journal is a directory of files named `fsblame-`{START}`.ndjson`, where {START} is \
         the UTC time the file was started, such as \
         `fsblame-20261016T140211.123456Z.ndjson`, so that their names sort in the order they \
         were started. Each line is one object exactly as `fsblame watch --json` prints it.",
    );
    p.p(
        "A new file is started before the current one would grow beyond `--max-size` (a single \
         longer line gets a file of its own); then the oldest files beyond `--keep` are deleted. \
         The first file is created with the first change, so a run that fails to start leaves \
         no file and deletes none.",
    );
    p.p(
        "Each line is written with one write(2) and nothing is buffered, so every line written \
         survives the recorder being killed; a crash or a full disk can at most leave the last \
         line torn, which `fsblame blame` skips.",
    );
    p.p(
        "The directory is created with mode 0700 if missing, and the files with mode 0600: they \
         hold the command lines and working directories of every user's processes. The default \
         directory, `/var/lib/fsblame`, is therefore writable and readable by root only.",
    );
    p.ss("Running as a service");
    p.p(
        "`fsblame-record.service` runs `fsblame record` from boot, with the journal in \
         `/var/lib/fsblame` (its state directory), the paths from `FSBLAME_PATHS` in \
         `/etc/default/fsblame` and further options from `FSBLAME_ARGS`. It runs with only \
         `CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_PTRACE` and `CAP_DAC_READ_SEARCH`, in a hardened \
         sandbox, and is not restarted after exit status 2, 4 or 5, which restarting cannot fix.",
    );
    p.code(&[
        "sudoedit /etc/default/fsblame       # set FSBLAME_PATHS",
        "sudo systemctl daemon-reload",
        "sudo systemctl enable --now fsblame-record.service",
        "journalctl -u fsblame-record        # why it failed, if it did",
    ]);
    filters(p);
    p.options();
    p.sh("EXIT STATUS");
    exit_codes(p, "stopped cleanly.");
    p.p(
        "Status 4 also means the journal directory could not be created or written for lack of \
         permission.",
    );
    p.sh("FILES");
    p.tp("`/var/lib/fsblame`", "The default journal directory.");
    p.tp(
        "`/etc/default/fsblame`",
        "`FSBLAME_PATHS` and `FSBLAME_ARGS` for the service.",
    );
    p.tp(
        "`/etc/systemd/system/fsblame-record.service`",
        "The service (or the distribution's unit directory).",
    );
    p.sh("EXAMPLES");
    p.example(
        "Record changes to /etc and /usr/local, except /usr/local/share:",
        &["sudo fsblame record /etc /usr/local --exclude /usr/local/share"],
    );
    p.example(
        "A smaller journal of 4 files of at most 16 MiB, in another directory:",
        &[
            "sudo fsblame record /etc --journal /srv/fsblame \\",
            "    --max-size 16M --keep 4",
        ],
    );
    see_also(p, &["blame", "watch"], &["systemctl(1)", "systemd.exec(5)"]);
}

/// fsblame-blame(1).
fn blame(p: &mut Page) {
    p.sh("DESCRIPTION");
    p.p(
        "`fsblame blame` shows who changed a path, from the journal `fsblame record` writes, in \
         the tree view `fsblame watch` prints live, or as NDJSON with `--json`. Changes are \
         shown in the order they were recorded; `--limit` keeps the most recent ones.",
    );
    p.p(
        "A change matches a {PATH} by any of its paths (a rename's old name, a link's target), \
         and a directory matches everything below it; the file need not exist any more. \
         Relative paths are taken from the current directory. Without {PATH}, every recorded \
         change is shown.",
    );
    p.p(
        "`blame` loads no BPF programs and needs no capabilities, only read access to the \
         journal, which by default is root's. It reports on stderr when no change matches, and \
         how many journal lines it skipped as malformed, such as a line cut short by a crash.",
    );
    p.ss("Times");
    p.p("`--since` and `--until` take either of:");
    p.bullet(
        "An RFC 3339 time: {YYYY}`-`{MM}`-`{DD}`T`{hh}`:`{mm}`:`{ss}, an optional fraction of up \
         to nine digits, then `Z` or an offset `+`{hh}`:`{mm} or `-`{hh}`:`{mm}, such as \
         `2026-10-16T14:00:00Z` or `2026-10-16T16:00:00+02:00`.",
    );
    p.bullet(
        "How long ago: a number with the unit `ms`, `s`, `m`, `h` or `d`, such as `30m`, `2h` \
         or `7d`; a bare number is seconds.",
    );
    p.p("Both bounds are inclusive.");
    filters_combine(p);
    p.options();
    p.sh("EXIT STATUS");
    p.tp(
        "0",
        "The journal was read, whether or not a change matched.",
    );
    p.tp(
        "2",
        "Usage error, such as an unknown option or an invalid time, or there is no journal \
         directory.",
    );
    p.tp(
        "4",
        "The journal cannot be read for lack of permission: run `blame` with sudo.",
    );
    p.tp(
        "6",
        "The journal could not be read for another reason, or the output not written.",
    );
    p.sh("EXAMPLES");
    p.example(
        "Every recorded change to /etc/hosts:",
        &["sudo fsblame blame /etc/hosts"],
    );
    p.example(
        "What changed permissions below /etc in the last two hours:",
        &["sudo fsblame blame /etc --since 2h --op chmod,chown"],
    );
    p.example(
        "Changes in a time window:",
        &[
            "sudo fsblame blame /etc/nginx \\",
            "    --since 2026-10-16T14:00:00Z --until 2026-10-16T15:00:00Z",
        ],
    );
    p.example(
        "The latest change, as NDJSON:",
        &["sudo fsblame blame /etc/hosts --limit 1 --json"],
    );
    see_also(p, &["record", "watch"], &[]);
}

/// fsblame-doctor(1).
fn doctor(p: &mut Page) {
    p.sh("DESCRIPTION");
    p.p(
        "`fsblame doctor` checks whether this system can run fsblame, and how to fix it if not. \
         It checks the platform, the kernel version and BTF, privileges, lockdown and security \
         modules, then loads every program of the real tracer and reports, for each of the 14 \
         operations, whether this kernel can report it and why not if it cannot. It also checks \
         the filesystems of the given paths (default: the current directory) for overlays, \
         network and FUSE mounts, where fsblame sees less.",
    );
    p.p(
        "Each check prints one line, `PASS`, `WARN`, `FAIL`, `INFO` or `SKIP`, with what it \
         found; a failing or warning check also names what it breaks and how to fix it. The \
         last line counts them and says whether fsblame is ready. Run it with the privileges \
         fsblame will have (such as sudo): without them, the privilege checks fail.",
    );
    p.p(
        "`--json` prints the report as one JSON document instead, with the result per operation \
         under `ops`. Please include `sudo fsblame doctor --json` in bug reports.",
    );
    p.options();
    p.sh("EXIT STATUS");
    p.tp("0", "No check failed (warnings allowed).");
    p.tp("2", "Usage error, such as an unknown option.");
    p.tp(
        "4",
        "A check failed that a setting can fix, such as missing privileges.",
    );
    p.tp(
        "5",
        "Only checks of the platform, the kernel or its programs failed.",
    );
    p.tp("6", "The report could not be written.");
    p.sh("EXAMPLES");
    p.example(
        "Can fsblame watch ~/proj here?",
        &["sudo fsblame doctor ~/proj"],
    );
    p.example(
        "Which operations this kernel can report:",
        &["sudo fsblame doctor --json | jq .ops"],
    );
    see_also(p, &["watch"], &["capabilities(7)", "kernel_lockdown(7)"]);
}

/// fsblame-completions(1).
fn completions(p: &mut Page) {
    p.sh("DESCRIPTION");
    p.p(
        "`fsblame completions` prints the completion script for {SHELL} to stdout. The release \
         archive ships the same scripts in its `completions` directory. Where to put them:",
    );
    p.tp_indent(
        12,
        "`bash`",
        "`/usr/local/share/bash-completion/completions/fsblame`, or for one user \
         `~/.local/share/bash-completion/completions/fsblame`; bash-completion loads it when \
         `fsblame` is first completed.",
    );
    p.tp_indent(
        12,
        "`zsh`",
        "A file named `_fsblame` in a directory on `$fpath`, such as \
         `/usr/local/share/zsh/site-functions/_fsblame`; start a new shell (or delete \
         `~/.zcompdump`) for `compinit` to find it.",
    );
    p.tp_indent(
        12,
        "`fish`",
        "`/usr/local/share/fish/vendor_completions.d/fsblame.fish`, or for one user \
         `~/.config/fish/completions/fsblame.fish`.",
    );
    p.tp_indent(
        12,
        "`elvish`",
        "Evaluate it from `~/.config/elvish/rc.elv`: `eval (fsblame completions elvish | slurp)`.",
    );
    p.tp_indent(
        12,
        "`powershell`",
        "Evaluate it from your profile (`$PROFILE`): \
         `fsblame completions powershell | Out-String | Invoke-Expression`.",
    );
    p.options();
    p.sh("EXIT STATUS");
    p.tp("0", "The script was printed.");
    p.tp("2", "Usage error, such as an unknown shell.");
    p.tp("6", "The script could not be written to stdout.");
    p.sh("EXAMPLES");
    p.example(
        "Install the bash completions for all users:",
        &[
            "fsblame completions bash > fsblame.bash",
            "sudo install -Dm 0644 fsblame.bash \\",
            "    /usr/local/share/bash-completion/completions/fsblame",
        ],
    );
    p.example(
        "Install the fish completions for yourself:",
        &["fsblame completions fish > ~/.config/fish/completions/fsblame.fish"],
    );
    see_also(p, &[], &["bash(1)", "zsh(1)", "fish(1)"]);
}

/// The PRIVILEGES section.
fn privileges(p: &mut Page) {
    p.sh("PRIVILEGES");
    p.p(
        "fsblame loads BPF programs, which needs `CAP_BPF` and `CAP_PERFMON`. Run it as root, \
         with sudo(8), or give the binary those capabilities once:",
    );
    p.code(&["sudo setcap cap_bpf,cap_perfmon+ep /usr/local/bin/fsblame"]);
    p.p("Then:");
    p.bullet(
        "Every user who can execute the binary can watch any path and read every user's command \
         lines. On a shared machine, restrict who may run it, for example with mode 0750 and a \
         group.",
    );
    p.bullet(
        "File capabilities are ignored on filesystems mounted `nosuid` (often `/tmp` and some \
         home directories), and are removed when the file is replaced: run setcap(8) again after \
         every upgrade.",
    );
    p.bullet(
        "Without `CAP_SYS_PTRACE` (root has it), the command lines and working directories of \
         other users' processes that started before fsblame cannot be read; `fsblame doctor` \
         says so.",
    );
    p.p(
        "Without either, fsblame prints what is missing, including the setcap(8) command for its \
         own path, and exits with status 4.",
    );
}

/// The exit statuses every command shares, with `ok` saying when it exits 0.
fn exit_codes(p: &mut Page, ok: &str) {
    p.tp("0", &format!("Success: {ok}"));
    p.tp(
        "2",
        "Usage error, such as an unknown option or a path that does not exist.",
    );
    p.tp(
        "4",
        "Missing privileges; fsblame prints what is missing and how to grant it.",
    );
    p.tp("5", "The kernel lacks something fsblame needs.");
    p.tp(
        "6",
        "Runtime error after start-up, such as a full disk under `fsblame record`.",
    );
}

/// The tree view, for the pages of the commands that print it.
fn human_output(p: &mut Page) {
    p.ss("Human output");
    p.p("Each change is one header line and a tree of the processes behind it:");
    p.code(&[
        "PATH  VERB  TIME  (DETAIL)",
        "  \u{2514}\u{2500} COMMAND LINE  (pid, cwd)   [WHERE]   [BUILD STEP \u{b7} CONFIDENCE]",
        "     \u{2514}\u{2500} PARENT'S COMMAND LINE  (pid)",
        "        \u{2514}\u{2500} \u{2026} N more ancestors",
    ]);
    p.p(
        "{WHERE} names the tmux pane, systemd unit and container of the process, those known, \
         such as `[unit cron.service]` or `[tmux %3 \u{b7} unit session-2.scope]`; {BUILD STEP} names the step and how sure fsblame is of it, \
         such as `[npm lifecycle: build webapp@1.4.2 \u{b7} high]`. Either is left out when \
         unknown. For example, a build that made a script executable (tags left out):",
    );
    p.code(&[
        "~/webapp/dist/bundle.js  chmod  15:10:40  (0644 \u{2192} 0755)",
        "  \u{2514}\u{2500} chmod 755 dist/bundle.js  (pid 3243819, cwd ~/webapp)",
        "     \u{2514}\u{2500} npm run build  (pid 3243806)",
        "        \u{2514}\u{2500} bash  (pid 3243787)",
    ]);
    p.bullet(
        "The verb is one of `modified`, `created`, `created dir`, `created node`, `symlinked`, \
         `hard-linked`, `deleted`, `removed dir`, `renamed`, `chmod`, `chown`, `truncated`, \
         `touched` (timestamps) and `attrs changed`. A rename shows {OLD} \u{2192} {NEW} as its \
         path.",
    );
    p.bullet(
        "The detail says what changed, such as `(+21 B, 2 writes)`, \
         `(shared writable mapping, mmap)`, `(0644 \u{2192} 0755)`, `(\u{2192} uid 1000, gid 1000)`, \
         `(\u{2192} 0 B)`, `(\u{2192}` {target}`)` for a symlink, `(=` {existing path}`)` for a \
         hard link, or the mode of a new file.",
    );
    p.bullet(
        "Writes are coalesced per process and file: the line appears once the file has been \
         quiet for 200 ms or after 1 s of continuous writing, when the process execs or exits, \
         before another change to the same file, or when fsblame stops.",
    );
    p.bullet(
        "Process facts: `pid`, `ns pid` for a process in a container's pid namespace, `exited` \
         {HH:MM:SS} when it had exited, and `cwd` where it differs from the line above. A \
         process fsblame has no record of shows as {comm} `(pid` {N}`, not tracked)`.",
    );
    p.bullet(
        "The build step (an npm, pnpm, yarn or bun lifecycle script, a cargo build script, pip \
         or make) sits on the process whose environment identified it.",
    );
    p.bullet("Paths below your home directory are shown with `~`, also under sudo.");
    p.p(
        "`--depth` sets how many ancestors are shown. `--color` makes the path bold, colors the \
         verb by kind of change and dims the ancestors. `--summary` ends the output with the \
         changes grouped by build step or command.",
    );
}

/// The paragraph on losses.
fn losses(p: &mut Page) {
    p.ss("Losses");
    p.p(
        "If changes arrive faster than fsblame can read them, the kernel drops records rather \
         than slow the system down. fsblame never hides a loss: it prints a warning on stderr \
         (a `lost` line in JSON) at most once per second while it happens, and the totals when \
         it stops. A larger `--ring-size` helps.",
    );
}

/// How the filters combine, for the pages of the commands that take them.
fn filters(p: &mut Page) {
    filters_combine(p);
    p.text(
        "`--op` applies in the kernel: operations not asked for are never recorded, and most \
         of their programs are not even loaded. The other filters apply in userspace.",
    );
}

/// The paragraph on how the filters combine.
fn filters_combine(p: &mut Page) {
    p.ss("Filters");
    p.p(
        "Filters of different kinds must all match; the values of one kind are alternatives; \
         `--ignore-comm` wins over everything else.",
    );
}

/// REPORTING BUGS.
fn reporting(p: &mut Page) {
    p.sh("REPORTING BUGS");
    p.p(
        "Report bugs, with the output of `fsblame --version` and `sudo fsblame doctor --json`, \
         at:",
    );
    p.code(&[ISSUES]);
    p.p("Please report security problems privately instead, at:");
    p.code(&[ADVISORIES]);
}

/// SEE ALSO: fsblame(1), the sibling pages `commands`, and `others` (`name(N)`).
fn see_also(p: &mut Page, commands: &[&str], others: &[&str]) {
    p.sh("SEE ALSO");
    let mut refs = vec!["`fsblame`(1)".to_owned()];
    refs.extend(commands.iter().map(|c| format!("`fsblame-{c}`(1)")));
    refs.extend(others.iter().map(|o| {
        let (name, section) = o.split_once('(').expect("name(N)");
        format!("`{name}`({section}")
    }));
    p.p(&refs.join(", "));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The section headings of a page, in order.
    fn sections(page: &str) -> Vec<&str> {
        page.lines()
            .filter_map(|l| l.strip_prefix(".SH "))
            .map(|h| h.trim_matches('"'))
            .collect()
    }

    #[test]
    fn every_command_has_a_complete_page() {
        let pages = pages();
        let top = cli::Cli::command();
        let mut expected = vec!["fsblame.1".to_owned()];
        expected.extend(
            top.get_subcommands()
                .map(|s| format!("fsblame-{}.1", s.get_name())),
        );
        let names: Vec<&str> = pages.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, expected);
        for (name, page) in &pages {
            let found = sections(page);
            let mut required = vec![
                "NAME",
                "SYNOPSIS",
                "DESCRIPTION",
                "OPTIONS",
                "EXIT STATUS",
                "EXAMPLES",
                "SEE ALSO",
            ];
            if name == "fsblame.1" {
                required.extend([
                    "COMMANDS",
                    "PRIVILEGES",
                    "ENVIRONMENT",
                    "FILES",
                    "REPORTING BUGS",
                    "AUTHORS",
                ]);
            }
            for section in required {
                assert!(
                    found.contains(&section),
                    "{name} lacks {section}: {found:?}"
                );
            }
            assert!(page.is_ascii(), "{name} has non-ASCII text");
            assert!(
                page.starts_with(".ie \\n(.g .ds Aq"),
                "{name} lacks the Aq string"
            );
            assert!(
                page.lines().any(|l| l.starts_with(".TH ") && l.contains(&format!("\"fsblame {VERSION}\""))),
                "{name} lacks the version"
            );
        }
    }

    #[test]
    fn main_synopsis_has_one_line_per_form_not_the_watch_flags() {
        let pages = pages();
        let synopsis = pages[0]
            .1
            .split(".SH SYNOPSIS\n")
            .nth(1)
            .and_then(|s| s.split("\n.SH").next())
            .expect("SYNOPSIS");
        assert!(!synopsis.contains("ring"), "{synopsis}");
        let forms = synopsis.lines().filter(|l| *l != ".br").count();
        // The shorthand, one per command, then help and version.
        assert_eq!(
            forms,
            cli::Cli::command().get_subcommands().count() + 2,
            "{synopsis}"
        );
        assert!(
            synopsis.contains(concat!(
                r"\%\fBfsblame \%run\fR \%[\fIOPTIONS\fR] \%[\fIPATH\fR...] ",
                r"\%\fB\-\-\fR \%\fICMD\fR...",
                "\n"
            )),
            "{synopsis}"
        );
    }

    #[test]
    fn markup_sets_fonts_and_escapes_the_rest() {
        assert_eq!(
            markup("`--op` {LIST}: it's a-b \\ (`fsblame run`)"),
            r"\%\fB\-\-op\fR \%\fILIST\fR: it\*(Aqs a\-b \e \%(\fBfsblame \%run\fR)"
        );
        assert_eq!(markup(".hidden"), r"\&.hidden");
        assert_eq!(escape_line("'quoted'"), r"\*(Aqquoted\*(Aq");
        assert_eq!(escape_line(""), r"\&");
        assert_eq!(escape("a \u{2192} b"), r"a \[u2192] b");
    }

    #[test]
    #[should_panic(expected = "unclosed")]
    fn markup_rejects_an_unclosed_mark() {
        markup("`--op");
    }
}
