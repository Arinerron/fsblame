//! Command-line interface.
//!
//! Depends only on clap, [`crate::ops`], [`crate::glob`] and [`crate::clock`]: `cargo xtask man`
//! compiles this
//! file into the xtask binary to render the man pages, without building the BPF object. The
//! `--version` text with the BPF ABI hash is added at run time by the binary's entry point.

use std::{ffi::OsString, path::PathBuf, time::Duration};

use clap::{Args, Parser, Subcommand, ValueEnum};
use clap_complete::Shell;

use crate::{clock::parse_rfc3339, glob::Glob, ops::Op};

/// Smallest `--ring-size`.
const RING_MIN: u64 = 256 << 10;
/// Largest `--ring-size`.
const RING_MAX: u64 = 1 << 30;
/// Smallest `--max-size` of a journal file.
const JOURNAL_MIN: u64 = 64 << 10;
/// Default `--journal` directory.
pub const DEFAULT_JOURNAL: &str = "/var/lib/fsblame";

/// Which command changed this file? Watches files and directory trees and prints every
/// modifying operation with the full lineage of the process that made it.
#[derive(Debug, Parser)]
#[command(
    name = "fsblame",
    version,
    args_conflicts_with_subcommands = true,
    subcommand_negates_reqs = true,
    arg_required_else_help = true
)]
pub struct Cli {
    /// Subcommand; `fsblame <PATH>...` is short for `fsblame watch <PATH>...`.
    #[command(subcommand)]
    pub command: Option<Command>,
    /// Shorthand form of `watch`.
    #[command(flatten)]
    pub watch: WatchArgs,
}

/// Subcommands.
#[derive(Debug, Subcommand)]
#[allow(
    clippy::large_enum_variant,
    reason = "parsed once per process; boxing would only obscure the clap definitions"
)]
pub enum Command {
    /// Watch paths live and print each change with the process lineage behind it.
    Watch(WatchArgs),
    /// Run a command and report every change made by it and by the processes it starts.
    ///
    /// Without PATH every filesystem but the pseudo ones (proc, sysfs, cgroup, debugfs, ...)
    /// is watched. Under sudo the command runs as the invoking user, with that user's HOME,
    /// USER, LOGNAME and SHELL and otherwise the environment sudo provides. The report goes
    /// to stderr (or --output), since the command owns stdout. fsblame ignores Ctrl-C, which
    /// reaches the command, passes SIGTERM and SIGHUP on to it, and stops when it exits.
    ///
    /// Exit status: the command's, 128 + N when signal N killed it, 127 when it was not
    /// found and 126 when it could not be executed. fsblame's own failures end with an
    /// `fsblame:` error line on stderr and exit 2 (usage), 4 (privileges) or 5 (kernel
    /// unsupported), all before the command starts, or 6 (runtime error, after waiting for
    /// the command if it started).
    Run(RunArgs),
    /// Watch paths and append each change to a rotating journal, for `fsblame blame`.
    Record(RecordArgs),
    /// Show who changed a path, from the journal `fsblame record` writes.
    Blame(BlameArgs),
    /// Check whether this system can run fsblame, and how to fix it if not.
    Doctor(DoctorArgs),
    /// Print a shell completion script to stdout.
    Completions {
        /// The shell to generate for.
        shell: Shell,
    },
}

/// Which changes to report: shared by the commands that watch and by `blame`.
#[derive(Clone, Debug, Args)]
pub struct FilterArgs {
    /// Report only these operations: write, create, mkdir, mknod, symlink, link, unlink,
    /// rmdir, rename, chmod, chown, truncate, utimes, setattr.
    #[arg(
        long,
        value_delimiter = ',',
        value_name = "LIST",
        hide_possible_values = true
    )]
    pub op: Vec<Op>,
    /// Report only changes to paths matching this glob (repeatable): `*.lock` matches the
    /// file name anywhere, `/etc/**` an absolute subtree, `node_modules/` any directory of
    /// that name. A rename or link matches by either of its paths.
    #[arg(long, value_name = "GLOB", help_heading = "Filters")]
    pub include: Vec<Glob>,
    /// Report only changes made by threads with these names (`comm`, first 15 bytes).
    #[arg(
        long,
        value_delimiter = ',',
        value_name = "LIST",
        help_heading = "Filters"
    )]
    pub comm: Vec<String>,
    /// Never report changes made by threads with these names, whatever else matches.
    #[arg(
        long,
        value_delimiter = ',',
        value_name = "LIST",
        help_heading = "Filters"
    )]
    pub ignore_comm: Vec<String>,
    /// Report only changes made by processes with these real uids.
    #[arg(
        long,
        value_delimiter = ',',
        value_name = "LIST",
        help_heading = "Filters"
    )]
    pub uid: Vec<u32>,
    /// Report only changes made in these systemd units (`.service`/`.scope` optional).
    #[arg(
        long,
        value_delimiter = ',',
        value_name = "LIST",
        help_heading = "Filters"
    )]
    pub unit: Vec<String>,
    /// Report only changes made by these process ids.
    #[arg(
        long,
        value_delimiter = ',',
        value_name = "LIST",
        help_heading = "Filters"
    )]
    pub pid: Vec<u32>,
}

/// How the commands that watch trace: shared by `watch`, `record` and `run`.
#[derive(Clone, Debug, Args)]
pub struct TraceArgs {
    /// Ignore changes below this path (repeatable).
    #[arg(long, value_name = "PATH")]
    pub exclude: Vec<PathBuf>,
    /// Kernel ring buffer size, such as 4M or 64M: a power of two from 256K to 1G (K, M
    /// and G are binary). Raise it when fsblame warns that records were lost.
    #[arg(long, value_name = "SIZE", default_value = "16M", value_parser = parse_ring_size)]
    pub ring_size: u32,
    /// Print only warnings and errors on stderr, not the start banner or the final count.
    #[arg(long, short)]
    pub quiet: bool,
    /// When stopping, print a summary of the changes grouped by build step or command.
    #[arg(long)]
    pub summary: bool,
    /// Which changes to report.
    #[command(flatten)]
    pub filter: FilterArgs,
}

/// When the commands that watch until stopped report readiness and stop: shared by `watch`
/// and `record`.
#[derive(Clone, Debug, Args)]
pub struct StopArgs {
    /// Stop after this long, such as 30s, 5m, 1h or 250ms.
    #[arg(long, value_name = "D", value_parser = parse_duration)]
    pub duration: Option<Duration>,
    /// Write `ready\n` to this file descriptor once attached, then close it.
    #[arg(long, value_name = "N")]
    pub ready_fd: Option<i32>,
}

/// How changes are shown: shared by the commands that print them.
#[derive(Clone, Debug, Args)]
pub struct ViewArgs {
    /// Print NDJSON, one object per line.
    #[arg(long)]
    pub json: bool,
    /// Ancestors shown per change in human output (JSON always has all).
    #[arg(long, value_name = "N", default_value_t = 4)]
    pub depth: usize,
    /// Color human output: auto (when stdout is a terminal and `NO_COLOR` is unset or
    /// empty), always, or never.
    #[arg(long, value_name = "WHEN", value_enum, default_value_t = ColorMode::Auto)]
    pub color: ColorMode,
}

/// `fsblame watch`.
#[derive(Clone, Debug, Args)]
pub struct WatchArgs {
    /// Files or directories to watch; a directory includes its whole subtree.
    #[arg(required = true, value_name = "PATH")]
    pub paths: Vec<PathBuf>,
    /// Report only changes by this process and its descendants, those running now and those
    /// it starts later (repeatable; a thread id stands for its process).
    #[arg(long, value_name = "PID")]
    pub tree: Vec<u32>,
    /// What to trace and report.
    #[command(flatten)]
    pub trace: TraceArgs,
    /// When to report readiness and stop.
    #[command(flatten)]
    pub stop: StopArgs,
    /// How to show the changes.
    #[command(flatten)]
    pub view: ViewArgs,
}

/// `fsblame run`.
#[derive(Clone, Debug, Args)]
pub struct RunArgs {
    /// Report only changes below these files or directories (default: every filesystem).
    #[arg(value_name = "PATH")]
    pub paths: Vec<PathBuf>,
    /// The command and its arguments, after `--`.
    #[arg(last = true, required = true, value_name = "CMD")]
    pub command: Vec<OsString>,
    /// Write the report to this file instead of stderr. A new file gets mode 0600 and, under
    /// sudo, the invoking user as owner; an existing one is truncated and must then belong
    /// to the invoking user. A symbolic link is refused.
    #[arg(long, short, value_name = "FILE")]
    pub output: Option<PathBuf>,
    /// What to trace and report.
    #[command(flatten)]
    pub trace: TraceArgs,
    /// How to show the changes.
    #[command(flatten)]
    pub view: ViewArgs,
}

/// `fsblame record`.
#[derive(Clone, Debug, Args)]
pub struct RecordArgs {
    /// Files or directories to watch; a directory includes its whole subtree.
    #[arg(required = true, value_name = "PATH")]
    pub paths: Vec<PathBuf>,
    /// What to trace and record.
    #[command(flatten)]
    pub trace: TraceArgs,
    /// When to report readiness and stop.
    #[command(flatten)]
    pub stop: StopArgs,
    /// Directory of the journal files, created with mode 0700 if missing.
    #[arg(long, value_name = "DIR", default_value = DEFAULT_JOURNAL)]
    pub journal: PathBuf,
    /// Start a new journal file before one would grow beyond this size, such as 16M or 1G
    /// (K, M and G are binary; at least 64K).
    #[arg(long, value_name = "SIZE", default_value = "64M", value_parser = parse_journal_size)]
    pub max_size: u64,
    /// Journal files to keep; the oldest beyond this many are deleted.
    #[arg(long, value_name = "N", default_value_t = 8, value_parser = clap::value_parser!(u32).range(1..))]
    pub keep: u32,
}

/// `fsblame blame`.
#[derive(Clone, Debug, Args)]
pub struct BlameArgs {
    /// Show changes to these files, or below these directories, by any of their paths (a
    /// rename's old name, a link's target); default: every change. The files need not
    /// exist anymore.
    #[arg(value_name = "PATH")]
    pub paths: Vec<PathBuf>,
    /// Directory of the journal files.
    #[arg(long, value_name = "DIR", default_value = DEFAULT_JOURNAL)]
    pub journal: PathBuf,
    /// Show only changes at or after this time: RFC 3339, such as 2026-10-16T14:00:00Z or
    /// 2026-10-16T16:00:00+02:00, or how long ago, such as 30m, 2h or 7d.
    #[arg(long, value_name = "TIME", value_parser = parse_time)]
    pub since: Option<TimeArg>,
    /// Show only changes at or before this time, written as for --since.
    #[arg(long, value_name = "TIME", value_parser = parse_time)]
    pub until: Option<TimeArg>,
    /// Show only the N most recent matching changes.
    #[arg(long, value_name = "N", value_parser = clap::value_parser!(u32).range(1..))]
    pub limit: Option<u32>,
    /// Which changes to show.
    #[command(flatten)]
    pub filter: FilterArgs,
    /// How to show them.
    #[command(flatten)]
    pub view: ViewArgs,
}

/// A point in time given on the command line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeArg {
    /// Nanoseconds since the Unix epoch.
    At(i128),
    /// This long before now.
    Ago(Duration),
}

impl TimeArg {
    /// Nanoseconds since the Unix epoch, with `now_ns` as now.
    pub fn unix_ns(self, now_ns: i128) -> i128 {
        match self {
            Self::At(ns) => ns,
            Self::Ago(ago) => {
                now_ns.saturating_sub(i128::try_from(ago.as_nanos()).unwrap_or(i128::MAX))
            }
        }
    }
}

/// When to color human output.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum ColorMode {
    /// When stdout is a terminal and `NO_COLOR` is unset or empty.
    Auto,
    /// Always.
    Always,
    /// Never.
    Never,
}

/// `fsblame doctor`.
#[derive(Clone, Debug, Args)]
pub struct DoctorArgs {
    /// Print the report as JSON.
    #[arg(long)]
    pub json: bool,
    /// Paths you plan to watch, for the filesystem check (default: the current directory).
    #[arg(value_name = "PATH")]
    pub paths: Vec<PathBuf>,
}

/// `250ms`, `30s`, `5m`, `1h`, `7d`; a bare number is seconds.
fn parse_duration(text: &str) -> Result<Duration, String> {
    let split = text
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(text.len());
    let (number, unit) = text.split_at(split);
    let value: f64 = number
        .parse()
        .map_err(|_| format!("{text:?} is not a duration such as 30s, 5m or 250ms"))?;
    let scale = match unit {
        "ms" => 0.001,
        "" | "s" => 1.0,
        "m" => 60.0,
        "h" => 3600.0,
        "d" => 86_400.0,
        _ => {
            return Err(format!(
                "unknown unit {unit:?} in {text:?}; use ms, s, m, h or d"
            ));
        }
    };
    Duration::try_from_secs_f64(value * scale).map_err(|e| format!("{text:?}: {e}"))
}

/// An RFC 3339 time, or a duration ([`parse_duration`]) meaning that long ago.
fn parse_time(text: &str) -> Result<TimeArg, String> {
    if let Some(ns) = parse_rfc3339(text) {
        return Ok(TimeArg::At(ns));
    }
    if text.contains(['-', ':']) {
        return Err(format!(
            "{text:?} is not an RFC 3339 time such as 2026-10-16T14:00:00Z"
        ));
    }
    parse_duration(text).map(TimeArg::Ago)
}

/// `4096K`, `16M`, `1G` as bytes (binary units; a bare number is bytes).
fn parse_size(text: &str) -> Result<u64, String> {
    let split = text
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(text.len());
    let (number, unit) = text.split_at(split);
    let shift = match unit.to_ascii_uppercase().as_str() {
        "" => 0,
        "K" => 10,
        "M" => 20,
        "G" => 30,
        _ => return Err(format!("unknown unit {unit:?}; use K, M or G, such as 16M")),
    };
    number
        .parse::<u64>()
        .ok()
        .and_then(|n| n.checked_mul(1 << shift))
        .ok_or_else(|| format!("{text:?} is not a size such as 4M or 64M"))
}

/// A size of whole kibibytes in the largest unit that divides it, such as `256K` or `1G`.
fn show_size(bytes: u64) -> String {
    match bytes.trailing_zeros() {
        30.. => format!("{}G", bytes >> 30),
        20.. => format!("{}M", bytes >> 20),
        _ => format!("{}K", bytes >> 10),
    }
}

/// A [`parse_size`] that is a power of two from 256K to 1G: the kernel needs a ring buffer
/// of a power-of-two number of pages.
fn parse_ring_size(text: &str) -> Result<u32, String> {
    let bytes = parse_size(text)?;
    if !(RING_MIN..=RING_MAX).contains(&bytes) {
        return Err(format!(
            "must be from {} to {}",
            show_size(RING_MIN),
            show_size(RING_MAX)
        ));
    }
    if !bytes.is_power_of_two() {
        let below = 1 << bytes.ilog2();
        return Err(format!(
            "must be a power of two, such as {} or {}",
            show_size(below),
            show_size(below << 1)
        ));
    }
    Ok(u32::try_from(bytes).expect("at most 1G"))
}

/// A [`parse_size`] of at least [`JOURNAL_MIN`].
fn parse_journal_size(text: &str) -> Result<u64, String> {
    let bytes = parse_size(text)?;
    if bytes < JOURNAL_MIN {
        return Err(format!("must be at least {}", show_size(JOURNAL_MIN)));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use clap::CommandFactory as _;

    #[test]
    fn durations_accept_units_and_bare_seconds() {
        assert_eq!(parse_duration("250ms"), Ok(Duration::from_millis(250)));
        assert_eq!(parse_duration("1.5s"), Ok(Duration::from_millis(1500)));
        assert_eq!(parse_duration("2m"), Ok(Duration::from_secs(120)));
        assert_eq!(parse_duration("7"), Ok(Duration::from_secs(7)));
        assert_eq!(parse_duration("7d"), Ok(Duration::from_secs(7 * 86_400)));
        assert!(parse_duration("5w").is_err());
        assert!(parse_duration("s").is_err());
    }

    #[test]
    fn times_are_rfc3339_or_how_long_ago() {
        assert_eq!(
            parse_time("2026-10-14T14:02:11Z"),
            Ok(TimeArg::At(1_791_986_531_000_000_000))
        );
        assert_eq!(
            parse_time("30m"),
            Ok(TimeArg::Ago(Duration::from_secs(1800)))
        );
        assert_eq!(
            TimeArg::Ago(Duration::from_secs(2)).unix_ns(5_000_000_000),
            3_000_000_000
        );
        assert_eq!(TimeArg::At(7).unix_ns(5_000_000_000), 7);
        // A time without a zone is not taken for a duration.
        assert_eq!(
            parse_time("2026-10-14T14:02:11"),
            Err(
                "\"2026-10-14T14:02:11\" is not an RFC 3339 time such as 2026-10-16T14:00:00Z"
                    .to_owned()
            )
        );
        assert!(parse_time("yesterday").is_err());
    }

    #[test]
    fn record_and_blame_parse_with_journal_defaults() {
        let cli =
            Cli::try_parse_from(["fsblame", "record", "a", "--op", "write", "--quiet"]).unwrap();
        let Some(Command::Record(args)) = cli.command else {
            panic!("not record");
        };
        assert_eq!(args.journal, Path::new(DEFAULT_JOURNAL));
        assert_eq!((args.max_size, args.keep), (64 << 20, 8));
        assert_eq!(args.trace.filter.op, [Op::Write]);
        assert!(args.trace.quiet);
        assert!(Cli::try_parse_from(["fsblame", "record"]).is_err());
        assert!(Cli::try_parse_from(["fsblame", "record", "a", "--json"]).is_err());
        assert!(Cli::try_parse_from(["fsblame", "record", "a", "--keep", "0"]).is_err());
        assert!(Cli::try_parse_from(["fsblame", "record", "a", "--max-size", "4K"]).is_err());

        let cli =
            Cli::try_parse_from(["fsblame", "blame", "--since", "2h", "--limit", "1"]).unwrap();
        let Some(Command::Blame(args)) = cli.command else {
            panic!("not blame");
        };
        assert!(args.paths.is_empty());
        assert_eq!(args.since, Some(TimeArg::Ago(Duration::from_secs(7200))));
        assert_eq!(args.limit, Some(1));
        assert!(Cli::try_parse_from(["fsblame", "blame", "--limit", "0"]).is_err());
        assert!(Cli::try_parse_from(["fsblame", "blame", "--ring-size", "4M"]).is_err());
    }

    #[test]
    fn journal_sizes_are_at_least_64k() {
        assert_eq!(parse_journal_size("64M"), Ok(64 << 20));
        assert_eq!(parse_journal_size("100000"), Ok(100_000));
        assert_eq!(parse_journal_size("3G"), Ok(3 << 30));
        assert_eq!(
            parse_journal_size("63K"),
            Err("must be at least 64K".to_owned())
        );
    }

    #[test]
    fn shorthand_paths_and_subcommands_both_parse() {
        Cli::command().debug_assert();
        let cli = Cli::try_parse_from(["fsblame", "a", "b"]).unwrap();
        assert!(cli.command.is_none());
        assert_eq!(cli.watch.paths, [PathBuf::from("a"), PathBuf::from("b")]);

        let cli = Cli::try_parse_from(["fsblame", "watch", "a", "--op", "write,rename", "--json"])
            .unwrap();
        let Some(Command::Watch(args)) = cli.command else {
            panic!("not watch");
        };
        assert_eq!(args.trace.filter.op, [Op::Write, Op::Rename]);
        assert!(args.view.json);

        assert!(Cli::try_parse_from(["fsblame", "doctor"]).is_ok());
        assert!(Cli::try_parse_from(["fsblame", "watch"]).is_err());
        assert!(Cli::try_parse_from(["fsblame", "watch", "a", "--op", "chmode"]).is_err());

        let cli = Cli::try_parse_from(["fsblame", "completions", "zsh"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Completions { shell: Shell::Zsh })
        ));
        assert!(Cli::try_parse_from(["fsblame", "completions", "tcsh"]).is_err());
        let cli = Cli::try_parse_from(["fsblame", "watch", "completions"]).unwrap();
        let Some(Command::Watch(args)) = cli.command else {
            panic!("not watch");
        };
        assert_eq!(args.paths, [PathBuf::from("completions")]);
    }

    #[test]
    fn ring_sizes_are_binary_powers_of_two_in_range() {
        assert_eq!(parse_ring_size("16M"), Ok(16 << 20));
        assert_eq!(parse_ring_size("256k"), Ok(256 << 10));
        assert_eq!(parse_ring_size("1G"), Ok(1 << 30));
        assert_eq!(parse_ring_size("524288"), Ok(512 << 10));
        assert_eq!(
            parse_ring_size("3M"),
            Err("must be a power of two, such as 2M or 4M".to_owned())
        );
        assert_eq!(
            parse_ring_size("128K"),
            Err("must be from 256K to 1G".to_owned())
        );
        assert!(parse_ring_size("2G").is_err());
        assert!(parse_ring_size("16MB").is_err());
        assert!(parse_ring_size("M").is_err());
        assert!(parse_ring_size("99999999999999G").is_err());
    }

    #[test]
    fn filters_take_repeats_and_comma_lists() {
        let cli = Cli::try_parse_from([
            "fsblame",
            "watch",
            "a",
            "--comm",
            "make,cc1",
            "--comm",
            "ld",
            "--uid",
            "0,1000",
            "--include",
            "*.rs",
            "--include",
            "a,b/**",
        ])
        .unwrap();
        let Some(Command::Watch(args)) = cli.command else {
            panic!("not watch");
        };
        let filter = &args.trace.filter;
        assert_eq!(filter.comm, ["make", "cc1", "ld"]);
        assert_eq!(filter.uid, [0, 1000]);
        // Globs may contain commas: --include is not split.
        let globs: Vec<String> = filter.include.iter().map(ToString::to_string).collect();
        assert_eq!(globs, ["*.rs", "a,b/**"]);
        assert_eq!(args.trace.ring_size, 16 << 20);
        assert_eq!(args.view.color, ColorMode::Auto);
        assert!(Cli::try_parse_from(["fsblame", "watch", "a", "--include", "[a"]).is_err());
        assert!(Cli::try_parse_from(["fsblame", "watch", "a", "--ring-size", "3M"]).is_err());
    }
}
