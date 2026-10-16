//! Command-line interface.

use std::{path::PathBuf, sync::LazyLock, time::Duration};

use clap::{Args, Parser, Subcommand};

use crate::ops::Op;

static LONG_VERSION: LazyLock<String> = LazyLock::new(|| {
    format!(
        "{}\nBPF ABI {:#018x}\nexit codes: 0 stopped cleanly, 2 usage, 4 privileges, 5 kernel unsupported, 6 runtime error",
        env!("CARGO_PKG_VERSION"),
        fsblame_bpf::ABI_HASH
    )
});

/// Which command changed this file? Watches files and directory trees and prints every
/// modifying operation with the full lineage of the process that made it.
#[derive(Debug, Parser)]
#[command(
    name = "fsblame",
    version,
    long_version = LONG_VERSION.as_str(),
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
pub enum Command {
    /// Watch paths live and print each change with the process lineage behind it.
    Watch(WatchArgs),
    /// Check whether this system can run fsblame, and how to fix it if not.
    Doctor(DoctorArgs),
}

/// `fsblame watch`.
#[derive(Clone, Debug, Args)]
pub struct WatchArgs {
    /// Files or directories to watch; a directory includes its whole subtree.
    #[arg(required = true, value_name = "PATH")]
    pub paths: Vec<PathBuf>,
    /// Report only these operations: write, create, mkdir, mknod, symlink, link, unlink,
    /// rmdir, rename, chmod, chown, truncate, utimes, setattr.
    #[arg(
        long,
        value_delimiter = ',',
        value_name = "LIST",
        hide_possible_values = true
    )]
    pub op: Vec<Op>,
    /// Ignore changes below this path (repeatable).
    #[arg(long, value_name = "PATH")]
    pub exclude: Vec<PathBuf>,
    /// Stop after this long, such as 30s, 5m, 1h or 250ms.
    #[arg(long, value_name = "D", value_parser = parse_duration)]
    pub duration: Option<Duration>,
    /// Print NDJSON, one object per line.
    #[arg(long)]
    pub json: bool,
    /// Write `ready\n` to this file descriptor once attached, then close it.
    #[arg(long, value_name = "N")]
    pub ready_fd: Option<i32>,
    /// Ancestors shown per change in human output (JSON always has all).
    #[arg(long, value_name = "N", default_value_t = 4)]
    pub depth: usize,
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

/// `250ms`, `30s`, `5m`, `1h`; a bare number is seconds.
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
        _ => {
            return Err(format!(
                "unknown unit {unit:?} in {text:?}; use ms, s, m or h"
            ));
        }
    };
    Duration::try_from_secs_f64(value * scale).map_err(|e| format!("{text:?}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory as _;

    #[test]
    fn durations_accept_units_and_bare_seconds() {
        assert_eq!(parse_duration("250ms"), Ok(Duration::from_millis(250)));
        assert_eq!(parse_duration("1.5s"), Ok(Duration::from_millis(1500)));
        assert_eq!(parse_duration("2m"), Ok(Duration::from_secs(120)));
        assert_eq!(parse_duration("7"), Ok(Duration::from_secs(7)));
        assert!(parse_duration("5d").is_err());
        assert!(parse_duration("s").is_err());
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
        assert_eq!(args.op, [Op::Write, Op::Rename]);
        assert!(args.json);

        assert!(Cli::try_parse_from(["fsblame", "doctor"]).is_ok());
        assert!(Cli::try_parse_from(["fsblame", "watch"]).is_err());
        assert!(Cli::try_parse_from(["fsblame", "watch", "a", "--op", "chmode"]).is_err());
    }
}
