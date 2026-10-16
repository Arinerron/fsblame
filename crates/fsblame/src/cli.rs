//! Command-line interface.
//!
//! Depends only on clap, [`crate::ops`] and [`crate::glob`]: `cargo xtask man` compiles this
//! file into the xtask binary to render the man pages, without building the BPF object. The
//! `--version` text with the BPF ABI hash is added at run time by the binary's entry point.

use std::{path::PathBuf, time::Duration};

use clap::{Args, Parser, Subcommand, ValueEnum};
use clap_complete::Shell;

use crate::{glob::Glob, ops::Op};

/// Smallest `--ring-size`.
const RING_MIN: u64 = 256 << 10;
/// Largest `--ring-size`.
const RING_MAX: u64 = 1 << 30;

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
    /// Check whether this system can run fsblame, and how to fix it if not.
    Doctor(DoctorArgs),
    /// Print a shell completion script to stdout.
    Completions {
        /// The shell to generate for.
        shell: Shell,
    },
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
    /// Kernel ring buffer size, such as 4M or 64M: a power of two from 256K to 1G (K, M
    /// and G are binary). Raise it when fsblame warns that records were lost.
    #[arg(long, value_name = "SIZE", default_value = "16M", value_parser = parse_ring_size)]
    pub ring_size: u32,
    /// Color human output: auto (when stdout is a terminal and `NO_COLOR` is unset or
    /// empty), always, or never.
    #[arg(long, value_name = "WHEN", value_enum, default_value_t = ColorMode::Auto)]
    pub color: ColorMode,
    /// Print only warnings and errors on stderr, not the start banner or the final count.
    #[arg(long, short)]
    pub quiet: bool,
    /// When stopping, print a summary of the changes grouped by build step or command.
    #[arg(long)]
    pub summary: bool,
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

/// `4096K`, `16M`, `1G` as bytes (binary units; a bare number is bytes), if a power of two
/// from 256K to 1G: the kernel needs a ring buffer of a power-of-two number of pages.
fn parse_ring_size(text: &str) -> Result<u32, String> {
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
    let bytes = number
        .parse::<u64>()
        .ok()
        .and_then(|n| n.checked_mul(1 << shift))
        .ok_or_else(|| format!("{text:?} is not a size such as 4M or 64M"))?;
    let show = |bytes: u64| match bytes.trailing_zeros() {
        30.. => format!("{}G", bytes >> 30),
        20.. => format!("{}M", bytes >> 20),
        _ => format!("{}K", bytes >> 10),
    };
    if !(RING_MIN..=RING_MAX).contains(&bytes) {
        return Err(format!(
            "must be from {} to {}",
            show(RING_MIN),
            show(RING_MAX)
        ));
    }
    if !bytes.is_power_of_two() {
        let below = 1 << bytes.ilog2();
        return Err(format!(
            "must be a power of two, such as {} or {}",
            show(below),
            show(below << 1)
        ));
    }
    Ok(u32::try_from(bytes).expect("at most 1G"))
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
        assert_eq!(args.comm, ["make", "cc1", "ld"]);
        assert_eq!(args.uid, [0, 1000]);
        // Globs may contain commas: --include is not split.
        let globs: Vec<String> = args.include.iter().map(ToString::to_string).collect();
        assert_eq!(globs, ["*.rs", "a,b/**"]);
        assert_eq!(args.ring_size, 16 << 20);
        assert_eq!(args.color, ColorMode::Auto);
        assert!(Cli::try_parse_from(["fsblame", "watch", "a", "--include", "[a"]).is_err());
        assert!(Cli::try_parse_from(["fsblame", "watch", "a", "--ring-size", "3M"]).is_err());
    }
}
