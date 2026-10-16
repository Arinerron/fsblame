//! fsblame: which command changed this file?
//!
//! Watches files and directory trees with eBPF and reports every modifying operation with the
//! lineage of the process behind it. The binary is a thin wrapper around [`main`]; the modules
//! are public for benchmarks and fuzzing.
//!
//! Exit codes: 0 clean stop, 2 usage, 4 privileges, 5 kernel unsupported, 6 runtime error.

pub mod cli;
pub mod clock;
pub mod doctor;
pub mod engine;
pub mod fail;
pub mod filter;
pub mod glob;
pub mod ops;
pub mod record;
pub mod render;
pub mod roots;
pub mod tracer;
pub mod watch;

use std::{
    io::{self, Write as _},
    process::ExitCode,
    sync::LazyLock,
};

use clap::{CommandFactory as _, FromArgMatches as _};

use crate::{
    cli::{Cli, Command},
    fail::Failure,
};

/// `--version` text: the version, the BPF ABI the binary was built against, and exit codes.
/// Set here rather than in [`cli`] so the man page generator can compile `cli.rs` without the
/// BPF object.
static LONG_VERSION: LazyLock<String> = LazyLock::new(|| {
    format!(
        "{}\nBPF ABI {:#018x}\nexit codes: 0 stopped cleanly, 2 usage, 4 privileges, 5 kernel unsupported, 6 runtime error",
        env!("CARGO_PKG_VERSION"),
        fsblame_bpf::ABI_HASH
    )
});

/// Minimal stderr logger for the `log` macros; `FSBLAME_LOG=debug` enables debug output.
struct StderrLog;

impl log::Log for StderrLog {
    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
        metadata.level() <= log::max_level()
    }

    fn log(&self, record: &log::Record<'_>) {
        if self.enabled(record.metadata()) {
            eprintln!(
                "fsblame: {}: {}",
                record.level().as_str().to_lowercase(),
                record.args()
            );
        }
    }

    fn flush(&self) {}
}

fn init_log() {
    static LOGGER: StderrLog = StderrLog;
    let level = match std::env::var("FSBLAME_LOG").as_deref() {
        Ok("trace") => log::LevelFilter::Trace,
        Ok("debug") => log::LevelFilter::Debug,
        Ok("info") => log::LevelFilter::Info,
        _ => log::LevelFilter::Warn,
    };
    if log::set_logger(&LOGGER).is_ok() {
        log::set_max_level(level);
    }
}

/// Parses the process arguments; on an error or `--help`/`--version` prints and exits as clap
/// does (exit 2 for usage errors).
fn parse_args() -> Cli {
    let mut command = Cli::command().long_version(LONG_VERSION.as_str());
    let mut matches = command.get_matches_mut();
    Cli::from_arg_matches_mut(&mut matches).unwrap_or_else(|e| e.format(&mut command).exit())
}

/// Writes the completion script for `shell` to stdout.
fn completions(shell: clap_complete::Shell) -> Result<(), Failure> {
    // Buffered: clap_complete panics on write errors (such as a closed pipe).
    let mut script = Vec::new();
    clap_complete::generate(shell, &mut Cli::command(), "fsblame", &mut script);
    io::stdout()
        .lock()
        .write_all(&script)
        .map_err(|e| Failure::Runtime(anyhow::Error::new(e).context("writing completions")))
}

/// The `fsblame` process: parses the arguments, runs the command and maps its outcome to the
/// documented exit code.
pub fn main() -> ExitCode {
    init_log();
    let cli = parse_args();
    let result = match &cli.command {
        Some(Command::Doctor(args)) => doctor::run(args),
        Some(Command::Watch(args)) => watch::run(args),
        Some(Command::Completions { shell }) => completions(*shell),
        None => watch::run(&cli.watch),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(failure) => {
            eprintln!("fsblame: {failure}");
            failure.exit_code()
        }
    }
}
