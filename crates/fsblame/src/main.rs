//! fsblame: which command changed this file?
//!
//! Exit codes: 0 clean stop, 2 usage, 4 privileges, 5 kernel unsupported, 6 runtime error.

mod cli;
mod clock;
mod doctor;
mod engine;
mod fail;
mod ops;
mod record;
mod render;
mod roots;
mod tracer;
mod watch;

use std::process::ExitCode;

use clap::Parser as _;

use crate::cli::{Cli, Command};

/// Minimal stderr logger for the `log` macros; `FSBLAME_LOG=debug` enables debug output.
struct StderrLog;

impl log::Log for StderrLog {
    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
        metadata.level() <= log::max_level()
    }

    fn log(&self, record: &log::Record<'_>) {
        if self.enabled(record.metadata()) {
            eprintln!("fsblame: {}: {}", record.level().as_str().to_lowercase(), record.args());
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

fn main() -> ExitCode {
    init_log();
    let cli = Cli::parse();
    let result = match &cli.command {
        Some(Command::Doctor(args)) => doctor::run(args),
        Some(Command::Watch(args)) => watch::run(args),
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
