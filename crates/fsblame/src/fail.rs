//! Command failures and their exit codes.

use std::{fmt, process::ExitCode};

/// Why a command stopped early. Each kind maps to a documented exit code.
#[derive(Debug)]
pub enum Failure {
    /// Bad arguments, such as a path that does not exist (exit 2, as clap's own errors).
    Usage(anyhow::Error),
    /// Missing capabilities or a refused `bpf(2)`; diagnostics were printed (exit 4).
    Privileges(anyhow::Error),
    /// The kernel lacks a required feature (exit 5).
    Unsupported(anyhow::Error),
    /// Anything else that went wrong after start-up (exit 6).
    Runtime(anyhow::Error),
}

impl Failure {
    /// The process exit code.
    pub fn exit_code(&self) -> ExitCode {
        ExitCode::from(match self {
            Self::Usage(_) => 2,
            Self::Privileges(_) => 4,
            Self::Unsupported(_) => 5,
            Self::Runtime(_) => 6,
        })
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (Self::Usage(e) | Self::Privileges(e) | Self::Unsupported(e) | Self::Runtime(e)) = self;
        write!(f, "{e:#}")
    }
}

impl From<anyhow::Error> for Failure {
    fn from(e: anyhow::Error) -> Self {
        Self::Runtime(e)
    }
}

/// The first OS error code in an error's source chain.
pub fn errno_of(e: &(dyn std::error::Error + 'static)) -> Option<i32> {
    let mut next = Some(e);
    while let Some(err) = next {
        if let Some(code) = err
            .downcast_ref::<std::io::Error>()
            .and_then(std::io::Error::raw_os_error)
        {
            return Some(code);
        }
        next = err.source();
    }
    None
}
