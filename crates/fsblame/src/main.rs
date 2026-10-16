//! fsblame: which command changed this file? See the library crate for the implementation.
//!
//! Exit codes: 0 clean stop, 2 usage, 4 privileges, 5 kernel unsupported, 6 runtime error.

use std::process::ExitCode;

fn main() -> ExitCode {
    fsblame::main()
}
