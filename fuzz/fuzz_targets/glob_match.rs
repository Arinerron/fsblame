//! `--include` globs and the paths they are matched against: any pattern and any path bytes.
//! The input is split at its first NUL into the pattern and the path (a path never contains
//! a NUL). Compiling either fails with an error or yields a glob whose matching never panics.
#![no_main]

use std::{ffi::OsStr, os::unix::ffi::OsStrExt as _, path::Path};

use fsblame::glob::Glob;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    let (pattern, path) = match input.iter().position(|&b| b == 0) {
        Some(nul) => (&input[..nul], &input[nul + 1..]),
        None => (input, &[][..]),
    };
    let Ok(pattern) = std::str::from_utf8(pattern) else {
        return;
    };
    if let Ok(glob) = Glob::new(pattern) {
        let _ = glob.matches(Path::new(OsStr::from_bytes(path)));
    }
});
