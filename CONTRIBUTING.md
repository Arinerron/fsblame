# Contributing to fsblame

Thanks for taking the time to help. Bug reports, fixes, kernel compatibility notes and new
tests are all welcome. This guide covers how to build and test fsblame and what a pull request
needs before it can be merged. [AGENTS.md](AGENTS.md) is the architecture and maintainer guide;
read it before changing the tracer, the wire format or the engine.

Everyone taking part in the project is expected to follow the
[Code of Conduct](CODE_OF_CONDUCT.md). Security problems go through the private process in
[SECURITY.md](SECURITY.md), not public issues.

## Getting the source

The shared crates (`wire`, `procctx`, `bpfdoctor`) live in the
[tracekit](https://github.com/Arinerron/tracekit) repository, pinned as a git submodule at
`./tracekit`. Clone with it:

```sh
git clone --recurse-submodules https://github.com/Arinerron/fsblame.git
```

or, in an existing clone:

```sh
git submodule update --init
```

Changes to tracekit belong in the tracekit repository; a pull request here only moves the
submodule pointer.

## Prerequisites

- **Rust**: the toolchain in [`rust-toolchain.toml`](rust-toolchain.toml) (stable, with
  clippy, rustfmt and the `x86_64-unknown-linux-musl` target); run `rustup toolchain install`
  in the checkout to install it.
  The minimum supported version is the `rust-version` in [`Cargo.toml`](Cargo.toml).
- **clang**: `crates/fsblame-bpf/build.rs` compiles the BPF objects with it
  (`-target bpf`). Set `CLANG=/path/to/clang` to use a specific one. No nightly Rust and no
  bpf-linker are needed.
- **A Linux kernel >= 5.17 with BTF** (`/sys/kernel/btf/vmlinux`) to run fsblame and the
  end-to-end tests. Building and the unit tests work on any Linux host.
- **Passwordless sudo** (`sudo -n`) and `setcap` (libcap) for `cargo xtask test-e2e` and
  `cargo xtask bench`.
- **Nightly Rust and cargo-fuzz** only for fuzzing.

## Building

Builds and the end-to-end work directories should not live on a small or `nosuid` tmpfs. If
your `/tmp` is one, point the temporary and target directories at a disk filesystem first:

```sh
export TMPDIR=~/.cache/fsblame-tmp CARGO_TARGET_DIR=~/.cache/fsblame-target
mkdir -p "$TMPDIR"
```

Then:

```sh
cargo build --release --target x86_64-unknown-linux-musl   # the shipped static binary (LTO, a few minutes)
cargo build -p fsblame                                      # fast debug build for iteration
cargo xtask man                                             # man pages, from the CLI definition
```

The release binary is at
`$CARGO_TARGET_DIR/x86_64-unknown-linux-musl/release/fsblame` (or under `target/` when
`CARGO_TARGET_DIR` is unset). Try it with:

```sh
sudo "$CARGO_TARGET_DIR/x86_64-unknown-linux-musl/release/fsblame" doctor
FSBLAME_LOG=debug sudo -E "$CARGO_TARGET_DIR/x86_64-unknown-linux-musl/release/fsblame" watch ~/proj
```

`FSBLAME_LOG=debug` prints per-program verifier instruction counts and full verifier logs.

## Tests and lints

Run these before opening a pull request; CI runs the same commands:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

### End-to-end tests

```sh
cargo xtask test-e2e                                                      # builds the release binary, runs every scenario
cargo xtask test-e2e --bin "$CARGO_TARGET_DIR/debug/fsblame" --only c,j   # a quick subset against a debug build
cargo xtask --help                                                        # usage and the list of scenarios
```

The suite runs fsblame against the running kernel. Run it as your normal user: it refuses to
run as root and calls `sudo -n` for each scenario. A typical scenario starts
`sudo -n fsblame watch --json` on a fresh directory, waits until every probe is attached, runs
a workload as you, stops the watcher with SIGINT and checks the NDJSON it printed; others run
`run`, `record` and `blame`, `doctor` or the completions the same way. The work
directory is `$FSBLAME_E2E_DIR` (default `~/.cache/fsblame-e2e`); it must be on a disk
filesystem that honours file capabilities, so tmpfs and `nosuid` mounts are refused.

CI runs the suite in [virtme-ng](https://github.com/arighi/virtme-ng) VMs on Linux 5.17 (the
oldest supported kernel), the 6.1, 6.6 and 6.12 LTS lines and the newest stable kernel. The
`e2e` job in [`.github/workflows/ci.yml`](.github/workflows/ci.yml) shows the exact `vng`
invocation if you want to reproduce a failure on one of those kernels locally. CI also builds
for aarch64 and smoke-tests the binary under qemu-user.

### Benchmarks

```sh
cargo xtask bench            # median of three runs per workload
cargo xtask bench --quick    # one run, fewer operations
cargo xtask bench --json     # one JSON object instead of the table
```

`bench` times synthetic workloads without fsblame and with `sudo -n fsblame watch --json`
attached, and reports fsblame's CPU time, peak memory and any lost events. Its work directory
is `$FSBLAME_BENCH_DIR` (default `~/.cache/fsblame-bench`). Include before and after numbers in
pull requests that touch the BPF programs, the drain loop or the engine.

### Fuzzing

The decoders are fuzzed with cargo-fuzz. `fuzz/` is a separate crate built with nightly:

```sh
cargo install cargo-fuzz
cd fuzz
cargo +nightly fuzz list                  # record_decode, report_line, glob_match
cargo +nightly fuzz run record_decode
```

CI runs each target for 60 seconds and uploads crashing inputs as the `fuzz-artifacts`
artifact. If you fix a crash, add a unit test with the crashing input next to the code it
exercises.

## Changing the BPF programs

`crates/fsblame-bpf/bpf/fsblame.bpf.c` runs inside the kernel verifier's budget of 1,000,000
processed instructions per program, and a change that looks harmless can multiply the verified
states. The full explanation is in the "Verifier budget" section of [AGENTS.md](AGENTS.md); in
short:

- Loop cursors that are used as memory offsets live in map values, not in the `bpf_loop`
  context on the stack.
- Clamp an offset to a compile-time constant mask right before each variable-length write;
  never bound it by another running scalar.
- No per-entry scans or string matching in the kernel. Copy raw data and filter it in
  userspace.
- Helper size arguments are constants or clamped to constants.

After a change, check the instruction counts with `sudo fsblame doctor --json | jq .ops` and
mention any program whose count grew noticeably in the pull request. The kernel/user record
layout is defined once in `crates/fsblame-abi` and rendered to a C header with static
assertions; change it there, never only on the C side.

## Coding standards

- `cargo fmt` formatting and a clean `cargo clippy --workspace --all-targets -- -D warnings`.
  The workspace enables `clippy::pedantic`; prefer fixing a lint to allowing it, and when an
  `#[allow]` is the right call, say why next to it.
- Every `unsafe` block carries a `// SAFETY:` comment explaining why it is sound
  (`unsafe_op_in_unsafe_fn` is denied).
- Public items and modules have doc comments that say what they do and why, including the
  kernel behaviour they depend on.
- Tests prove behaviour: what a user or a caller would notice if it broke (reported ops and
  paths, lineage, boundaries, error messages and exit codes). Engine logic gets unit tests;
  anything that depends on the kernel gets an end-to-end scenario.
- Keep the user-facing output stable. The NDJSON format is versioned; changes to it are noted
  in the changelog.
- Update [README.md](README.md) for user-visible changes, and [AGENTS.md](AGENTS.md) when you
  change the BPF programs, the wire ABI, the architecture or the end-to-end scenarios.

## Commit messages

Use a short, imperative subject line, prefixed with the area it touches, as in the existing
history:

```
engine: coalesce writes from a reused struct file
bpf: clamp the rename walk cursor before the second path
xtask: add an overlay scenario to test-e2e
```

Wrap the body at about 72 columns and explain why the change is needed, not only what it does.
Keep unrelated changes in separate commits.

## Pull requests

Before you open one:

- [ ] `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings` and
      `cargo test --workspace` pass.
- [ ] `cargo xtask test-e2e` passes on your kernel, if the change affects what fsblame reports
      (say which kernel you ran it on).
- [ ] New behaviour has tests; fixed bugs have a test that fails without the fix.
- [ ] README.md, CHANGELOG.md and the doc comments describe the change where users will see it.
- [ ] AGENTS.md is updated for BPF, ABI or architecture changes.

Small, focused pull requests are reviewed fastest. For a larger change or a new feature, open
an issue first so the design can be discussed before you invest the time.

## Reporting bugs

Open an issue with the bug report form. The most useful details are:

- the output of `sudo fsblame doctor --json` (add the paths you watch: `sudo fsblame doctor --json PATH...`),
- `fsblame --version`,
- the kernel version (`uname -r`) and the distribution,
- the exact commands that reproduce the problem, and what you expected to see,
- the filesystem involved, and whether it is an overlay, a container or a network or FUSE
  mount.

## License

fsblame is licensed under the [MIT License](LICENSE). By contributing, you agree that your
contributions are licensed under the same terms.
