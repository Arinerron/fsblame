# Changelog

All notable changes to fsblame are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). The NDJSON
output has its own schema version, the `v` field of every line; see
[docs/json.md](docs/json.md).

## [Unreleased]

## [0.1.1] - 2026-10-17

### Added

- `cargo install fsblame --locked`: fsblame is published on crates.io, as the crates
  `fsblame`, `fsblame-bpf` and `fsblame-abi`.
- More ways to install, see the README: an install script (`curl -fsSL
  https://github.com/Arinerron/fsblame/releases/latest/download/install.sh | sh`), `.deb`,
  `.rpm`, `.apk` and Arch packages attached to each release (with `SHA256SUMS`), the AUR
  packages `fsblame-bin` and `fsblame`, a Nix flake (`nix run github:Arinerron/fsblame`)
  with a NixOS module for the recording service, a container image
  (`ghcr.io/arinerron/fsblame`) and `cargo binstall fsblame`. The system and AUR packages
  install `fsblame-record.service`, not enabled, and keep your `/etc/default/fsblame` across
  upgrades.
- A new loss reason, `skipped`: runs of fsblame's kernel programs that the kernel skipped
  because the same program was already running on that CPU, which happens under heavy
  parallel load. It counts the programs whose skipped run can lose a change; those changes
  went missing silently before. The summary's `lost` object gains `skipped`.
- Release archives include `THIRD_PARTY_LICENSES.md`, the licenses of everything built into
  the binary.

### Changed

- `write-evicted` losses also count write totals whose record was dropped with the ring buffer
  full; the warning now reads "kernel write table or ring buffer full".
- `fsblame doctor` treats an empty `NO_COLOR` as unset, as `watch` does.
- Creates, mkdirs, mknods and symlinks report the inode number and mode the new file got
  (after the umask, a default ACL or a setgid directory), read once the operation succeeded.
  Before, only creates confirmed by `open` had the inode; the others had inode 0 and the mode
  the call asked for, as operations reported at their check still do.
- The man pages are rewritten, with exit status, environment, files and examples for each
  command; `man fsblame` gives the overview.
- The embedded BPF objects are reproducible: clang no longer records the build directory in
  their debug and BTF line info.

### Fixed

- Operations that failed are no longer reported, such as an `rmdir` of a directory that is
  not empty, a `chmod` or `chown` the kernel refused, or a rename onto a non-empty directory.
  Each operation is reported once its call has succeeded, stamped with the time it returned.
  Creates by `open(O_CREAT)` are confirmed this way on Linux 6.9 and newer.
- A `chown` of a setuid or setgid file is reported as a `chown`, not as a `chmod`.
- Symlink targets of 1024 bytes or more were cut without being marked; they are now cut at
  1023 bytes, end in `…` and are marked `truncated`.
- Writes through a descriptor kept open across a rename of its file (a log being rotated) are
  reported at the new name, and writes through one inherited across an exec carry the new
  program's name.
- Write totals that the kernel handed over while fsblame had not read the previous ones yet
  are no longer dropped.
- A step of the system clock (NTP's first sync, `date -s`) is applied to later timestamps;
  before, the offset taken at start was used for the whole run.
- Under `fsblame run`, a Ctrl-C after the command exited no longer cuts short the report of
  its last changes; SIGTERM and SIGHUP still do.

### Security

- The tree view shows control characters in reported text (file names, command lines, units
  and the rest) as visible escapes, and quotes arguments holding them as `$'...'`, so a
  crafted file name or command line can no longer inject terminal escape sequences or fake
  lines. `--json` is unchanged.
- `fsblame run -o FILE` refuses FIFOs, sockets and devices, and opens without blocking.
  Without sudo (run as root from `su` or cron), it now also requires an existing file to
  belong to the user fsblame runs as, and leaves the kernel's `fs.protected_regular` and
  `fs.protected_fifos` in force, so another user's file in `/tmp` can no longer be truncated
  through it.

## [0.1.0] - 2026-10-16

The first public release.

### Added

- `fsblame watch PATH...` (or just `fsblame PATH...`): reports every change to the watched
  files and directory trees as it happens: writes, creates, mkdir, mknod, symlinks, hard
  links, unlinks, rmdir, renames, chmod, chown, truncate, timestamp and other attribute
  changes, and writes through shared writable memory mappings.
- Each change comes with the process that made it and its full lineage: command line, working
  directory captured at exec, executable, uid, every ancestor up to init (also after they have
  exited), the systemd unit, container, tmux pane and cgroup, and the pid inside a container's
  pid namespace.
- Build-step detection from the process chain's environment: npm, pnpm, yarn and bun lifecycle
  scripts, cargo build scripts, pip builds and make, with the package, version, phase and a
  confidence.
- Writes are coalesced into one change per process and file, with the bytes requested and the
  number of calls, and reported in causal order with the other changes to the same file.
- `fsblame run [PATH...] -- CMD`: runs a command (as the invoking user under sudo) and reports
  every change it and its descendants make, on every filesystem or below the given paths, and
  exits with the command's status. `-o FILE` writes the report to a private file (mode 0600,
  owned by the invoking user; symbolic links and other users' files are refused).
- `fsblame watch --tree PID`: only the changes of a process and its descendants.
- `fsblame record` and `fsblame blame`: a rotating, private NDJSON journal of changes, and
  queries over it by path (any of a change's paths, including files that no longer exist),
  time (`--since`, `--until`) and count (`--limit`), shown in the same tree view as `watch`.
- A hardened systemd unit for `record`, `contrib/systemd/fsblame-record.service`, with its
  settings in `/etc/default/fsblame`.
- Filters shared by `watch`, `run`, `record` and `blame`: `--op`, `--include` (gitignore-style
  globs), `--comm`, `--ignore-comm`, `--uid`, `--unit`, `--pid`; and `--exclude` for subtrees.
- Output: a colored tree view (`--depth`, `--color`, `NO_COLOR`), versioned NDJSON (`--json`,
  schema version 1, documented in `docs/json.md`), an end-of-run summary grouped by build step
  or command (`--summary`), `--quiet`, `--duration` and `--ready-fd`.
- Stopping (Ctrl-C, SIGTERM, SIGHUP, `--duration`, or the end of `run`'s command) reports
  every change made before the stop, reading for up to 10 s if fsblame is behind; a second
  stop signal cuts that short.
- Loss reporting: records dropped with the ring buffer full, evicted write counts, untracked
  processes and records still unread when fsblame stopped are reported live as `lost` lines
  or warnings and in the totals, never silently; `--ring-size` sets the kernel ring buffer.
- Overlay filesystems (container root filesystems) are watched through their merged view, and
  each change is reported once, at its merged path.
- `fsblame doctor [--json] [PATH...]`: checks the kernel, BTF, privileges, lockdown and the
  watched filesystems, loads every tracer program and reports per operation whether this
  kernel can report it, with the verifier instruction counts, and how to fix what is missing.
- Runs with `sudo` or with file capabilities (`setcap cap_bpf,cap_perfmon+ep`); without
  privileges it says exactly what is missing.
- Static musl binaries for x86_64 and aarch64, published with SHA-256 checksums; each archive
  also holds shell completions (`fsblame completions`: bash, zsh, fish, elvish, PowerShell),
  man pages and the systemd unit.
- Modest footprint: an idle `watch` uses about 19 MiB of memory, most of it the kernel ring
  buffer (16 MiB by default; RSS is roughly 2.5 MiB plus `--ring-size`), and peaks at about
  24 MiB while loading.
- Linux 5.17 and newer with BTF. Opens with `O_CREAT` of existing files are told apart from
  real creates on Linux 6.9 and newer.

[Unreleased]: https://github.com/Arinerron/fsblame/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/Arinerron/fsblame/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/Arinerron/fsblame/releases/tag/v0.1.0
