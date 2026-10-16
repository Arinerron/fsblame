# Changelog

All notable changes to fsblame are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). The NDJSON
output has its own schema version, the `v` field of every line; see
[docs/json.md](docs/json.md).

## [Unreleased]

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

[Unreleased]: https://github.com/Arinerron/fsblame/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Arinerron/fsblame/releases/tag/v0.1.0
