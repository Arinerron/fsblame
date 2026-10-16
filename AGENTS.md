# fsblame: notes for agents and maintainers

fsblame answers "which command changed this file?": it watches files and directory trees and
reports every modifying operation with the full lineage of the process behind it (argv, cwd,
ancestors, systemd unit or container, and the build step such as an npm `postinstall`). It is
a C CO-RE BPF object loaded with aya 0.14, shipped as one static musl binary for x86_64 and
aarch64. Users read [README.md](README.md); the NDJSON schema is [docs/json.md](docs/json.md).

## Layout

| Path | What |
|------|------|
| `crates/fsblame-abi` | Kernel/user ABI: `wire!` structs (`RecHeader`, `ForkRec`, `ExecRec`, `ExitRec`, `FsRec`, map keys and values, `DevFilter`) and `wire_consts!`. `build.rs` of `fsblame-bpf` renders it to `fsblame_wire.h`, which static-asserts every size and offset; change the ABI here, never only in C. |
| `crates/fsblame-bpf` | `bpf/fsblame.bpf.c` (the tracer), `bpf/probe.bpf.c` (do-nothing programs per attach point, for `doctor`), `bpf/vmlinux_min.h` (hand-written CO-RE subset of vmlinux.h; every struct is `preserve_access_index`), `bpf/include/bpf/` (vendored libbpf headers). `build.rs` compiles both objects with clang (`-target bpfel/bpfeb -O2 -g -mcpu=v3 -Wall -Werror`; `CLANG=` overrides) and writes the ABI hash shown by `--version`. |
| `crates/fsblame/src` | The CLI and library (modules are public for the fuzz targets and benches). |
| `xtask` | `cargo xtask test-e2e`, `bench`, `man`. `main.rs` has scenarios a..l and the harness; `e2e_core.rs` m..r; `e2e_features.rs` s..ac; `e2e_startup.rs` ad; `bench.rs` the benchmark. It compiles `cli.rs`, `clock.rs`, `glob.rs` and `ops.rs` in with `#[path]` to render man pages without building BPF. |
| `fuzz/` | cargo-fuzz crate (nightly, its own workspace): `record_decode`, `report_line`, `glob_match`. `corpus/` and `artifacts/` are gitignored. |
| `tracekit/` | Git submodule (tracekit v0.1.0): `wire` (ABI macros and header builder), `procctx` (process table, lineage, context, origin classification), `bpfdoctor` (shared checks). **Changes go to the tracekit repository**; here only the submodule pointer moves. |
| `contrib/systemd/` | `fsblame-record.service` (hardened `record` unit) and `fsblame.default` (`/etc/default/fsblame`); shipped in the release archives as `systemd/`. |
| `.github/` | `workflows/ci.yml`, `workflows/release.yml`, `actions/setup` (clang plus the pinned toolchain), issue and PR templates, dependabot. |

Modules of `crates/fsblame/src`:

| Module | Role |
|--------|------|
| `main.rs`, `lib.rs` | Entry point, `--version` text (with the BPF ABI hash), `FSBLAME_LOG` logger, dispatch, exit codes. |
| `cli.rs` | clap definitions. Shared argument groups: `FilterArgs` (watch, run, record, blame), `TraceArgs` (watch, run, record), `StopArgs` (watch, record), `ViewArgs` (watch, run, blame). Depends only on clap, `ops`, `glob`, `clock`. |
| `ops.rs` | `Op` (14 ops, names, verbs), `OpSet` (the BPF `op_mask`), `FS_HOOKS` (16 fentry/fexit hooks in attach order, each `Reports` or `Supplements(what is lost)`), `SCHED_HOOKS`, `EXEC_CWD_HOOK`. |
| `tracer.rs` | Opens the object, sets `.rodata`, resizes maps, fills `roots`, loads and attaches, classifies failures (`Cause`: verifier-limit, missing-hook, permission, verifier-rejected, error), sets `armed`, reads `stats`. `Tracer` keeps only the program links (`FdLink`; the kernel keeps the maps alive through the programs) and the four maps it uses (`events`, `writes`, `tracked`, `stats`); the rest of the aya object is dropped after loading. `TRACKED_MAX` = 65,536. |
| `btf.rs` | `KernelBtf::read` reads `/sys/kernel/btf/vmlinux` once; the same bytes give aya's parse (to load against) and, through fsblame's own raw BTF parser, kernel function prototypes (`security_inode_setattr` arity). `btf::loader` drops the copy aya's `EbpfLoader::new` parses on its own first, so one parse (about 16 MiB on 7.2) is in memory at a time; the tracer frees it after the last attach, before the ring is mapped. `doctor` shares one parse across its probe checks. |
| `roots.rs` | Watch roots: canonicalizes paths, pins `(dev, ino)`, nested mounts, overlay model, excludes, device filter, path rebuild (`Roots::path`), mountinfo parsing. |
| `ring.rs` | Reader of the `events` ring buffer: maps the consumer page read-write and the producer and data pages once, read-only (aya's `RingBuf` maps the data twice, all resident, which showed the 16 MiB ring as 32 MiB of RSS); copies the one record per lap that wraps into a reused buffer. Keeps aya's memory ordering (acquire header and producer loads, release consumer store, fence before rechecking). |
| `record.rs` | Decodes ring buffer items (`Record::{Fork, Exec, Exit, Fs}`) and their payloads; never panics (fuzzed). |
| `engine.rs` | Records to touches: feeds procctx, write bindings and windows, exec/exit flushes, lineage cache, filter, emits `ChangeReport`s. `engine_tests.rs` drives it with synthetic records, a fake `writes` map and `/proc` fixtures. |
| `watch.rs` | The drain loop shared by watch, record and run (`run`, `follow`, `Follow`), signals via signalfd, epoll, loss meters, banners, `--tree`. |
| `run.rs` | `fsblame run`: fork, park the child until it is tracked, drop to the sudo user, exec; pidfd for the end; exit status passthrough. |
| `report.rs` | The report model: `Line` (`touch`, `lost`, `summary`), schema version, `LineEncoder` (reuses encoded lineages, 64 slots), `Summary`. |
| `render.rs` | Sinks: `Human` (tree view, color palette, `~` for home) and `Json`. |
| `filter.rs`, `glob.rs` | Change selection (cheapest test first: pid, uid, comm, ignore_comm, unit, include) and byte-wise gitignore-style globs (never allocate while matching; fuzzed). |
| `journal.rs` | `fsblame record` (`journal::command`, the watch loop with a journal sink) and the rotating NDJSON journal: `fsblame-<UTC start>.ndjson`, one `write(2)` per line and nothing buffered (a crash can only tear the last line), dir 0700 and files 0600, rotation at `--max-size`, oldest beyond `--keep` deleted, first file created at the first line. |
| `blame.rs` | `fsblame blame`: reads the journal files in name order through one buffer, pre-checks each line's timestamp and the queried path as a JSON substring before parsing, matches a change by any of its paths component-wise (as given, with parent symlinks resolved, and canonical), keeps a `--limit` ring, skips torn lines, and renders through the `watch` sinks. |
| `doctor.rs` | `doctor` and the `watch` preflight: bpfdoctor's shared checks plus fsblame's probes and `fsblame.watchfs`. |
| `clock.rs` | `CLOCK_BOOTTIME` to wall clock, RFC 3339 formatting and parsing. |
| `fail.rs` | `Failure` and its exit codes. |

## Build, run, test

`/tmp` on the maintainer host is a small `nosuid` tmpfs. Build with:

```sh
export TMPDIR=~/.cache/fsblame-tmp CARGO_TARGET_DIR=~/.cache/fsblame-target
mkdir -p "$TMPDIR"

cargo build --release --target x86_64-unknown-linux-musl   # shipped static-pie binary (LTO)
cargo build -p fsblame                                       # fast debug build for iteration
cargo test --workspace                                       # unit tests
cargo clippy --workspace --all-targets -- -D warnings        # clippy::pedantic is on
cargo xtask test-e2e                                         # builds release, runs every scenario
cargo xtask test-e2e --bin "$CARGO_TARGET_DIR/debug/fsblame" --only c,j   # quick subset
cargo xtask bench --quick                                    # what watching costs
cargo xtask man                                              # man pages into $CARGO_TARGET_DIR/man
```

Run:

```sh
BIN=$CARGO_TARGET_DIR/x86_64-unknown-linux-musl/release/fsblame
sudo $BIN watch ~/proj                       # tree view; Ctrl-C stops and flushes
sudo $BIN watch ~/proj --json --duration 30s --op write,rename --exclude ~/proj/target
sudo $BIN run -- sh -c 'echo hi > ~/x'       # one command's changes, anywhere
sudo $BIN doctor ~/proj                      # what works here and why not
sudo $BIN doctor --json ~/proj | jq .ops     # per-op availability and verifier insns
FSBLAME_LOG=debug sudo -E $BIN watch ~/proj  # per-program verifier insns, full verifier logs on failure
```

Exit codes: 0 clean stop, 2 usage, 4 privileges, 5 kernel unsupported, 6 runtime error; `run`
passes the command's status through (128 + N for signal N, 127 not found, 126 not
executable).

## Architecture

```mermaid
flowchart LR
  K["fentry security_inode_*, security_file_*, rw_verify_area, security_mmap_file, fexit vfs_rename"] -->|FsRec| R[("events ring buffer (--ring-size)")]
  S["tp_btf sched_process_fork/exec/exit"] -->|"ForkRec, ExecRec, ExitRec"| R
  K -->|counts| M[("writes map: per-binding totals")]
  R --> W["watch.rs drain loop, 100 ms tick"]
  W --> E["engine.rs"]
  M -.polled.-> E
  E -->|"fork/exec/exit"| P["procctx ProcTable"]
  E -->|ChangeReport| O["render.rs tree / NDJSON, journal.rs"]
```

### Probes and attach points

Optional programs (`FS_HOOKS`, then `EXEC_CWD_HOOK`) are skipped with a warning naming what is
lost when they cannot attach for an `Unsupported` cause; a privilege failure aborts.

| Program | Attach | Role | Without it |
|---------|--------|------|------------|
| `on_rw_verify_area` | `fentry/rw_verify_area` | stashes the byte count of the write in flight, per CPU | writes reported without byte counts |
| `on_file_free` | `fentry/security_file_free` | ends an open instance of a `struct file` (`files` delete) | a reused `struct file` is told apart only by inode pointer and `i_generation`; successive opens of one file may be one window |
| `on_file_permission` | `fentry/security_file_permission` (`MAY_WRITE`, regular files) | write: counts into `writes`; the first write of a binding emits a record | write not reported |
| `on_mmap_file` | `fentry/security_mmap_file` | `mmap(MAP_SHARED, PROT_WRITE)` of a file open for writing: one record per binding (`F_MAPPED`, `MAP_VIA_MMAP`) | writes through shared mappings not reported |
| `on_file_mprotect` | `fentry/security_file_mprotect` | read-only shared mapping made writable (`MAP_VIA_MPROTECT`) | those writes not reported |
| `on_create` | `fentry/security_inode_create` | create; once `creates_confirmed` is set, leaves an `open(O_CREAT)` whose dentry is still `d_in_lookup` (`may_o_create` checks before the lookup) to `on_file_post_open` via `creating`, matched by dentry since an overlay runs its own upper-layer create in between | create not reported |
| `on_file_post_open` | `fentry/security_file_post_open` (Linux 6.9+) | reports such a create only if the open set `FMODE_CREATED`; sets `creates_confirmed` when it first runs | an `open(O_CREAT)` of an existing file not in the dentry cache is reported as a create |
| `on_mkdir`, `on_mknod`, `on_symlink`, `on_link`, `on_unlink`, `on_rmdir` | `fentry/security_inode_<op>` | that op | op not reported |
| `on_rename` | `fentry/security_inode_rename` | rename (new + old path, flags, replaced inode); bumps `dir_epoch` when a directory moves on a walked filesystem | always attached; without `--op rename` only the epoch bump survives dead-code elimination |
| `on_renamed` | `fexit/vfs_rename` | bumps `dir_epoch` again after a successful directory move: a scope walk between `on_rename`'s bump and `d_move` cached a verdict from the old tree | always attached; such a verdict lasts until the next directory rename |
| `on_setattr` | `fentry/security_inode_setattr` | chmod, chown, truncate, utimes, setattr (by `ia_valid`) | ops not reported |
| `on_exec_cwd` | `tp_btf/sched_process_exec`, attached before `on_exec` | walks the new image's cwd up to the mount-namespace root into `cwd_buf` | cwd read from `/proc` when the event is handled, too late for quick processes |
| `on_fork`, `on_exec`, `on_exit` | `tp_btf/sched_process_{fork,exec,exit}` | lineage records; `on_fork`/`on_exit` maintain `tracked` | **required**: load fails (exit 5) |

On 7.2.6 every hook is ftrace-attachable and in vmlinux BTF; `doctor` re-checks on any host
(`probe.fentry_security`, `probe.sched_tp`, `probe.ops`). `security_file_post_open` exists
from 6.9 only; everything else from the 5.17 floor.

`Tracer::load` attaches `on_exec_cwd`, then the sched tracepoints (lineage complete before the
first file event), then each wanted fentry/fexit hook. If no selected op has a reporting hook
the load fails with that hook's error. File hooks report nothing until the loader sets
`armed` (`.data.armed`) after the last attach: hooks are loaded, verified and attached one by
one, and without the gate early hooks reported for hundreds of milliseconds while later ones
(`on_rename`) were not attached. Every op starts at the same instant, before the
`fsblame: watching` line and `--ready-fd`; changes before it are not reported.

### Wire records (`fsblame-abi`)

Every record starts with `RecHeader { kind, op, flags, ts_ns }` (`CLOCK_BOOTTIME`).

- `ForkRec` (parent tgid, child tgid, child `start_boottime`) and `ExitRec` (tgid, `exit_code`,
  start): fixed size. Threads are not reported; `ExitRec` only for the last thread.
- `ExecRec` + payload: execve filename (`FILENAME_CAP` 256), the raw environment block, raw
  argv (`ARGV_CAP` 4 KiB, `F_ARGV_TRUNC`), then with `F_CWD` the cwd as dentry names leaf
  first up to the mount-namespace root (none: `/`; `F_CWD_TRUNC`: upper part missing). The
  environment is copied whole up to `ENV_CAP` (8 KiB); a longer one keeps its first and last
  halves (`F_ENV_TRUNC`) because tools append their variables (npm's `npm_lifecycle_event`
  follows the inherited environment); `Exec::env_entries` drops the two entries cut at the gap.
- `FsRec` + payload: `tgid`, `tid`, `ns_tgid` (pid in its own pid namespace, 0 in the initial
  one), `start_ns`, `comm`, `uid`, `dev`, `ino`, `mode`, `root`/`root2`, `path_len`/`path2_len`,
  `aux`/`aux2`, `bytes`, `file`. Paths are dentry names leaf first, NUL-terminated; `path2` is
  the rename's old name, the link's existing name, or a symlink's raw target
  (`root2 == ROOT_RAW`). `root` is a watch root id, `ROOT_FSROOT` (relative to the
  filesystem root, mapped back through mountinfo) or `ROOT_NONE`.

| op | path | path2 | aux | aux2 |
|----|------|-------|-----|------|
| `OP_WRITE` | file | – | replaced binding's bytes (`F_REPLACED`) | replaced binding's calls |
| `OP_WRITE` + `F_MAPPED` | file | – | `MAP_VIA_MMAP`/`MAP_VIA_MPROTECT` | – |
| `OP_RENAME` | new name | old name | rename flags | inode replaced at the new name |
| `OP_LINK` | new link | existing name | – | – |
| `OP_SYMLINK` | new link | target (`ROOT_RAW`) | – | – |
| `OP_MKNOD` | node | – | `rdev` | – |
| `OP_CHMOD`… | file | – | `ia_valid` | new mode, size, or `uid << 32 \| gid` |

Flags: `F_PATH_TRUNC` 1, `F_PATH2_TRUNC` 2, `F_REPLACED` 4, `F_MAPPED` 8, `F_ARGV_TRUNC` 16,
`F_ENV_TRUNC` 32, `F_CWD` 64, `F_CWD_TRUNC` 128.

### Maps and globals

| Map | Type, size | Purpose |
|-----|------------|---------|
| `events` | ringbuf, `--ring-size` (default 16 MiB, power of two 256K..1G) | all records |
| `roots` | hash, resized to the root count | `(dev, ino)` → watch root id or `ROOT_F_EXCLUDE` |
| `verdicts` | LRU 65,536 | dentry → `{parent, ino, epoch, root, depth}` |
| `writes` | LRU 16,384 | `(tgid, struct file)` → `{dev, ino, bytes, calls, first_ns, last_ns}`; polled by userspace |
| `mapped` | LRU 4,096 | `(tgid, struct file)` → reported writable mapping `{ino, start_ns, first_ns, dev}` |
| `files` | LRU 16,384 | `struct file` → open instance `{since, inode ptr, i_generation}` |
| `creating` | LRU 4,096 | tid → dentry of a pending `open(O_CREAT)` |
| `tracked` | hash, 1 entry, or `TRACKED_MAX` when following | tgids whose changes are reported (`run`, `--tree`) |
| `stash` | per-CPU array 1 | byte count of the write in flight |
| `fs_buf` | per-CPU array, `OP_COUNT + 3` slots | record scratch; each reporting program owns a slot (`SLOT_MMAP`, `SLOT_MPROTECT`, `SLOT_POST_OPEN` after the op slots) |
| `exec_buf` | per-CPU array 1 | exec record scratch |
| `cwd_buf` | per-CPU array 1 | the cwd `on_exec_cwd` walked, keyed by `bprm` and tgid, consumed by `on_exec` |
| `stats` | per-CPU array, `STAT_COUNT` | `STAT_RING_DROPS`, `STAT_TRACK_FULL` |

| Global | Section | Meaning |
|--------|---------|---------|
| `self_tgid`, `op_mask`, `dev_filter` | `.rodata` | fsblame's own pid (never reported), selected ops (bit `1 << OP_*`), superblocks holding roots (`MAX_DEVS` 16; count 0 disables the filter) |
| `scope` | `.rodata` | `SCOPE_ROOTS` (watch roots), `SCOPE_ALL` (`run` without paths: every non-pseudo filesystem, no walk), `SCOPE_ALL_EXCLUDES` (the same, walking the excluded superblocks) |
| `track` | `.rodata` | report only tgids in `tracked` |
| `setattr_idmap` | `.rodata` | `security_inode_setattr` takes a leading idmap (6.0+, and backports such as EL9's 5.14); set from the BTF prototype by `btf.rs` |
| `dir_epoch`, `creates_confirmed` | `.bss` | verdict invalidation counter; set by `on_file_post_open` on its first run |
| `armed` | `.data.armed` | start gate; its own map so the loader writes it without touching `.bss` |

The verifier treats `.rodata` as constants: deselected ops, tracking off and `SCOPE_ROOTS`
compile away.

### Watched-path matching

Userspace (`Roots::resolve`) canonicalizes each watch and exclude path and pins it by
`(superblock dev, inode)`. Every mount below a watch root becomes an extra ("nested") root,
because the kernel walk does not cross mounts; mounts made after start are not added. A path
through `/proc/<pid>/root` or `cwd` into another mount namespace is refused
(`roots::canonical`); the error names where this namespace sees the same file. In the
kernel, `scope_of(dentry, dev)`:

1. Beyond the roots (`scope != SCOPE_ROOTS`): pseudo and kernel-internal filesystems
   (`SB_KERNMOUNT`, proc, sysfs, cgroup, devpts, debugfs, tracefs, bpffs, securityfs, ...) are
   out; otherwise the default verdict is `ROOT_FSROOT`, and with `SCOPE_ALL` that is final.
2. `dev_filter`: one compare per watched superblock; other filesystems cost nothing more.
3. `verdicts` LRU keyed by dentry pointer, valid while the dentry's parent, inode number and
   `dir_epoch` match. `on_rename` bumps `dir_epoch` when a directory moves on a walked
   filesystem, `on_renamed` again after the move.
4. Otherwise a `bpf_loop(SCOPE_WALK_MAX = 4096)` `d_parent` walk looking each ancestor's inode
   up in `roots`; the first root or exclude wins (an exclude gives `ROOT_NONE`; a watch root
   inside an exclude wins over it). The verdict records the root id and the depth. 4096 hops
   cover any path the kernel resolves in one call (`PATH_MAX` holds at most 2048 names), so a
   change deeper than the `WALK_MAX` (64) names a record carries is still reported, truncated.

Overlays (module docs of `roots.rs`): a change through an overlay's merged view reaches the
hooks twice in the same process, as the overlay's operation and as overlayfs's operations on
the upper layer (plus copy-up or whiteout steps in its work directory). fsblame reports only
the overlay's, at the merged path: `Roots::resolve` excludes the `upperdir=`/`workdir=` of
every overlay it watches (or everywhere under `run`), watches a path inside an upper layer
through its merged counterpart, and brings an overlay's merged view into scope when its upper
layer lies in a watched tree. Relative layer options (Docker and Podman use them for long
layer lists) are resolved below the ancestors of the mount point, confirmed by the `work`
subdirectory. Merged-view roots are identified by mountinfo's device and `stat`'s inode
number. With layers on several filesystems and xino off, overlayfs renumbers directory inodes
on every load and they can equal a file's, so roots below such an overlay's root are held
open and `fsblame.watchfs` warns. Before Linux 6.9 overlayfs opened a layer's file under the
overlay's path (`open_with_fake_path`, from 6.6 a backing file), so a write through the
overlay passed the write hook again with that file; `layer_file()` (its inode is not its
dentry's) makes `on_file_permission` and `report_mapped` skip it. `security_file_mprotect`
gets the layer's file on every kernel, so mprotect-made writable mappings of overlay files are
not reported.

### Path reconstruction

`emit_names` walks `d_parent` again and writes up to `depth` names (at most `WALK_MAX` = 64),
leaf first, into the slot's scratch, at most `PATH_CAP` (1024) bytes per path; userspace
(`Roots::path`) reverses them and joins them to the root's canonical path. A side outside
every root (`ROOT_FSROOT`) is walked to its filesystem root and mapped back through the
mountinfo read at start; an unknown device renders as `<dev M:m>/...`. Cut walks set
`F_PATH_TRUNC`/`F_PATH2_TRUNC` and render as `root/…/<lowest names>`.

### Writes

`on_rw_verify_area` stashes the requested count per CPU (with file and tid); the
`security_file_permission(MAY_WRITE)` that follows consumes it. A binding is
`(tgid, struct file)` in `writes`, valid for one open instance of that `struct file`:
`file_since()` keeps `files[file] = {since, inode, i_generation}`, `on_file_free` deletes it,
and a binding counts as current only if `first_ns >= since` and its dev/ino match. The slab
hands a freed `struct file` straight back and ext4 reuses inode numbers, so without this the
writes of distinct files merged. Only a binding's first write emits a record; a stale binding
is replaced and its final totals ride along (`F_REPLACED`, `aux`/`aux2`). Shared writable
mappings use `mapped` the same way and are reported once per binding, outside coalescing.

Userspace (`engine.rs`) keeps a `Binding` per kernel binding and sums them into a `Window` per
`(tgid, start time, file)`, so a process that opens, appends and closes one file 200 times
reports one change. Bindings are polled every 100 ms while active (1 s after 5 s idle). A
window is reported when the file has been quiet 200 ms (`QUIET_NS`) or open 1 s (`HOLD_NS`),
when the process execs or exits, before any other change to the same inode (causal order),
or at stop. A binding the LRU evicted is counted as `write-evicted`.

### Lineage

`engine.rs` feeds fork/exec/exit to `procctx::ProcTable`. The fork event's parent wins over
the exec record's `real_parent` (the reaper if the parent already exited). On exec, the
process's pending write windows are flushed first, so `sh -c 'echo x >> f; exec mkdir d'`
attributes the write to `sh`, not `mkdir`; on exit, they are flushed while the record is
still live. The exec record's cwd is used; a process without one (it predates fsblame, or the
walk failed) gets `/proc/<pid>/cwd` on its first file event. The lineage last built for a
process is reused while its chain holds the same records (`lineages`, `LineageId`), and the
NDJSON encoder reuses the encoded lineage. `classify_origin` derives the build step
(npm/pnpm/yarn/bun lifecycle, cargo build script, make, pip) from the allow-listed
environment of the chain.

### Tracking (`run`, `watch --tree`)

With `track` set only tgids in `tracked` are reported. `on_fork` adds the new process of a
tracked one (counting `STAT_TRACK_FULL` when the map is full); `on_exit` removes it. Every
reporting path checks this after its scalar tests and before `scope_of`. `run` forks the
command, which parks on a pipe until its pid is in `tracked`, so tracking covers it from its
first instruction; it then drops to `SUDO_UID`/`SUDO_GID` (with supplementary groups),
restores signal handling and execs. `--tree` seeds each pid, then its `/proc/<pid>/task/*/children`
recursively (needs `CONFIG_PROC_CHILDREN`, else exit 5). fsblame must run in the initial pid
namespace.

### Userspace pipeline

`watch::watch` runs the preflight, resolves roots, loads the tracer, then loops on epoll
(ring buffer, signalfd, the follower's pidfd) with a 100 ms tick: drain, `Engine::poll`,
`lost` lines (at most one per reason per second), flush the 64 KiB output buffer. On stop it
drains for up to 1 s, finishes every window, writes the remaining losses and the summary.
Human output writes losses to stderr; NDJSON writes them as lines. A closed pipe ends the run
cleanly. `record` uses the same loop with a `journal::Writer` sink; `blame` replays journal
lines through the same sinks, so its tree view is byte-identical to `watch`'s.

## Verifier budget (read before touching `fsblame.bpf.c`)

The verifier stops at 1,000,000 processed instructions per program (`E2BIG`, "BPF program is
too large"). `bpf_loop` callbacks are verified until the loop state converges; imprecise
scalars are widened, but a *precise* scalar (used as a memory offset or helper size) in the
caller's stack frame takes a new value every iteration, so every iteration is a new state. Two
dentry walks in one program (rename, link) multiplied that past the limit.

Rules:

- **Loop state used as offsets lives in map values, not in the `bpf_loop` context on the
  stack.** `fs_scratch.cur` holds the path-walk write cursor, and the walk's end state (`cut`,
  `top`) lives there too: on the stack, each way the walk can stop was a state of its own for
  the rest of the program (2x the instructions, 6x for rename/link). `cwd_scratch.cur` likewise.
- **Clamp to a compile-time constant right before a variable-length write**, never bound it
  by another running scalar: `pos = s->cur; if (pos > FS_DATA_MASK) pos = FS_DATA_MASK;
  bpf_probe_read_kernel_str(&s->data[pos], NAME_CAP, ...)`. Buffers carry slack after the
  mask for the largest single write; the logical offsets never reach the mask.
- **Combine flags without branches after a walk** (`*trunc |= s->cut | (whole & (s->top ^ 1))`):
  a branch splits every later state.
- **No per-entry scans or string matching in the kernel.** The environment is copied raw (head
  and tail) and filtered by procctx.
- **Size arguments are constants or clamped** (`ENV_CAP / 2`, `ARGV_CAP`, `PATH_CAP`,
  `CWD_BYTES`).
- **Heavy walks get their own program.** The cwd walk is `on_exec_cwd`, so `on_exec` loads
  without its budget; they meet in `cwd_buf`.
- **`bpf_core_read` relocates every member access in its source expression.** Reading a field
  of a local struct inside it (`bpf_core_read(&x, sizeof(x), &((struct vfsmount *)w.mnt)->...)`
  with `w` a `struct cwd_walk`) emits a CO-RE relocation against a type the kernel's BTF does
  not have, and the load fails. Copy the local field to a variable first, then read through it.
- **Arity that differs across kernels:** `on_setattr` reads its arguments from `ctx` in two
  `asm` branches selected by `.rodata` `setattr_idmap`. The verifier refuses ctx reads past
  the prototype, so only the live branch may load them, and `asm` keeps clang from merging the
  two into one load at a computed offset.
- **Fields that moved:** use `bpf_core_enum_value_exists`/`bpf_core_field_exists` (see
  `in_lookup()`: `DCACHE_PAR_LOOKUP` became an enum in 6.15).

Verified instruction counts on 7.2.6 (`FSBLAME_LOG=debug`, or `sudo fsblame doctor --json | jq .ops`
for the reporting programs):

| Program | Insns | Program | Insns |
|---------|------:|---------|------:|
| `on_rename` | 3,208 | `on_symlink` | 1,011 |
| `on_link` | 3,126 | `on_file_post_open` | 983 |
| `on_file_permission` | 1,606 | `on_mknod` | 976 |
| `on_exec` | 1,511 | `on_mkdir` | 968 |
| `on_file_mprotect` | 1,296 | `on_unlink`, `on_rmdir` | 950 |
| `on_mmap_file` | 1,295 | `on_exec_cwd` | 319 |
| `on_setattr` | 1,036 | `on_renamed` | 62 |
| `on_create` | 1,030 | `on_exit`, `on_fork` | 44, 41 |
| `on_file_free` | 32 | `on_rw_verify_area` | 20 |

Before the cursor rule, single-walk programs took 95k to 392k and rename/link more than
1,000,000. Tracking and `SCOPE_ALL_EXCLUDES` add code (`run` without paths: rename about
6,300). Mention any count that grows noticeably in the pull request.

The loader asks for verifier statistics only (`VerifierLogLevel::STATS`); `FSBLAME_LOG=debug`
adds the instruction trace. A full trace of a program at the limit is hundreds of megabytes
and aya re-verifies with ever larger buffers, which turned a rejected program into a
multi-minute "hang" at start-up.

## Privileges

fsblame needs `CAP_BPF` and `CAP_PERFMON`; `CAP_SYS_PTRACE` adds argv, cwd and environment of
other users' processes that started before fsblame (also under `hidepid=`), and
`CAP_DAC_READ_SEARCH` lets the service resolve paths in other users' private directories.
Either `sudo`, or `sudo setcap cap_bpf,cap_perfmon+ep /path/to/fsblame` once (ignored on
`nosuid` mounts such as `/tmp`). Without them the preflight prints the failing checks,
including the `setcap` line, and exits 4. `run` under sudo drops the command to the invoking
user; `record`'s journal is 0700/0600.

## Doctor

`fsblame doctor [--json] [PATH...]` runs bpfdoctor's shared checks (platform x86_64/aarch64,
kernel version against `min_kernel` 5.17, BTF, capabilities, file caps, nosuid, no_new_privs,
lockdown, LSMs, sysctls, memlock, namespaces, seccomp, cgroup2, hidepid, ring buffer, memcg)
plus:

- `probe.fentry_security`: an fentry trampoline attaches to `security_inode_unlink`, then to
  every `FS_HOOKS` function (probe object).
- `probe.sched_tp`: the three sched `tp_btf` tracepoints attach.
- `probe.ops`: loads every optional program of the **real** tracer, shaped for the given
  paths, and reports each op as available or disabled with a cause: `verifier-limit`
  (E2BIG/ENOSPC; "on_X exceeded the BPF verifier instruction limit (N insns > 1,000,000)"),
  `missing-hook` (not in BTF / not ftrace-attachable), `permission` (EPERM/EACCES before
  verification: caps or lockdown), `verifier-rejected`, `error`. A missing supplementing hook
  (such as `security_file_post_open` before 6.9) makes it warn with what is lost. `--json`
  adds `ops: [{name, status, reason, program, insns, detail}]`.
- `fsblame.watchfs`: INFO for paths in an overlay's merged view, in an upper layer, or holding
  upper layers; WARN for an overlay with repeating inode numbers, an overlay whose `upperdir=`
  is not found here, and network (nfs, cifs, 9p, ceph, ...) and FUSE filesystems.

`watch`, `run` and `record` run the fast preflight subset (`platform.os_arch`,
`kernel.version`, `kernel.btf`, capabilities, nosuid, nnp, lockdown, namespaces, plus
`fsblame.watchfs`) and refuse to start on a required failure: exit 5 when only `kernel.`,
`platform.` or `probe.` checks failed, else 4. The version check is by number, so a 5.14
kernel with backported `bpf_loop` (EL9) is refused.

## Tests

### Unit tests

`cargo test --workspace`. `engine_tests.rs` drives the engine with synthetic records, a fake
`writes` map and per-test `/proc` fixtures (write windows, replacement, eviction, exec/exit
flushes, lineage). `report.rs` round-trips every line type. `glob.rs`, `filter.rs`, `cli.rs`,
`journal.rs`, `blame.rs`, `roots.rs` (mountinfo, overlay rules) and `btf.rs` have their own.

### End-to-end (`cargo xtask test-e2e`)

Runs as the normal user (refuses root), calls `sudo -n` per scenario, works in
`$FSBLAME_E2E_DIR` (default `~/.cache/fsblame-e2e`; refuses tmpfs and `nosuid`). A watching
scenario starts `sudo -n fsblame watch --json` on a fresh directory, waits for the
`fsblame: watching` line (never a sleep), runs its workload, sends SIGINT (sudo relays it) and
asserts on the NDJSON, usually that exactly the expected set of changes was reported.

| id | asserts |
|----|---------|
| a | `dd conv=fsync` → `write`, `bytes > 0`, `proc.comm == "dd"` |
| b | `touch` + `rm` → `create` and `unlink` |
| c | `mv` across two watch roots → `rename` with `old_path`; `ln` → `link` with `target` |
| d | `chmod 600` → `chmod`, `change.mode == "0600"` |
| e | `mkdir -p a/b/c` + deep write → `mkdir` x3 and `create`/`write` with full paths |
| f | `sh -c 'sh -c "sleep 0.3; echo x > f" & exit 0'` → writer `sh`, parent the exited outer `sh`, chain reaches the xtask pid |
| g | npm lifecycle env → `origin.kind == "npm-lifecycle"`, package `demo`, phase `postinstall` |
| h | unprivileged run → exit 4, stderr has `setcap cap_bpf,cap_perfmon+ep` |
| i | `setcap` copy in `$FSBLAME_E2E_DIR/bin` run as the user → write reported; caps removed after |
| j | `doctor --json` → all 14 ops available, `probe.ops` pass (or warn only for hooks absent from BTF), rename/link insns < 1,000,000 |
| k | `--duration 2s` → exits 0 about 2 s after attaching |
| l | overlay in the work dir, whole tree watched: append to a cold lower file, chmod, rm, create + write, mkdir → each once at its merged path, nothing under `upper/` or `work/` (one create for the append allowed without `security_file_post_open`) |
| m | `--exclude`: nothing below the exclude, siblings sharing its name prefix reported, a watch root inside the exclude wins, a rename out of it has `old_path` |
| n | ext4 loop mount and a tmpfs on top of it below the root → full paths through both |
| o | directory moves in, out and within the tree invalidate cached verdicts (dir_epoch) |
| p | 200-byte names past `PATH_CAP`, and a chain past `WALK_MAX` (64 names whole, 100 cut) → `root/…/<lowest names>`, `truncated` exactly where cut |
| q | hard links across roots, into one and out of one → exact absolute `target`s |
| r | 256K ring, fsblame `SCHED_IDLE` on a CPU an exec storm saturates → `ring-full` lines while running, totals match summary and stderr, later write still reported, exit 0 |
| s | `mmap` twice through one open file and `mprotect` of another → one write each, `change.mapped` |
| t | `sh -c 'cd sub && exec mv a b'` → rename's `proc.cwd` is `sub` (exec-time cwd) |
| u | `run --json -o FILE` → the command's changes in the work dir and `/dev/shm`, as the invoking uid, unrelated writer excluded; `run -- sh -c 'exit 7'` exits 7 |
| v | `watch --tree` → only the tree's changes, including a child it starts; missing pid exits 2 (exit 5 without `CONFIG_PROC_CHILDREN`) |
| w | `--include`, `--ignore-comm`, `--comm`, `--pid` in four parallel watchers → exact sets and matching summaries |
| x | `record` + `blame`: 0700/0600 journal, exact lines, `--limit`, `--since`, unprivileged exit 4, human blame identical to live watch |
| y | bash, zsh, fish completions name every subcommand and parse |
| z | `v` on every line, `--summary`, `-q` with `--ready-fd`, `--color always/never/auto` on a pty, `NO_COLOR` |
| aa | 300 recycled struct files and inode numbers stay 300 writes; 200 reopen-append rounds are one write with `calls == 200` |
| ab | `sh -c 'echo x >> f; exec mkdir d'` → the write is `sh`'s, not `mkdir`'s |
| ac | after `drop_caches`, `>>` to an existing file → one write, no create when `security_file_post_open` exists |
| ad | 20,000-file churn started at the `fsblame: watching` line → every change reported or counted in `lost` lines and the summary |

### CI, release and the kernel matrix

`ci.yml`: `lint` (fmt, clippy `-D warnings`), `build-test` (static musl build checked with
`file`, unit tests, completions and man smoke, uploads `fsblame` + `xtask`), `aarch64` (check,
static build via `rust-lld`, `--version` and completions under qemu-user), `fuzz` (each target
60 s on nightly, crashing inputs uploaded), `e2e` (needs `build-test`; the full suite under
virtme-ng on Ubuntu mainline kernels v5.17.15, v6.1.190, v6.6.159, v6.12.113, v7.2.6).
`release.yml`: a `v*` tag builds both targets, packages
`fsblame-<tag>-<arch>-linux-musl.tar.gz` (binary, LICENSE, README, `completions/`, `man/`,
and `contrib/systemd` as `systemd/`) with a `.sha256` each, and publishes a GitHub release
with generated notes.

Reproduce a matrix kernel locally (vng downloads and caches the kernel), from a directory
holding prebuilt `fsblame` and `xtask` binaries:

```sh
truncate -s 1G e2e.img && mkfs.ext4 -q -F e2e.img
vng --run v6.1.190 --disable-microvm --user "$USER" --memory 4G --cpus 4 --disk e2e.img \
  --exec 'set -e; export FSBLAME_E2E_DIR=/tmp/e2e; uname -r; sudo mkdir -p /tmp/e2e; sudo mount /dev/vda /tmp/e2e; sudo chown $(id -u):$(id -g) /tmp/e2e; ./xtask test-e2e --bin ./fsblame --only a,j' < /dev/null
```

Gotchas:

- `--disable-microvm`: the microvm machine hangs at ACPI init with Ubuntu mainline kernels.
- Keep `--exec` short: vng passes it on the kernel command line, and an over-long one hangs
  the guest silently. vng returns the guest's exit code.
- The guest sees the host's root filesystem read-only over virtiofs, with a RAM overlay on
  `/home` and `/etc`; on 5.17, `mkdir` in that overlay fails with `ENOSYS`. Scratch goes on
  the ext4 image (`/dev/vda`): the suite refuses tmpfs and needs file capabilities.
- Prebuild the binaries; the guest needs no network or toolchain. `< /dev/null` keeps vng off
  the terminal.
- Never stop a `sudo`-started fsblame with SIGSTOP in tests: without a pty, sudo stops itself
  too and stays stopped after SIGCONT, so the SIGINT never arrives.

## Bench (`cargo xtask bench [--bin PATH] [--quick] [--json]`)

Five workloads (exec storm, file churn, writes inside, writes outside, mmap churn) run as the
user, pinned to the fastest CPU, without and with `sudo -n fsblame watch --json watched/`;
median of three (one with `--quick`). Reports ops/s both ways, overhead, fsblame's CPU since
attaching (10 ms resolution) and per op, touches, `ring-full` and `write-evicted` losses, and
peak RSS (`VmHWM`). Work dir `$FSBLAME_BENCH_DIR` (default `~/.cache/fsblame-bench`).
Kernel-side overhead varies by about plus or minus four points between runs. On 7.2.6 (Core
Ultra 7 155H, load about 5): exec +3.5%, 35 µs CPU per exec; churn +22.7%, 41 µs per file
(four changes); writes inside +32.6% (2 touches for 2M writes); outside +19.3%; mmap +4.6%;
peak RSS 23.5 MiB (idle RSS about 19 MiB: roughly 2.5 MiB plus the ring). Post numbers
before and after for changes to the BPF programs, the drain loop or the engine.

## Fuzz

```sh
cd fuzz && cargo +nightly fuzz run record_decode   # or report_line, glob_match
```

`record_decode`: any bytes decode to a record or `Malformed`, accessors never panic.
`report_line`: any text either fails to parse or round-trips stably after one normalization.
`glob_match`: pattern and path split at the first NUL; compile errors or a match, never a
panic. Add a unit test with each crashing input next to the code it exercises.

## Known limitations

- Only changes after the `fsblame: watching` line; history needs `record`.
- Network and FUSE filesystems: other clients' changes are never seen, and a FUSE daemon's
  writes to its backing store are attributed to the daemon (`fsblame.watchfs` warns).
- An overlay mounted in another mount namespace (rootless Podman) is not visible, so its upper
  layer is reported as a plain directory. Writes through a shared mapping of an overlay file
  made writable by `mprotect(2)` are not seen on any kernel.
- Mounts made below a watch root after start are not watched; `ROOT_FSROOT` paths on devices
  mounted after start render as `<dev M:m>/...` (mountinfo is read once).
- A path longer than `PATH_CAP` (1024 bytes) or `WALK_MAX` (64) names below its root is cut at
  the top and marked truncated.
- cwd is captured at exec (inherited at fork); a later `chdir` of a running process is not
  seen.
- argv beyond 4 KiB is cut; an environment longer than 8 KiB loses its middle, and variables
  set there are not seen by origin detection.
- `bytes` is the count requested by each write call. Stores through a shared mapping are
  reported once, when the mapping becomes writable.
- Before 6.9 (no `security_file_post_open`), an `open(O_CREAT)` of an existing file whose name
  is not in the dentry cache is reported as a create.
- `run`/`--tree` follow the process tree only: work started on the command's behalf elsewhere
  (systemd units, D-Bus activation, dockerd) is missed; `run` stops when the command exits;
  under `--tree`, a descendant re-parented away before seeding reached it is missed.
- fsblame must run in the initial pid namespace.
