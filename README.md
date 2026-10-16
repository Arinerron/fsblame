# fsblame

**Which command changed this file?** fsblame watches files and directory trees and prints every
modifying operation — writes, creates, renames, links, deletes, chmod/chown/truncate — with the
full lineage of the process that made it: its argv and cwd, every ancestor up to init, the
systemd unit, and the build step it ran under (npm/pnpm/yarn lifecycle script, cargo build
script, make, pip). It uses eBPF (fentry on the VFS security hooks, sched tracepoints for
lineage), so it sees every process, including ones that exited long before you looked.

```console
$ sudo fsblame watch ~/.cache/fsblame-demo/src ~/.cache/fsblame-demo/dist --depth 2 --duration 4s
fsblame: watching /home/aaron/.cache/fsblame-demo/src, /home/aaron/.cache/fsblame-demo/dist for all ops; Ctrl-C to stop
~/.cache/fsblame-demo/dist/bundle.tmp  created  10:42:49  (0644)
  └─ cp src/index.js dist/bundle.tmp                      (pid 1585232, cwd ~/.cache/fsblame-demo)   [unit kitty-3186744-4.scope]   [npm lifecycle: build demo-app@2.1.0 · high]
     └─ sh -c 'cp src/index.js dist/bundle.tmp && mv dist/bundle.tm…  (pid 1585230)
        └─ omp                                            (pid 3526622, cwd /tmp)
           └─ … 6 more ancestors
~/.cache/fsblame-demo/dist/bundle.tmp  modified  10:42:49  (+17 B, 2 writes)
  └─ cp src/index.js dist/bundle.tmp                      (pid 1585232, cwd ~/.cache/fsblame-demo)   [unit kitty-3186744-4.scope]   [npm lifecycle: build demo-app@2.1.0 · high]
     └─ sh -c 'cp src/index.js dist/bundle.tmp && mv dist/bundle.tm…  (pid 1585230)
        └─ omp                                            (pid 3526622, cwd /tmp)
           └─ … 6 more ancestors
~/.cache/fsblame-demo/dist/bundle.tmp → ~/.cache/fsblame-demo/dist/bundle.js  renamed  10:42:49
  └─ mv dist/bundle.tmp dist/bundle.js                    (pid 1585233)   [unit kitty-3186744-4.scope]   [npm lifecycle: build demo-app@2.1.0 · high]
     └─ sh -c 'cp src/index.js dist/bundle.tmp && mv dist/bundle.tm…  (pid 1585230)
        └─ omp                                            (pid 3526622, cwd /tmp)
           └─ … 6 more ancestors
~/.cache/fsblame-demo/dist/bundle.js  chmod  10:42:49  (0644 → 0755)
  └─ chmod 755 dist/bundle.js     (pid 1585230)   [unit kitty-3186744-4.scope]   [npm lifecycle: build demo-app@2.1.0 · high]
     └─ omp                       (pid 3526622, cwd /tmp)
        └─ zsh                    (pid 3526447, cwd ~)
           └─ … 5 more ancestors
fsblame: 4 changes reported
```

Above, an npm-style build script (`npm_lifecycle_event=build`) ran
`sh -c 'cp src/index.js dist/bundle.tmp && mv dist/bundle.tmp dist/bundle.js; chmod 755 dist/bundle.js'`.
`--json` prints one NDJSON object per change (`op`, `path`, `old_path`, `target`, `bytes`,
`proc`, `ancestry`, `context`, `origin`).

## Use

```sh
sudo fsblame watch ~/proj                         # or: fsblame ~/proj
sudo fsblame watch ~/proj --op write,rename --exclude ~/proj/target --duration 5m
sudo fsblame watch ~/proj --json > changes.ndjson
sudo fsblame doctor ~/proj                        # can it run here? which ops are available?
```

To run without sudo, grant the binary its capabilities once (not on `/tmp` or another `nosuid`
mount): `sudo setcap cap_bpf,cap_perfmon+ep ~/.local/bin/fsblame`.

Requirements: Linux ≥ 5.17 with BTF (`/sys/kernel/btf/vmlinux`), x86_64 or another architecture
with fentry support; `fsblame doctor` checks everything and says how to fix what is missing.

## Build

```sh
export TMPDIR=~/.cache/fsblame-tmp CARGO_TARGET_DIR=~/.cache/fsblame-target
cargo build --release --target x86_64-unknown-linux-musl   # static binary; needs clang
cargo xtask test-e2e                                       # end-to-end tests (passwordless sudo)
```

See [AGENTS.md](AGENTS.md) for the architecture, the BPF verifier constraints and the tests.

## Status

MVP. Local filesystems only (overlay, network and FUSE filesystems are flagged by `doctor`);
the cwd of a process that exits before its event is handled may be missing.
