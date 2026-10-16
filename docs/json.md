# NDJSON output, schema version 1

fsblame writes newline-delimited JSON: one UTF-8 JSON object per line, each with a `type` and
the schema version `v`. The same lines appear wherever fsblame writes JSON:

| Where | Lines |
|-------|-------|
| `fsblame watch --json` | stdout |
| `fsblame run --json` | stderr, or the file given with `-o`/`--output` (the command owns stdout) |
| `fsblame record` | the journal files, `fsblame-<UTC start time>.ndjson` in `--journal` |
| `fsblame blame --json` | stdout: the matching `touch` lines from the journal, plus the `lost` and `summary` lines recorded among them |

There are three line types:

| `type` | When |
|--------|------|
| [`touch`](#touch-one-change) | One change to a watched path. |
| [`lost`](#lost-data-the-kernel-side-could-not-deliver) | The kernel side lost data: at most one line per reason per second while running, and a final one at the end for anything not yet reported. |
| [`summary`](#summary-the-whole-run) | Once, as the last line, when `--summary` is given. |

Paths and command lines are Linux byte strings; bytes that are not valid UTF-8 are replaced
with U+FFFD. Times are RFC 3339 in UTC with microseconds, such as
`2026-10-16T22:11:26.804885Z`.

## Compatibility

- `v` is `1` on every line of this schema.
- Within version 1, fields are only ever added. No field is removed, renamed or given another
  type.
- Readers must ignore fields they do not know. fsblame itself does, so a newer journal stays
  readable by `fsblame blame` as long as `v` matches.
- A change that would break existing readers bumps `v`. fsblame refuses to read a line of
  another version: `report version 2 is not supported (this fsblame reads version 1)`.

Check `v` before relying on a line, and read fields by name, not by position.

## `touch`: one change

A real line from `fsblame watch --json ~/webapp` while `npm run build` copied a file (the
home directory renamed to `/home/alice`, the ancestry shortened to its first two entries):

```json
{
  "type": "touch",
  "v": 1,
  "ts": "2026-10-16T22:11:26.804885Z",
  "op": "write",
  "path": "/home/alice/webapp/dist/bundle.tmp",
  "old_path": null,
  "target": null,
  "truncated": false,
  "bytes": 21,
  "calls": 2,
  "file": { "dev": "253:0", "ino": 41499654, "mode": "100644" },
  "change": null,
  "tid": 3245791,
  "comm": "cp",
  "uid": 1000,
  "proc": {
    "pid": 3245791,
    "comm": "cp",
    "exe": "/usr/bin/cp",
    "argv": ["cp", "src/index.js", "dist/bundle.tmp"],
    "argv_truncated": false,
    "cwd": "/home/alice/webapp",
    "uid": 1000,
    "exited": false,
    "exit_ts": null
  },
  "ancestry": [
    {
      "pid": 3245789,
      "comm": "sh",
      "exe": "/usr/bin/sh",
      "argv": ["sh", "-c", "mkdir -p dist && cp src/index.js dist/bundle.tmp && mv dist/bundle.tmp dist/bundle.js && chmod 755 dist/bundle.js"],
      "argv_truncated": false,
      "cwd": "/home/alice/webapp",
      "uid": 1000,
      "exited": false,
      "exit_ts": null
    },
    {
      "pid": 3245777,
      "comm": "node",
      "exe": "/usr/bin/node",
      "argv": ["node", "/usr/bin/npm", "run", "build"],
      "argv_truncated": false,
      "cwd": "/home/alice/webapp",
      "uid": 1000,
      "exited": false,
      "exit_ts": null
    }
  ],
  "ancestry_complete": true,
  "context": {
    "unit": "kitty-3186744-14.scope",
    "container": null,
    "tmux": null,
    "cgroup": "/user.slice/user-1000.slice/user@1000.service/kitty-3186744-14.scope"
  },
  "origin": {
    "kind": "npm-lifecycle",
    "package": "webapp",
    "version": "1.4.2",
    "phase": "build",
    "confidence": "high",
    "via_pid": 3245791,
    "evidence": [
      "env:npm_lifecycle_event@3245791",
      "env:npm_package_name@3245791",
      "env:npm_config_user_agent@3245791"
    ]
  }
}
```

fsblame writes each line compactly, on one line; it is indented here for reading.

### Fields

| Field | Type | Null | Meaning |
|-------|------|------|---------|
| `type` | string | no | `"touch"`. |
| `v` | integer | no | `1`. |
| `ts` | string | no | When it happened. For a write, the time of the latest write call of the window. |
| `op` | string | no | The operation, see [Operations](#operations). |
| `path` | string | no | The absolute path changed: for a rename the new name, for a link or symlink the new link. |
| `old_path` | string | yes | The old name of a rename; `null` for every other op. |
| `target` | string | yes | `symlink`: the link's target text as stored, not resolved (`"util.js"`). `link`: the absolute path of the existing name the new link points at. `null` for every other op. |
| `truncated` | boolean | no | Upper components of `path`, `old_path` or `target` are missing: the kernel walk emits at most 1024 bytes or 64 names per path. A cut path keeps its lowest names and reads `<watch root>/…/<names>`. |
| `bytes` | integer | yes | Write windows: bytes requested by the window's write calls (the count passed to the call, not what it returned). `null` for every other op and for a shared mapping. |
| `calls` | integer | yes | Write windows: the number of write calls. `null` otherwise. |
| `file` | object | no | The file's identity, see below. |
| `change` | object | yes | What the operation changed, see [The `change` object](#the-change-object). `null` when there is nothing beyond the op. |
| `tid` | integer | no | The acting thread's id. |
| `comm` | string | no | The acting thread's name (`comm`, at most 15 bytes) at the time of the operation. |
| `uid` | integer | no | The acting thread's real uid at the time of the operation. |
| `ns_pid` | integer | absent | The acting process's pid inside its own pid namespace (a container). The field is left out when the process is in the initial pid namespace. |
| `proc` | object | no | The acting process, see [Process objects](#process-objects). |
| `ancestry` | array | no | The acting process's ancestors as process objects, parent first. Empty when fsblame does not know the process. |
| `ancestry_complete` | boolean | no | `true` when the chain ends at the root of the process tree, `false` when it stops at a process fsblame has no record of. |
| `context` | object | no | Where the process runs, see below. |
| `origin` | object | yes | The build step the process runs under, see below. `null` when none was recognized. |

All pids are as seen from the initial pid namespace, except `ns_pid`.

`file`:

| Field | Type | Meaning |
|-------|------|---------|
| `dev` | string | The filesystem's device number, `"MAJOR:MINOR"` (for an overlay, the overlay's own). |
| `ino` | integer | The inode number; `0` for a name that has no inode yet (`create`, `mkdir`, `mknod`, `symlink`), except a create confirmed after its `open` (see below), which has its new inode. |
| `mode` | string | The inode's `i_mode` in octal, such as `"100644"` (type and permission bits) at the time of the operation, so before a `chmod`. For `create`, `mkdir` and `mknod` the mode the caller asked for, before the umask (a create confirmed after its `open`: the new file's mode); `"0"` for `symlink`. |

A create "confirmed after its open" is an `open(O_CREAT)` of a name that was not in the
kernel's dentry cache. On Linux 6.9 and newer fsblame waits until the open has run, to report
it only if it did create the file; the file exists by then.

`context` (every field may be `null`):

| Field | Type | Meaning |
|-------|------|---------|
| `unit` | string | The systemd unit, such as `"nginx.service"` or `"session-3.scope"`. |
| `container` | string | `"RUNTIME:ID"`, such as `"docker:3f4e…"` with the full container id, or the machine name for LXC and systemd-nspawn. |
| `tmux` | string | The tmux pane, such as `"%3"`. |
| `cgroup` | string | The cgroup v2 path. |

`origin`:

| Field | Type | Null | Meaning |
|-------|------|------|---------|
| `kind` | string | no | `npm-lifecycle`, `pnpm-lifecycle`, `yarn-lifecycle`, `bun-lifecycle`, `cargo-build-script`, `pip-build`, `make`, or `other`. |
| `package` | string | yes | The package being built. |
| `version` | string | yes | Its version. |
| `phase` | string | yes | The lifecycle phase or script, such as `"postinstall"` or `"build"`. |
| `confidence` | string | no | `high`, `medium`, `low` or `unknown`. |
| `via_pid` | integer | no | The process (the actor or one of its ancestors) whose environment identified the step. |
| `evidence` | array of strings | no | The facts the classification rests on, such as `"env:npm_lifecycle_event@3245791"`. |

### Process objects

`proc` and each entry of `ancestry`:

| Field | Type | Null | Meaning |
|-------|------|------|---------|
| `pid` | integer | no | Process id. |
| `comm` | string | no | Process name. |
| `exe` | string | yes | The executable. |
| `argv` | array of strings | no | The arguments, the program name first. Empty when unknown. |
| `argv_truncated` | boolean | no | `argv` was cut at the kernel's capture limit (4096 bytes). |
| `cwd` | string | yes | The working directory: captured at exec, inherited at fork, or read from `/proc` for a process that started before fsblame. |
| `uid` | integer | yes | Real uid. |
| `exited` | boolean | yes | Whether the process had exited when the change was reported. `null` means fsblame has no record of the process: then only `pid`, `comm` and `uid` are filled in, and `ancestry` is empty. |
| `exit_ts` | string | yes | When it exited, if it has. |

### Operations

| `op` | Reported for |
|------|--------------|
| `write` | Data written to a regular file (`write`, `pwrite`, `writev`, `splice`, `copy_file_range`, `fallocate`, reflinks), coalesced into one line per process and file: the window closes once the file has been quiet for 200 ms, after 1 s, when the process execs or exits, before another change to the same file is reported, or when fsblame stops. Also a shared mapping of the file made writable (`change.mapped`). |
| `create` | A regular file created. |
| `mkdir` | A directory created. |
| `mknod` | A special file created (FIFO, socket, device node). |
| `symlink` | A symbolic link created. |
| `link` | A hard link created. |
| `unlink` | A name removed. |
| `rmdir` | A directory removed. |
| `rename` | A name moved. |
| `chmod` | Permissions changed. |
| `chown` | Owner or group changed. |
| `truncate` | Size changed (`truncate`, `O_TRUNC`). |
| `utimes` | Timestamps set (`utimensat`, `touch`). |
| `setattr` | Any other attribute change, such as the kernel clearing setuid bits. |

### The `change` object

Only the keys of the operation's kind are present:

| `op` | `change` | Example |
|------|----------|---------|
| `chmod` | `mode`, `old_mode`: permission bits as four octal digits | `{"mode":"0600","old_mode":"0644"}` |
| `chown` | `uid`, `gid`: the new owner and group; each only if it changed | `{"uid":1000,"gid":1000}` |
| `truncate` | `size`: the new size in bytes | `{"size":4}` |
| `mknod` | `rdev`: the device number, `"MAJOR:MINOR"` (`"0:0"` for FIFOs and sockets) | `{"rdev":"0:0"}` |
| `rename` | `exchange`: the two names swapped files (`RENAME_EXCHANGE`); `noreplace`: `RENAME_NOREPLACE` was asked for; `replaced`: an existing file at the new name was replaced | `{"exchange":false,"noreplace":false,"replaced":true}` |
| `write` (mapping) | `mapped`: `"mmap"` for `mmap(MAP_SHARED, PROT_WRITE)`, `"mprotect"` for a read-only shared mapping made writable; `bytes` and `calls` are `null`, since stores through a mapping make no write calls | `{"mapped":"mmap"}` |
| every other op, and write windows | `null` | |

A mapping is reported once per process and open file, when it becomes writable, not per store.

Further examples from one run (fields shown: `op`, `path`, `old_path`, `target`, `bytes`,
`calls`, `change`):

```json
{"op":"symlink","path":"/home/alice/webapp/src/current.js","old_path":null,"target":"util.js","bytes":null,"calls":null,"change":null}
{"op":"link","path":"/home/alice/webapp/src/util-hardlink.js","old_path":null,"target":"/home/alice/webapp/src/util.js","bytes":null,"calls":null,"change":null}
{"op":"chmod","path":"/home/alice/webapp/src/util.js","old_path":null,"target":null,"bytes":null,"calls":null,"change":{"mode":"0600","old_mode":"0644"}}
{"op":"write","path":"/home/alice/webapp/src/index.js","old_path":null,"target":null,"bytes":null,"calls":null,"change":{"mapped":"mmap"}}
{"op":"rename","path":"/home/alice/webapp/src/util.js","old_path":"/home/alice/webapp/src/next.js","target":null,"bytes":null,"calls":null,"change":{"exchange":false,"noreplace":false,"replaced":true}}
```

### Paths outside the watch roots

A rename or hard link with one side outside every watch root reports that side too, as an
absolute path resolved through the mount table fsblame read at start. So does `fsblame run`
without paths, which watches every filesystem. A change on a filesystem mounted after
fsblame started has no entry in that table and reads `<dev MAJOR:MINOR>/path/below/its/root`.

## `lost`: data the kernel side could not deliver

```json
{"type":"lost","v":1,"ts":"2026-10-16T22:11:46.612758Z","reason":"ring-full","count":3092}
```

| Field | Type | Meaning |
|-------|------|---------|
| `type` | string | `"lost"`. |
| `v` | integer | `1`. |
| `ts` | string | When fsblame noticed the loss. |
| `reason` | string | What was lost, see below. |
| `count` | integer | How many since the previous `lost` line of the same reason. |

| `reason` | `count` counts | What is missing |
|----------|----------------|-----------------|
| `ring-full` | records | The kernel ring buffer was full: changes, or the process events lineage is built from, were dropped. Raise `--ring-size`. |
| `write-evicted` | write bindings | The kernel's write table evicted open files before fsblame read their latest totals: their `bytes` and `calls` since the previous read are missing. |
| `track-full` | processes | `fsblame run` and `watch --tree` only: the table of followed processes was full (65,536 entries), so new processes started by followed ones were not followed, and their changes are missing. |

The counts of all `lost` lines of a run add up to the run's totals in the `summary` line and
in the warning fsblame prints on stderr when it stops. In human output, losses go to stderr
as warnings instead.

## `summary`: the whole run

Written last when `--summary` is given (from a real run, shortened to two groups):

```json
{
  "type": "summary",
  "v": 1,
  "ts": "2026-10-16T22:11:12.662355Z",
  "changes": 18,
  "lost": { "ring_full": 0, "write_evicted": 0, "track_full": 0 },
  "groups": [
    {
      "group": { "comm": "bash" },
      "changes": 4,
      "ops": { "write": 2, "create": 2 },
      "paths": 2,
      "paths_untracked": 0,
      "first_paths": ["/home/alice/webapp/src/util.js", "/home/alice/webapp/src/next.js"]
    },
    {
      "group": { "comm": "rm" },
      "changes": 3,
      "ops": { "unlink": 3 },
      "paths": 3,
      "paths_untracked": 0,
      "first_paths": [
        "/home/alice/webapp/src/util-hardlink.js",
        "/home/alice/webapp/tmp/pipe",
        "/home/alice/webapp/src/current.js"
      ]
    }
  ]
}
```

| Field | Type | Meaning |
|-------|------|---------|
| `type` | string | `"summary"`. |
| `v` | integer | `1`. |
| `ts` | string | When the run stopped. |
| `changes` | integer | Changes reported (after the filters). |
| `lost` | object | The run's losses: `ring_full` (records), `write_evicted` (write bindings), `track_full` (processes); see [`lost`](#lost-data-the-kernel-side-could-not-deliver). |
| `groups` | array | Changes grouped by build step, or by the acting process's `comm` when there is none. Most changes first, ties in the order they first changed something. |

Each group:

| Field | Type | Meaning |
|-------|------|---------|
| `group` | object or string | `{"origin":{"kind":…,"package":…,"version":…,"phase":…}}` (the fields as in `origin`, nullable the same way), `{"comm":"vim"}`, or the string `"other"`: the changes of every group beyond the first 32, listed last. |
| `changes` | integer | Changes in the group. |
| `ops` | object | Changes per op, only the ops that occurred, such as `{"write":3,"create":1}`. |
| `paths` | integer | Distinct paths changed, counted up to 1024 per group. |
| `paths_untracked` | integer | Changes to paths beyond those 1024, whose distinctness was not tracked; usually `0`. |
| `first_paths` | array of strings | Up to three distinct paths, in the order they changed. |

## jq recipes

These use [jq](https://jqlang.org/); `changes.ndjson` is the output of
`sudo fsblame watch ~/proj --json > changes.ndjson`, or of `sudo fsblame blame --json`.

One line per change, tab-separated:

```sh
jq -r 'select(.type == "touch") | [.ts, .op, .path, (.proc.argv | join(" "))] | @tsv' changes.ndjson
```

Everything that touched one file, under any of its names, with the chain of commands:

```sh
jq -c --arg p "$HOME/proj/package.json" '
  select(.type == "touch" and (.path == $p or .old_path == $p or .target == $p))
  | {ts, op, argv: .proc.argv, chain: [.ancestry[].comm]}' changes.ndjson
```

Changes per operation:

```sh
jq -s -c 'map(select(.type == "touch")) | group_by(.op) | map({op: .[0].op, changes: length})' changes.ndjson
```

Changes made by npm lifecycle scripts, with the package and phase:

```sh
jq -c 'select(.origin.kind == "npm-lifecycle") | {package: .origin.package, phase: .origin.phase, op, path}' changes.ndjson
```

The files written the most, by bytes:

```sh
jq -r 'select(.type == "touch" and .bytes != null) | "\(.bytes)\t\(.path)"' changes.ndjson | sort -rn | head
```

Losses per reason:

```sh
jq -s -c 'map(select(.type == "lost")) | group_by(.reason) | map({reason: .[0].reason, count: (map(.count) | add)})' changes.ndjson
```

A live, one-line-per-change feed:

```sh
sudo fsblame watch ~/proj --json | jq --unbuffered -r 'select(.type == "touch") | "\(.op) \(.path) by \(.proc.comm)"'
```
