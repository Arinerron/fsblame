# Security policy

fsblame loads BPF programs into the kernel and reads the command lines, working directories
and environments of other users' processes, so security problems in it matter. Thank you for
reporting them responsibly.

## Supported versions

Security fixes go into the latest release. Older releases are not patched; please upgrade to
the newest version from the [releases page](https://github.com/Arinerron/fsblame/releases)
before reporting, if you can.

## Reporting a vulnerability

Please do not open a public issue, pull request or discussion for a security problem.

Report it privately through GitHub's private vulnerability reporting: open the repository's
**Security** tab and choose **Report a vulnerability**, or go directly to
<https://github.com/Arinerron/fsblame/security/advisories/new>. If that is not possible, use
the contact details on the maintainer's GitHub profile, <https://github.com/Arinerron>.

Please include:

- the fsblame version (`fsblame --version`) or the commit you tested,
- the kernel version (`uname -r`), the distribution and the architecture,
- how fsblame was run: as root under `sudo`, or with file capabilities from `setcap`, and
  which subcommand and options,
- the steps or a proof of concept that reproduce the problem,
- what an attacker gains and from which position (an unprivileged local user, a process in a
  container, someone who can write to a watched directory, and so on),
- the output of `sudo fsblame doctor --json`, if it is relevant.

## What to expect

fsblame is maintained by one person on a best-effort basis. You can expect an acknowledgement
within a week, and updates as the report is investigated. Once a fix is ready, it is released
and a GitHub security advisory is published, crediting you unless you prefer otherwise. Please
keep the details private until then.

## Scope

Issues that are in scope include, for example:

- **Privilege boundaries.** fsblame runs with `CAP_BPF` and `CAP_PERFMON`, either as root under
  `sudo` or through file capabilities granted with `setcap`. Anything that lets another user
  or a watched process abuse those privileges, such as making fsblame write, delete or follow
  files it should not, is in scope. Untrusted input reaches fsblame from file names, symlink
  targets, process command lines, environments, `/proc` and mountinfo.
- **`fsblame run`.** Under `sudo`, `run` drops the command it starts to the invoking user (from
  `SUDO_UID`/`SUDO_GID`, with that user's supplementary groups) before executing it, and checks
  that root cannot be regained. A way for the command to keep or regain root, capabilities or
  fsblame's open file descriptors is a vulnerability.
- **Journal confidentiality.** The journal written by `fsblame record` (default
  `/var/lib/fsblame`) holds the command lines and working directories of every user's
  processes. Its directory is created with mode 0700 and its files with mode 0600, so only the
  user running the recorder (root, under the shipped systemd unit or `sudo`) can read them. A
  way for another user to read or tamper with it, or to make fsblame write it elsewhere, is in
  scope.
- **The shipped systemd unit.** Weaknesses in the sandboxing or capability set of
  `contrib/systemd/fsblame-record.service`.
- **Report output.** Output that lets crafted file names or command lines inject terminal
  escape sequences into the tree view, or forge or break lines in the NDJSON output, is in
  scope.
- **Memory safety.** Crashes in record decoding or in parsing the journal, especially ones
  reachable from data a less privileged user controls.

Out of scope:

- Changes fsblame does not see because of a documented limitation (network and FUSE
  filesystems, overlays in other mount namespaces, the items under "Known limitations" in
  [AGENTS.md](AGENTS.md)), unless you can hide a change that fsblame claims to report.
- The information fsblame shows to whoever already has the privileges to run it: anyone with
  `CAP_BPF` and `CAP_PERFMON`, or root, can already observe these processes.
- Vulnerabilities in the kernel's BPF subsystem itself. Please report those to the kernel
  security team, <security@kernel.org>.
- Problems in the tracekit crates may be reported here; they are fixed in the
  [tracekit](https://github.com/Arinerron/tracekit) repository.
