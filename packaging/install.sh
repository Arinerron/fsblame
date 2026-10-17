#!/bin/sh
# Installs fsblame from its GitHub release (https://github.com/Arinerron/fsblame):
#
#   curl -fsSL https://github.com/Arinerron/fsblame/releases/latest/download/install.sh | sh
#
# Options (as `sh -s -- OPTIONS` when piped):
#   --prefix DIR   install to DIR/bin, DIR/share/... (env FSBLAME_PREFIX). Default:
#                  /usr/local (directly as root, else through sudo or doas), or ~/.local
#                  when neither is available.
# Environment:
#   FSBLAME_VERSION   release tag to install, e.g. v0.1.1 (default: the latest release)
#
# Downloads the static tarball for this machine and its .sha256, verifies it, and installs
# the binary, man pages, bash/zsh/fish completions and license files. No telemetry; it
# talks to github.com only. Running it again reinstalls (or upgrades) in place. The systemd
# unit stays in the tarball (README, Running as a service).
#
# This file is uploaded as the release asset install.sh by .github/workflows/packages.yml.

set -eu

repo=https://github.com/Arinerron/fsblame

say() { printf '%s\n' "$*"; }
die() {
	printf 'fsblame install: error: %s\n' "$*" >&2
	exit 1
}
has() { command -v "$1" >/dev/null 2>&1; }

usage() {
	cat <<'EOF'
Install fsblame from its GitHub release.

Usage: install.sh [--prefix DIR]

  --prefix DIR   install under DIR (env FSBLAME_PREFIX); default /usr/local, or
                 ~/.local without root, sudo or doas
  -h, --help     show this help

Environment: FSBLAME_VERSION=vX.Y.Z installs that release instead of the latest.
EOF
}

# download URL FILE
download() {
	if has curl; then
		curl -fsSL --proto '=https' --tlsv1.2 -o "$2" "$1"
	elif has wget; then
		wget -q -O "$2" "$1"
	else
		die "neither curl nor wget is installed"
	fi
}

# The tag /releases/latest redirects to.
latest_tag() {
	if has curl; then
		url=$(curl -fsSLI --proto '=https' --tlsv1.2 -o /dev/null -w '%{url_effective}' \
			"$repo/releases/latest") || return 1
	elif has wget; then
		url=$(wget -S --spider "$repo/releases/latest" 2>&1 |
			sed -n 's/^ *[Ll]ocation: *\([^[:space:]]*\).*/\1/p' | tail -n 1) || return 1
	else
		die "neither curl nor wget is installed"
	fi
	printf '%s\n' "${url##*/}"
}

sha256_check() {
	if has sha256sum; then
		sha256sum -c "$1" >/dev/null
	elif has shasum; then
		shasum -a 256 -c "$1" >/dev/null
	else
		die "neither sha256sum nor shasum is installed, cannot verify the download"
	fi
}

# writable DIR: DIR, or its closest existing ancestor, is writable by us.
writable() {
	d=$1
	while [ ! -e "$d" ]; do d=$(dirname "$d"); done
	[ -w "$d" ]
}

# physical FILE: FILE with its directory's symlinks resolved (/usr/local/sbin may be bin).
physical() { printf '%s/%s\n' "$(cd -P "$(dirname "$1")" 2>/dev/null && pwd -P)" "${1##*/}"; }

main() {
	prefix=${FSBLAME_PREFIX:-}
	while [ $# -gt 0 ]; do
		case $1 in
		--prefix)
			[ $# -ge 2 ] || die "--prefix needs a directory"
			prefix=$2
			shift 2
			;;
		--prefix=*)
			prefix=${1#--prefix=}
			shift
			;;
		-h | --help)
			usage
			exit 0
			;;
		*) die "unknown option: $1 (see --help)" ;;
		esac
	done

	os=$(uname -s)
	[ "$os" = Linux ] || die "fsblame runs on Linux only (it traces with eBPF), not on $os"
	case $(uname -m) in
	x86_64 | amd64) arch=x86_64 ;;
	aarch64 | arm64) arch=aarch64 ;;
	*) die "no release build for $(uname -m); fsblame supports x86_64 and aarch64 (or build from source: cargo install fsblame --locked)" ;;
	esac
	has tar || die "tar is not installed"
	has gzip || die "gzip is not installed"

	tag=${FSBLAME_VERSION:-}
	if [ -z "$tag" ]; then
		tag=$(latest_tag) || die "could not look up the latest release at $repo/releases/latest"
	fi
	case $tag in
	v*) ;;
	*) tag=v$tag ;;
	esac
	case $tag in
	v[0-9]*.[0-9]*.[0-9]*) ;;
	*) die "not a release tag: $tag (expected e.g. v0.1.1)" ;;
	esac

	default_prefix=
	case $prefix in
	'') prefix=/usr/local default_prefix=1 ;;
	/*) prefix=${prefix%/} ;;
	*) die "--prefix must be an absolute path: $prefix" ;;
	esac
	sudo=
	if ! writable "$prefix"; then
		if has sudo; then
			sudo=sudo
		elif has doas; then
			sudo=doas
		elif [ -n "$default_prefix" ] && [ -n "${HOME:-}" ]; then
			prefix=$HOME/.local
		else
			die "$prefix is not writable and neither sudo nor doas is available"
		fi
	fi

	name=fsblame-$tag-$arch-linux-musl
	tmp=$(mktemp -d) || die "could not create a temporary directory"
	trap 'rm -rf "$tmp"' EXIT
	trap 'exit 130' INT
	trap 'exit 143' TERM

	say "Downloading fsblame $tag ($arch)"
	base=$repo/releases/download/$tag
	download "$base/$name.tar.gz" "$tmp/$name.tar.gz" ||
		die "download failed: $base/$name.tar.gz (does release $tag exist?)"
	download "$base/$name.tar.gz.sha256" "$tmp/$name.tar.gz.sha256" ||
		die "download failed: $base/$name.tar.gz.sha256"
	(cd "$tmp" && sha256_check "$name.tar.gz.sha256") ||
		die "checksum mismatch for $name.tar.gz"
	tar -xzf "$tmp/$name.tar.gz" -C "$tmp" || die "could not unpack $name.tar.gz"
	src=$tmp/$name
	[ -x "$src/fsblame" ] || die "unexpected tarball layout: $name/fsblame is missing"

	bindir=$prefix/bin
	share=$prefix/share
	say "Installing to $prefix${sudo:+ (using $sudo)}"
	{
		$sudo mkdir -p "$bindir" "$share/man/man1" "$share/bash-completion/completions" \
			"$share/zsh/site-functions" "$share/fish/vendor_completions.d" \
			"$share/licenses/fsblame" &&
			$sudo install -m 755 "$src/fsblame" "$bindir/fsblame" &&
			$sudo install -m 644 "$src"/man/*.1 "$share/man/man1/" &&
			$sudo install -m 644 "$src/completions/fsblame.bash" \
				"$share/bash-completion/completions/fsblame" &&
			$sudo install -m 644 "$src/completions/_fsblame" "$share/zsh/site-functions/_fsblame" &&
			$sudo install -m 644 "$src/completions/fsblame.fish" \
				"$share/fish/vendor_completions.d/fsblame.fish" &&
			$sudo install -m 644 "$src/LICENSE" "$share/licenses/fsblame/" &&
			# 0.1.0's tarballs have no THIRD_PARTY_LICENSES.md.
			if [ -f "$src/THIRD_PARTY_LICENSES.md" ]; then
				$sudo install -m 644 "$src/THIRD_PARTY_LICENSES.md" "$share/licenses/fsblame/"
			fi
	} || die "could not install to $prefix (choose another with --prefix DIR, e.g. --prefix \$HOME/.local)"

	# --version prints the version, then the BPF ABI and the exit codes.
	version=$("$bindir/fsblame" --version) || die "the installed $bindir/fsblame does not run"
	version=$(printf '%s\n' "$version" | head -n 1)
	say "Installed $version: $bindir/fsblame"

	cmd=$bindir/fsblame
	case :${PATH:-}: in
	*:"$bindir":*)
		found=$(command -v fsblame || true)
		if [ "$(physical "$found")" = "$(physical "$bindir/fsblame")" ]; then
			cmd=fsblame
		elif [ -n "$found" ]; then
			say "Note: $found comes first in PATH"
		fi
		;;
	*) say "Note: $bindir is not in PATH" ;;
	esac
	case $share in
	/usr/share | /usr/local/share) ;;
	*) say "Note: for zsh completions, add $share/zsh/site-functions to fpath" ;;
	esac

	# sudo's secure_path covers only the system bin directories.
	case $bindir in
	/usr/bin | /usr/local/bin) sudo_cmd=$cmd ;;
	*) sudo_cmd=$bindir/fsblame ;;
	esac
	run="sudo $sudo_cmd run -- COMMAND"
	say ""
	say "fsblame needs CAP_BPF and CAP_PERFMON. With sudo, \`run\` still runs COMMAND as you:"
	printf "  %-${#run}s   %s\n" "sudo $sudo_cmd watch PATH" "print each change to PATH as it happens" \
		"$run" "everything COMMAND changes, anywhere" \
		"sudo $sudo_cmd doctor PATH" "check that this system can run it"
	say "Optional: run it without sudo (every user who can execute it can then watch any file):"
	say "  sudo setcap cap_bpf,cap_perfmon+ep $bindir/fsblame"
}

main "$@"
