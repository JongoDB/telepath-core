#!/usr/bin/env sh
# install.sh — bootstrap installer for telepath on macOS + Linux.
#
# Detects the host OS and architecture, downloads the matching release
# tarball from GitHub, extracts the binary into a temp dir, and hands off
# to `telepath install` which copies itself into ~/.local/bin and prints
# the PATH-setup line appropriate for the operator's shell.
#
# Typical use (one-liner):
#   curl -sSL https://raw.githubusercontent.com/JongoDB/telepath-core/main/scripts/install.sh | sh
#
# Pin a version:
#   curl -sSL https://raw.githubusercontent.com/JongoDB/telepath-core/main/scripts/install.sh | VERSION=v0.1.2 sh
#
# Windows operators: download the windows-amd64.zip from the Releases page
# and run `./telepath install` from an extracted copy — PowerShell flow is
# documented in `telepath install --help`.

set -eu

REPO="${TELEPATH_REPO:-JongoDB/telepath-core}"
VERSION="${VERSION:-latest}"

# --- OS/arch detection ---

OS_RAW=$(uname -s)
case "$OS_RAW" in
    Darwin) OS=darwin ;;
    Linux)  OS=linux ;;
    *) echo "telepath install.sh: unsupported OS '$OS_RAW'" >&2
       echo "For Windows, download telepath-*-windows-amd64.zip from:" >&2
       echo "  https://github.com/$REPO/releases" >&2
       exit 1 ;;
esac

ARCH_RAW=$(uname -m)
case "$ARCH_RAW" in
    x86_64|amd64)       ARCH=amd64 ;;
    arm64|aarch64)      ARCH=arm64 ;;
    *) echo "telepath install.sh: unsupported arch '$ARCH_RAW'" >&2
       exit 1 ;;
esac

# --- resolve 'latest' via the Releases API ---

if [ "$VERSION" = "latest" ]; then
    VERSION=$(curl -sSL \
        -H 'Accept: application/vnd.github+json' \
        "https://api.github.com/repos/$REPO/releases/latest" \
        | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n1)
    if [ -z "$VERSION" ]; then
        echo "telepath install.sh: could not resolve latest version from GitHub API" >&2
        echo "Pin explicitly: VERSION=v0.1.X $0" >&2
        exit 1
    fi
fi

ARCHIVE="telepath-${VERSION}-${OS}-${ARCH}.tar.gz"
URL="https://github.com/$REPO/releases/download/${VERSION}/${ARCHIVE}"

# --- download + extract + hand off ---

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

echo "telepath install.sh: fetching $ARCHIVE"
if ! curl --fail -sSL -o "$TMPDIR/bin.tar.gz" "$URL"; then
    echo "Download failed: $URL" >&2
    echo "Check that the tag and asset exist: https://github.com/$REPO/releases/tag/$VERSION" >&2
    exit 1
fi
tar -xzf "$TMPDIR/bin.tar.gz" -C "$TMPDIR"

if [ ! -x "$TMPDIR/telepath" ]; then
    echo "telepath install.sh: extracted archive did not contain an executable 'telepath'" >&2
    exit 1
fi

echo ""
exec "$TMPDIR/telepath" install
