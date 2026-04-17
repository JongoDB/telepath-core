#!/usr/bin/env sh
# install.sh — install telepath from a local release bundle.
#
# Usage:
#   1. Extract the release archive (e.g. telepath-0.1.0.tar.gz).
#   2. cd into that directory.
#   3. ./install.sh
#
# Artifacts expected in the current directory:
#   telepath-<version>-<os>-<arch>.tar.gz   (macOS + Linux)
#
# The script detects your OS/arch, extracts the right binary into
# $INSTALL_DIR (default ~/.local/bin), and prints the shell-specific line to
# add that directory to PATH — copy/paste it into your rc file.

set -eu

OS=$(uname -s)
ARCH=$(uname -m)

case "$OS" in
    Darwin) os=darwin ;;
    Linux)  os=linux ;;
    *) echo "Unsupported OS: $OS" >&2; exit 1 ;;
esac

case "$ARCH" in
    arm64|aarch64) arch=arm64 ;;
    x86_64|amd64)  arch=amd64 ;;
    *) echo "Unsupported arch: $ARCH" >&2; exit 1 ;;
esac

# On macOS amd64 we haven't shipped a binary (v0.1 ships darwin/arm64 only).
# Operators on Intel Macs should build from source for now.
if [ "$os" = "darwin" ] && [ "$arch" != "arm64" ]; then
    echo "telepath v0.1 ships only darwin/arm64 (Apple Silicon)." >&2
    echo "On Intel Macs, build from source: clone the repo, run 'go build ./cmd/telepath'." >&2
    exit 1
fi

ARTIFACT=""
for candidate in telepath-*-${os}-${arch}.tar.gz; do
    [ -f "$candidate" ] && ARTIFACT="$candidate"
done
if [ -z "$ARTIFACT" ]; then
    echo "No telepath tarball for ${os}/${arch} found in $(pwd)." >&2
    echo "Files present:" >&2
    ls -1 telepath-*.tar.gz 2>/dev/null >&2 || echo "  (none)" >&2
    exit 1
fi

INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"
mkdir -p "$INSTALL_DIR"

echo "Installing $ARTIFACT -> $INSTALL_DIR/telepath"
tar -xzf "$ARTIFACT" -C "$INSTALL_DIR"
chmod 0755 "$INSTALL_DIR/telepath"

if [ -x "$INSTALL_DIR/telepath" ]; then
    echo "Installed: $("$INSTALL_DIR/telepath" --version 2>/dev/null || echo telepath)"
else
    echo "Install verification failed: $INSTALL_DIR/telepath not executable" >&2
    exit 1
fi

echo ""
echo "To add telepath to your PATH, paste this into your shell rc file:"
echo ""

case "${SHELL:-}" in
    */zsh)
        RC="~/.zshrc"
        LINE="export PATH=\"$INSTALL_DIR:\$PATH\""
        echo "  echo '$LINE' >> $RC"
        ;;
    */bash)
        RC="~/.bashrc"
        LINE="export PATH=\"$INSTALL_DIR:\$PATH\""
        echo "  echo '$LINE' >> $RC"
        ;;
    */fish)
        RC="~/.config/fish/config.fish"
        LINE="set -gx PATH $INSTALL_DIR \$PATH"
        echo "  echo '$LINE' >> $RC"
        ;;
    *)
        RC="~/.profile"
        LINE="export PATH=\"$INSTALL_DIR:\$PATH\""
        echo "  echo '$LINE' >> $RC"
        ;;
esac

echo ""
echo "Then reload the shell: source $RC"
echo "Verify with: telepath --version"
echo ""
echo "Next steps:"
echo "  1. telepath config init        # set up operator identity + Claude Code auth"
echo "  2. telepath daemon run &        # start the daemon"
echo "  3. telepath engagement new ... # create your first engagement"
