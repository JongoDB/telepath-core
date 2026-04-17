#!/usr/bin/env bash
# build-release.sh — cross-compile telepath for every supported target,
# package as .tar.gz/.zip/.deb/.rpm, produce SHA256SUMS, and copy the
# install scripts into dist/.
#
# Usage:  scripts/build-release.sh [VERSION]
#
# Environment overrides:
#   VERSION     release version (defaults to 0.1.0)
#   DIST_DIR    output directory (defaults to ./dist)
#   NFPM        path to nfpm binary (defaults to $(which nfpm))
#
# This script runs from any cwd; it resolves the repo root from its own path.
set -euo pipefail

VERSION=${VERSION:-${1:-0.1.0}}
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
DIST=${DIST_DIR:-$REPO_ROOT/dist}
NFPM_BIN=${NFPM:-$(command -v nfpm || echo "")}

rm -rf "$DIST"
mkdir -p "$DIST"

cd "$REPO_ROOT"

# Cross-compile one target. Args: goos goarch [extension]
build() {
    local goos=$1 goarch=$2 ext=${3:-}
    local outdir="$DIST/${goos}-${goarch}"
    local outbin="$outdir/telepath${ext}"
    mkdir -p "$outdir"
    echo ">> build ${goos}/${goarch}"
    CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
        go build \
        -trimpath \
        -ldflags "-s -w -X github.com/fsc/telepath-core/internal/daemon.Version=${VERSION}" \
        -o "$outbin" \
        ./cmd/telepath
}

build linux amd64
build darwin arm64
build windows amd64 ".exe"

# Tarball a single binary from <dist>/<os>-<arch>/telepath.
tarball() {
    local goos=$1 goarch=$2
    local outdir="$DIST/${goos}-${goarch}"
    local archive="$DIST/telepath-${VERSION}-${goos}-${goarch}.tar.gz"
    echo ">> tar ${goos}/${goarch} -> $(basename "$archive")"
    tar -czf "$archive" -C "$outdir" telepath
}

zipball() {
    local goos=$1 goarch=$2
    local outdir="$DIST/${goos}-${goarch}"
    local archive="$DIST/telepath-${VERSION}-${goos}-${goarch}.zip"
    echo ">> zip ${goos}/${goarch} -> $(basename "$archive")"
    if command -v zip >/dev/null; then
        (cd "$outdir" && zip -q "$archive" telepath.exe)
    else
        # Python is nearly universally available on build machines; fall
        # back to it when zip isn't installed (e.g. minimal CI images).
        python3 - "$outdir/telepath.exe" "$archive" <<'PY'
import sys, zipfile
src, out = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(out, 'w', compression=zipfile.ZIP_DEFLATED) as z:
    z.write(src, arcname='telepath.exe')
PY
    fi
}

tarball linux amd64
tarball darwin arm64
zipball windows amd64

# nfpm packaging for linux amd64 (.deb and .rpm). Requires nfpm on PATH.
if [[ -n "$NFPM_BIN" && -x "$NFPM_BIN" ]]; then
    echo ">> nfpm .deb"
    "$NFPM_BIN" package --config "$SCRIPT_DIR/nfpm.yaml" --packager deb --target "$DIST/" | sed 's/^/   /'
    echo ">> nfpm .rpm"
    "$NFPM_BIN" package --config "$SCRIPT_DIR/nfpm.yaml" --packager rpm --target "$DIST/" | sed 's/^/   /'
else
    echo "!! nfpm not on PATH; skipping .deb/.rpm build"
fi

# Copy installers next to the artifacts so they live in the release tree.
cp "$SCRIPT_DIR/install.sh"  "$DIST/install.sh"
cp "$SCRIPT_DIR/install.ps1" "$DIST/install.ps1"
chmod +x "$DIST/install.sh"

# Clean up the per-OS staging directories; the tarballs and installers are
# what ship. Keep them inside dist/ so test runners can still inspect.
rm -rf "$DIST/linux-amd64" "$DIST/darwin-arm64" "$DIST/windows-amd64"

# SHA256SUMS. Generate a stable, sorted list.
cd "$DIST"
sha256_files=()
for f in telepath-*.tar.gz telepath-*.zip telepath*.deb telepath*.rpm install.sh install.ps1; do
    [[ -f "$f" ]] && sha256_files+=("$f")
done
sha256sum "${sha256_files[@]}" | sort > SHA256SUMS

echo
echo ">> release artifacts in $DIST"
ls -la "$DIST"
echo
echo ">> sha256sums:"
cat "$DIST/SHA256SUMS"
