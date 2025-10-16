#!/usr/bin/env bash
set -euo pipefail
PREFIX=${1:-/opt/nets}
VERSION=${VERSION:-0.1.0}
OUTDIR=dist/deb
mkdir -p "$OUTDIR/DEBIAN" "$OUTDIR$PREFIX/bin"
cat >"$OUTDIR/DEBIAN/control" <<CONTROL
Package: nets
Version: $VERSION
Section: net
Priority: optional
Architecture: amd64
Maintainer: Local Monitoring Team
Description: Local-only network flow monitoring toolkit
CONTROL
cp target/x86_64-unknown-linux-gnu/release/cli "$OUTDIR$PREFIX/bin/nets-cli"
cp target/x86_64-unknown-linux-gnu/release/ui "$OUTDIR$PREFIX/bin/nets-ui"
cp target/x86_64-unknown-linux-gnu/release/analyzer "$OUTDIR$PREFIX/bin/nets-analyzer" || true
dpkg-deb --build "$OUTDIR" dist/nets_${VERSION}_amd64.deb
