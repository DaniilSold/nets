#!/usr/bin/env bash
set -euo pipefail
PREFIX=${1:-/Applications/NETS.app}
VERSION=${VERSION:-0.1.0}
DIST=dist/dmg
mkdir -p "$DIST"
cp target/x86_64-apple-darwin/release/cli "$DIST/nets-cli" 2>/dev/null || true
hdiutil create -volname "NETS $VERSION" -srcfolder "$DIST" -ov -format UDZO "dist/nets-$VERSION.dmg"
