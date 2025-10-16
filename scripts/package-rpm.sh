#!/usr/bin/env bash
set -euo pipefail
PREFIX=${1:-/opt/nets}
VERSION=${VERSION:-0.1.0}
BUILDROOT=$(pwd)/dist/rpm/buildroot
mkdir -p "$BUILDROOT$PREFIX/bin"
cp target/x86_64-unknown-linux-gnu/release/cli "$BUILDROOT$PREFIX/bin/nets-cli"
cp target/x86_64-unknown-linux-gnu/release/ui "$BUILDROOT$PREFIX/bin/nets-ui"
cp target/x86_64-unknown-linux-gnu/release/analyzer "$BUILDROOT$PREFIX/bin/nets-analyzer" || true
cat >dist/nets.spec <<SPEC
Name: nets
Version: $VERSION
Release: 1%{?dist}
Summary: Local-only network flow monitoring toolkit
License: Apache-2.0
BuildArch: x86_64
%description
Local-only network flow monitoring toolkit.
%install
mkdir -p %{buildroot}$PREFIX/bin
cp -r $BUILDROOT$PREFIX/bin/* %{buildroot}$PREFIX/bin/
%files
$PREFIX/bin/*
SPEC
rpmbuild --bb dist/nets.spec --buildroot "$BUILDROOT"
