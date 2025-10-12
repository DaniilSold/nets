#!/usr/bin/env bash
set -euo pipefail
/usr/bin/time -v cargo run -p cli -- --config config/config.toml flows --limit 1 >/tmp/nets_mem.log
