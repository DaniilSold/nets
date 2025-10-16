#!/usr/bin/env bash
set -euo pipefail
perf stat -e task-clock,cycles,instructions cargo run -p cli -- --config config/config.toml tui >/tmp/nets_cpu.log
