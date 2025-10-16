#!/usr/bin/env bash
set -euo pipefail
if lsof -i -a -c nets | grep -E '(ESTABLISHED|SYN)'; then
  echo "Outgoing connection detected" >&2
  exit 1
fi
echo "No outgoing connections"
