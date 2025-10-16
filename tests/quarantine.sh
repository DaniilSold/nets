#!/usr/bin/env bash
set -euo pipefail
PROC_NAME=${1:-python3}
PORT=${2:-8080}
sudo nft add table inet nets-test || true
sudo nft add chain inet nets-test quarantine '{ type filter hook input priority 0; policy accept; }' || true
sudo nft add rule inet nets-test quarantine tcp dport $PORT reject || true
echo "Applied quarantine rule for port $PORT"
sleep 2
sudo nft delete table inet nets-test
