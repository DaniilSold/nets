#!/usr/bin/env bash
set -euo pipefail
# Placeholder automation orchestrating anomaly scenarios for NETS.
SCENARIOS=(listener arp-spoof dns-nx-spike smb-burst)
IFACE=${IFACE:-lo}
for scenario in "${SCENARIOS[@]}"; do
  echo "[+] Running scenario: $scenario"
  python3 tools/traffic_gen.py --scenario "$scenario" --iface "$IFACE" --capture "tests/pcap/${scenario}.pcap"
  # Replay via collector mock (actual integration uses pcap replay API)
  echo "Captured tests/pcap/${scenario}.pcap"
done
