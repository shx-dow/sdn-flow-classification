#!/usr/bin/env bash
# Reconnaissance capture: SYN scan.
# Run on the Mininet VM from the repo root: sudo bash tools/gen_scan.sh [pcap]
set -euo pipefail
PCAP="${1:-data/raw/scan.pcap}"
mkdir -p "$(dirname "$PCAP")"
sudo python3 tools/run_scenario.py --scenario scan --pcap "$PCAP"
