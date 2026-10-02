#!/usr/bin/env bash
# Abuse capture: SYN flood.
# Run on the Mininet VM from the repo root: sudo bash tools/gen_flood.sh [pcap]
set -euo pipefail
PCAP="${1:-data/raw/flood.pcap}"
mkdir -p "$(dirname "$PCAP")"
sudo python3 tools/run_scenario.py --scenario flood --pcap "$PCAP"
