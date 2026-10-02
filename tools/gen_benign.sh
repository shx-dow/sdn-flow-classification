#!/usr/bin/env bash
# Benign baseline capture: mice (ping) + elephant (iperf).
# Run on the Mininet VM from the repo root: sudo bash tools/gen_benign.sh [pcap]
set -euo pipefail
PCAP="${1:-data/raw/benign.pcap}"
mkdir -p "$(dirname "$PCAP")"
sudo python3 tools/run_scenario.py --scenario benign --pcap "$PCAP"
