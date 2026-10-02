"""Reproducible Mininet traffic scenarios for Flow Security captures.

Runs on the Mininet VM only (requires mininet, openvswitch, tcpdump,
iperf, nmap, hping3). The command builders below are pure functions so
they are unit-tested on any machine without Mininet installed.

Usage on the VM (from the repo root after syncing)::

    sudo python3 tools/run_scenario.py --scenario benign --pcap data/raw/benign.pcap
    sudo python3 tools/run_scenario.py --scenario scan --pcap data/raw/scan.pcap
    sudo python3 tools/run_scenario.py --scenario flood --pcap data/raw/flood.pcap
"""

import argparse
import time

SCENARIOS = ("benign", "scan", "flood")

BENIGN_SERVER = "h1"
BENIGN_CLIENT = "h2"
SCAN_SOURCE = "h1"
FLOOD_TARGET = "10.0.0.2"


def tcpdump_command(interface, pcap_path):
    return ["tcpdump", "-i", interface, "-w", str(pcap_path), "-U"]


def benign_commands():
    """Mice (ping) + elephant (iperf) baseline, mirroring the README demo."""
    return [
        f"{BENIGN_SERVER} ping -c 20 {BENIGN_CLIENT}",
        f"{BENIGN_SERVER} iperf -s -D",
        f"{BENIGN_CLIENT} iperf -c {BENIGN_SERVER} -t 20",
    ]


def scan_commands(target=FLOOD_TARGET):
    """Reconnaissance: fast SYN scan across the target's ports."""
    return [f"{SCAN_SOURCE} nmap -sS -F --min-rate 100 {target}"]


def flood_commands(target=FLOOD_TARGET, duration=20):
    """Abuse: SYN flood at line rate for a bounded duration."""
    return [f"h2 timeout {duration} hping3 -S --flood -p 5001 {target}"]


def build_commands(scenario, target=FLOOD_TARGET, duration=20):
    if scenario == "benign":
        return benign_commands()
    if scenario == "scan":
        return scan_commands(target)
    if scenario == "flood":
        return flood_commands(target, duration)
    raise ValueError(f"Unknown scenario: {scenario}. Choose from {SCENARIOS}.")


def run(args):
    from mininet.net import Mininet
    from mininet.node import RemoteController
    from mininet.topo import SingleSwitchTopo

    net = Mininet(
        topo=SingleSwitchTopo(k=4),
        controller=lambda name: RemoteController(name, ip=args.controller_ip, port=args.controller_port),
    )
    net.start()
    time.sleep(2)
    switch = net.switches[0]
    capture = switch.popen(tcpdump_command(args.interface, args.pcap))
    try:
        for command in build_commands(args.scenario, args.target, args.duration):
            host, _, host_cmd = command.partition(" ")
            node = net.get(host) if host in net else switch
            node.cmd(host_cmd if host in net else command)
            time.sleep(1)
        time.sleep(args.duration if args.scenario == "benign" else 5)
    finally:
        capture.terminate()
        net.stop()
    print(f"Saved capture: {args.pcap}")


def main():
    parser = argparse.ArgumentParser(description="Run a Mininet capture scenario.")
    parser.add_argument("--scenario", choices=SCENARIOS, required=True)
    parser.add_argument("--pcap", default="data/raw/capture.pcap")
    parser.add_argument("--interface", default="any")
    parser.add_argument("--target", default=FLOOD_TARGET)
    parser.add_argument("--duration", type=int, default=20)
    parser.add_argument("--controller-ip", default="127.0.0.1")
    parser.add_argument("--controller-port", type=int, default=6633)
    run(parser.parse_args())


if __name__ == "__main__":
    main()
