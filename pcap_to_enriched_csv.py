from pathlib import Path

import pandas as pd
from scapy.all import ICMP, IP, TCP, UDP, PcapReader


PCAP_FILES = [
    ("icmp_ping.pcap", "icmp"),
    ("tcp_iperf.pcap", "tcp"),
    ("udp_iperf.pcap", "udp"),
    ("http.pcap", "http"),
]


def extract_ports(packet):
    if packet.haslayer(TCP):
        return packet[TCP].sport, packet[TCP].dport
    if packet.haslayer(UDP):
        return packet[UDP].sport, packet[UDP].dport
    if packet.haslayer(ICMP):
        return 0, 0
    return 0, 0


def process_pcap(path, label):
    rows = []

    with PcapReader(str(path)) as packets:
        for packet in packets:
            if not packet.haslayer(IP):
                continue

            src_port, dst_port = extract_ports(packet)
            ip = packet[IP]

            rows.append(
                {
                    "src_ip": ip.src,
                    "dst_ip": ip.dst,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "protocol": ip.proto,
                    "packet_length": len(packet),
                    "timestamp": float(packet.time),
                    "label": label,
                }
            )

    return pd.DataFrame(rows)


def main():
    frames = []

    for pcap_name, label in PCAP_FILES:
        pcap_path = Path(pcap_name)
        if not pcap_path.exists():
            print(f"Skipping missing file: {pcap_name}")
            continue

        print(f"Reading {pcap_name}...")
        frames.append(process_pcap(pcap_path, label))

    if not frames:
        raise FileNotFoundError("No PCAP files were found.")

    dataset = pd.concat(frames, ignore_index=True)
    dataset = dataset.sort_values("timestamp").reset_index(drop=True)
    dataset.to_csv("dataset_with_ports.csv", index=False)

    print("Created dataset_with_ports.csv")
    print(f"Rows: {len(dataset)}")


if __name__ == "__main__":
    main()
