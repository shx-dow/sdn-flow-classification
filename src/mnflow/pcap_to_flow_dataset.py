import argparse
import csv
import math
from pathlib import Path

from scapy.all import ICMP, IP, TCP, UDP, PcapReader

from .features import (
    BYTE_THRESHOLD,
    DURATION_THRESHOLD,
    PACKET_THRESHOLD,
    RISK_BULK_PACKETS,
    RISK_ICMP_FLOOD_RATE,
    RISK_ICMP_HIGH,
    RISK_ICMP_MED,
    RISK_MIN_PACKETS,
    RISK_RST_MED,
    RISK_SMALL_BULK,
    RISK_SYN_HIGH,
    RISK_SYN_MED,
    SECURITY_FEATURE_COLUMNS,
    SMALL_PACKET_THRESHOLD,
)

TCP_SYN = 0x02
TCP_RST = 0x04
TCP_ACK = 0x10


def packet_ports(packet):
    if packet.haslayer(TCP):
        return packet[TCP].sport, packet[TCP].dport
    if packet.haslayer(UDP):
        return packet[UDP].sport, packet[UDP].dport
    if packet.haslayer(ICMP):
        return 0, 0
    return 0, 0


def flow_key(ip, src_port, dst_port, window_id=None):
    src = (ip.src, int(src_port))
    dst = (ip.dst, int(dst_port))
    endpoint_a, endpoint_b = sorted((src, dst))
    key = (
        endpoint_a[0],
        endpoint_a[1],
        endpoint_b[0],
        endpoint_b[1],
        int(ip.proto),
    )
    if window_id is not None:
        key = key + (window_id,)
    return key


def new_stats(timestamp, packet_length):
    return {
        "total_packets": 0,
        "total_bytes": 0,
        "start_time": timestamp,
        "end_time": timestamp,
        "min_packet_size": packet_length,
        "max_packet_size": packet_length,
        "tcp_packets": 0,
        "syn_packets": 0,
        "rst_packets": 0,
        "icmp_packets": 0,
        "small_packets": 0,
        "flag_counts": {},
        "last_ts": None,
        "iat_mean": 0.0,
        "iat_m2": 0.0,
        "iat_n": 0,
    }


def update_stats(stats, timestamp, packet_length, packet=None):
    stats["total_packets"] += 1
    stats["total_bytes"] += packet_length
    stats["start_time"] = min(stats["start_time"], timestamp)
    stats["end_time"] = max(stats["end_time"], timestamp)
    stats["min_packet_size"] = min(stats["min_packet_size"], packet_length)
    stats["max_packet_size"] = max(stats["max_packet_size"], packet_length)
    if packet is not None:
        update_security_stats(stats, timestamp, packet_length, packet)


def update_security_stats(stats, timestamp, packet_length, packet):
    last = stats["last_ts"]
    if last is None:
        stats["last_ts"] = timestamp
    else:
        interval = max(timestamp - last, 0.0)
        stats["iat_n"] += 1
        delta = interval - stats["iat_mean"]
        stats["iat_mean"] += delta / stats["iat_n"]
        stats["iat_m2"] += delta * (interval - stats["iat_mean"])
        stats["last_ts"] = timestamp

    if packet.haslayer(TCP):
        stats["tcp_packets"] += 1
        flags = int(packet[TCP].flags)
        stats["flag_counts"][flags] = stats["flag_counts"].get(flags, 0) + 1
        if flags & TCP_SYN and not flags & TCP_ACK:
            stats["syn_packets"] += 1
        if flags & TCP_RST:
            stats["rst_packets"] += 1
    if packet.haslayer(ICMP):
        stats["icmp_packets"] += 1
    if packet_length < SMALL_PACKET_THRESHOLD:
        stats["small_packets"] += 1


def flag_entropy(flag_counts):
    total = sum(flag_counts.values())
    if total <= 1:
        return 0.0
    return -sum((count / total) * math.log2(count / total) for count in flag_counts.values())


def security_features(stats):
    """Behavioral features for the security classifier.

    Live approximation notes (Phase 5): syn/rst/icmp ratios come from
    PacketIn flag inspection; inter_arrival_std falls back to 0.0 when
    per-packet timestamps are unavailable from FlowStats deltas.
    """
    total = stats["total_packets"]
    tcp = stats["tcp_packets"]
    iat_n = stats["iat_n"]
    return {
        "syn_ratio": stats["syn_packets"] / tcp if tcp else 0.0,
        "rst_ratio": stats["rst_packets"] / tcp if tcp else 0.0,
        "icmp_ratio": stats["icmp_packets"] / total if total else 0.0,
        "inter_arrival_std": math.sqrt(stats["iat_m2"] / iat_n) if iat_n else 0.0,
        "tcp_flag_entropy": flag_entropy(stats["flag_counts"]),
        "small_packet_ratio": stats["small_packets"] / total if total else 0.0,
    }


def classify_flow(stats, byte_threshold, duration_threshold, packet_threshold):
    duration = max(stats["end_time"] - stats["start_time"], 0)
    is_elephant = (
        stats["total_bytes"] >= byte_threshold
        or duration >= duration_threshold
        or stats["total_packets"] >= packet_threshold
    )
    return "elephant" if is_elephant else "mice"


def classify_risk(
    total_packets,
    packet_rate,
    sec,
    syn_high=RISK_SYN_HIGH,
    syn_med=RISK_SYN_MED,
    min_packets=RISK_MIN_PACKETS,
    rst_med=RISK_RST_MED,
    icmp_med=RISK_ICMP_MED,
    icmp_high=RISK_ICMP_HIGH,
    icmp_flood_rate=RISK_ICMP_FLOOD_RATE,
    bulk_packets=RISK_BULK_PACKETS,
    small_bulk=RISK_SMALL_BULK,
):
    """Seed heuristic mapping behavioral features to Low/Medium/High.

    v1 is deliberately conservative: High needs corroboration (SYN-heavy
    plus volume, or ICMP at flood rate, or a bulk of small packets).
    Refine thresholds once real scan/flood captures are available.
    """
    if (
        (sec["syn_ratio"] >= syn_high and total_packets >= min_packets)
        or (sec["icmp_ratio"] >= icmp_high and packet_rate >= icmp_flood_rate)
        or (total_packets >= bulk_packets and sec["small_packet_ratio"] >= small_bulk)
    ):
        return "High"
    if (
        sec["syn_ratio"] >= syn_med
        or sec["rst_ratio"] >= rst_med
        or sec["icmp_ratio"] >= icmp_med
    ):
        return "Medium"
    return "Low"


def build_flow_dataset(
    input_pcap,
    output_csv,
    byte_threshold,
    duration_threshold,
    packet_threshold,
    progress_interval,
    window_seconds,
):
    flows = {}
    packet_count = 0
    ip_packet_count = 0
    first_timestamp = None

    with PcapReader(str(input_pcap)) as packets:
        for packet in packets:
            packet_count += 1
            if progress_interval and packet_count % progress_interval == 0:
                print(f"Processed {packet_count:,} packets; current flows: {len(flows):,}")

            if not packet.haslayer(IP):
                continue

            ip_packet_count += 1
            src_port, dst_port = packet_ports(packet)
            timestamp = float(packet.time)
            if first_timestamp is None:
                first_timestamp = timestamp
            window_id = None
            if window_seconds:
                window_id = int((timestamp - first_timestamp) // window_seconds)
            packet_length = len(packet)
            key = flow_key(packet[IP], src_port, dst_port, window_id)

            if key not in flows:
                flows[key] = new_stats(timestamp, packet_length)
            update_stats(flows[key], timestamp, packet_length, packet)

    fieldnames = [
        "flow_id",
        "endpoint_a_ip",
        "endpoint_a_port",
        "endpoint_b_ip",
        "endpoint_b_port",
        "protocol",
        "window_id",
        "total_packets",
        "total_bytes",
        "start_time",
        "end_time",
        "flow_duration",
        "packet_rate",
        "byte_rate",
        "avg_packet_size",
        "min_packet_size",
        "max_packet_size",
        *SECURITY_FEATURE_COLUMNS,
        "flow_label",
        "risk_label",
    ]

    with open(output_csv, "w", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()

        for flow_id, (key, stats) in enumerate(sorted(flows.items()), start=1):
            duration = max(stats["end_time"] - stats["start_time"], 0)
            rate_duration = duration if duration > 0 else 1e-9
            total_packets = stats["total_packets"]
            total_bytes = stats["total_bytes"]
            packet_rate = total_packets / rate_duration
            sec = security_features(stats)
            row = {
                "flow_id": flow_id,
                "endpoint_a_ip": key[0],
                "endpoint_a_port": key[1],
                "endpoint_b_ip": key[2],
                "endpoint_b_port": key[3],
                "protocol": key[4],
                "window_id": key[5] if window_seconds else "",
                "total_packets": total_packets,
                "total_bytes": total_bytes,
                "start_time": stats["start_time"],
                "end_time": stats["end_time"],
                "flow_duration": duration,
                "packet_rate": packet_rate,
                "byte_rate": total_bytes / rate_duration,
                "avg_packet_size": total_bytes / total_packets,
                "min_packet_size": stats["min_packet_size"],
                "max_packet_size": stats["max_packet_size"],
                **sec,
                "flow_label": classify_flow(
                    stats, byte_threshold, duration_threshold, packet_threshold
                ),
                "risk_label": classify_risk(total_packets, packet_rate, sec),
            }
            writer.writerow(row)

    return packet_count, ip_packet_count, len(flows)


def main():
    parser = argparse.ArgumentParser(
        description="Create a Flow Security dataset (traffic + security features) from a pcap file."
    )
    parser.add_argument("--input", default="data/raw/traffic.pcap", help="Input pcap file")
    parser.add_argument("--output", default="data/flow_dataset_training.csv", help="Output CSV")
    parser.add_argument("--byte-threshold", type=int, default=BYTE_THRESHOLD)
    parser.add_argument("--duration-threshold", type=float, default=DURATION_THRESHOLD)
    parser.add_argument("--packet-threshold", type=int, default=PACKET_THRESHOLD)
    parser.add_argument("--progress-interval", type=int, default=100_000)
    parser.add_argument(
        "--window-seconds",
        type=float,
        default=0,
        help="Split each 5-tuple into fixed time-window samples. Use 0 for whole flows.",
    )
    args = parser.parse_args()

    packet_count, ip_packet_count, flow_count = build_flow_dataset(
        Path(args.input),
        Path(args.output),
        args.byte_threshold,
        args.duration_threshold,
        args.packet_threshold,
        args.progress_interval,
        args.window_seconds,
    )

    print(f"Created {args.output}")
    print(f"Packets processed: {packet_count:,}")
    print(f"IP packets used: {ip_packet_count:,}")
    print(f"Flows created: {flow_count:,}")


if __name__ == "__main__":
    main()
