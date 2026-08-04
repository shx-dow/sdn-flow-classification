import argparse
import csv
from pathlib import Path

from scapy.all import ICMP, IP, TCP, UDP, PcapReader

from .features import BYTE_THRESHOLD, DURATION_THRESHOLD, PACKET_THRESHOLD


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
    }


def update_stats(stats, timestamp, packet_length):
    stats["total_packets"] += 1
    stats["total_bytes"] += packet_length
    stats["start_time"] = min(stats["start_time"], timestamp)
    stats["end_time"] = max(stats["end_time"], timestamp)
    stats["min_packet_size"] = min(stats["min_packet_size"], packet_length)
    stats["max_packet_size"] = max(stats["max_packet_size"], packet_length)


def classify_flow(stats, byte_threshold, duration_threshold, packet_threshold):
    duration = max(stats["end_time"] - stats["start_time"], 0)
    is_elephant = (
        stats["total_bytes"] >= byte_threshold
        or duration >= duration_threshold
        or stats["total_packets"] >= packet_threshold
    )
    return "elephant" if is_elephant else "mice"


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
            update_stats(flows[key], timestamp, packet_length)

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
        "flow_label",
    ]

    with open(output_csv, "w", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()

        for flow_id, (key, stats) in enumerate(sorted(flows.items()), start=1):
            duration = max(stats["end_time"] - stats["start_time"], 0)
            rate_duration = duration if duration > 0 else 1e-9
            total_packets = stats["total_packets"]
            total_bytes = stats["total_bytes"]
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
                "packet_rate": total_packets / rate_duration,
                "byte_rate": total_bytes / rate_duration,
                "avg_packet_size": total_bytes / total_packets,
                "min_packet_size": stats["min_packet_size"],
                "max_packet_size": stats["max_packet_size"],
                "flow_label": classify_flow(
                    stats, byte_threshold, duration_threshold, packet_threshold
                ),
            }
            writer.writerow(row)

    return packet_count, ip_packet_count, len(flows)


def main():
    parser = argparse.ArgumentParser(
        description="Create an elephant/mice flow dataset directly from a pcap file."
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
