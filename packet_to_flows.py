import argparse
from pathlib import Path

import pandas as pd


def add_flow_keys(packets):
    has_ports = {"src_port", "dst_port"}.issubset(packets.columns)

    if has_ports:
        src_endpoint = list(zip(packets["src_ip"], packets["src_port"]))
        dst_endpoint = list(zip(packets["dst_ip"], packets["dst_port"]))
        endpoint_a = [src if src <= dst else dst for src, dst in zip(src_endpoint, dst_endpoint)]
        endpoint_b = [dst if src <= dst else src for src, dst in zip(src_endpoint, dst_endpoint)]

        packets["endpoint_a_ip"] = [endpoint[0] for endpoint in endpoint_a]
        packets["endpoint_a_port"] = [endpoint[1] for endpoint in endpoint_a]
        packets["endpoint_b_ip"] = [endpoint[0] for endpoint in endpoint_b]
        packets["endpoint_b_port"] = [endpoint[1] for endpoint in endpoint_b]
        return ["endpoint_a_ip", "endpoint_a_port", "endpoint_b_ip", "endpoint_b_port", "protocol"]

    endpoint_a = packets[["src_ip", "dst_ip"]].min(axis=1)
    endpoint_b = packets[["src_ip", "dst_ip"]].max(axis=1)
    packets["endpoint_a_ip"] = endpoint_a
    packets["endpoint_b_ip"] = endpoint_b
    return ["endpoint_a_ip", "endpoint_b_ip", "protocol"]


def build_flows(input_csv, output_csv, byte_threshold, duration_threshold, packet_threshold):
    packets = pd.read_csv(input_csv)

    required = {"src_ip", "dst_ip", "protocol", "packet_length"}
    missing = required - set(packets.columns)
    if missing:
        raise ValueError(f"Missing required columns: {', '.join(sorted(missing))}")

    packets = packets.copy()
    packets["packet_length"] = pd.to_numeric(packets["packet_length"], errors="coerce").fillna(0)

    if "timestamp" in packets.columns:
        packets["timestamp"] = pd.to_numeric(packets["timestamp"], errors="coerce").fillna(0)
    elif "time_delta" in packets.columns:
        packets["time_delta"] = pd.to_numeric(packets["time_delta"], errors="coerce").fillna(0)
        # A few packet exporters can produce tiny negative deltas at capture boundaries.
        packets["timestamp"] = packets["time_delta"].clip(lower=0).cumsum()
    else:
        raise ValueError("Input CSV must contain either timestamp or time_delta.")

    group_cols = add_flow_keys(packets)

    aggregations = {
        "total_packets": ("packet_length", "size"),
        "total_bytes": ("packet_length", "sum"),
        "start_time": ("timestamp", "min"),
        "end_time": ("timestamp", "max"),
        "min_packet_size": ("packet_length", "min"),
        "max_packet_size": ("packet_length", "max"),
        "avg_packet_size": ("packet_length", "mean"),
    }
    if "label" in packets.columns:
        aggregations["traffic_type"] = (
            "label",
            lambda values: values.mode().iat[0] if not values.mode().empty else "unknown",
        )

    flows = packets.groupby(group_cols, dropna=False).agg(**aggregations).reset_index()
    if "traffic_type" not in flows.columns:
        flows["traffic_type"] = "unknown"

    flows["flow_duration"] = (flows["end_time"] - flows["start_time"]).clip(lower=0)
    duration_for_rate = flows["flow_duration"].replace(0, 1e-9)
    flows["packet_rate"] = flows["total_packets"] / duration_for_rate
    flows["byte_rate"] = flows["total_bytes"] / duration_for_rate

    is_elephant = (
        (flows["total_bytes"] >= byte_threshold)
        | (flows["flow_duration"] >= duration_threshold)
        | (flows["total_packets"] >= packet_threshold)
    )
    flows["flow_label"] = is_elephant.map({True: "elephant", False: "mice"})

    flows.insert(0, "flow_id", range(1, len(flows) + 1))
    flows.to_csv(output_csv, index=False)
    return flows


def main():
    parser = argparse.ArgumentParser(
        description="Convert packet-level CSV data into elephant/mice flow-level data."
    )
    parser.add_argument("--input", default="dataset_with_ports.csv", help="Packet-level input CSV")
    parser.add_argument("--output", default="flow_dataset_5tuple.csv", help="Flow-level output CSV")
    parser.add_argument("--byte-threshold", type=int, default=1_000_000)
    parser.add_argument("--duration-threshold", type=float, default=10.0)
    parser.add_argument("--packet-threshold", type=int, default=1000)
    args = parser.parse_args()

    flows = build_flows(
        Path(args.input),
        Path(args.output),
        args.byte_threshold,
        args.duration_threshold,
        args.packet_threshold,
    )

    print(f"Created {args.output}")
    print(f"Total flows: {len(flows)}")
    print(flows["flow_label"].value_counts().to_string())


if __name__ == "__main__":
    main()
