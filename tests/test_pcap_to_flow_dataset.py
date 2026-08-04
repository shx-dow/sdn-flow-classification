import csv

from scapy.all import IP

from mnflow.pcap_to_flow_dataset import (
    build_flow_dataset,
    classify_flow,
    flow_key,
    new_stats,
    update_stats,
)

BYTE = 1000
DURATION = 5.0
PACKETS = 20


def read_dataset(path):
    with open(path, newline="") as csv_file:
        return list(csv.DictReader(csv_file))


def test_classify_flow_thresholds():
    stats = {"total_bytes": 500, "start_time": 0.0, "end_time": 0.2, "total_packets": 3}
    assert classify_flow(stats, BYTE, DURATION, PACKETS) == "mice"
    stats["total_bytes"] = 1500
    assert classify_flow(stats, BYTE, DURATION, PACKETS) == "elephant"


def test_classify_flow_duration_threshold():
    stats = {"total_bytes": 500, "start_time": 0.0, "end_time": 6.0, "total_packets": 3}
    assert classify_flow(stats, BYTE, DURATION, PACKETS) == "elephant"


def test_update_stats_tracks_min_max():
    stats = new_stats(1.0, 100)
    update_stats(stats, 2.0, 200)
    update_stats(stats, 3.0, 50)
    assert stats["total_packets"] == 2
    assert stats["total_bytes"] == 250
    assert stats["min_packet_size"] == 50
    assert stats["max_packet_size"] == 200
    assert stats["start_time"] == 1.0
    assert stats["end_time"] == 3.0


def test_flow_key_normalizes_direction():
    forward = IP(src="10.0.0.1", dst="10.0.0.2", proto=6)
    reverse = IP(src="10.0.0.2", dst="10.0.0.1", proto=6)
    assert flow_key(forward, 1234, 80) == flow_key(reverse, 80, 1234)


def test_flow_key_distinguishes_window():
    ip = IP(src="10.0.0.1", dst="10.0.0.2", proto=6)
    assert flow_key(ip, 1234, 80, window_id=0) != flow_key(ip, 1234, 80, window_id=1)


def test_build_flow_dataset_whole_flow(whole_flow_pcap, tmp_path):
    output = tmp_path / "whole_flow.csv"
    build_flow_dataset(
        whole_flow_pcap,
        output,
        byte_threshold=BYTE,
        duration_threshold=DURATION,
        packet_threshold=PACKETS,
        progress_interval=0,
        window_seconds=0,
    )
    rows = read_dataset(output)
    assert len(rows) == 2
    assert {row["flow_label"] for row in rows} == {"elephant", "mice"}


def test_build_flow_dataset_windowed(windowed_pcap, tmp_path):
    output = tmp_path / "windowed.csv"
    build_flow_dataset(
        windowed_pcap,
        output,
        byte_threshold=BYTE,
        duration_threshold=DURATION,
        packet_threshold=PACKETS,
        progress_interval=0,
        window_seconds=1,
    )
    rows = read_dataset(output)
    labels = {row["flow_label"] for row in rows}
    assert labels == {"elephant", "mice"}
    assert len(rows) == 80
    assert all(row["window_id"] for row in rows)
