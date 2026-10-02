import csv
import json

import pandas as pd
from scapy.all import IP, TCP, wrpcap

from mnflow.features import RISK_LABEL_COLUMN, SECURITY_FEATURE_COLUMNS
from mnflow.pcap_to_flow_dataset import build_flow_dataset, classify_risk
from mnflow.train_security import load_dataset, save_metadata, train_model

BYTE = 100_000_000
DURATION = 10_000.0
PACKETS = 1_000_000


def test_classify_risk_high_flood():
    sec = {
        "syn_ratio": 1.0,
        "rst_ratio": 0.0,
        "icmp_ratio": 0.0,
        "inter_arrival_std": 0.01,
        "tcp_flag_entropy": 0.0,
        "small_packet_ratio": 1.0,
    }
    assert classify_risk(20, 21.0, sec) == "High"


def test_classify_risk_medium_probe():
    sec = {
        "syn_ratio": 1.0,
        "rst_ratio": 0.0,
        "icmp_ratio": 0.0,
        "inter_arrival_std": 0.0,
        "tcp_flag_entropy": 0.0,
        "small_packet_ratio": 1.0,
    }
    assert classify_risk(1, 1e9, sec) == "Medium"


def test_classify_risk_low_benign():
    sec = {
        "syn_ratio": 0.1,
        "rst_ratio": 0.0,
        "icmp_ratio": 0.0,
        "inter_arrival_std": 0.4,
        "tcp_flag_entropy": 1.5,
        "small_packet_ratio": 0.0,
    }
    assert classify_risk(10, 5.0, sec) == "Low"


def _packet(src, dst, sport, dport, flags, length, time):
    payload = b"x" * max(0, length - 40)
    packet = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags) / payload
    packet.time = time
    return packet


def _build_rows(tmp_path, packets):
    pcap = tmp_path / "risk.pcap"
    wrpcap(str(pcap), packets)
    output = tmp_path / "risk.csv"
    build_flow_dataset(
        pcap,
        output,
        byte_threshold=BYTE,
        duration_threshold=DURATION,
        packet_threshold=PACKETS,
        progress_interval=0,
        window_seconds=0,
    )
    with open(output, newline="") as csv_file:
        return list(csv.DictReader(csv_file))


def test_builder_assigns_risk_labels(tmp_path):
    benign = [_packet("10.0.0.1", "10.0.0.2", 1111, 80, "S", 1000, 0.0)]
    benign += [_packet("10.0.0.1", "10.0.0.2", 1111, 80, "A", 1000, 1.0 + i) for i in range(9)]
    flood = [_packet("10.0.0.1", "10.0.0.9", 2222, 5001, "S", 100, i * 0.05) for i in range(20)]
    rows = {r["endpoint_b_ip"]: r for r in _build_rows(tmp_path, benign + flood)}
    assert rows["10.0.0.2"]["risk_label"] == "Low"
    assert rows["10.0.0.9"]["risk_label"] == "High"


def _synthetic_frame(n_per_class=8):
    lows = [
        {
            "syn_ratio": 0.05,
            "rst_ratio": 0.0,
            "icmp_ratio": 0.0,
            "inter_arrival_std": 0.4,
            "tcp_flag_entropy": 1.6,
            "small_packet_ratio": 0.0,
            RISK_LABEL_COLUMN: "Low",
        }
    ] * n_per_class
    highs = [
        {
            "syn_ratio": 1.0,
            "rst_ratio": 0.0,
            "icmp_ratio": 0.0,
            "inter_arrival_std": 0.01,
            "tcp_flag_entropy": 0.0,
            "small_packet_ratio": 1.0,
            RISK_LABEL_COLUMN: "High",
        }
    ] * n_per_class
    return pd.DataFrame(lows + highs)


def test_train_security_separates_risk(tmp_path):
    frame = _synthetic_frame()
    dataset_path = tmp_path / "risk_train.csv"
    frame.to_csv(dataset_path, index=False)

    dataset = load_dataset(dataset_path)
    model, _x_train, _x_test, _y_train, y_test, predictions = train_model(dataset, 42)
    assert (predictions == y_test.to_numpy()).all()

    model_path = tmp_path / "security.pkl"
    metadata_path = tmp_path / "security_metadata.json"
    import joblib

    joblib.dump(model, model_path)
    save_metadata(metadata_path, dataset, model)
    metadata = json.loads(metadata_path.read_text())
    assert metadata["feature_columns"] == SECURITY_FEATURE_COLUMNS
    assert metadata["label_column"] == RISK_LABEL_COLUMN
    assert set(metadata["class_counts"]) == {"Low", "High"}


def test_load_dataset_rejects_missing_columns(tmp_path):
    bad = tmp_path / "bad.csv"
    pd.DataFrame([{"syn_ratio": 0.5}]).to_csv(bad, index=False)
    try:
        load_dataset(bad)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
