import csv

from scapy.all import ICMP, IP, TCP, wrpcap

from mnflow.features import FEATURE_COLUMNS, LABEL_COLUMN, SECURITY_FEATURE_COLUMNS
from mnflow.pcap_to_flow_dataset import (
    build_flow_dataset,
    new_stats,
    security_features,
    update_stats,
)

BYTE = 100_000
DURATION = 50.0
PACKETS = 10_000


def _tcp(src, dst, sport, dport, flags, length, time):
    payload = b"x" * max(0, length - 40)
    packet = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags) / payload
    packet.time = time
    return packet


def _icmp(src, dst, length, time):
    payload = b"x" * max(0, length - 28)
    packet = IP(src=src, dst=dst) / ICMP() / payload
    packet.time = time
    return packet


def _write_pcap(path, packets):
    wrpcap(str(path), packets)
    return path


def _rows(path):
    with open(path, newline="") as csv_file:
        return list(csv.DictReader(csv_file))


def _build(tmp_path, packets, name="sec.pcap"):
    pcap = _write_pcap(tmp_path / name, packets)
    output = tmp_path / "sec.csv"
    build_flow_dataset(
        pcap,
        output,
        byte_threshold=BYTE,
        duration_threshold=DURATION,
        packet_threshold=PACKETS,
        progress_interval=0,
        window_seconds=0,
    )
    return _rows(output)


def test_syn_ratio_full_and_half(tmp_path):
    packets = [_tcp("10.0.0.1", "10.0.0.2", 1111, 80, "S", 100, float(i)) for i in range(4)]
    packets += [_tcp("10.0.0.1", "10.0.0.3", 2222, 80, "S", 100, float(i)) for i in range(2)]
    packets += [_tcp("10.0.0.1", "10.0.0.3", 2222, 80, "A", 100, 10.0 + i) for i in range(2)]
    rows = {r["endpoint_b_ip"]: r for r in _build(tmp_path, packets)}
    assert float(rows["10.0.0.2"]["syn_ratio"]) == 1.0
    assert float(rows["10.0.0.3"]["syn_ratio"]) == 0.5


def test_rst_and_icmp_ratios(tmp_path):
    packets = [_tcp("10.0.0.1", "10.0.0.2", 1111, 80, "R", 100, float(i)) for i in range(3)]
    packets += [_icmp("10.0.0.1", "10.0.0.4", 100, float(i)) for i in range(3)]
    rows = {r["endpoint_b_ip"]: r for r in _build(tmp_path, packets)}
    assert float(rows["10.0.0.2"]["rst_ratio"]) == 1.0
    assert float(rows["10.0.0.2"]["icmp_ratio"]) == 0.0
    assert float(rows["10.0.0.4"]["icmp_ratio"]) == 1.0
    assert float(rows["10.0.0.4"]["syn_ratio"]) == 0.0


def test_inter_arrival_std(tmp_path):
    even = [_tcp("10.0.0.1", "10.0.0.2", 1111, 80, "A", 500, float(i)) for i in range(4)]
    varied = [_tcp("10.0.0.1", "10.0.0.3", 2222, 80, "A", 500, t) for t in (0.0, 1.0, 3.0, 6.0)]
    rows = {r["endpoint_b_ip"]: r for r in _build(tmp_path, even + varied)}
    assert float(rows["10.0.0.2"]["inter_arrival_std"]) == 0.0
    assert float(rows["10.0.0.3"]["inter_arrival_std"]) > 0.0


def test_flag_entropy_and_small_ratio(tmp_path):
    packets = [_tcp("10.0.0.1", "10.0.0.2", 1111, 80, "S", 100, float(i)) for i in range(4)]
    packets += [_tcp("10.0.0.1", "10.0.0.3", 2222, 80, "S", 100, float(i)) for i in range(2)]
    packets += [_tcp("10.0.0.1", "10.0.0.3", 2222, 80, "A", 100, 10.0 + i) for i in range(2)]
    rows = {r["endpoint_b_ip"]: r for r in _build(tmp_path, packets)}
    assert float(rows["10.0.0.2"]["tcp_flag_entropy"]) == 0.0
    assert float(rows["10.0.0.3"]["tcp_flag_entropy"]) == 1.0
    assert float(rows["10.0.0.2"]["small_packet_ratio"]) == 1.0


def test_dataset_keeps_traffic_contract(tmp_path):
    packets = [_tcp("10.0.0.1", "10.0.0.2", 1111, 80, "A", 500, float(i)) for i in range(3)]
    rows = _build(tmp_path, packets)
    assert len(rows) == 1
    for column in FEATURE_COLUMNS + SECURITY_FEATURE_COLUMNS + [LABEL_COLUMN]:
        assert column in rows[0]


def test_legacy_update_stats_without_packet():
    stats = new_stats(1.0, 100)
    update_stats(stats, 2.0, 200)
    features = security_features(stats)
    assert features["syn_ratio"] == 0.0
    assert features["inter_arrival_std"] == 0.0
