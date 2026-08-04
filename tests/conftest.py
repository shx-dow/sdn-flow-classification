import pytest
from scapy.all import IP, TCP, wrpcap


def _packet(src, dst, sport, dport, length, time):
    payload = b"x" * max(0, length - 40)
    packet = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport) / payload
    packet.time = time
    return packet


@pytest.fixture
def whole_flow_pcap(tmp_path):
    path = tmp_path / "whole_flow.pcap"
    packets = []
    for time in (0.0, 0.1, 0.2):
        packets.append(_packet("10.0.0.1", "10.0.0.2", 1234, 5001, 100, time))
    for i in range(15):
        packets.append(_packet("10.0.0.1", "10.0.0.3", 2345, 5002, 1000, 1.0 + i * 0.1))
    wrpcap(str(path), packets)
    return path


@pytest.fixture
def windowed_pcap(tmp_path):
    path = tmp_path / "windowed.pcap"
    packets = []
    for i in range(40):
        packets.append(_packet("10.0.0.1", "10.0.0.2", 1234, 5001, 100, float(i)))
    for i in range(40):
        packets.append(_packet("10.0.0.1", "10.0.0.3", 2345, 5002, 1000, float(i)))
    wrpcap(str(path), packets)
    return path
