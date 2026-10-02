"""Shared feature definitions for Flow Security classification."""

LABEL_COLUMN = "flow_label"

FEATURE_COLUMNS = [
    "protocol",
    "total_packets",
    "total_bytes",
    "flow_duration",
    "packet_rate",
    "byte_rate",
    "avg_packet_size",
    "min_packet_size",
    "max_packet_size",
]

# Behavioral features for the security (Low/Medium/High) classifier.
# Each one is computable offline from pcap and approximable live from
# FlowStats + PacketIn (see Phase 5 approximations in pox/).
SECURITY_FEATURE_COLUMNS = [
    "syn_ratio",
    "rst_ratio",
    "icmp_ratio",
    "inter_arrival_std",
    "tcp_flag_entropy",
    "small_packet_ratio",
]

BYTE_THRESHOLD = 1_000_000
DURATION_THRESHOLD = 10.0
PACKET_THRESHOLD = 1000
SMALL_PACKET_THRESHOLD = 200

# Risk (Low/Medium/High) labeling contract.
# v1 seed heuristic: SYN-heavy or RST-heavy small-packet behavior is
# suspicious; single-packet windows never reach High (need >= 3 packets)
# so ordinary windowing artifacts stay Low/Medium.
RISK_LABEL_COLUMN = "risk_label"
RISK_CLASSES = ["Low", "Medium", "High"]

RISK_SYN_HIGH = 0.9
RISK_SYN_MED = 0.5
RISK_MIN_PACKETS = 3
RISK_RST_MED = 0.2
RISK_ICMP_MED = 0.5
RISK_ICMP_HIGH = 0.9
RISK_ICMP_FLOOD_RATE = 20.0
RISK_BULK_PACKETS = 100
RISK_SMALL_BULK = 0.9
