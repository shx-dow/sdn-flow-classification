"""Shared feature definitions for elephant/mice flow classification."""

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

BYTE_THRESHOLD = 1_000_000
DURATION_THRESHOLD = 10.0
PACKET_THRESHOLD = 1000
