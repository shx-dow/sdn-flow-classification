from mnflow.features import (
    BYTE_THRESHOLD,
    DURATION_THRESHOLD,
    FEATURE_COLUMNS,
    PACKET_THRESHOLD,
)


def test_feature_columns_complete():
    assert "protocol" in FEATURE_COLUMNS
    assert "total_packets" in FEATURE_COLUMNS
    assert "total_bytes" in FEATURE_COLUMNS
    assert "flow_duration" in FEATURE_COLUMNS
    assert len(FEATURE_COLUMNS) == 9


def test_thresholds_are_positive():
    assert BYTE_THRESHOLD > 0
    assert DURATION_THRESHOLD > 0
    assert PACKET_THRESHOLD > 0
