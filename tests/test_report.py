import csv
import json

from mnflow.report import (
    flows_table,
    load_records,
    records_from_csv,
    summarize,
    summary_table,
)


def _audit_record(traffic="mice", risk="Low", action="forward"):
    return {
        "ts": 0.0,
        "dpid": "00-00-00-00-00-01",
        "nw_src": "10.0.0.1",
        "tp_src": 1111,
        "nw_dst": "10.0.0.2",
        "tp_dst": 80,
        "nw_proto": 6,
        "packets": 10,
        "bytes": 1000,
        "traffic": traffic,
        "risk": risk,
        "action": action,
    }


def test_summarize_counts_actions():
    records = [
        _audit_record("mice", "Low", "forward"),
        _audit_record("elephant", "High", "block"),
        _audit_record("elephant", "High", "block"),
    ]
    counts = summarize(records)
    assert counts[("mice", "Low", "forward")] == 1
    assert counts[("elephant", "High", "block")] == 2


def test_tables_render_without_tty():
    records = [_audit_record("elephant", "High", "block")]
    assert summary_table(summarize(records)).row_count == 1
    assert flows_table(records).row_count == 1


def test_load_records_from_audit(tmp_path):
    audit = tmp_path / "audit.jsonl"
    with open(audit, "w") as audit_file:
        audit_file.write(json.dumps(_audit_record()) + "\n")
        audit_file.write("not json\n")
    records = load_records(audit, None)
    assert len(records) == 1
    assert records[0]["action"] == "forward"


def test_records_from_csv_applies_decision_engine(tmp_path):
    path = tmp_path / "flows.csv"
    with open(path, "w", newline="") as csv_file:
        writer = csv.DictWriter(
            csv_file,
            fieldnames=["endpoint_a_ip", "endpoint_a_port", "endpoint_b_ip",
                        "endpoint_b_port", "flow_label", "risk_label"],
        )
        writer.writeheader()
        writer.writerow(
            {
                "endpoint_a_ip": "10.0.0.1",
                "endpoint_a_port": 1111,
                "endpoint_b_ip": "10.0.0.9",
                "endpoint_b_port": 5001,
                "flow_label": "elephant",
                "risk_label": "High",
            }
        )
    records = records_from_csv(path)
    assert records[0]["action"] == "block"


def test_records_from_csv_rejects_missing_labels(tmp_path):
    path = tmp_path / "flows.csv"
    with open(path, "w", newline="") as csv_file:
        csv_file.write("flow_label\nmice\n")
    try:
        records_from_csv(path)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
