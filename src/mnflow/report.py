"""Flow Security CLI report: rich tables over audit JSONL or flow CSVs."""

import argparse
import csv
import json
import time
from collections import Counter
from pathlib import Path

from rich.console import Console
from rich.table import Table

from .decision_engine import decide, describe


def parse_audit(path):
    records = []
    with open(path) as audit_file:
        for line in audit_file:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return records


def flow_id(record):
    src = f"{record.get('nw_src', '?')}:{record.get('tp_src', 0)}"
    dst = f"{record.get('nw_dst', '?')}:{record.get('tp_dst', 0)}"
    return f"{src} -> {dst}"


def records_from_csv(path):
    records = []
    with open(path, newline="") as csv_file:
        for row in csv.DictReader(csv_file):
            if "flow_label" not in row or "risk_label" not in row:
                raise ValueError(f"{path} needs flow_label and risk_label columns")
            traffic, risk = row["flow_label"], row["risk_label"]
            records.append(
                {
                    "nw_src": row.get("endpoint_a_ip", "?"),
                    "tp_src": row.get("endpoint_a_port", 0),
                    "nw_dst": row.get("endpoint_b_ip", "?"),
                    "tp_dst": row.get("endpoint_b_port", 0),
                    "traffic": traffic,
                    "risk": risk,
                    "action": decide(traffic, risk),
                }
            )
    return records


def summarize(records):
    return Counter((r["traffic"], r["risk"], r["action"]) for r in records)


def summary_table(counts):
    table = Table(title="Flow Security summary")
    table.add_column("Traffic")
    table.add_column("Risk")
    table.add_column("Action")
    table.add_column("Effect")
    table.add_column("Flows", justify="right")
    for (traffic, risk, action), count in sorted(counts.items()):
        table.add_row(traffic, risk, action, describe(action), str(count))
    return table


def flows_table(records, limit=20):
    table = Table(title="Latest flows")
    table.add_column("Flow")
    table.add_column("Traffic")
    table.add_column("Risk")
    table.add_column("Action")
    for record in records[-limit:]:
        table.add_row(
            flow_id(record), record["traffic"], record["risk"], record["action"]
        )
    return table


def load_records(audit, flows):
    records = []
    if audit is not None:
        records.extend(parse_audit(audit))
    if flows is not None:
        records.extend(records_from_csv(flows))
    return records


def run_summary(records, limit, console):
    counts = summarize(records)
    console.print(summary_table(counts))
    console.print(flows_table(records, limit))
    return len(records)


def run_live(audit, limit, refresh, console):
    from rich.live import Live

    position = 0
    records = []
    with Live(console=console, refresh_per_second=1) as live:
        while True:
            with open(audit) as audit_file:
                audit_file.seek(position)
                for line in audit_file:
                    line = line.strip()
                    if line:
                        try:
                            records.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
                position = audit_file.tell()
            live.update(flows_table(records, limit))
            time.sleep(refresh)


def main():
    parser = argparse.ArgumentParser(description="Render Flow Security reports as CLI tables.")
    parser.add_argument("--audit", default=None, help="POX JSONL audit file")
    parser.add_argument("--flows", default=None, help="Flow CSV with flow_label+risk_label")
    parser.add_argument("--mode", choices=("summary", "live"), default="summary")
    parser.add_argument("--limit", type=int, default=20)
    parser.add_argument("--refresh", type=float, default=1.0)
    args = parser.parse_args()

    if args.mode == "live" and args.audit is None:
        parser.error("--mode live needs --audit")
    if args.audit is None and args.flows is None:
        parser.error("give --audit and/or --flows")

    console = Console()
    if args.mode == "live":
        run_live(Path(args.audit), args.limit, args.refresh, console)
        return

    records = load_records(
        Path(args.audit) if args.audit else None, Path(args.flows) if args.flows else None
    )
    if not records:
        console.print("No records found.")
        return
    total = run_summary(records, args.limit, console)
    console.print(f"Total records: {total}")


if __name__ == "__main__":
    main()
