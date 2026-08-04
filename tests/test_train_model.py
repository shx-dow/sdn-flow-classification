import json

import pandas as pd
import pytest

from mnflow.train_model import load_dataset, save_metadata, train_model

COLUMNS = [
    "protocol",
    "total_packets",
    "total_bytes",
    "flow_duration",
    "packet_rate",
    "byte_rate",
    "avg_packet_size",
    "min_packet_size",
    "max_packet_size",
    "flow_label",
]


def make_dataset(rows):
    return pd.DataFrame(
        {
            "protocol": [6] * rows,
            "total_packets": [10 + i for i in range(rows)],
            "total_bytes": [1000 + i * 100 for i in range(rows)],
            "flow_duration": [1.0] * rows,
            "packet_rate": [10.0] * rows,
            "byte_rate": [1000.0] * rows,
            "avg_packet_size": [100.0] * rows,
            "min_packet_size": [80] * rows,
            "max_packet_size": [120] * rows,
            "flow_label": ["elephant" if i % 2 else "mice" for i in range(rows)],
        }
    )


def test_load_dataset_missing_columns_raises(tmp_path):
    path = tmp_path / "bad.csv"
    pd.DataFrame({"total_packets": [1]}).to_csv(path, index=False)
    with pytest.raises(ValueError):
        load_dataset(path)


def test_load_dataset_returns_numeric_rows(tmp_path):
    path = tmp_path / "good.csv"
    make_dataset(4).to_csv(path, index=False)
    dataset = load_dataset(path)
    assert len(dataset) == 4
    assert set(dataset["flow_label"]) == {"elephant", "mice"}


def test_train_model_runs(tmp_path):
    dataset = make_dataset(40)
    model, _, _, _, y_test, predictions = train_model(dataset, random_state=42)
    assert len(predictions) == len(y_test)
    assert set(predictions) <= {"elephant", "mice"}

    model_path = tmp_path / "model.pkl"
    metadata_path = tmp_path / "metadata.json"
    import joblib

    joblib.dump(model, model_path)
    save_metadata(metadata_path, dataset, model)
    metadata = json.loads(metadata_path.read_text())
    assert metadata["feature_columns"] == COLUMNS[:-1]
    assert metadata["label_column"] == "flow_label"
