import pandas as pd
import pytest

from mnflow.evaluate_model import calculate_metrics, load_dataset, load_features

FEATURES = ["total_bytes", "total_packets", "flow_duration"]


def test_calculate_metrics():
    y_true = ["mice", "mice", "elephant"]
    y_pred = ["mice", "mice", "mice"]
    metrics = calculate_metrics(y_true, y_pred)
    assert metrics["accuracy"] == pytest.approx(2 / 3)
    assert metrics["precision_weighted"] >= 0
    assert metrics["f1_weighted"] >= 0


def test_load_features(tmp_path):
    path = tmp_path / "metadata.json"
    path.write_text('{"feature_columns": ["a", "b"]}')
    assert load_features(path) == ["a", "b"]


def test_load_dataset_missing_columns_raises(tmp_path):
    path = tmp_path / "data.csv"
    pd.DataFrame({"total_bytes": [1]}).to_csv(path, index=False)
    with pytest.raises(ValueError):
        load_dataset(path, FEATURES)
