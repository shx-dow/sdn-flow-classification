import json

import pandas as pd
import pytest

from mnflow.predict_flow import load_feature_columns, load_prediction_data


def test_load_feature_columns(tmp_path):
    path = tmp_path / "metadata.json"
    path.write_text(json.dumps({"feature_columns": ["a", "b"]}))
    assert load_feature_columns(path) == ["a", "b"]


def test_load_feature_columns_missing_raises(tmp_path):
    path = tmp_path / "metadata.json"
    path.write_text(json.dumps({}))
    with pytest.raises(ValueError):
        load_feature_columns(path)


def test_load_prediction_data_missing_columns_raises(tmp_path):
    path = tmp_path / "data.csv"
    pd.DataFrame({"protocol": [6]}).to_csv(path, index=False)
    with pytest.raises(ValueError):
        load_prediction_data(path, ["protocol", "total_bytes"])


def test_load_prediction_data_drops_invalid_rows(tmp_path):
    path = tmp_path / "data.csv"
    pd.DataFrame(
        {
            "protocol": [6, 6],
            "total_bytes": [1000, None],
        }
    ).to_csv(path, index=False)
    data = load_prediction_data(path, ["protocol", "total_bytes"])
    assert len(data) == 1
