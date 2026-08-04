import json

import joblib
import pandas as pd

from mnflow.pcap_to_flow_dataset import build_flow_dataset
from mnflow.predict_flow import load_feature_columns, load_prediction_data
from mnflow.train_model import load_dataset, save_metadata, train_model

BYTE = 1000
DURATION = 5.0
PACKETS = 20


def test_end_to_end_pipeline(windowed_pcap, tmp_path):
    dataset_csv = tmp_path / "windowed.csv"
    build_flow_dataset(
        windowed_pcap,
        dataset_csv,
        byte_threshold=BYTE,
        duration_threshold=DURATION,
        packet_threshold=PACKETS,
        progress_interval=0,
        window_seconds=1,
    )

    dataset = load_dataset(dataset_csv)
    assert len(dataset) == 80

    model, *_ = train_model(dataset, random_state=42)

    model_path = tmp_path / "model.pkl"
    metadata_path = tmp_path / "metadata.json"
    joblib.dump(model, model_path)
    save_metadata(metadata_path, dataset, model)

    predictions_csv = tmp_path / "predictions.csv"
    feature_columns = load_feature_columns(metadata_path)
    data = load_prediction_data(dataset_csv, feature_columns)
    data["predicted_flow_label"] = model.predict(data[feature_columns])
    data.to_csv(predictions_csv, index=False)

    predicted = pd.read_csv(predictions_csv)
    assert len(predicted) == 80
    assert set(predicted["predicted_flow_label"]) <= {"elephant", "mice"}
    assert predicted["predicted_flow_label"].notna().all()

    metadata = json.loads(metadata_path.read_text())
    assert metadata["feature_columns"] == list(dataset[feature_columns].columns)
