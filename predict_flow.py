import argparse
import json
from pathlib import Path

import joblib
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)


def load_feature_columns(metadata_path):
    metadata = json.loads(Path(metadata_path).read_text())
    feature_columns = metadata.get("feature_columns")
    if not feature_columns:
        raise ValueError("Metadata file does not contain feature_columns.")
    return feature_columns


def load_prediction_data(input_path, feature_columns):
    data = pd.read_csv(input_path)
    missing = set(feature_columns) - set(data.columns)
    if missing:
        raise ValueError(f"Missing required feature columns: {', '.join(sorted(missing))}")

    data = data.copy()
    data[feature_columns] = data[feature_columns].apply(pd.to_numeric, errors="coerce")
    bad_rows = data[feature_columns].isna().any(axis=1)
    if bad_rows.any():
        print(f"Dropping {bad_rows.sum()} rows with invalid feature values.")
        data = data.loc[~bad_rows].copy()
    return data


def print_evaluation(data, predictions, label_column):
    if label_column not in data.columns:
        return

    labels = sorted(data[label_column].dropna().unique())
    print(f"Precision: {precision_score(data[label_column], predictions, average='weighted', zero_division=0):.4f}")
    print(f"Recall: {recall_score(data[label_column], predictions, average='weighted', zero_division=0):.4f}")
    print(f"Accuracy: {accuracy_score(data[label_column], predictions):.4f}")
    print(f"F1 score: {f1_score(data[label_column], predictions, average='weighted', zero_division=0):.4f}")
    print("\nClassification report:")
    print(classification_report(data[label_column], predictions, labels=labels))
    print("Confusion matrix:")
    matrix = confusion_matrix(data[label_column], predictions, labels=labels)
    print(pd.DataFrame(matrix, index=labels, columns=labels))


def main():
    parser = argparse.ArgumentParser(
        description="Predict elephant/mice labels for flow feature rows."
    )
    parser.add_argument("--input", default="flow_dataset_training_windowed.csv")
    parser.add_argument("--model", default="elephant_mice_model.pkl")
    parser.add_argument("--metadata", default="model_metadata.json")
    parser.add_argument("--output", default="flow_predictions.csv")
    parser.add_argument("--label-column", default="flow_label")
    args = parser.parse_args()

    feature_columns = load_feature_columns(args.metadata)
    model = joblib.load(args.model)
    data = load_prediction_data(args.input, feature_columns)

    predictions = model.predict(data[feature_columns])
    data["predicted_flow_label"] = predictions
    data.to_csv(args.output, index=False)

    print(f"Input rows predicted: {len(data)}")
    print("Prediction counts:")
    print(pd.Series(predictions).value_counts().to_string())
    print()
    print_evaluation(data, predictions, args.label_column)
    print(f"\nSaved predictions: {args.output}")


if __name__ == "__main__":
    main()
