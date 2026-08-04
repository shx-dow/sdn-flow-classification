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
from sklearn.model_selection import train_test_split


def load_features(metadata_path):
    metadata = json.loads(Path(metadata_path).read_text())
    return metadata["feature_columns"]


def calculate_metrics(y_true, y_pred):
    return {
        "precision_weighted": precision_score(
            y_true, y_pred, average="weighted", zero_division=0
        ),
        "recall_weighted": recall_score(
            y_true, y_pred, average="weighted", zero_division=0
        ),
        "accuracy": accuracy_score(y_true, y_pred),
        "f1_weighted": f1_score(y_true, y_pred, average="weighted", zero_division=0),
    }


def evaluate(name, y_true, y_pred):
    labels = sorted(pd.Series(y_true).dropna().unique())
    metrics = calculate_metrics(y_true, y_pred)
    print(f"\n{name}")
    print("-" * len(name))
    print(f"Rows: {len(y_true)}")
    print(f"Precision: {metrics['precision_weighted']:.4f}")
    print(f"Recall: {metrics['recall_weighted']:.4f}")
    print(f"Accuracy: {metrics['accuracy']:.4f}")
    print(f"F1 score: {metrics['f1_weighted']:.4f}")
    print("\nClassification report:")
    print(classification_report(y_true, y_pred, labels=labels))
    print("Confusion matrix:")
    print(pd.DataFrame(confusion_matrix(y_true, y_pred, labels=labels), index=labels, columns=labels))
    return metrics


def load_dataset(path, feature_columns):
    dataset = pd.read_csv(path)
    required = set(feature_columns + ["flow_label"])
    missing = required - set(dataset.columns)
    if missing:
        raise ValueError(f"{path} is missing columns: {', '.join(sorted(missing))}")

    dataset = dataset.dropna(subset=feature_columns + ["flow_label"]).copy()
    dataset[feature_columns] = dataset[feature_columns].apply(pd.to_numeric, errors="coerce")
    return dataset.dropna(subset=feature_columns)


def main():
    parser = argparse.ArgumentParser(description="Generate model evaluation metrics.")
    parser.add_argument("--model", default="elephant_mice_model.pkl")
    parser.add_argument("--metadata", default="model_metadata.json")
    parser.add_argument("--windowed-data", default="flow_dataset_training_windowed.csv")
    parser.add_argument("--whole-flow-data", default="flow_dataset_training.csv")
    parser.add_argument("--metrics-output", default="evaluation_metrics.json")
    parser.add_argument("--random-state", type=int, default=42)
    args = parser.parse_args()

    feature_columns = load_features(args.metadata)
    model = joblib.load(args.model)

    windowed = load_dataset(args.windowed_data, feature_columns)
    _, test = train_test_split(
        windowed,
        test_size=0.25,
        random_state=args.random_state,
        stratify=windowed["flow_label"],
    )
    windowed_predictions = model.predict(test[feature_columns])
    windowed_metrics = evaluate(
        "Windowed holdout evaluation", test["flow_label"], windowed_predictions
    )

    whole_flow = load_dataset(args.whole_flow_data, feature_columns)
    whole_flow_predictions = model.predict(whole_flow[feature_columns])
    whole_flow_metrics = evaluate(
        "Whole-flow generalization check",
        whole_flow["flow_label"],
        whole_flow_predictions,
    )

    metrics_output = {
        "model": args.model,
        "windowed_holdout": {
            "rows": int(len(test)),
            **windowed_metrics,
        },
        "whole_flow_generalization": {
            "rows": int(len(whole_flow)),
            **whole_flow_metrics,
        },
    }
    Path(args.metrics_output).write_text(json.dumps(metrics_output, indent=2))

    print("\nNote:")
    print(
        "The windowed score is high because the labels are threshold-generated from the same feature family. "
        "The whole-flow check is a harder mismatch test and is useful for discussing limitations."
    )
    print(f"\nSaved metrics: {args.metrics_output}")


if __name__ == "__main__":
    main()
