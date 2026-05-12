import argparse
import json
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import train_test_split


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


def load_dataset(path):
    dataset = pd.read_csv(path)
    missing = set(FEATURE_COLUMNS + ["flow_label"]) - set(dataset.columns)
    if missing:
        raise ValueError(f"Missing required columns: {', '.join(sorted(missing))}")

    dataset = dataset.dropna(subset=FEATURE_COLUMNS + ["flow_label"]).copy()
    dataset[FEATURE_COLUMNS] = dataset[FEATURE_COLUMNS].apply(pd.to_numeric, errors="coerce")
    dataset = dataset.dropna(subset=FEATURE_COLUMNS)
    return dataset


def train_model(dataset, random_state):
    x = dataset[FEATURE_COLUMNS]
    y = dataset["flow_label"]

    x_train, x_test, y_train, y_test = train_test_split(
        x,
        y,
        test_size=0.25,
        random_state=random_state,
        stratify=y,
    )

    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=None,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=random_state,
    )
    model.fit(x_train, y_train)

    predictions = model.predict(x_test)
    return model, x_train, x_test, y_train, y_test, predictions


def save_metadata(path, dataset, model):
    importances = {
        feature: float(importance)
        for feature, importance in zip(FEATURE_COLUMNS, model.feature_importances_)
    }
    metadata = {
        "feature_columns": FEATURE_COLUMNS,
        "label_column": "flow_label",
        "class_counts": dataset["flow_label"].value_counts().to_dict(),
        "model_type": "RandomForestClassifier",
        "feature_importances": dict(
            sorted(importances.items(), key=lambda item: item[1], reverse=True)
        ),
    }
    path.write_text(json.dumps(metadata, indent=2))


def main():
    parser = argparse.ArgumentParser(
        description="Train a Random Forest model for elephant/mice flow classification."
    )
    parser.add_argument("--input", default="flow_dataset_training_windowed.csv")
    parser.add_argument("--model-output", default="elephant_mice_model.pkl")
    parser.add_argument("--metadata-output", default="model_metadata.json")
    parser.add_argument("--random-state", type=int, default=42)
    args = parser.parse_args()

    dataset = load_dataset(Path(args.input))
    model, x_train, x_test, y_train, y_test, predictions = train_model(
        dataset, args.random_state
    )

    joblib.dump(model, args.model_output)
    save_metadata(Path(args.metadata_output), dataset, model)

    labels = sorted(dataset["flow_label"].unique())
    print(f"Dataset rows: {len(dataset)}")
    print("Class counts:")
    print(dataset["flow_label"].value_counts().to_string())
    print(f"Train rows: {len(x_train)}")
    print(f"Test rows: {len(x_test)}")
    print(f"Accuracy: {accuracy_score(y_test, predictions):.4f}")
    print("\nClassification report:")
    print(classification_report(y_test, predictions, labels=labels))
    print("Confusion matrix:")
    print(pd.DataFrame(confusion_matrix(y_test, predictions, labels=labels), index=labels, columns=labels))
    print(f"\nSaved model: {args.model_output}")
    print(f"Saved metadata: {args.metadata_output}")


if __name__ == "__main__":
    main()
