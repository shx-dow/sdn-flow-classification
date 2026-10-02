import argparse
import json
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split

from .features import RISK_LABEL_COLUMN, SECURITY_FEATURE_COLUMNS


def load_dataset(path):
    dataset = pd.read_csv(path)
    missing = set(SECURITY_FEATURE_COLUMNS + [RISK_LABEL_COLUMN]) - set(dataset.columns)
    if missing:
        raise ValueError(f"Missing required columns: {', '.join(sorted(missing))}")

    dataset = dataset.dropna(subset=SECURITY_FEATURE_COLUMNS + [RISK_LABEL_COLUMN]).copy()
    dataset[SECURITY_FEATURE_COLUMNS] = dataset[SECURITY_FEATURE_COLUMNS].apply(
        pd.to_numeric, errors="coerce"
    )
    dataset = dataset.dropna(subset=SECURITY_FEATURE_COLUMNS)
    return dataset


def print_metrics(y_true, y_pred):
    print(f"Precision: {precision_score(y_true, y_pred, average='weighted', zero_division=0):.4f}")
    print(f"Recall: {recall_score(y_true, y_pred, average='weighted', zero_division=0):.4f}")
    print(f"Accuracy: {accuracy_score(y_true, y_pred):.4f}")
    print(f"F1 score: {f1_score(y_true, y_pred, average='weighted', zero_division=0):.4f}")


def train_model(dataset, random_state):
    x = dataset[SECURITY_FEATURE_COLUMNS]
    y = dataset[RISK_LABEL_COLUMN]

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
        for feature, importance in zip(SECURITY_FEATURE_COLUMNS, model.feature_importances_)
    }
    metadata = {
        "feature_columns": SECURITY_FEATURE_COLUMNS,
        "label_column": RISK_LABEL_COLUMN,
        "class_counts": dataset[RISK_LABEL_COLUMN].value_counts().to_dict(),
        "model_type": "RandomForestClassifier",
        "feature_importances": dict(
            sorted(importances.items(), key=lambda item: item[1], reverse=True)
        ),
    }
    path.write_text(json.dumps(metadata, indent=2))


def main():
    parser = argparse.ArgumentParser(
        description="Train a Random Forest model for flow security risk classification."
    )
    parser.add_argument("--input", default="data/flow_dataset_training_windowed.csv")
    parser.add_argument("--model-output", default="models/security_model.pkl")
    parser.add_argument("--metadata-output", default="models/security_metadata.json")
    parser.add_argument("--random-state", type=int, default=42)
    args = parser.parse_args()

    dataset = load_dataset(Path(args.input))
    model, x_train, x_test, _y_train, y_test, predictions = train_model(
        dataset, args.random_state
    )

    joblib.dump(model, args.model_output)
    save_metadata(Path(args.metadata_output), dataset, model)

    labels = sorted(dataset[RISK_LABEL_COLUMN].unique())
    print(f"Dataset rows: {len(dataset)}")
    print("Class counts:")
    print(dataset[RISK_LABEL_COLUMN].value_counts().to_string())
    print(f"Train rows: {len(x_train)}")
    print(f"Test rows: {len(x_test)}")
    print_metrics(y_test, predictions)
    print("\nClassification report:")
    print(classification_report(y_test, predictions, labels=labels))
    print("Confusion matrix:")
    print(pd.DataFrame(confusion_matrix(y_test, predictions, labels=labels), index=labels, columns=labels))
    print(f"\nSaved model: {args.model_output}")
    print(f"Saved metadata: {args.metadata_output}")


if __name__ == "__main__":
    main()
