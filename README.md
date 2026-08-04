# ML-Based Elephant and Mice Flow Classification in SDN

This project classifies SDN network flows as **elephant flows** or **mice flows** using a Random Forest model. Traffic is generated in Mininet, captured as PCAP, converted into flow-level features, trained with scikit-learn, and used live inside a POX controller.

## Tech Stack

- Python
- Mininet
- Open vSwitch
- POX Controller
- Scapy
- Pandas
- Scikit-learn
- Wireshark/tcpdump

## Project Structure

```text
.
├── data/
│   ├── flow_dataset_training.csv        # whole-flow dataset (committed)
│   ├── flow_dataset_training_windowed.csv  # 1-second windowed dataset (committed)
│   ├── raw/                             # pcap captures (gitignored)
│   ├── predictions/                     # prediction output (gitignored)
│   └── evaluation_metrics.json          # generated metrics report (gitignored)
├── models/
│   ├── elephant_mice_model.pkl          # saved trained model
│   └── model_metadata.json              # feature order and model metadata
├── pox/
│   └── pox_elephant_mice.py             # POX controller for live prediction
├── src/mnflow/                          # pip-installable package
│   ├── features.py                      # shared feature columns and thresholds
│   ├── pcap_to_flow_dataset.py          # pcap -> flow-level dataset
│   ├── train_model.py                   # train the Random Forest model
│   ├── predict_flow.py                  # offline prediction on flow CSVs
│   └── evaluate_model.py                # evaluation metrics
└── tests/                               # pytest unit + integration tests
```

## Installation

```bash
python -m venv .venv
.venv/Scripts/activate  # Windows
# source .venv/bin/activate  # macOS/Linux

python -m pip install -e ".[dev]"
```

This installs the `mnflow` package and its console commands.

## Workflow

1. Capture Mininet traffic as a PCAP file into `data/raw/`.
2. Convert packets into flow samples with `mn-pcap-to-dataset`.
3. Label flows as `elephant` or `mice` using thresholds.
4. Train a Random Forest classifier with `mn-train`.
5. Load the saved model inside POX.
6. Classify live SDN flows from OpenFlow stats.

## Dataset Generation

Generate a whole-flow dataset:

```bash
mn-pcap-to-dataset --input data/raw/traffic.pcap --output data/flow_dataset_training.csv
```

Generate a 1-second windowed dataset for live-controller style training:

```bash
mn-pcap-to-dataset --input data/raw/traffic.pcap --output data/flow_dataset_training_windowed.csv --window-seconds 1
```

The equivalent module invocations are `python -m mnflow.pcap_to_flow_dataset`, etc.

## Model Training

```bash
mn-train --input data/flow_dataset_training_windowed.csv
```

This creates:

- `models/elephant_mice_model.pkl`
- `models/model_metadata.json`

## Offline Prediction Test

```bash
mn-predict --input data/flow_dataset_training_windowed.csv --output data/predictions/flow_predictions.csv
```

## Evaluation Metrics

```bash
mn-evaluate
```

This writes the metrics to `data/evaluation_metrics.json`.

Current results:

```text
Windowed holdout evaluation:
Precision: 1.0000
Recall: 1.0000
Accuracy: 1.0000
F1 score: 1.0000

Whole-flow generalization check:
Precision: 0.7833
Recall: 0.6316
Accuracy: 0.6316
F1 score: 0.5621
```

The windowed score validates the demo pipeline. The whole-flow score is a harder check because the model was trained on 1-second samples but tested on complete flow records.

## POX Live Demo

Copy these files into the POX `ext/` folder:

- `pox/pox_elephant_mice.py`
- `models/elephant_mice_model.pkl`
- `models/model_metadata.json`

Start POX:

```bash
cd ~/pox
python3 pox.py log.level --DEBUG openflow.of_01 --port=6633 pox_elephant_mice \
  --model_path=ext/elephant_mice_model.pkl \
  --metadata_path=ext/model_metadata.json \
  --poll_interval=1
```

Start Mininet in another terminal:

```bash
sudo mn --topo single,4 --mac --switch ovsk --controller remote,ip=127.0.0.1,port=6633
```

Generate mice traffic:

```bash
h1 ping -c 3 h2
```

Generate elephant traffic:

```bash
h1 iperf -s &
h2 iperf -c h1 -t 20
```

The POX terminal prints live predictions such as:

```text
prediction=mice
prediction=elephant
```

## Artifact Policy

Committed: training datasets in `data/`, model artifacts in `models/`. Both are small and make the demo runnable out of the box.

Gitignored (regenerable): pcap captures (`data/raw/`), prediction output (`data/predictions/`), and the metrics report (`data/evaluation_metrics.json`).

## Current Demo Dataset

The current windowed dataset contains:

```text
299 flow samples
214 mice
85 elephant
```

This is suitable for demo and initial testing.

## Limitations

- Labels are threshold-based.
- The dataset is suitable for a prototype demo, not a large-scale production model.
- More varied Mininet traffic would improve generalization.
- OpenFlow stats do not expose packet-level minimum and maximum packet sizes, so the POX controller approximates them using average packet size.

## Development

Run tests and linting:

```bash
pytest
ruff check .
```
