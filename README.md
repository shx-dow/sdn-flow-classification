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

## Workflow

1. Capture Mininet traffic as a PCAP file.
2. Convert packets into 5-tuple flow samples.
3. Extract flow features.
4. Label flows as `elephant` or `mice` using thresholds.
5. Train a Random Forest classifier.
6. Load the saved model inside POX.
7. Classify live SDN flows from OpenFlow stats.

## Important Files

- `pcap_to_flow_dataset.py` - converts a PCAP into flow-level datasets.
- `train_model.py` - trains the Random Forest model.
- `predict_flow.py` - tests predictions from the saved model.
- `pox_elephant_mice.py` - POX controller for live prediction.
- `flow_dataset_training_windowed.csv` - demo training dataset.
- `elephant_mice_model.pkl` - saved trained model.
- `model_metadata.json` - feature order and model metadata.

Raw PCAP files are ignored because they are large.

## Dataset Generation

Generate a whole-flow dataset:

```bash
python pcap_to_flow_dataset.py --input traffic.pcap --output flow_dataset_training.csv
```

Generate a 1-second windowed dataset for live-controller style training:

```bash
python pcap_to_flow_dataset.py --input traffic.pcap --output flow_dataset_training_windowed.csv --window-seconds 1
```

## Model Training

```bash
python train_model.py --input flow_dataset_training_windowed.csv
```

This creates:

- `elephant_mice_model.pkl`
- `model_metadata.json`

## Offline Prediction Test

```bash
python predict_flow.py --input flow_dataset_training_windowed.csv --output flow_predictions.csv
```

## POX Live Demo

Copy these files into the POX `ext/` folder:

- `pox_elephant_mice.py`
- `elephant_mice_model.pkl`
- `model_metadata.json`

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
