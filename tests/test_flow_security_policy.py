import importlib.util
import os

import pytest

from mnflow.decision_engine import decide as mnflow_decide
from mnflow.pcap_to_flow_dataset import classify_risk

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_policy():
    path = os.path.join(REPO, "pox", "flow_security_policy.py")
    spec = importlib.util.spec_from_file_location("flow_security_policy", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


policy = load_policy()

SECS = [
    {
        "syn_ratio": 1.0,
        "rst_ratio": 0.0,
        "icmp_ratio": 0.0,
        "inter_arrival_std": 0.01,
        "tcp_flag_entropy": 0.0,
        "small_packet_ratio": 1.0,
    },
    {
        "syn_ratio": 0.1,
        "rst_ratio": 0.0,
        "icmp_ratio": 0.0,
        "inter_arrival_std": 0.4,
        "tcp_flag_entropy": 1.5,
        "small_packet_ratio": 0.0,
    },
    {
        "syn_ratio": 0.0,
        "rst_ratio": 0.5,
        "icmp_ratio": 0.0,
        "inter_arrival_std": 0.2,
        "tcp_flag_entropy": 0.8,
        "small_packet_ratio": 0.3,
    },
]


def test_decide_matches_mnflow():
    for traffic in ("mice", "elephant"):
        for risk in ("Low", "Medium", "High"):
            assert policy.decide(traffic, risk) == mnflow_decide(traffic, risk)


def test_risk_heuristic_matches_offline():
    for sec in SECS:
        for total, rate in ((1, 1e9), (5, 5.0), (20, 21.0), (150, 150.0)):
            assert policy.risk_heuristic(total, rate, sec) == classify_risk(total, rate, sec)


def test_live_features_from_observations():
    obs = policy.new_observation()
    policy.update_observation(obs, 0.0, True, 0x02, False, 60)
    policy.update_observation(obs, 1.0, True, 0x02, False, 60)
    policy.update_observation(obs, 2.0, True, 0x10, False, 1500)
    features = policy.live_security_features(obs)
    assert features["syn_ratio"] == pytest.approx(2 / 3)
    assert features["rst_ratio"] == 0.0
    assert features["icmp_ratio"] == 0.0
    assert features["inter_arrival_std"] == 0.0
    assert features["tcp_flag_entropy"] > 0.0
    assert features["small_packet_ratio"] == pytest.approx(2 / 3)


def test_live_features_empty_observation():
    features = policy.live_security_features(policy.new_observation())
    assert all(value == 0.0 for value in features.values())


def test_rejects_unknown_labels():
    with pytest.raises(ValueError):
        policy.decide("whale", "Low")
    with pytest.raises(ValueError):
        policy.decide("mice", "Critical")
