"""Live policy helpers for the POX Flow Security controller.

Pure Python with no POX imports so it runs both inside POX (copied flat
into ``ext/`` next to the controller) and under pytest here.

Mirrors :mod:`mnflow.decision_engine` (traffic x risk -> action) and the
risk heuristic in :mod:`mnflow.pcap_to_flow_dataset`. Keep the threshold
constants in sync with ``src/mnflow/features.py``.
"""

import math

TRAFFIC_CLASSES = ("mice", "elephant")
RISK_CLASSES = ("Low", "Medium", "High")
ACTIONS = ("forward", "reroute", "monitor", "rate_limit", "block")

ACTION_EFFECTS = {
    "forward": "normal flow_mod",
    "reroute": "alternate output port / high-priority path",
    "monitor": "forward + JSONL audit record",
    "rate_limit": "constrained flow_mod + audit record",
    "block": "high-priority drop flow_mod",
}

RISK_SYN_HIGH = 0.9
RISK_SYN_MED = 0.5
RISK_MIN_PACKETS = 3
RISK_RST_MED = 0.2
RISK_ICMP_MED = 0.5
RISK_ICMP_HIGH = 0.9
RISK_ICMP_FLOOD_RATE = 20.0
RISK_BULK_PACKETS = 100
RISK_SMALL_BULK = 0.9

SMALL_PACKET_THRESHOLD = 200


def decide(traffic, risk):
    if traffic not in TRAFFIC_CLASSES:
        raise ValueError(
            "Unknown traffic label: {!r}. Expected {!r}.".format(traffic, TRAFFIC_CLASSES)
        )
    if risk not in RISK_CLASSES:
        raise ValueError("Unknown risk label: {!r}. Expected {!r}.".format(risk, RISK_CLASSES))
    if risk == "High":
        return "block"
    if risk == "Medium":
        return "rate_limit" if traffic == "elephant" else "monitor"
    return "reroute" if traffic == "elephant" else "forward"


def describe(action):
    if action not in ACTION_EFFECTS:
        raise ValueError("Unknown action: {!r}. Expected {!r}.".format(action, ACTIONS))
    return ACTION_EFFECTS[action]


def risk_heuristic(total_packets, packet_rate, sec):
    if (
        (sec["syn_ratio"] >= RISK_SYN_HIGH and total_packets >= RISK_MIN_PACKETS)
        or (sec["icmp_ratio"] >= RISK_ICMP_HIGH and packet_rate >= RISK_ICMP_FLOOD_RATE)
        or (
            total_packets >= RISK_BULK_PACKETS
            and sec["small_packet_ratio"] >= RISK_SMALL_BULK
        )
    ):
        return "High"
    if (
        sec["syn_ratio"] >= RISK_SYN_MED
        or sec["rst_ratio"] >= RISK_RST_MED
        or sec["icmp_ratio"] >= RISK_ICMP_MED
    ):
        return "Medium"
    return "Low"


def new_observation():
    return {
        "total": 0,
        "tcp": 0,
        "syn": 0,
        "rst": 0,
        "icmp": 0,
        "small": 0,
        "flag_counts": {},
        "iat_n": 0,
        "iat_mean": 0.0,
        "iat_m2": 0.0,
        "last_ts": None,
    }


def update_observation(obs, timestamp, is_tcp, flags, is_icmp, size):
    """Fold one PacketIn-sized observation into per-flow counters.

    flags is an int bitmask (SYN=0x02, RST=0x04, ACK=0x10) or None when
    flag detail is unavailable; sizes use SMALL_PACKET_THRESHOLD.
    """
    last = obs["last_ts"]
    if last is None:
        obs["last_ts"] = timestamp
    else:
        interval = max(timestamp - last, 0.0)
        obs["iat_n"] += 1
        delta = interval - obs["iat_mean"]
        obs["iat_mean"] += delta / obs["iat_n"]
        obs["iat_m2"] += delta * (interval - obs["iat_mean"])
        obs["last_ts"] = timestamp
    obs["total"] += 1
    if is_tcp:
        obs["tcp"] += 1
        if flags is not None:
            obs["flag_counts"][flags] = obs["flag_counts"].get(flags, 0) + 1
            if flags & 0x02 and not flags & 0x10:
                obs["syn"] += 1
            if flags & 0x04:
                obs["rst"] += 1
    if is_icmp:
        obs["icmp"] += 1
    if size < SMALL_PACKET_THRESHOLD:
        obs["small"] += 1


def live_security_features(obs):
    """Approximate the 6 security features from PacketIn observations.

    inter_arrival_std falls back to 0.0 when fewer than two observations
    exist; small_packet_ratio falls back to size-based counts only.
    """
    total = obs["total"]
    tcp = obs["tcp"]
    counts = obs["flag_counts"]
    counted = sum(counts.values())
    if counted > 1:
        entropy = -sum(
            (c / counted) * (math.log(c / counted) / math.log(2)) for c in counts.values()
        )
    else:
        entropy = 0.0
    return {
        "syn_ratio": obs["syn"] / tcp if tcp else 0.0,
        "rst_ratio": obs["rst"] / tcp if tcp else 0.0,
        "icmp_ratio": obs["icmp"] / total if total else 0.0,
        "inter_arrival_std": math.sqrt(obs["iat_m2"] / obs["iat_n"]) if obs["iat_n"] else 0.0,
        "tcp_flag_entropy": entropy,
        "small_packet_ratio": obs["small"] / total if total else 0.0,
    }
