"""Centralized decision engine for Flow Security.

Pure function of (traffic label, risk label) -> action. No POX imports:
the controller calls :func:`decide` and translates the action into
OpenFlow rules. Security takes precedence on conflict.
"""

from .features import RISK_CLASSES

TRAFFIC_CLASSES = ("mice", "elephant")

ACTIONS = ("forward", "reroute", "monitor", "rate_limit", "block")

ACTION_EFFECTS = {
    "forward": "normal flow_mod",
    "reroute": "alternate output port / high-priority path",
    "monitor": "forward + JSONL audit record",
    "rate_limit": "constrained flow_mod + audit record",
    "block": "high-priority drop flow_mod",
}


def decide(traffic, risk):
    """Map a (traffic, risk) pair to an enforcement action."""
    if traffic not in TRAFFIC_CLASSES:
        raise ValueError(f"Unknown traffic label: {traffic!r}. Expected {TRAFFIC_CLASSES}.")
    if risk not in RISK_CLASSES:
        raise ValueError(f"Unknown risk label: {risk!r}. Expected {RISK_CLASSES}.")

    if risk == "High":
        return "block"
    if risk == "Medium":
        return "rate_limit" if traffic == "elephant" else "monitor"
    return "reroute" if traffic == "elephant" else "forward"


def describe(action):
    """Human-readable OpenFlow effect for an action (for CLI/audit)."""
    if action not in ACTION_EFFECTS:
        raise ValueError(f"Unknown action: {action!r}. Expected {ACTIONS}.")
    return ACTION_EFFECTS[action]
