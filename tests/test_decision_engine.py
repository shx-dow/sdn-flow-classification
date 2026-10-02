import pytest

from mnflow.decision_engine import ACTIONS, decide, describe


def test_full_matrix():
    assert decide("mice", "Low") == "forward"
    assert decide("elephant", "Low") == "reroute"
    assert decide("mice", "Medium") == "monitor"
    assert decide("elephant", "Medium") == "rate_limit"
    assert decide("mice", "High") == "block"
    assert decide("elephant", "High") == "block"


def test_security_takes_precedence():
    assert decide("elephant", "High") == decide("mice", "High") == "block"


def test_rejects_unknown_labels():
    with pytest.raises(ValueError):
        decide("whale", "Low")
    with pytest.raises(ValueError):
        decide("mice", "Critical")


def test_every_action_is_described():
    for action in ACTIONS:
        assert describe(action)
    with pytest.raises(ValueError):
        describe("throttle")
