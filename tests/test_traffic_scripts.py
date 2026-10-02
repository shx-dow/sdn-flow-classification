import importlib.util
import os
import stat

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLS = os.path.join(REPO, "tools")


def load_run_scenario():
    path = os.path.join(TOOLS, "run_scenario.py")
    spec = importlib.util.spec_from_file_location("run_scenario", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


rs = load_run_scenario()


def test_scenario_registry():
    assert set(rs.SCENARIOS) == {"benign", "scan", "flood"}


def test_benign_covers_mice_and_elephant():
    commands = " ".join(rs.benign_commands())
    assert "ping" in commands
    assert "iperf" in commands


def test_scan_is_syn_scan():
    commands = " ".join(rs.scan_commands())
    assert "nmap" in commands
    assert "-sS" in commands


def test_flood_is_bounded_syn_flood():
    commands = " ".join(rs.flood_commands())
    assert "hping3" in commands
    assert "-S" in commands
    assert "--flood" in commands
    assert "timeout" in commands


def test_tcpdump_writes_pcap():
    assert "-w" in rs.tcpdump_command("any", "data/raw/x.pcap")


def test_build_commands_rejects_unknown():
    with pytest.raises(ValueError):
        rs.build_commands("nope")


def test_wrappers_exist_and_executable():
    for name in ("gen_benign.sh", "gen_scan.sh", "gen_flood.sh"):
        path = os.path.join(TOOLS, name)
        assert os.path.isfile(path)
        assert os.stat(path).st_mode & stat.S_IXUSR
