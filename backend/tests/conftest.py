"""Shared pytest helpers: build a scenario, write it to a temporary pcap and analyse it."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.analyzer import analyze_pcap  # noqa: E402
from lab.packets import Timeline  # noqa: E402
from lab.scenarios import all_scenarios  # noqa: E402

SCENARIOS = {s.name: s for s in all_scenarios()}


def run_timeline(tl: Timeline, tmp_path: Path, name: str = "capture.pcap") -> dict:
    path = tmp_path / name
    tl.write(str(path))
    return analyze_pcap(path)


def kinds(result: dict) -> set[str]:
    return {f["kind"] for f in result["findings"]}


def check_scenario(name: str, tmp_path: Path) -> dict:
    """Assert a scenario's ground truth and return the analysis result."""
    scenario = SCENARIOS[name]
    result = run_timeline(scenario.build(), tmp_path, f"{name}.pcap")
    found = kinds(result)
    missing = scenario.expect - found
    assert not missing, f"{name}: expected {sorted(missing)} but got {sorted(found)}"
    unexpected = scenario.forbid & found
    assert not unexpected, f"{name}: must not report {sorted(unexpected)}"
    for kind, assessment in scenario.expect_assessment.items():
        got = {f["assessment"] for f in result["findings"] if f["kind"] == kind}
        assert assessment in got, f"{name}: {kind} assessed as {got}, expected {assessment}"
    if scenario.forbid_attacks:
        attacks = [f["kind"] for f in result["findings"] if f["assessment"] == "attack"]
        assert not attacks, f"{name}: benign/fault scenario produced attack findings {attacks}"
    return result


@pytest.fixture
def scenario(tmp_path):
    return lambda name: check_scenario(name, tmp_path)
