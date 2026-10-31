"""Every labelled scenario in lab/scenarios must meet its ground truth.

This covers each detector's positive cases (expected kinds and assessments) and negative
cases (forbidden kinds, no attack verdicts on benign or fault-only traffic), and it also
catches cross-detector false alarms because all detectors run on every scenario.
"""
import pytest

from conftest import SCENARIOS


@pytest.mark.parametrize("name", sorted(SCENARIOS))
def test_scenario_ground_truth(name, scenario):
    result = scenario(name)
    # Every finding must carry traceable evidence that resolves to a packet summary.
    for finding in result["findings"]:
        assert finding["evidence"], f"{finding['kind']} has no evidence"
        for item in finding["evidence"][:20]:
            assert str(item["packet"]) in {str(k) for k in result["packets"]}
        assert finding["summary"] and finding["likely_cause"] and finding["recommendations"]


def test_benign_office_is_completely_clean(scenario):
    result = scenario("benign_office")
    problems = [f["kind"] for f in result["findings"] if f["severity"] != "info"]
    assert not problems
    assert result["verdict"]["status"] == "clean"
