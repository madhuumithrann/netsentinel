from conftest import SCENARIOS
import pytest


@pytest.mark.parametrize("name", [n for n in SCENARIOS if n.startswith("rst_")])
def test_reset_scenarios(name, scenario):
    scenario(name)


def test_refused_evidence_pairs_syn_and_rst(scenario):
    result = scenario("rst_service_down")
    finding = next(f for f in result["findings"] if f["kind"] == "TCP_CONNECTION_REFUSED")
    roles = {e["role"] for e in finding["evidence"]}
    assert any("SYN" in r for r in roles) and any("RST" in r for r in roles)
    assert finding["metrics"]["port"] == 8080
    assert finding["hosts"]["server"] == ["192.168.1.20"]
    # Every referenced packet has a readable summary in the response.
    for e in finding["evidence"]:
        assert e["packet"] in result["packets"]
