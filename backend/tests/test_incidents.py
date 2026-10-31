"""End-to-end incident reconstruction on multi-stage captures."""
from __future__ import annotations


def _incident_with(result, kind):
    ids = {f["id"] for f in result["findings"] if f["kind"] == kind}
    return next(i for i in result["incidents"] if ids & set(i["findings"]))


def test_mitm_chain_is_one_attack_incident(scenario):
    result = scenario("incident_mitm_chain")
    inc = _incident_with(result, "ARP_SPOOFING")
    assert set(inc["kinds"]) >= {"PORT_SCAN", "ARP_SPOOFING", "DNS_HIJACK_SUSPECTED"}
    assert inc["verdict"] == "attack"
    assert inc["title"].startswith("Man-in-the-middle")
    assert inc["confidence"] == "strong"
    assert {l["type"] for l in inc["links"]} == {"chain"}
    # The reconstructed timeline is chronological and starts with the reconnaissance.
    times = [e["time"] for e in inc["timeline"]]
    assert times == sorted(times)
    # Reconnaissance happens before the victim receives forged DNS answers.
    first = {}
    for e in inc["timeline"]:
        first.setdefault(e["kind"], e["time"])
    assert first["PORT_SCAN"] < first["DNS_HIJACK_SUSPECTED"]
    addresses = {h["address"] for h in inc["affected_hosts"]}
    assert "192.168.1.66" in addresses and "192.168.1.10" in addresses
    assert result["verdict"]["status"] == "attack"


def test_outage_and_unrelated_attack_are_separated(scenario):
    result = scenario("incident_outage_vs_attack")
    scan = _incident_with(result, "PORT_SCAN")
    outage = _incident_with(result, "DNS_SERVER_UNRESPONSIVE")
    assert scan["id"] != outage["id"]
    assert scan["verdict"] == "attack" and scan["kinds"] == ["PORT_SCAN"]
    assert outage["verdict"] == "fault"
    assert set(outage["kinds"]) == {"DNS_SERVER_UNRESPONSIVE", "TCP_SYN_RETRIES"}
    assert outage["links"][0]["type"] == "same_problem"
    assert result["verdict"]["counts"] == {"attack": 1, "fault": 1}
