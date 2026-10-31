"""Incident reconstruction tests with hand-built findings (independent of the detectors)."""
from __future__ import annotations

from app.config import DEFAULT_SETTINGS
from app.context import AnalysisContext
from app.correlate import build_incidents
from app.model import ATTACK, FAULT, Evidence, Finding, Indicator, PacketRecord


def _ctx() -> AnalysisContext:
    records = [PacketRecord(n=i, ts=1000.0 + i, caplen=60, wirelen=60, ip_src="10.0.0.1", ip_dst="10.0.0.2")
               for i in range(1, 301)]
    return AnalysisContext(records, DEFAULT_SETTINGS)


def _f(fid, kind, assessment, hosts, t0, t1, strength="moderate", severity="medium", detector=None):
    f = Finding(detector=detector or kind.lower(), kind=kind, title=kind.replace("_", " ").title(),
                category="attack" if assessment == ATTACK else "fault", assessment=assessment,
                severity=severity, evidence_strength=strength, summary=f"{kind} summary",
                impact="impact", likely_cause=f"{kind} cause", recommendations=[f"fix {kind}"],
                facts=[f"{kind} fact"], limitations=[f"{kind} limitation"],
                indicators=[Indicator(f"{kind} indicator", assessment, strength)],
                hosts=hosts, time_start=1000.0 + t0, time_end=1000.0 + t1,
                evidence=[Evidence(int(t0) + 1, f"{kind} evidence"), Evidence(int(t1) + 1, f"{kind} evidence")])
    f.id = fid
    return f


def _by_findings(incidents):
    return {tuple(sorted(i["findings"])): i for i in incidents}


def test_empty_is_clean():
    incidents, verdict = build_incidents([], _ctx())
    assert incidents == [] and verdict["status"] == "clean"


def test_mitm_chain_grouped_as_attack():
    arp = _f("F-001", "ARP_SPOOFING", ATTACK, {"attacker": ["02:00:00:00:00:66"], "victim": ["192.168.1.10"]},
             10, 100, "strong", "high")
    dns = _f("F-002", "DNS_HIJACK_SUSPECTED", ATTACK, {"client": ["192.168.1.10"], "server": ["192.168.1.1"]},
             40, 45, "strong", "high")
    incidents, verdict = build_incidents([arp, dns], _ctx())
    assert len(incidents) == 1
    inc = incidents[0]
    assert inc["verdict"] == "attack"
    assert "Man-in-the-middle" in inc["title"]
    assert inc["links"] and inc["links"][0]["type"] == "chain"
    assert "192.168.1.10" in inc["links"][0]["basis"]
    assert any("Correlation does not prove causation" in u for u in inc["uncertainty"])
    assert inc["timeline"] == sorted(inc["timeline"], key=lambda e: (e["time"], e["packet"]))
    assert verdict["status"] == "attack"


def test_scan_side_effects_are_not_reported_as_separate_fault():
    scan = _f("F-001", "PORT_SCAN", ATTACK, {"scanner": ["192.168.1.66"], "target": ["192.168.1.20"]}, 5, 20, "strong", "high")
    refused = _f("F-002", "TCP_CONNECTION_REFUSED", FAULT, {"server": ["192.168.1.20"], "client": ["192.168.1.66"]}, 6, 19)
    incidents, _ = build_incidents([scan, refused], _ctx())
    assert len(incidents) == 1
    inc = incidents[0]
    assert inc["verdict"] == "attack"
    assert inc["root_finding"] == "F-001"
    assert any("side effect" in n for n in inc["verdict_notes"])


def test_unrelated_findings_at_same_time_stay_separate():
    # Same time window, but no shared host and no documented relationship.
    arp = _f("F-001", "ARP_SPOOFING", ATTACK, {"attacker": ["02:00:00:00:00:66"], "victim": ["192.168.1.10"]}, 10, 50, "strong", "high")
    mtu = _f("F-002", "MTU_ICMP_FRAG_NEEDED", FAULT, {"client": ["192.168.1.30"], "router": ["10.9.9.9"]}, 10, 50)
    incidents, verdict = build_incidents([arp, mtu], _ctx())
    assert len(incidents) == 2
    assert {i["verdict"] for i in incidents} == {"attack", "fault"}
    assert verdict["status"] == "attack"


def test_shared_host_without_relation_is_not_linked():
    # Both involve the same client, but a DGA pattern does not cause an MTU problem.
    dga = _f("F-001", "DNS_DGA_PATTERN", ATTACK, {"client": ["192.168.1.10"]}, 10, 20)
    mtu = _f("F-002", "MTU_ICMP_FRAG_NEEDED", FAULT, {"client": ["192.168.1.10"]}, 10, 20)
    incidents, _ = build_incidents([dga, mtu], _ctx())
    assert len(incidents) == 2


def test_far_apart_in_time_not_linked():
    scan = _f("F-001", "PORT_SCAN", ATTACK, {"scanner": ["192.168.1.66"]}, 0, 5, "strong")
    arp = _f("F-002", "ARP_SPOOFING", ATTACK, {"attacker": ["192.168.1.66"]}, 280, 290, "strong")
    ctx = _ctx()
    gap = ctx.thresholds.correlation_gap_seconds
    assert 275 > gap
    incidents, _ = build_incidents([scan, arp], ctx)
    assert len(incidents) == 2


def test_fault_cause_chain_and_root_cause():
    mtu = _f("F-001", "MTU_BLACKHOLE_SUSPECTED", FAULT, {"client": ["192.168.1.10"], "server": ["93.184.216.34"]}, 10, 40)
    retx = _f("F-002", "TCP_RETRANSMISSIONS", FAULT, {"client": ["192.168.1.10"], "server": ["93.184.216.34"]}, 12, 41)
    incidents, verdict = build_incidents([retx, mtu], _ctx())
    assert len(incidents) == 1
    inc = incidents[0]
    assert inc["verdict"] == "fault"
    assert inc["root_finding"] == "F-001"          # retransmissions are the effect, MTU the cause
    assert verdict["status"] == "fault"


def test_time_only_outage_link():
    dns = _f("F-001", "DNS_SERVER_UNRESPONSIVE", FAULT, {"server": ["192.168.1.1"], "client": ["192.168.1.10"]}, 10, 60)
    syn = _f("F-002", "TCP_SYN_RETRIES", FAULT, {"server": ["93.184.216.34"], "client": ["192.168.1.11"]}, 15, 55)
    incidents, _ = build_incidents([dns, syn], _ctx())
    assert len(incidents) == 1
    assert "time-only" in incidents[0]["links"][0]["basis"]


def test_mixed_attack_and_unexplained_fault():
    arp = _f("F-001", "ARP_SPOOFING", ATTACK, {"attacker": ["02:00:00:00:00:66"], "victim": ["192.168.1.10"]}, 10, 100, "strong", "high")
    dns = _f("F-002", "DNS_HIJACK_SUSPECTED", ATTACK, {"client": ["192.168.1.10"]}, 20, 30, "strong", "high")
    # A DNS outage linked to the hijack via a shared host is not explained as a side effect.
    out = _f("F-003", "DNS_SERVER_FAILURE", FAULT, {"client": ["192.168.1.10"], "server": ["192.168.1.1"]}, 20, 30)
    incidents, _ = build_incidents([arp, dns, out], _ctx())
    linked = [i for i in incidents if "F-003" in i["findings"]]
    assert linked and linked[0]["verdict"] in ("fault", "mixed")


def test_independent_detectors_raise_confidence():
    a = _f("F-001", "ARP_SPOOFING", ATTACK, {"victim": ["192.168.1.10"]}, 10, 20, "moderate", "high", detector="arp")
    b = _f("F-002", "DNS_HIJACK_SUSPECTED", ATTACK, {"client": ["192.168.1.10"]}, 12, 18, "moderate", "high", detector="dns")
    incidents, _ = build_incidents([a, b], _ctx())
    assert incidents[0]["confidence"] == "strong"
    assert "independent detectors" in incidents[0]["confidence_reason"]
