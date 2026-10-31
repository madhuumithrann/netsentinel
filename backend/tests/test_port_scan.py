from conftest import SCENARIOS, run_timeline
import pytest

from app.config import DEFAULT_SETTINGS
from app.context import AnalysisContext
from app.detectors import port_scan
from app.model import ACK, FIN, SYN, PacketRecord
from lab.packets import ATTACKER, CLIENT, CLIENT2, SERVER, Timeline, host, office_background
from lab.scenarios.port_scan import probe

ATTACKER_IP, SERVER_IP = ATTACKER.ip, SERVER.ip


def _scan_findings(result, kind=None):
    return [f for f in result["findings"] if f["detector"] == "port_scan" and (kind is None or f["kind"] == kind)]


def _one(result, kind="PORT_SCAN"):
    found = _scan_findings(result, kind)
    assert len(found) == 1, [f["title"] for f in _scan_findings(result)]
    return found[0]


@pytest.mark.parametrize("name", [n for n in SCENARIOS if n.startswith("scan_")])
def test_scan_scenarios(name, scenario):
    result = scenario(name)
    status = {d["name"]: d["status"] for d in result["detectors"]}
    assert status.get("port_scan") == "ok"


def test_vertical_scope_attribution_and_evidence(scenario):
    result = scenario("scan_vertical_syn")
    f = _one(result)
    m = f["metrics"]
    assert (m["probes"], m["distinct_ports"], m["distinct_targets"], m["host_port_pairs"]) == (100, 100, 1, 100)
    assert m["outcomes"] == {"open": 2, "closed": 96, "filtered": 2, "open|filtered": 0, "session": 0}
    assert m["open_ports"] == {SERVER_IP: ["22/tcp", "80/tcp"]}
    assert m["scan_types"] == ["TCP SYN half-open"]
    assert m["triggers"] == ["vertical"] and m["bursts"] == 1
    assert f["hosts"]["scanner"] == [ATTACKER_IP] and f["hosts"]["target"] == [SERVER_IP]
    assert f["hosts"]["scanner_mac"] == [ATTACKER.mac]
    assert f["category"] == "attack" and f["assessment"] == "attack" and f["severity"] == "high"
    assert "100 different port" in f["summary"] and "22/tcp, 80/tcp on 192.168.1.20" in f["summary"]
    roles = [e["role"] for e in f["evidence"]]
    assert f"SYN/ACK: port 22 open on {SERVER_IP}" in roles
    assert f"SYN/ACK: port 80 open on {SERVER_IP}" in roles
    assert any("half-open" in r for r in roles)
    assert any(r.startswith("SYN probe to 192.168.1.20 port") and r.endswith("(closed)") for r in roles)
    assert any(r.startswith("RST: port") for r in roles)
    assert any("port 25/tcp (filtered, no answer)" in r for r in roles)
    assert any("port 69/tcp (filtered, no answer)" in r for r in roles)
    for e in f["evidence"]:
        pkt = result["packets"][e["packet"]]
        assert {pkt["src"], pkt["dst"]} == {ATTACKER_IP, SERVER_IP}     # never background traffic
        assert "len=0" in pkt["info"]                                  # never session data
    # One refusal per port: the outage detector must not misread the scan as a broken service.
    assert not [x for x in result["findings"] if x["kind"] == "TCP_CONNECTION_REFUSED"]


def test_open_port_roles_point_at_synacks(scenario):
    result = scenario("scan_vertical_syn")
    f = _one(result)
    for e in f["evidence"]:
        pkt = result["packets"][e["packet"]]
        if e["role"].startswith("SYN/ACK"):
            assert "[SYN,ACK]" in pkt["info"] and pkt["src"] == SERVER_IP
            assert pkt["sport"] == int(e["role"].split("port ")[1].split()[0])
        if e["role"].startswith("SYN probe"):
            assert "[SYN]" in pkt["info"] and pkt["src"] == ATTACKER_IP


def test_horizontal_sweep(scenario):
    result = scenario("scan_horizontal_sweep")
    f = _one(result, "HOST_SWEEP")
    m = f["metrics"]
    assert m["distinct_targets"] == 30 and m["distinct_ports"] == 1 and m["triggers"] == ["horizontal"]
    assert m["open_hosts"] == 4 and m["outcomes"]["filtered"] == 6 and m["outcomes"]["closed"] == 20
    assert set(m["open_ports"]) == {"192.168.1.100", "192.168.1.105", "192.168.1.110", "192.168.1.115"}
    assert len(f["hosts"]["target"]) == 30
    assert "port 22/tcp" in f["title"]


def test_slow_scan_detected_only_by_slow_rule(scenario):
    f = _one(scenario("scan_slow"))
    m = f["metrics"]
    assert m["triggers"] == ["slow"]
    assert m["peak_ports_in_window"] < DEFAULT_SETTINGS.thresholds.scan_vertical_ports
    assert m["distinct_ports"] == 150 and m["duration_seconds"] == pytest.approx(745, abs=1)
    assert any(i["strength"] == "moderate" and "slow" in i["text"] for i in f["indicators"])
    assert f["assessment"] == "attack"


def test_stealth_flags(scenario):
    f = _one(scenario("scan_stealth_fin_null_xmas"))
    m = f["metrics"]
    assert m["scan_types"] == ["TCP FIN", "TCP NULL (no flags)", "TCP XMAS (FIN+PSH+URG)"]
    assert m["stealth_probes"] == 30 and m["outcomes"]["open|filtered"] == 3
    assert "stealth" in m["triggers"]
    small = _one(scenario("scan_stealth_small"))
    assert small["metrics"]["triggers"] == ["stealth"] and small["metrics"]["distinct_ports"] == 6


def test_udp_scan_counts(scenario):
    result = scenario("scan_udp")
    f = _one(result)
    m = f["metrics"]
    assert m["scan_types"] == ["UDP"] and m["distinct_ports"] == 42
    assert m["outcomes"]["closed"] == 36 and m["outcomes"]["open|filtered"] == 4
    assert m["open_ports"] == {SERVER_IP: ["161/udp", "500/udp"]}
    assert any("port unreachable" in e["role"] for e in f["evidence"])


def test_connect_scan_technique(scenario):
    f = _one(scenario("scan_connect"))
    assert f["metrics"]["scan_types"] == ["TCP connect"]
    assert any("connect scan" in e["role"] for e in f["evidence"])
    # OS-built SYNs carry MSS and fresh source ports: the crafted-packet indicators must not fire.
    assert not any("MSS" in i["text"] or "Source port" in i["text"] for i in f["indicators"])


def test_ipv6_scan(scenario):
    f = _one(scenario("scan_ipv6"))
    assert f["hosts"]["scanner"] == ["fd00::66"] and f["hosts"]["target"] == ["fd00::20"]
    assert f["metrics"]["distinct_ports"] == 30 and f["metrics"]["open_ports"] == {"fd00::20": ["22/tcp"]}


def test_two_bursts_one_finding(scenario):
    f = _one(scenario("scan_two_bursts"))
    m = f["metrics"]
    assert m["bursts"] == 2 and m["probes"] == 80 and m["distinct_targets"] == 2
    assert [b["probes"] for b in m["burst_detail"]] == [40, 40]
    assert m["open_ports"] == {SERVER_IP: ["22/tcp"], "192.168.1.30": ["21/tcp"]}
    assert "2 separate bursts" in f["summary"]


def test_large_scan_true_scope_and_capped_evidence(tmp_path):
    tl = Timeline()
    office_background(tl, duration=20)
    for i, port in enumerate(range(1, 1001)):
        probe(tl, 2 + i * 0.002, ATTACKER, SERVER, 54321, port, "synack" if port in (22, 80, 443) else "rst")
    f = _one(run_timeline(tl, tmp_path))
    assert f["metrics"]["distinct_ports"] == 1000 and f["metrics"]["probes"] == 1000
    assert "1000 different port" in f["summary"]
    assert f["evidence_total"] <= port_scan.OPEN_EVIDENCE_PROBES * 3 + port_scan.FAILED_EVIDENCE_PROBES * 2
    assert f["metrics"]["open_ports"] == {SERVER_IP: ["22/tcp", "80/tcp", "443/tcp"]}


def test_one_finding_per_source_with_legit_traffic_mixed_in(tmp_path):
    tl = Timeline()
    office_background(tl, duration=30)            # CLIENT/CLIENT2/CLIENT3 browse normally
    for i, port in enumerate(range(1000, 1040)):
        probe(tl, 3 + i * 0.01, ATTACKER, SERVER, 50000, port, "rst")
    for i, n in enumerate(range(140, 160)):
        probe(tl, 4 + i * 0.03, CLIENT2, host(n), 41000, 3389, "rst", isn=5000 + i)
    result = run_timeline(tl, tmp_path)
    scans = _scan_findings(result)
    by_src = {f["hosts"]["scanner"][0]: f for f in scans}
    assert set(by_src) == {ATTACKER_IP, CLIENT2.ip}
    assert by_src[ATTACKER_IP]["kind"] == "PORT_SCAN" and by_src[CLIENT2.ip]["kind"] == "HOST_SWEEP"
    # CLIENT2's normal HTTPS browsing (background) is not part of its sweep.
    assert by_src[CLIENT2.ip]["metrics"]["distinct_ports"] == 1
    assert CLIENT.ip not in by_src


def test_window_boundary_is_inclusive():
    events = [(0.0, 1, False), (30.0, 2, False), (60.0, 3, False), (60.01, 4, False)]
    best, peak = port_scan._window(events, 60.0, 0.6)
    assert peak == 3 and best[0] == 3
    used = [(0.0, k, True) for k in range(20)]
    best, peak = port_scan._window(used, 60.0, 0.6)
    assert best is None and peak == 20


def test_detector_survives_malformed_records():
    def rec(n, **kw):
        return PacketRecord(n=n, ts=1000.0 + n, caplen=60, wirelen=60, **kw)

    records = [
        rec(1, l3="IPv4", ip_src="10.0.0.1", ip_dst="10.0.0.2", l4="TCP", tcp_flags=None, sport=7, dport=80),
        rec(2, l3="IPv4", ip_src="10.0.0.1", ip_dst="10.0.0.2", l4="TCP", tcp_flags=SYN, sport=1, dport=2),
        rec(9, l3="IPv4", ip_src="10.0.0.1", ip_dst="10.0.0.2", l4="TCP", tcp_flags=None, sport=1, dport=2),
        rec(3, l3="IPv4", ip_src="10.0.0.2", ip_dst="10.0.0.1", l4="ICMP", icmp_type=3, icmp_code=3,
            icmp_inner={"proto": 17}),
        rec(4, l3="IPv4", ip_src="10.0.0.2", ip_dst="10.0.0.1", l4="ICMP", icmp_type=3, icmp_code=3,
            icmp_inner={"src": "10.0.0.1", "dst": "10.0.0.2", "proto": 17, "sport": "x", "dport": None}),
        rec(5, l3="IPv4", ip_src="10.0.0.1", ip_dst="10.0.0.2", l4="UDP", sport=None, dport=None),
        rec(6, l3="IPv4", ip_src="10.0.0.9", ip_dst="10.0.0.1", l4="UDP", sport=53, dport=5000, app="DNS",
            dns={"qr": 1, "answers": [None, {"type": "A"}]}),
        rec(7, l3="IPv4", ip_src="10.0.0.1", ip_dst="10.0.0.2", l4="TCP", tcp_flags=FIN | ACK, sport=5, dport=6),
        rec(8, malformed="truncated Ethernet header"),
    ]
    assert port_scan.detect(AnalysisContext(records, DEFAULT_SETTINGS)) == []
