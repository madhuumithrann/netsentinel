"""Precise assertions on what each detector reports (attribution, counts, classification).

The ground-truth checks in test_scenarios.py prove that the right kinds fire; these tests prove
the details a user acts on are correct: who the attacker is, which server is rogue, how many
segments were really lost, and why.
"""
from __future__ import annotations


def _one(result, kind):
    found = [f for f in result["findings"] if f["kind"] == kind]
    assert len(found) == 1, [f["kind"] for f in result["findings"]]
    return found[0]


def test_retransmissions_counts_are_exact(scenario):
    f = _one(scenario("retx_lossy_internet_path"), "TCP_RETRANSMISSIONS")
    m = f["metrics"]
    assert m["retransmissions"] == 15          # 5 dropped segments x 3 downloads
    assert m["flows"] == 3 and m["spurious"] == 0 and m["capture_duplicates"] == 0
    assert m["fast_retransmissions"] + m["other_retransmissions"] == 15
    assert f["hosts"]["server"] == ["93.184.216.34"]


def test_timeout_retransmissions_classified(scenario):
    m = _one(scenario("retx_timeout_losses"), "TCP_RETRANSMISSIONS")["metrics"]
    assert m["retransmissions"] == 5 and m["timeout_retransmissions"] == 5
    assert abs(m["median_delay_seconds"] - 0.3) < 0.01


def test_capture_duplicates_are_not_loss(scenario):
    result = scenario("retx_neg_capture_duplicates")
    assert not [f for f in result["findings"] if f["kind"] == "TCP_RETRANSMISSIONS"]


def test_mtu_icmp_reports_value_and_router(scenario):
    f = _one(scenario("mtu_icmp_frag_needed"), "MTU_ICMP_FRAG_NEEDED")
    assert f["metrics"]["mtu_values"] == [1400]
    assert f["metrics"]["flows_adapted"] == 2
    assert f["hosts"]["reporting router"] == ["192.168.1.1"]


def test_mtu_blackhole_brackets_sizes(scenario):
    m = _one(scenario("mtu_blackhole"), "MTU_BLACKHOLE_SUSPECTED")["metrics"]
    assert m["smallest_failed_packet"] == 1500
    assert m["largest_acknowledged_packet"] < 1500
    assert m["resized_and_acknowledged"] == 1


def test_arp_spoofing_names_attacker_and_victims(scenario):
    f = _one(scenario("arp_spoofing_mitm"), "ARP_SPOOFING")
    assert "02:00:00:00:00:66" in f["hosts"]["attacker"]
    assert "192.168.1.1" in f["hosts"]["impersonated"]
    # Victims are local hosts, never the internet servers whose traffic was intercepted.
    assert f["hosts"]["victim"] and all(v.startswith("192.168.1.") for v in f["hosts"]["victim"])
    assert "192.168.1.10" in f["hosts"]["victim"]
    assert f["assessment"] == "attack" and f["evidence_strength"] == "strong"


def test_duplicate_ip_names_both_devices(scenario):
    f = _one(scenario("arp_duplicate_ip"), "DUPLICATE_IP")
    assert f["hosts"]["address"] == ["192.168.1.50"]
    assert len(f["hosts"]["device"]) == 2
    assert f["assessment"] == "fault"


def test_rogue_dhcp_identifies_rogue_and_offered_settings(scenario):
    f = _one(scenario("dhcp_rogue_server"), "ROGUE_DHCP_SERVER")
    assert f["hosts"]["rogue_server"][0] == "192.168.1.66"
    assert f["hosts"]["legitimate_server"][0] == "192.168.1.1"
    assert "6.6.6.6" in f["hosts"]["rogue_dns"]


def test_dns_hijack_shows_forged_answer(scenario):
    f = _one(scenario("dns_hijack_race"), "DNS_HIJACK_SUSPECTED")
    assert "192.168.1.66" in f["hosts"]["forged_answer_address"]
    assert f["hosts"]["dns_server"] == ["192.168.1.1"]
    roles = " ".join(e["role"] for e in f["evidence"]).lower()
    assert "forged" in roles or "conflicting" in roles


def test_port_scan_reports_true_scope(scenario):
    f = _one(scenario("scan_vertical_syn"), "PORT_SCAN")
    assert f["hosts"]["scanner"] == ["192.168.1.66"]
    assert "100 ports" in f["title"]


def test_slow_application_not_blamed_on_network(scenario):
    f = _one(scenario("delay_slow_application"), "SLOW_SERVER_RESPONSE")
    assert "network is fine" in f["title"]
    assert f["hosts"]["server"] == ["192.168.1.20"]


def test_dns_outage_attributed_to_server_not_client(scenario):
    f = _one(scenario("dns_server_outage"), "DNS_SERVER_UNRESPONSIVE")
    assert f["hosts"]["dns_server"] == ["192.168.1.20"]
    assert len(f["hosts"]["client"]) == 3
