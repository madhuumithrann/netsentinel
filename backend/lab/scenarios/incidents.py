"""Multi-stage scenarios that exercise the incident reconstruction engine.

Single-detector scenarios live in the other modules. These combine several problems in one
capture to check that related findings are merged into one incident (with the right verdict)
and that unrelated problems stay separate - the "outage or attack?" question from the brief.
"""
from __future__ import annotations

from ..packets import ATTACKER, CLIENT, CLIENT2, CLIENT3, GATEWAY, SERVER, WEB, Timeline, dns_lookup, office_background
from . import Scenario
from .arp import _mitm
from .dns import _injection_race
from .port_scan import probe
from .tcp_retransmissions import seg


def _mitm_chain() -> Timeline:
    """Reconnaissance, then ARP poisoning with traffic relaying, then forged DNS for a bank."""
    tl = _mitm()                      # two-way ARP poisoning of CLIENT <-> GATEWAY from t=8 s
    # Step 1 (t=2 s): the attacker scans the file server before attacking.
    for i, port in enumerate(range(1, 101)):
        answer = "synack" if port in (22, 445) else "rst"
        probe(tl, 2 + i * 0.01, ATTACKER, SERVER, 54321, port, answer)
    # Step 3 (t=24 s, while in the middle): forged DNS answers for the victim's bank.
    _injection_race(tl, 24.0, CLIENT, "bank.example.com", 20001, 33001)
    return tl


def _outage_and_unrelated_scan() -> Timeline:
    """The internet uplink fails at t=20 s (DNS and new connections time out together), while an
    unrelated host scans the file server. A good tool reports one fault and one attack."""
    tl = Timeline()
    office_background(tl, duration=18)
    clients = (CLIENT, CLIENT2, CLIENT3)
    for k in range(18):
        c = clients[k % 3]
        t = 20 + k * 1.6
        # DNS on the router gets no answer from upstream: queries time out and are retried.
        dns_lookup(tl, t, c, GATEWAY, f"site{k % 6}.example.com", txid=9000 + k, sport=60000 + k,
                   respond=False)
        dns_lookup(tl, t + 1.0, c, GATEWAY, f"site{k % 6}.example.com", txid=9100 + k,
                   sport=60100 + k, respond=False)
    # Already-resolved sites: connection attempts are never answered (SYN retried with backoff).
    for k, c in enumerate((CLIENT, CLIENT2, CLIENT3, CLIENT)):
        isn = 80_000 + 1000 * k
        for delay in (0, 1, 3, 7):
            seg(tl, 21 + 4 * k + delay, c, WEB, 52500 + k, 443, isn, 0, "S", dmac=GATEWAY.mac)
    # Unrelated: a compromised workstation scans the file server.
    for i, port in enumerate(range(1000, 1060)):
        probe(tl, 30 + i * 0.02, ATTACKER, SERVER, 40404, port, "rst")
    return tl


SCENARIOS = [
    Scenario("incident_mitm_chain",
             "Multi-stage attack: port scan, ARP poisoning man-in-the-middle, then forged DNS for a bank",
             _mitm_chain, expect={"PORT_SCAN", "ARP_SPOOFING", "DNS_HIJACK_SUSPECTED"},
             expect_assessment={"ARP_SPOOFING": "attack", "DNS_HIJACK_SUSPECTED": "attack"},
             sample="incident_mitm_chain.pcap"),
    Scenario("incident_outage_vs_attack",
             "Internet outage (DNS and connections failing) at the same time as an unrelated port scan",
             _outage_and_unrelated_scan,
             expect={"DNS_SERVER_UNRESPONSIVE", "TCP_SYN_RETRIES", "PORT_SCAN"},
             expect_assessment={"DNS_SERVER_UNRESPONSIVE": "fault", "PORT_SCAN": "attack"},
             sample="incident_outage_vs_attack.pcap"),
]
