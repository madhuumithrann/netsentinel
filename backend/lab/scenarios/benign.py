"""Benign baselines: realistic healthy traffic that must not raise faults or attacks."""
from __future__ import annotations

from ..packets import (CLIENT, CLIENT2, CLIENT3, GATEWAY, SERVER, Timeline, arp_exchange, arp_probe,
                       dhcp_dora, dns_lookup, office_background, tcp_session)
from . import Scenario

# Every problem kind NetSentinel can report. A healthy capture must produce none of them.
ALL_PROBLEM_KINDS = {
    "TCP_RETRANSMISSIONS", "TCP_SYN_RETRIES", "TCP_CONNECTION_REFUSED", "TCP_CONNECTION_RESET",
    "PORT_SCAN", "HOST_SWEEP", "ARP_SPOOFING", "DUPLICATE_IP", "ARP_CONFLICT",
    "DNS_SERVER_UNRESPONSIVE", "DNS_SERVER_FAILURE", "DNS_NXDOMAIN", "DNS_DGA_PATTERN",
    "DNS_SLOW_RESPONSES", "DNS_HIJACK_SUSPECTED", "ROGUE_DHCP_SERVER", "MULTIPLE_DHCP_SERVERS",
    "DHCP_NO_RESPONSE", "DHCP_SERVER_PROBLEM", "SLOW_TCP_HANDSHAKE", "SLOW_SERVER_RESPONSE",
    "MTU_ICMP_FRAG_NEEDED", "MTU_BLACKHOLE_SUSPECTED",
}


def _office() -> Timeline:
    """Two minutes of a healthy small office: DHCP, ARP, DNS, web, file server, downloads."""
    tl = Timeline()
    # A laptop joins the network: ARP probe for its new address, then DHCP.
    arp_probe(tl, 0.0, "02:00:00:00:00:30", "192.168.1.30")
    dhcp_dora(tl, 0.2, GATEWAY, "02:00:00:00:00:30", 0x1234, "192.168.1.30", GATEWAY.ip, [GATEWAY.ip])
    office_background(tl, duration=120)
    # Large file-server download with delayed ACKs (looked like retransmissions to the old engine).
    tcp_session(tl, 15, CLIENT2, SERVER, 49152, 445, exchanges=[(400, 600_000)], rtt=0.002,
                isn_c=3_000_000, isn_s=4_000_000)
    # Many short connections from one browser to one server (looked like a scan to some tools).
    for i in range(30):
        tcp_session(tl, 40 + i * 0.2, CLIENT3, SERVER, 50100 + i, 443, exchanges=[(300, 900)],
                    isn_c=6_000_000 + i * 10_000, isn_s=7_000_000 + i * 10_000)
    # A client legitimately uses several services on the server.
    for j, port in enumerate((22, 80, 139, 445, 3389, 8080)):
        tcp_session(tl, 70 + j, CLIENT, SERVER, 51000 + j, port, exchanges=[(100, 500)],
                    isn_c=8_000_000 + j * 10_000, isn_s=9_000_000 + j * 10_000)
    for t in (5, 35, 65, 95):
        arp_exchange(tl, t, CLIENT2, SERVER)
        dns_lookup(tl, t + 0.5, CLIENT3, GATEWAY, "intranet.local", answers=["192.168.1.20"],
                   txid=40000 + int(t), sport=40000 + int(t))
    return tl


SCENARIOS = [
    Scenario("benign_office", "Healthy small-office network: DHCP, ARP, DNS, web browsing, file transfer",
             _office, forbid=ALL_PROBLEM_KINDS, forbid_attacks=True, sample="benign_office.pcap"),
]
