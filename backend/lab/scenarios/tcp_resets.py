"""Ground-truth scenarios for the TCP reset detector."""
from __future__ import annotations

from ..packets import CLIENT, CLIENT2, CLIENT3, SERVER, Timeline, office_background, tcp_refused, tcp_session
from . import Scenario


def _service_down() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=40)
    # Three clients keep retrying the intranet web app on port 8080, which has crashed.
    for i in range(6):
        for j, c in enumerate((CLIENT, CLIENT2, CLIENT3)):
            tcp_refused(tl, 5 + i * 4 + j * 0.3, c, SERVER, 51000 + i * 3 + j, 8080, isn=1000 + i * 10 + j)
    return tl


def _browser_rst_close() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=30)
    # Normal: clients finish downloads and close with RST instead of FIN (common browser behaviour).
    for i in range(15):
        tcp_session(tl, 2 + i * 1.5, CLIENT, SERVER, 52000 + i, 443, exchanges=[(300, 3000)],
                    close="rst", isn_c=5000 + i * 100_000, isn_s=70_000 + i * 100_000)
    return tl


def _server_aborts() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=30)
    # The server resets connections in the middle of large downloads (application crash loop).
    for i in range(8):
        end = tcp_session(tl, 2 + i * 3, CLIENT2, SERVER, 53000 + i, 8443, exchanges=[(200, 6000)],
                          close="none", isn_c=9000 + i * 100_000, isn_s=80_000 + i * 100_000)
        from scapy.layers.inet import IP, TCP
        from scapy.layers.l2 import Ether
        tl.add(end + 0.01, Ether(src=SERVER.mac, dst=CLIENT2.mac) / IP(src=SERVER.ip, dst=CLIENT2.ip) /
               TCP(sport=8443, dport=53000 + i, flags="R", seq=80_000 + i * 100_000 + 6001))
    return tl


SCENARIOS = [
    Scenario("rst_service_down", "Clients repeatedly refused by a crashed service on port 8080",
             _service_down, expect={"TCP_CONNECTION_REFUSED"}, forbid={"PORT_SCAN"},
             expect_assessment={"TCP_CONNECTION_REFUSED": "fault"}, forbid_attacks=True,
             sample="fault_service_refused.pcap"),
    Scenario("rst_browser_close", "Normal sessions closed with RST after completing (benign)",
             _browser_rst_close, forbid={"TCP_CONNECTION_REFUSED", "TCP_CONNECTION_RESET"},
             forbid_attacks=True),
    Scenario("rst_server_aborts", "Server resets established downloads mid-transfer",
             _server_aborts, expect={"TCP_CONNECTION_RESET"},
             expect_assessment={"TCP_CONNECTION_RESET": "fault"}, forbid_attacks=True),
]
