"""Ground-truth scenarios for the port-scan / host-sweep detector.

Positive scenarios cover every scanning technique the detector claims (SYN half-open,
connect, FIN/NULL/XMAS, UDP, IPv6, horizontal sweep, slow scan, two bursts). Negative
scenarios reproduce the traffic that naive scan detectors misreport: clients using many
services, FTP data connections, browsers, retries, late DNS answers, uplink loss, mtr and
malformed frames. All packets are built offline with explicit MAC addresses.
"""
from __future__ import annotations

from scapy.layers.inet import ICMP, IP, TCP, UDP, IPerror, TCPerror, UDPerror
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from ..packets import (ATTACKER, CLIENT, CLIENT2, CLIENT3, GATEWAY, PUBLIC_DNS, SERVER, WEB, Host,
                       Timeline, dns_lookup, host, icmp_port_unreachable, office_background, tcp_refused,
                       tcp_session)
from . import Scenario

ATTACKER6 = Host("fd00::66", ATTACKER.mac)
SERVER6 = Host("fd00::20", SERVER.mac)
PORT_SCAN_KINDS = {"PORT_SCAN", "HOST_SWEEP"}


# --- local builders --------------------------------------------------------------------------

def _ip(src: Host, dst: Host, **kw):
    if ":" in src.ip:
        return IPv6(src=src.ip, dst=dst.ip, **({"hlim": kw["ttl"]} if "ttl" in kw else {}))
    return IP(src=src.ip, dst=dst.ip, **kw)


def probe(tl: Timeline, t: float, src: Host, dst: Host, sport: int, dport: int, answer: str | None,
          flags: str = "S", mss: int | None = None, isn: int = 4242, rtt: float = 0.002,
          connect: bool = False, l2dst: str | None = None) -> None:
    """One TCP probe and the target's answer.

    ``answer``: "rst" (closed), "synack" (open, SYN probes only) or None (silently dropped).
    For an open port the prober either resets (half-open) or completes the handshake and then
    resets (``connect=True``). Stealth probes pass ``flags`` like "F", "" or "FPU".
    """
    dmac = l2dst or dst.mac
    opts = [("MSS", mss)] if mss else []
    tl.add(t, Ether(src=src.mac, dst=dmac) / _ip(src, dst) /
           TCP(sport=sport, dport=dport, flags=flags, seq=isn, options=opts, window=1024 if not mss else 64240))
    back = Ether(src=dmac, dst=src.mac) / _ip(dst, src)
    if answer == "rst":
        ack = isn + (1 if "S" in flags else 0)
        tl.add(t + rtt, back / TCP(sport=dport, dport=sport, flags="RA", seq=0, ack=ack))
    elif answer == "synack":
        tl.add(t + rtt, back / TCP(sport=dport, dport=sport, flags="SA", seq=880000, ack=isn + 1,
                                   options=[("MSS", 1460)]))
        fwd = Ether(src=src.mac, dst=dmac) / _ip(src, dst)
        if connect:
            tl.add(t + 2 * rtt, fwd / TCP(sport=sport, dport=dport, flags="A", seq=isn + 1, ack=880001))
            tl.add(t + 3 * rtt, fwd / TCP(sport=sport, dport=dport, flags="RA", seq=isn + 1, ack=880001))
        else:
            tl.add(t + 2 * rtt, fwd / TCP(sport=sport, dport=dport, flags="R", seq=isn + 1))


def udp_probe(tl: Timeline, t: float, src: Host, dst: Host, sport: int, dport: int, answer: str | None) -> None:
    """A UDP probe; ``answer`` is "unreach" (ICMP port unreachable), "reply" (open) or None."""
    tl.add(t, Ether(src=src.mac, dst=dst.mac) / IP(src=src.ip, dst=dst.ip) /
           UDP(sport=sport, dport=dport) / Raw(b"\x00" * 8))
    if answer == "unreach":
        icmp_port_unreachable(tl, t + 0.002, dst, src, sport, dport)
    elif answer == "reply":
        tl.add(t + 0.002, Ether(src=dst.mac, dst=src.mac) / IP(src=dst.ip, dst=src.ip) /
               UDP(sport=dport, dport=sport) / Raw(b"\x30" * 40))


# --- positive scenarios ----------------------------------------------------------------------

def _vertical() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=30)
    # nmap -sS style: raw SYNs (no MSS) from one fixed source port, ports 1-100.
    for i, port in enumerate(range(1, 101)):
        answer = "synack" if port in (22, 80) else None if port in (25, 69) else "rst"
        probe(tl, 5 + i * 0.01, ATTACKER, SERVER, 54321, port, answer)
    return tl


def _vertical_15() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=30)
    for i, port in enumerate([21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3306, 3389, 8080]):
        probe(tl, 5 + i * 0.5, ATTACKER, SERVER, 54321, port, "synack" if port == 22 else "rst")
    return tl


def _horizontal() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=30)
    # Is SSH open anywhere? Port 22 on 192.168.1.100-129.
    for i, n in enumerate(range(100, 130)):
        answer = "synack" if n in (100, 105, 110, 115) else None if 120 <= n <= 125 else "rst"
        probe(tl, 5 + i * 0.05, ATTACKER, host(n), 40123, 22, answer, isn=7000 + i)
    return tl


def _slow() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=760)
    # One probe every 5 s: 12 per minute, below the 15-per-window threshold, 150 ports in total.
    for i, port in enumerate(range(1, 151)):
        probe(tl, 2 + i * 5.0, ATTACKER, SERVER, 50505, port, "synack" if port in (22, 143) else "rst",
              isn=10_000 + i)
    return tl


def _stealth() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=30)
    # FIN, NULL and XMAS probes. RFC 793 targets answer closed ports with RST and stay silent
    # on open ones (21, 22, 25 here).
    for i, (flags, port) in enumerate([("F", p) for p in range(1, 11)] + [("", p) for p in range(11, 21)]
                                       + [("FPU", p) for p in range(21, 31)]):
        probe(tl, 5 + i * 0.02, ATTACKER, SERVER, 61000, port, None if port in (21, 22, 25) else "rst",
              flags=flags)
    return tl


def _stealth_small() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=30)
    # Only 6 XMAS probes: far below the vertical threshold, but XMAS has no legitimate use.
    for i, port in enumerate([21, 22, 23, 25, 80, 443]):
        probe(tl, 5 + i * 0.3, ATTACKER, SERVER, 61001, port, None if port in (22, 80) else "rst", flags="FPU")
    return tl


def _udp() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=30)
    ports = list(range(100, 140)) + [161, 500]
    for i, port in enumerate(ports):
        if port in (161, 500):
            answer = "reply"
        elif port % 10 == 5:
            answer = None           # ICMP rate limited: no answer for these
        else:
            answer = "unreach"
        udp_probe(tl, 5 + i * 0.05, ATTACKER, SERVER, 47000, port, answer)
    return tl


def _connect() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=30)
    # nmap -sT: the OS stack does the work (MSS option, new source port per probe, full handshake).
    for i, port in enumerate(range(1, 51)):
        probe(tl, 5 + i * 0.02, ATTACKER, SERVER, 45000 + i, port, "synack" if port in (22, 25) else "rst",
              mss=1460, isn=20_000 + i * 1000, connect=True)
    return tl


def _ipv6() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=30)
    for i, port in enumerate(range(1, 31)):
        probe(tl, 5 + i * 0.01, ATTACKER6, SERVER6, 54000, port, "synack" if port == 22 else "rst")
    return tl


def _two_bursts() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=260)
    target2 = host(30)
    for i, port in enumerate(range(1, 41)):
        probe(tl, 5 + i * 0.02, ATTACKER, SERVER, 54321, port, "synack" if port == 22 else "rst")
    for i, port in enumerate(range(1, 41)):
        probe(tl, 200 + i * 0.02, ATTACKER, target2, 54322, port, "synack" if port == 21 else "rst")
    return tl


# --- negative scenarios ----------------------------------------------------------------------

SERVICES = [21, 22, 25, 53, 80, 110, 143, 389, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 5900, 8080,
            8443, 9000]


def _multi_service() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=40)
    # An admin workstation really uses 20 services on the server within 20 seconds.
    for i, port in enumerate(SERVICES):
        tcp_session(tl, 2 + i * 1.0, CLIENT, SERVER, 41000 + i, port, exchanges=[(120, 900)],
                    isn_c=100_000 * (i + 1), isn_s=5_000_000 + 100_000 * i)
    return tl


def _ftp_passive() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=40)
    tcp_session(tl, 1, CLIENT, SERVER, 40021, 21, exchanges=[(30, 80)] * 25, rtt=0.02)
    # 20 passive-mode data connections to negotiated high ports (download: server-only data).
    for i in range(20):
        tcp_session(tl, 2 + i * 0.8, CLIENT, SERVER, 41100 + i, 50000 + i, exchanges=[(0, 6000)],
                    isn_c=300_000 + i * 10_000, isn_s=7_000_000 + i * 50_000)
    # 10 active-mode data connections from the server's port 20 to client high ports.
    for i in range(10):
        tcp_session(tl, 20 + i * 0.8, SERVER, CLIENT, 20, 60000 + i, exchanges=[(4000, 0)],
                    isn_c=900_000 + i * 10_000, isn_s=8_000_000 + i * 50_000)
    return tl


def _ftp_passive_blocked() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=40)
    tcp_session(tl, 1, CLIENT, SERVER, 40021, 21, exchanges=[(30, 80)] * 25, rtt=0.02)
    # A firewall without an FTP helper drops every passive data connection: 20 high ports,
    # each SYN retransmitted by the OS (same sequence number). A configuration fault.
    for i in range(20):
        for k, delay in enumerate((0.0, 1.0, 3.0)):
            tl.add(2 + i * 0.8 + delay, Ether(src=CLIENT.mac, dst=SERVER.mac) / IP(src=CLIENT.ip, dst=SERVER.ip) /
                   TCP(sport=41200 + i, dport=50100 + i, flags="S", seq=600_000 + i, options=[("MSS", 1460)]))
    return tl


def _browser() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=30)
    dns_lookup(tl, 1.0, CLIENT, GATEWAY, "shop.example.com", answers=[WEB.ip], txid=4444)
    for i in range(30):
        tcp_session(tl, 1.1 + i * 0.2, CLIENT, WEB, 42000 + i, 443, exchanges=[(400, 8000)],
                    isn_c=1_000_000 + i * 50_000, isn_s=3_000_000 + i * 70_000, server_mac=GATEWAY.mac)
    return tl


def _below_threshold() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=30)
    # 14 distinct ports: one below scan_vertical_ports. Negative by design (documented boundary).
    for i, port in enumerate([21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3306, 3389]):
        probe(tl, 5 + i * 0.5, ATTACKER, SERVER, 54321, port, "rst", mss=1460, isn=30_000 + i)
    return tl


def _retry_same_port() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=40)
    # A client keeps retrying one crashed service: many attempts, one port.
    for i in range(30):
        tcp_refused(tl, 2 + i * 1.0, CLIENT2, SERVER, 51000 + i, 8080, isn=7000 + i * 13)
    return tl


def _late_dns() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=40)
    # The resolver answers after the client gave up and closed the socket, so the client
    # answers each late reply with ICMP port unreachable for 20 different ephemeral ports.
    for i in range(20):
        sport = 53100 + i
        dns_lookup(tl, 2 + i * 1.0, CLIENT, PUBLIC_DNS, f"host{i}.example.net", txid=6000 + i, sport=sport,
                   delay=3.0, l2server=GATEWAY)
        icmp_port_unreachable(tl, 2 + i * 1.0 + 3.001, CLIENT, PUBLIC_DNS, 53, sport)
    return tl


def _uplink_down() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=20)
    # The internet link drops: a client resolves 20 sites and every HTTPS SYN goes unanswered
    # (retransmitted by the OS with the same sequence number).
    for i in range(20):
        ip = f"203.0.113.{10 + i}"
        dns_lookup(tl, 22 + i * 0.5, CLIENT3, GATEWAY, f"site{i}.example.com", answers=[ip], txid=7000 + i,
                   sport=55000 + i)
        for delay in (0.03, 1.03, 3.03):
            tl.add(22 + i * 0.5 + delay, Ether(src=CLIENT3.mac, dst=GATEWAY.mac) / IP(src=CLIENT3.ip, dst=ip) /
                   TCP(sport=46000 + i, dport=443, flags="S", seq=111_000 + i, options=[("MSS", 1460)]))
    return tl


def _mtr() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=40)
    # mtr --udp: continuous traceroute, a new destination port per probe. Routers answer with
    # time-exceeded; the destination answers every final-hop probe with port unreachable.
    hops = [GATEWAY.ip] + [f"10.{h}.0.1" for h in range(2, 8)]
    for rnd in range(20):
        for h in range(1, 9):
            t = 2 + rnd * 1.5 + h * 0.01
            dport = 33434 + rnd * 8 + h
            tl.add(t, Ether(src=CLIENT.mac, dst=GATEWAY.mac) / IP(src=CLIENT.ip, dst=WEB.ip, ttl=h) /
                   UDP(sport=39000, dport=dport) / Raw(b"\x00" * 24))
            if h < 8:
                tl.add(t + 0.005, Ether(src=GATEWAY.mac, dst=CLIENT.mac) / IP(src=hops[h - 1], dst=CLIENT.ip) /
                       ICMP(type=11, code=0) / IPerror(src=CLIENT.ip, dst=WEB.ip, proto=17, ttl=1) /
                       UDPerror(sport=39000, dport=dport))
            else:
                tl.add(t + 0.02, Ether(src=GATEWAY.mac, dst=CLIENT.mac) / IP(src=WEB.ip, dst=CLIENT.ip) /
                       ICMP(type=3, code=3) / IPerror(src=CLIENT.ip, dst=WEB.ip, proto=17) /
                       UDPerror(sport=39000, dport=dport))
    return tl


def _malformed() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=30)
    eth = Ether(src=ATTACKER.mac, dst=SERVER.mac)
    back = Ether(src=SERVER.mac, dst=ATTACKER.mac)
    for i in range(30):
        t = 3 + i * 0.05
        # Truncated TCP header (8 bytes) - the decoder flags it as malformed, no ports known.
        tl.add(t, eth / IP(src=ATTACKER.ip, dst=SERVER.ip, proto=6) / Raw(bytes([0x1f, 0x90, 0, i + 1, 0, 0, 0, 0])))
        # ICMP port unreachable that quotes only an IP header (no UDP ports) ...
        tl.add(t + 0.01, back / IP(src=SERVER.ip, dst=ATTACKER.ip) / ICMP(type=3, code=3) /
               IPerror(src=ATTACKER.ip, dst=SERVER.ip, proto=17))
        # ... and one that quotes garbage instead of an IP header.
        tl.add(t + 0.02, back / IP(src=SERVER.ip, dst=ATTACKER.ip) / ICMP(type=3, code=3) / Raw(b"\x00" * 6))
    # A TCP-quoting unreachable for a probe that was never sent (inner ports present, no SYN).
    tl.add(5.0, back / IP(src=SERVER.ip, dst=ATTACKER.ip) / ICMP(type=3, code=13) /
           IPerror(src=ATTACKER.ip, dst=SERVER.ip, proto=6) / TCPerror(sport=1234, dport=80))
    return tl


NEG = dict(forbid=PORT_SCAN_KINDS, forbid_attacks=True)
SCAN = {"PORT_SCAN": "attack"}

SCENARIOS = [
    Scenario("scan_vertical_syn", "SYN half-open scan of ports 1-100 on one server (22 and 80 open)",
             _vertical, expect={"PORT_SCAN"}, forbid={"HOST_SWEEP", "TCP_CONNECTION_REFUSED"},
             expect_assessment=SCAN, sample="attack_port_scan.pcap"),
    Scenario("scan_vertical_exact_threshold", "Exactly 15 ports probed in 7 s (threshold boundary, positive)",
             _vertical_15, expect={"PORT_SCAN"}, expect_assessment=SCAN),
    Scenario("scan_horizontal_sweep", "Port 22 checked on 30 hosts in 1.5 s (4 open)",
             _horizontal, expect={"HOST_SWEEP"}, forbid={"PORT_SCAN"},
             expect_assessment={"HOST_SWEEP": "attack"}),
    Scenario("scan_slow", "Slow scan: one probe every 5 s over 150 ports (below the window rate)",
             _slow, expect={"PORT_SCAN"}, expect_assessment=SCAN),
    Scenario("scan_stealth_fin_null_xmas", "FIN, NULL and XMAS probes against 30 ports",
             _stealth, expect={"PORT_SCAN"}, expect_assessment=SCAN),
    Scenario("scan_stealth_small", "Only 6 XMAS probes: below the port threshold but no legitimate use",
             _stealth_small, expect={"PORT_SCAN"}, expect_assessment=SCAN),
    Scenario("scan_udp", "UDP scan of 42 ports answered by ICMP port unreachable (161, 500 open)",
             _udp, expect={"PORT_SCAN"}, expect_assessment=SCAN),
    Scenario("scan_connect", "TCP connect scan of 50 ports (full handshake then RST on open ports)",
             _connect, expect={"PORT_SCAN"}, expect_assessment=SCAN),
    Scenario("scan_ipv6", "IPv6 SYN scan of 30 ports", _ipv6, expect={"PORT_SCAN"}, expect_assessment=SCAN),
    Scenario("scan_two_bursts", "Same source scans two hosts 195 s apart (one finding, two bursts)",
             _two_bursts, expect={"PORT_SCAN"}, expect_assessment=SCAN),
    Scenario("scan_neg_multi_service", "Admin workstation completing sessions to 20 services (benign)",
             _multi_service, **NEG),
    Scenario("scan_neg_ftp_passive", "FTP passive data connections to 20 high ports + active-mode data",
             _ftp_passive, **NEG),
    Scenario("scan_neg_ftp_passive_blocked", "Firewall drops 20 passive-FTP data connections (fault, not scan)",
             _ftp_passive_blocked, **NEG),
    Scenario("scan_neg_browser", "Browser opening 30 HTTPS connections to one server", _browser, **NEG),
    Scenario("scan_neg_below_threshold", "14-port probe: one below the threshold (negative by design)",
             _below_threshold, **NEG),
    Scenario("scan_neg_retry_same_port", "Client retrying one refused port 30 times", _retry_same_port, **NEG),
    Scenario("scan_neg_late_dns", "Late DNS answers to closed client ports cause ICMP port unreachable",
             _late_dns, **NEG),
    Scenario("scan_neg_uplink_down", "Internet down: SYNs to 20 resolved sites on 443 unanswered",
             _uplink_down, **NEG),
    Scenario("scan_neg_mtr", "mtr --udp continuous traceroute (destination port unreachable per round)",
             _mtr, **NEG),
    Scenario("scan_neg_malformed", "Truncated TCP headers and ICMP errors without quoted ports",
             _malformed, **NEG),
]
