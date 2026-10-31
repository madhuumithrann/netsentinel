"""Ground-truth scenarios for the DHCP detector (rogue / redundant servers, relays, faults).

The builders below extend ``lab.packets`` with relay (giaddr) support, spoofed server
identifiers and INIT-REBOOT requests. Every frame has explicit source and destination MACs
and nothing is ever sent on a network.
"""
from __future__ import annotations

from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from ..packets import (ATTACKER, BROADCAST, GATEWAY, WEB, Host, Timeline, arp_exchange, dns_lookup,
                       office_background, tcp_session)
from . import Scenario

ZERO = "0.0.0.0"


def _mac_bytes(mac: str) -> bytes:
    return bytes(int(x, 16) for x in mac.split(":")) + b"\x00" * 10


def _bootp(tl: Timeline, t: float, src_ip: str, src_mac: str, dst_ip: str, dst_mac: str, op: int,
           xid: int, chaddr: str, options: list, yiaddr: str = ZERO, ciaddr: str = ZERO,
           giaddr: str = ZERO, sport: int = 67, dport: int = 68) -> None:
    tl.add(t, Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip) / UDP(sport=sport, dport=dport) /
           BOOTP(op=op, xid=xid, chaddr=_mac_bytes(chaddr), yiaddr=yiaddr, ciaddr=ciaddr, giaddr=giaddr) /
           DHCP(options=options + ["end"]))


def client_msg(tl: Timeline, t: float, client_mac: str, xid: int, msg: str, server_id: str | None = None,
               requested: str | None = None) -> None:
    opts: list = [("message-type", msg)]
    if server_id:
        opts.append(("server_id", server_id))
    if requested:
        opts.append(("requested_addr", requested))
    _bootp(tl, t, ZERO, client_mac, "255.255.255.255", BROADCAST, 1, xid, client_mac, opts, sport=68, dport=67)


def server_msg(tl: Timeline, t: float, src_ip: str, src_mac: str, client_mac: str, xid: int, msg: str,
               offer_ip: str = ZERO, router: str | None = None, dns: list[str] | None = None,
               server_id: str | None = None, giaddr: str = ZERO, dst_ip: str = "255.255.255.255",
               dst_mac: str = BROADCAST, dport: int = 68, with_server_id: bool = True) -> None:
    opts: list = [("message-type", msg)]
    if with_server_id:
        opts.append(("server_id", server_id or src_ip))
    if router:
        opts.append(("router", router))
    if dns:
        opts.append(("name_server", *dns))
    if msg != "nak":
        opts += [("lease_time", 86400), ("subnet_mask", "255.255.255.0")]
    _bootp(tl, t, src_ip, src_mac, dst_ip, dst_mac, 2, xid, client_mac, opts, yiaddr=offer_ip,
           giaddr=giaddr, dport=dport)


def dora(tl: Timeline, t: float, server: Host, client_mac: str, xid: int, offer_ip: str, router: str,
         dns: list[str], server_id: str | None = None) -> None:
    sid = server_id or server.ip
    client_msg(tl, t, client_mac, xid, "discover")
    server_msg(tl, t + 0.01, server.ip, server.mac, client_mac, xid, "offer", offer_ip, router, dns, sid)
    client_msg(tl, t + 0.02, client_mac, xid, "request", sid, offer_ip)
    server_msg(tl, t + 0.03, server.ip, server.mac, client_mac, xid, "ack", offer_ip, router, dns, sid)


def raced_dora(tl: Timeline, t: float, first: Host, second: Host, client_mac: str, xid: int,
               first_cfg: tuple, second_cfg: tuple, choose_first: bool, first_sid: str | None = None,
               second_sid: str | None = None) -> None:
    """One DISCOVER answered by two servers; the client accepts one of them.

    ``*_cfg`` is (offer_ip, router, dns_list).
    """
    s1, s2 = first_sid or first.ip, second_sid or second.ip
    client_msg(tl, t, client_mac, xid, "discover")
    server_msg(tl, t + 0.004, first.ip, first.mac, client_mac, xid, "offer", *first_cfg, server_id=s1)
    server_msg(tl, t + 0.012, second.ip, second.mac, client_mac, xid, "offer", *second_cfg, server_id=s2)
    chosen, cfg, sid = (first, first_cfg, s1) if choose_first else (second, second_cfg, s2)
    client_msg(tl, t + 0.02, client_mac, xid, "request", sid, cfg[0])
    server_msg(tl, t + 0.03, chosen.ip, chosen.mac, client_mac, xid, "ack", *cfg, server_id=sid)


def _new_mac(i: int) -> str:
    return f"02:00:00:00:01:{i:02x}"


LEGIT_CFG = ("192.168.1.1", ["192.168.1.1"])


# --- positive scenarios ------------------------------------------------------------------

VICTIM = Host("192.168.1.130", "02:00:00:00:00:30")


def _rogue_server() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=60)
    # The attacker's server appears at t=5, *before* the legitimate server answers anybody,
    # and wins the race for the victim: "first seen" would wrongly call the attacker legit.
    raced_dora(tl, 5.0, ATTACKER, GATEWAY, VICTIM.mac, 0x5001,
               (VICTIM.ip, ATTACKER.ip, ["6.6.6.6"]), ("192.168.1.102", *LEGIT_CFG), choose_first=True)
    # The victim now uses the attacker as gateway and 6.6.6.6 (reached via the attacker) as DNS.
    arp_exchange(tl, 5.2, VICTIM, ATTACKER)
    rogue_dns = Host("6.6.6.6", ATTACKER.mac)
    for i in range(3):
        dns_lookup(tl, 6 + i * 4, VICTIM, rogue_dns, "bank.example.com", answers=[ATTACKER.ip],
                   txid=0x7000 + i, sport=55000 + i)
        tcp_session(tl, 6.2 + i * 4, VICTIM, WEB, 46000 + i, 443, exchanges=[(300, 2400)],
                    isn_c=3_000_000 + i * 100_000, isn_s=4_000_000 + i * 100_000, server_mac=ATTACKER.mac)
    # Legitimate leases for other new devices.
    for i in range(4):
        dora(tl, 10 + i * 8, GATEWAY, _new_mac(i), 0x6000 + i, f"192.168.1.{110 + i}", *LEGIT_CFG)
    # A second race that the legitimate server wins.
    raced_dora(tl, 26.0, ATTACKER, GATEWAY, "02:00:00:00:00:31", 0x5002,
               ("192.168.1.131", ATTACKER.ip, ["6.6.6.6"]), ("192.168.1.103", *LEGIT_CFG), choose_first=False)
    return tl


def _spoofed_server_id() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=50)
    # The attacker's own traffic, so its real IP is known.
    dns_lookup(tl, 2.0, ATTACKER, GATEWAY, "example.com", txid=0x4444, sport=54444)
    impostor = Host(GATEWAY.ip, ATTACKER.mac)       # claims to be 192.168.1.1 from another MAC
    for i in range(3):
        dora(tl, 6 + i * 10, GATEWAY, _new_mac(0x20 + i), 0x6100 + i, f"192.168.1.{120 + i}", *LEGIT_CFG)
    for i in range(2):
        raced_dora(tl, 11 + i * 10, impostor, GATEWAY, _new_mac(0x30 + i), 0x6200 + i,
                   (f"192.168.1.{140 + i}", ATTACKER.ip, [ATTACKER.ip]), (f"192.168.1.{125 + i}", *LEGIT_CFG),
                   choose_first=True)
    return tl


def _home_router() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=40)
    home = Host("192.168.0.1", "02:00:00:00:00:77")
    # A consumer router plugged in with its LAN port: different subnet, nobody accepts it here.
    for i in range(3):
        raced_dora(tl, 5 + i * 9, GATEWAY, home, _new_mac(0x40 + i), 0x6300 + i,
                   (f"192.168.1.{150 + i}", *LEGIT_CFG), (f"192.168.0.{100 + i}", "192.168.0.1", ["192.168.0.1"]),
                   choose_first=True)
    return tl


def _outage() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=60)
    # Three devices boot and retry with RFC 2131 back-off; nobody answers.
    for c in range(3):
        mac = _new_mac(0x50 + c)
        for k, delay in enumerate((0, 4, 12, 28)):
            client_msg(tl, 10 + c * 0.7 + delay, mac, 0x7100 + c, "discover")
    # One more DISCOVER right at the end of the capture: still pending, must not be counted.
    client_msg(tl, 58.0, _new_mac(0x50), 0x7100, "discover")
    return tl


def _nak_storm() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=40)
    for i in range(2):
        dora(tl, 3 + i * 5, GATEWAY, _new_mac(0x60 + i), 0x7200 + i, f"192.168.1.{160 + i}", *LEGIT_CFG)
    # Two laptops moved from the 10.10.0.0/24 office keep asking for their old address.
    for k in range(3):
        mac = _new_mac(0x70)
        client_msg(tl, 12 + k * 6, mac, 0x7300 + k, "request", requested="10.10.0.57")
        server_msg(tl, 12.01 + k * 6, GATEWAY.ip, GATEWAY.mac, mac, 0x7300 + k, "nak")
    for k in range(2):
        mac = _new_mac(0x71)
        client_msg(tl, 14 + k * 6, mac, 0x7400 + k, "request", requested="10.10.0.88")
        server_msg(tl, 14.01 + k * 6, GATEWAY.ip, GATEWAY.mac, mac, 0x7400 + k, "nak")
    return tl


# --- negative scenarios ------------------------------------------------------------------

def _normal_dora() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=60)
    for i in range(20):
        dora(tl, 2 + i * 2.7, GATEWAY, _new_mac(0x80 + i), 0x8000 + i, f"192.168.1.{100 + i}", *LEGIT_CFG)
    return tl


RELAY_INNER_MAC = "02:00:00:00:10:01"     # the router's interface on the server VLAN
REMOTE_SERVER = Host("10.0.0.5", "02:00:00:00:10:05")


def _relayed_exchange(tl: Timeline, t: float, client_mac: str, xid: int, offer_ip: str, server: Host,
                      relay_ip: str, relay_mac: str, router: str, dns: list[str], client_leg: bool = True) -> None:
    """DORA through a relay agent, capturing both the client leg and the relay <-> server leg."""
    def relay_to_server(when, msg, **kw):
        opts = [("message-type", msg)] + ([("server_id", kw["sid"])] if kw.get("sid") else []) + \
               ([("requested_addr", kw["req"])] if kw.get("req") else [])
        _bootp(tl, when, relay_ip, RELAY_INNER_MAC, server.ip, server.mac, 1, xid, client_mac, opts,
               giaddr=relay_ip, sport=67, dport=67)

    def server_to_relay(when, msg):
        server_msg(tl, when, server.ip, server.mac, client_mac, xid, msg, offer_ip, router, dns,
                   giaddr=relay_ip, dst_ip=relay_ip, dst_mac=RELAY_INNER_MAC, dport=67)

    def relay_to_client(when, msg):
        server_msg(tl, when, relay_ip, relay_mac, client_mac, xid, msg, offer_ip, router, dns,
                   server_id=server.ip, giaddr=relay_ip)

    if client_leg:
        client_msg(tl, t, client_mac, xid, "discover")
    relay_to_server(t + 0.002, "discover")
    server_to_relay(t + 0.010, "offer")
    if client_leg:
        relay_to_client(t + 0.012, "offer")
        client_msg(tl, t + 0.020, client_mac, xid, "request", server.ip, offer_ip)
    relay_to_server(t + 0.022, "request", sid=server.ip, req=offer_ip)
    server_to_relay(t + 0.030, "ack")
    if client_leg:
        relay_to_client(t + 0.032, "ack")


def _relay() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=50)
    # Old detector: two "servers" (10.0.0.5 and the relay 192.168.1.1). Really one server.
    for i in range(6):
        _relayed_exchange(tl, 3 + i * 7, _new_mac(0x90 + i), 0x9000 + i, f"192.168.1.{170 + i}", REMOTE_SERVER,
                          GATEWAY.ip, GATEWAY.mac, "192.168.1.1", ["10.0.0.53"])
    return tl


def _redundant() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=50)
    a, b = Host("192.168.1.2", "02:00:00:00:00:02"), Host("192.168.1.3", "02:00:00:00:00:03")
    for i in range(6):
        raced_dora(tl, 3 + i * 7, a, b, _new_mac(0xa0 + i), 0xa000 + i,
                   (f"192.168.1.{100 + i}", *LEGIT_CFG), (f"192.168.1.{200 + i}", *LEGIT_CFG),
                   choose_first=i % 2 == 0)
    return tl


def _multiscope_core() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=40)
    second = Host("10.0.0.6", "02:00:00:00:10:06")
    # Captured at the data-centre core: each server serves its own relayed subnets, so their
    # different gateways are expected (old detector: three "servers", rogue alert).
    for i in range(3):
        _relayed_exchange(tl, 2 + i * 9, _new_mac(0xb0 + i), 0xb000 + i, f"10.1.0.{50 + i}", REMOTE_SERVER,
                          "10.1.0.1", RELAY_INNER_MAC, "10.1.0.1", ["10.0.0.53"], client_leg=False)
        _relayed_exchange(tl, 4 + i * 9, _new_mac(0xb8 + i), 0xb100 + i, f"10.2.0.{50 + i}", REMOTE_SERVER,
                          "10.2.0.1", RELAY_INNER_MAC, "10.2.0.1", ["10.0.0.53"], client_leg=False)
        _relayed_exchange(tl, 6 + i * 9, _new_mac(0xc0 + i), 0xb200 + i, f"10.3.0.{50 + i}", second,
                          "10.3.0.1", RELAY_INNER_MAC, "10.3.0.1", ["10.0.0.54"], client_leg=False)
    return tl


def _below_thresholds() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=60)
    # A laptop back from another office: one NAK for its old address, then a normal DORA.
    roam = _new_mac(0xd0)
    client_msg(tl, 5.0, roam, 0xd000, "request", requested="10.10.0.57")
    server_msg(tl, 5.01, GATEWAY.ip, GATEWAY.mac, roam, 0xd000, "nak")
    dora(tl, 5.5, GATEWAY, roam, 0xd001, "192.168.1.180", *LEGIT_CFG)
    # A slow server: two DISCOVER retries before the OFFER arrives.
    slow = _new_mac(0xd1)
    client_msg(tl, 12.0, slow, 0xd100, "discover")
    client_msg(tl, 16.0, slow, 0xd100, "discover")
    server_msg(tl, 17.5, GATEWAY.ip, GATEWAY.mac, slow, 0xd100, "offer", "192.168.1.181", *LEGIT_CFG)
    client_msg(tl, 17.51, slow, 0xd100, "request", GATEWAY.ip, "192.168.1.181")
    server_msg(tl, 17.52, GATEWAY.ip, GATEWAY.mac, slow, 0xd100, "ack", "192.168.1.181", *LEGIT_CFG)
    # Two unanswered DISCOVERs (one below the threshold of 3) plus one pending at capture end.
    late = _new_mac(0xd2)
    for ts in (50.0, 54.0, 58.4):
        client_msg(tl, ts, late, 0xd200, "discover")
    return tl


def _malformed() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=30)
    c1, c2, c3 = _new_mac(0xe0), _new_mac(0xe1), _new_mac(0xe2)
    # Reply without server identifier: identity falls back to the IP source.
    client_msg(tl, 3.0, c1, 0xe000, "discover")
    server_msg(tl, 3.01, GATEWAY.ip, GATEWAY.mac, c1, 0xe000, "offer", "192.168.1.190", *LEGIT_CFG,
               with_server_id=False)
    # Offer without router / DNS options.
    client_msg(tl, 6.0, c2, 0xe001, "discover")
    server_msg(tl, 6.01, GATEWAY.ip, GATEWAY.mac, c2, 0xe001, "offer", "192.168.1.191")
    # Plain BOOTP reply with no DHCP message type.
    _bootp(tl, 9.0, GATEWAY.ip, GATEWAY.mac, "255.255.255.255", BROADCAST, 2, 0xe002, c3, [],
           yiaddr="192.168.1.192")
    # Truncated BOOTP payload (the decoder must skip it, not crash).
    tl.add(12.0, Ether(src=GATEWAY.mac, dst=BROADCAST) / IP(src=GATEWAY.ip, dst="255.255.255.255") /
           UDP(sport=67, dport=68) / Raw(b"\x02\x01\x06\x00" + b"\x00" * 60))
    # Non-DHCP garbage on port 67.
    tl.add(13.0, Ether(src=c3, dst=BROADCAST) / IP(src=ZERO, dst="255.255.255.255") /
           UDP(sport=68, dport=67) / Raw(b"\xff" * 300))
    return tl


DHCP_KINDS = {"ROGUE_DHCP_SERVER", "MULTIPLE_DHCP_SERVERS", "DHCP_NO_RESPONSE", "DHCP_NAK"}

SCENARIOS = [
    Scenario("dhcp_rogue_server", "Attacker DHCP server offers itself as gateway and 6.6.6.6 as DNS; "
             "one client accepts and its traffic is redirected", _rogue_server,
             expect={"ROGUE_DHCP_SERVER"}, forbid={"MULTIPLE_DHCP_SERVERS", "DHCP_NO_RESPONSE"},
             expect_assessment={"ROGUE_DHCP_SERVER": "attack"}, sample="attack_rogue_dhcp.pcap"),
    Scenario("dhcp_spoofed_server_id", "Rogue answers with the legitimate server identifier from another MAC",
             _spoofed_server_id, expect={"ROGUE_DHCP_SERVER"}, forbid={"MULTIPLE_DHCP_SERVERS"},
             expect_assessment={"ROGUE_DHCP_SERVER": "attack"}),
    Scenario("dhcp_home_router", "Consumer router plugged in: second server handing out another subnet",
             _home_router, expect={"ROGUE_DHCP_SERVER"}, forbid={"MULTIPLE_DHCP_SERVERS"}),
    Scenario("dhcp_outage", "Three devices send DISCOVERs that nobody answers", _outage,
             expect={"DHCP_NO_RESPONSE"}, forbid={"ROGUE_DHCP_SERVER", "MULTIPLE_DHCP_SERVERS", "DHCP_NAK"},
             expect_assessment={"DHCP_NO_RESPONSE": "fault"}, forbid_attacks=True),
    Scenario("dhcp_nak_storm", "Laptops from another network repeatedly NAKed for their old address",
             _nak_storm, expect={"DHCP_NAK"}, forbid={"ROGUE_DHCP_SERVER", "DHCP_NO_RESPONSE"},
             expect_assessment={"DHCP_NAK": "fault"}, forbid_attacks=True),
    Scenario("dhcp_normal_dora", "One server, 20 normal DORA exchanges (benign)", _normal_dora,
             forbid=DHCP_KINDS, forbid_attacks=True),
    Scenario("dhcp_relay", "Remote server reached through a DHCP relay; both legs captured (benign)",
             _relay, forbid=DHCP_KINDS, forbid_attacks=True),
    Scenario("dhcp_redundant_servers", "Two split-scope servers with identical options (benign)",
             _redundant, expect={"MULTIPLE_DHCP_SERVERS"}, forbid={"ROGUE_DHCP_SERVER"},
             expect_assessment={"MULTIPLE_DHCP_SERVERS": "benign"}, forbid_attacks=True),
    Scenario("dhcp_multiscope_core", "Core capture: two servers serving different relayed subnets (benign)",
             _multiscope_core, forbid=DHCP_KINDS, forbid_attacks=True),
    Scenario("dhcp_below_thresholds", "One roaming NAK, a slow server and 2 unanswered DISCOVERs (benign)",
             _below_thresholds, forbid=DHCP_KINDS, forbid_attacks=True),
    Scenario("dhcp_malformed_options", "Replies missing options, plain BOOTP, truncated payloads",
             _malformed, forbid=DHCP_KINDS, forbid_attacks=True),
]
