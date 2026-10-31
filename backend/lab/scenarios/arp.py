"""Ground-truth scenarios for the ARP detector (spoofing, duplicate IPs, conflicts, benign changes).

Every scenario contains realistic office background traffic. Packets are only built, never sent;
every Ethernet header carries explicit source and destination MACs.
"""
from __future__ import annotations

from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Dot1Q, Ether
from scapy.packet import Raw

from ..packets import (ATTACKER, BROADCAST, CLIENT, CLIENT2, CLIENT3, GATEWAY, SERVER, WEB, WEB2, Host,
                       Timeline, arp_exchange, arp_probe, arp_reply, arp_request, dhcp_dora, dns_lookup,
                       gratuitous_arp, office_background, syn_probe, tcp_session, udp_packet)
from . import Scenario

ARP_KINDS = {"ARP_SPOOFING", "DUPLICATE_IP", "ARP_CONFLICT", "ARP_MAPPING_CHANGED"}
NAMES = ["example.com", "intranet.local", "updates.vendor.com", "mail.example.org"]


# --- builders this module needs that lab/packets.py does not provide ---------------------------

def _relay(tl: Timeline, build, victim: Host, gw: Host, mitm: Host, ip_id: list[int],
           latency: float = 0.0002) -> None:
    """Re-route a conversation through a man-in-the-middle.

    ``build(tmp)`` writes the normal victim <-> gateway conversation into a scratch timeline.
    Each frame is then emitted twice: victim -> MITM (because of the poisoned cache) and
    MITM -> real next hop with the same IP header and TTL decreased by one (IP forwarding).
    """
    tmp = Timeline()
    build(tmp)
    for t, _, pkt in sorted(tmp.items, key=lambda x: (x[0], x[1])):
        ip_id[0] += 1
        pkt[IP].id = ip_id[0] & 0xFFFF
        from_victim = pkt[Ether].src == victim.mac
        first = pkt.copy()
        first[Ether].dst = mitm.mac
        tl.add(t, first)
        second = pkt.copy()
        second[Ether].src = mitm.mac
        second[Ether].dst = gw.mac if from_victim else victim.mac
        second[IP].ttl = max(pkt[IP].ttl - 1, 1)
        tl.add(t + latency, second)


def _background_via(tl: Timeline, t0: float, duration: float, router_mac: str,
                    clients=(CLIENT, CLIENT2, CLIENT3), seed: int = 0) -> None:
    """office_background() equivalent whose router (and DNS on it) answers from ``router_mac``."""
    router = Host(GATEWAY.ip, router_mac)
    t, k = t0, seed
    clients = list(clients)
    while t < t0 + duration:
        c = clients[k % len(clients)]
        dns_lookup(tl, t, c, GATEWAY, NAMES[k % len(NAMES)], txid=3000 + k, sport=56000 + k, l2server=router)
        tcp_session(tl, t + 0.05, c, WEB if k % 2 == 0 else WEB2, 33000 + k, 443,
                    exchanges=[(300, 3000)], rtt=0.03, isn_c=700_000 + 10_000 * k,
                    isn_s=800_000 + 10_000 * k, server_mac=router_mac)
        t += 2.5
        k += 1


def _arp(tl: Timeline, t: float, op: int, eth_src: str, eth_dst: str, hwsrc: str, psrc: str,
         hwdst: str, pdst: str, vlan: int | None = None) -> None:
    eth = Ether(src=eth_src, dst=eth_dst)
    arp = ARP(op=op, hwsrc=hwsrc, psrc=psrc, hwdst=hwdst, pdst=pdst)
    tl.add(t, eth / Dot1Q(vlan=vlan) / arp if vlan is not None else eth / arp)


def _dhcp_decline(tl: Timeline, t: float, client_mac: str, xid: int, server_ip: str, ip: str) -> None:
    mac_bytes = bytes(int(x, 16) for x in client_mac.split(":"))
    tl.add(t, Ether(src=client_mac, dst=BROADCAST) / IP(src="0.0.0.0", dst="255.255.255.255") /
           UDP(sport=68, dport=67) / BOOTP(op=1, xid=xid, chaddr=mac_bytes + b"\x00" * 10) /
           DHCP(options=[("message-type", "decline"), ("server_id", server_ip), ("requested_addr", ip), "end"]))


def _host_sessions(tl: Timeline, me: Host, times, port_base: int, isn_base: int) -> None:
    """A workstation's own browsing (DNS + HTTPS through the gateway)."""
    for i, t in enumerate(times):
        dns_lookup(tl, t, me, GATEWAY, NAMES[i % len(NAMES)], txid=isn_base // 1000 + i, sport=port_base + 500 + i)
        tcp_session(tl, t + 0.05, me, WEB, port_base + i, 443, exchanges=[(250, 2500)], rtt=0.03,
                    isn_c=isn_base + i * 10_000, isn_s=isn_base + 5_000_000 + i * 10_000,
                    server_mac=GATEWAY.mac)


# --- positives: attacks ------------------------------------------------------------------------

def _mitm() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=60, clients=(CLIENT2, CLIENT3))
    arp_exchange(tl, 0.3, CLIENT, GATEWAY)          # client learns the real gateway MAC
    arp_exchange(tl, 0.4, GATEWAY, CLIENT)          # gateway learns the client
    arp_exchange(tl, 5.0, ATTACKER, GATEWAY)        # attacker resolves both victims first
    arp_exchange(tl, 5.1, ATTACKER, CLIENT)
    # arpspoof-style poisoning in both directions, every 2 s.
    for k in range(25):
        t = 8.0 + 2 * k
        arp_reply(tl, t, GATEWAY.ip, ATTACKER.mac, CLIENT)
        arp_reply(tl, t + 0.01, CLIENT.ip, ATTACKER.mac, GATEWAY)
    arp_exchange(tl, 31.5, GATEWAY, CLIENT)         # the gateway re-asserts itself (cache refresh)
    # The client's traffic now flows via the attacker, which forwards it (IP forwarding on).
    ip_id = [4000]
    for k in range(8):
        t = 10.0 + 5.5 * k
        sport = 45000 + k

        def build(tmp, t=t, sport=sport, k=k):
            dns_lookup(tmp, t, CLIENT, GATEWAY, NAMES[k % len(NAMES)], txid=7000 + k, sport=sport + 1000)
            tcp_session(tmp, t + 0.05, CLIENT, WEB if k % 2 == 0 else WEB2, sport, 443,
                        exchanges=[(400, 3000)], rtt=0.03, isn_c=2_000_000 + 10_000 * k,
                        isn_s=3_000_000 + 10_000 * k, server_mac=GATEWAY.mac)
        _relay(tl, build, CLIENT, GATEWAY, ATTACKER, ip_id)
    return tl


SWEEP_IPS = [GATEWAY.ip, CLIENT2.ip, CLIENT3.ip, SERVER.ip] + [f"192.168.1.{n}" for n in range(100, 116)]


def _sweep() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=50)
    arp_exchange(tl, 0.5, CLIENT, SERVER)
    arp_exchange(tl, 4.0, ATTACKER, GATEWAY)
    for rnd in range(2):
        for j, ip in enumerate(SWEEP_IPS):
            arp_reply(tl, 10 + rnd * 15 + j * 0.05, ip, ATTACKER.mac, CLIENT)
    return tl


FAKE_MAC = "02:de:ad:be:ef:01"


def _mismatch() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=45)
    arp_exchange(tl, 0.5, CLIENT, SERVER)
    arp_exchange(tl, 3.0, ATTACKER, GATEWAY)
    for i in range(6):
        tcp_session(tl, 2 + 6 * i, CLIENT2, SERVER, 47000 + i, 445, exchanges=[(200, 900)],
                    isn_c=11_000_000 + i * 10_000, isn_s=12_000_000 + i * 10_000)
    # Crafted replies: sent by the attacker's NIC, but the ARP payload names a forged MAC.
    for k in range(6):
        arp_reply(tl, 10 + 3 * k, SERVER.ip, FAKE_MAC, CLIENT, eth_src=ATTACKER.mac)
    return tl


def _workstation_poison(count: int):
    def build() -> Timeline:
        tl = Timeline()
        office_background(tl, duration=45)
        for k in range(count):
            arp_reply(tl, 10 + 4 * k, CLIENT2.ip, ATTACKER.mac, CLIENT)
        # CLIENT2 keeps using its address and re-asserts it in ARP between the false replies.
        arp_exchange(tl, 15.0, CLIENT2, GATEWAY)
        arp_exchange(tl, 23.0, CLIENT2, GATEWAY)
        return tl
    return build


# --- positives: faults -------------------------------------------------------------------------

DUP_A = Host("192.168.1.50", "02:00:00:00:00:50")
DUP_B = Host("192.168.1.50", "02:00:00:00:01:50")


def _duplicate() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=60)
    arp_exchange(tl, 0.5, DUP_A, GATEWAY)
    _host_sessions(tl, DUP_A, [2, 12, 22, 32, 42, 52], 30000, 20_000_000)
    # A second PC is configured with the same static address and boots at t=20.
    gratuitous_arp(tl, 20.0, DUP_B.ip, DUP_B.mac)
    arp_exchange(tl, 20.2, DUP_B, GATEWAY)
    _host_sessions(tl, DUP_B, [25, 35, 45, 55], 31000, 30_000_000)
    # Other hosts ask for .50 and both PCs answer, in varying order.
    for t, first, second in ((24.0, DUP_A, DUP_B), (34.0, DUP_B, DUP_A), (44.0, DUP_A, DUP_B)):
        arp_request(tl, t, CLIENT, DUP_A.ip)
        arp_reply(tl, t + 0.001, first.ip, first.mac, CLIENT)
        arp_reply(tl, t + 0.002, second.ip, second.mac, CLIENT)
    arp_request(tl, 50.0, SERVER, DUP_A.ip)
    arp_reply(tl, 50.001, DUP_B.ip, DUP_B.mac, SERVER)
    return tl


PRINTER = Host("192.168.1.30", "02:00:00:00:00:30")
NEWDEV_MAC = "02:00:00:00:03:30"


def _probe_defended() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=40)
    arp_exchange(tl, 3.0, CLIENT, PRINTER)
    udp_packet(tl, 5.0, PRINTER, CLIENT, 9100, 50500, size=120)
    udp_packet(tl, 25.0, PRINTER, CLIENT, 9100, 50501, size=120)
    # The DHCP server hands out .30, which the printer uses statically.
    dhcp_dora(tl, 15.0, GATEWAY, NEWDEV_MAC, 0x1234, PRINTER.ip, GATEWAY.ip, [GATEWAY.ip])
    arp_probe(tl, 15.5, NEWDEV_MAC, PRINTER.ip)
    _arp(tl, 15.502, 2, PRINTER.mac, NEWDEV_MAC, PRINTER.mac, PRINTER.ip, NEWDEV_MAC, "0.0.0.0")
    _dhcp_decline(tl, 15.6, NEWDEV_MAC, 0x1234, GATEWAY.ip, PRINTER.ip)
    # The client retries, gets .31, probes it (nobody answers) and announces it.
    dhcp_dora(tl, 18.0, GATEWAY, NEWDEV_MAC, 0x1235, "192.168.1.31", GATEWAY.ip, [GATEWAY.ip])
    for k in range(3):
        arp_probe(tl, 18.2 + k, NEWDEV_MAC, "192.168.1.31")
    gratuitous_arp(tl, 22.5, "192.168.1.31", NEWDEV_MAC)
    return tl


LAPTOP = Host(GATEWAY.ip, "02:00:00:00:00:99")


def _gateway_duplicate() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=60)
    # A laptop was given the gateway's address as a static IP by mistake.
    arp_exchange(tl, 20.0, LAPTOP, CLIENT3)
    for t in (21, 31, 41, 51):
        udp_packet(tl, t, LAPTOP, CLIENT3, 137, 137, size=50)
    for t, first, second in ((25.0, GATEWAY, LAPTOP), (35.0, LAPTOP, GATEWAY), (45.0, GATEWAY, LAPTOP)):
        arp_request(tl, t, CLIENT2, GATEWAY.ip)
        arp_reply(tl, t + 0.001, first.ip, first.mac, CLIENT2)
        arp_reply(tl, t + 0.002, second.ip, second.mac, CLIENT2)
    # CLIENT2 cached the laptop's MAC for a moment: its Internet traffic goes nowhere.
    syn_probe(tl, 36.0, CLIENT2, WEB, 39001, 443, answer=None, isn=123, l2dst=LAPTOP)
    syn_probe(tl, 37.0, CLIENT2, WEB, 39001, 443, answer=None, isn=123, l2dst=LAPTOP)
    return tl


# --- negatives -----------------------------------------------------------------------------------

OLD_NAS = Host("192.168.1.40", "02:00:00:00:00:40")
NEW_NAS = Host("192.168.1.40", "02:00:00:00:02:40")


def _replacement() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=60)
    arp_exchange(tl, 0.6, OLD_NAS, GATEWAY)
    arp_exchange(tl, 5.0, CLIENT2, OLD_NAS)
    for i, t in enumerate((3, 10, 18)):
        tcp_session(tl, t, CLIENT2, OLD_NAS, 48000 + i, 445, exchanges=[(200, 2000)],
                    isn_c=40_000_000 + i * 10_000, isn_s=41_000_000 + i * 10_000)
    # The NAS is swapped for new hardware with the same IP; it announces itself once at boot.
    gratuitous_arp(tl, 30.0, NEW_NAS.ip, NEW_NAS.mac)
    arp_exchange(tl, 30.1, NEW_NAS, GATEWAY)
    arp_exchange(tl, 35.0, CLIENT2, NEW_NAS)
    for i, t in enumerate((36, 45, 55)):
        tcp_session(tl, t, CLIENT2, NEW_NAS, 48100 + i, 445, exchanges=[(200, 2000)],
                    isn_c=42_000_000 + i * 10_000, isn_s=43_000_000 + i * 10_000)
    return tl


ROUTER2 = Host("192.168.1.2", "02:00:00:00:00:fe")


def _failover() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=28)
    arp_exchange(tl, 2.0, ROUTER2, CLIENT)          # the standby router uses its own address .2
    # The primary router dies; the standby takes over the virtual IP with one gratuitous ARP.
    gratuitous_arp(tl, 30.0, GATEWAY.ip, ROUTER2.mac)
    _background_via(tl, 31.0, 29.0, ROUTER2.mac)
    arp_exchange(tl, 40.0, CLIENT3, Host(GATEWAY.ip, ROUTER2.mac))
    return tl


def _normal_chatter() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=60)
    hosts = [CLIENT, CLIENT2, CLIENT3, SERVER]
    t = 1.0
    for rnd in range(4):
        for a in hosts:
            for b in hosts:
                if a is not b:
                    arp_exchange(tl, t, a, b)
                    t += 0.07
        t += 10
    gratuitous_arp(tl, 0.8, CLIENT3.ip, CLIENT3.mac)        # boot announcement
    for k in range(5):                                       # Linux unicast reachability probes
        tt = 5 + 11 * k
        _arp(tl, tt, 1, SERVER.mac, CLIENT.mac, SERVER.mac, SERVER.ip, CLIENT.mac, CLIENT.ip)
        _arp(tl, tt + 0.001, 2, CLIENT.mac, SERVER.mac, CLIENT.mac, CLIENT.ip, SERVER.mac, SERVER.ip)
    return tl


NLB_IP = "192.168.1.80"
NLB_CLUSTER_MAC = "02:bf:c0:a8:01:50"


def _special_cases() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=40)
    # Proxy ARP: the router answers (when asked) for addresses behind it.
    for k in range(6):
        ip = f"10.20.0.{5 + k}"
        arp_request(tl, 3 + k, CLIENT, ip)
        arp_reply(tl, 3 + k + 0.001, ip, GATEWAY.mac, CLIENT)
    # The same private address re-used on two VLANs by two different devices.
    for k in range(3):
        tt = 6 + 8 * k
        _arp(tl, tt, 1, "02:00:00:0a:00:05", BROADCAST, "02:00:00:0a:00:05", "10.0.0.5", "00:00:00:00:00:00",
             "10.0.0.1", vlan=10)
        _arp(tl, tt + 0.001, 2, "02:00:00:0a:00:01", "02:00:00:0a:00:05", "02:00:00:0a:00:01", "10.0.0.1",
             "02:00:00:0a:00:05", "10.0.0.5", vlan=10)
        _arp(tl, tt + 0.5, 1, "02:00:00:14:00:05", BROADCAST, "02:00:00:14:00:05", "10.0.0.5", "00:00:00:00:00:00",
             "10.0.0.1", vlan=20)
        _arp(tl, tt + 0.501, 2, "02:00:00:14:00:01", "02:00:00:14:00:05", "02:00:00:14:00:01", "10.0.0.1",
             "02:00:00:14:00:05", "10.0.0.5", vlan=20)
    # Microsoft NLB unicast mode: each node answers with the cluster MAC but a masked source MAC.
    for k in range(3):
        tt = 9 + 9 * k
        arp_request(tl, tt, CLIENT2, NLB_IP)
        for node in (1, 2):
            _arp(tl, tt + 0.001 * node, 2, f"02:0{node}:c0:a8:01:50", CLIENT2.mac, NLB_CLUSTER_MAC, NLB_IP,
                 CLIENT2.mac, CLIENT2.ip)
    # IPv6 link-local chatter must not disturb IPv4 ARP analysis.
    for k in range(5):
        tl.add(2 + 7 * k, Ether(src=CLIENT.mac, dst="33:33:00:00:00:fb") /
               IPv6(src="fe80::1", dst="ff02::fb") / UDP(sport=5000, dport=5000) / Raw(b"x" * 20))
        tl.add(2.5 + 7 * k, Ether(src=CLIENT2.mac, dst="33:33:00:00:00:fb") /
               IPv6(src="fe80::1", dst="ff02::fb") / UDP(sport=5000, dport=5000) / Raw(b"x" * 20))
    return tl


def _probe_unanswered() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=40)
    newcomer = Host("192.168.1.31", "02:00:00:00:00:31")
    dhcp_dora(tl, 10.0, GATEWAY, newcomer.mac, 0x2222, newcomer.ip, GATEWAY.ip, [GATEWAY.ip])
    for k in range(3):
        arp_probe(tl, 10.1 + k, newcomer.mac, newcomer.ip)
    gratuitous_arp(tl, 14.2, newcomer.ip, newcomer.mac)
    gratuitous_arp(tl, 16.2, newcomer.ip, newcomer.mac)
    _host_sessions(tl, newcomer, [17, 27], 34000, 50_000_000)
    for k in range(3):                                       # a second device probing its own address
        arp_probe(tl, 20 + k * 1.5, "02:00:00:00:00:32", "192.168.1.32")
    return tl


def _malformed() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=30)
    # Truncated ARP payload.
    tl.add(4.0, Ether(src=ATTACKER.mac, dst=BROADCAST, type=0x0806) / Raw(b"\x00\x01\x08\x00\x06\x04\x00\x02"))
    # Unsupported hardware type (IEEE 802 / token ring).
    tl.add(5.0, Ether(src=ATTACKER.mac, dst=BROADCAST) /
           ARP(hwtype=6, op=2, hwsrc=ATTACKER.mac, psrc=GATEWAY.ip, hwdst=CLIENT.mac, pdst=CLIENT.ip))
    # RARP and InARP opcodes, a zero sender MAC, broadcast and loopback sender addresses.
    _arp(tl, 6.0, 3, ATTACKER.mac, BROADCAST, ATTACKER.mac, "0.0.0.0", ATTACKER.mac, "0.0.0.0")
    _arp(tl, 6.5, 8, ATTACKER.mac, CLIENT.mac, ATTACKER.mac, GATEWAY.ip, CLIENT.mac, CLIENT.ip)
    _arp(tl, 7.0, 2, ATTACKER.mac, CLIENT.mac, "00:00:00:00:00:00", "192.168.1.150", CLIENT.mac, CLIENT.ip)
    _arp(tl, 7.5, 2, ATTACKER.mac, CLIENT.mac, ATTACKER.mac, "255.255.255.255", CLIENT.mac, CLIENT.ip)
    _arp(tl, 8.0, 2, ATTACKER.mac, CLIENT.mac, ATTACKER.mac, "127.0.0.1", CLIENT.mac, CLIENT.ip)
    _arp(tl, 8.5, 1, ATTACKER.mac, BROADCAST, ATTACKER.mac, "0.0.0.0", "00:00:00:00:00:00", "0.0.0.0")
    return tl


SCENARIOS = [
    Scenario("arp_spoofing_mitm",
             "Attacker poisons gateway and client every 2 s, then relays the client's traffic (MITM)",
             _mitm, expect={"ARP_SPOOFING"}, forbid={"DUPLICATE_IP", "ARP_MAPPING_CHANGED"},
             expect_assessment={"ARP_SPOOFING": "attack"}, sample="attack_arp_spoofing_mitm.pcap"),
    Scenario("arp_spoofing_ip_sweep", "One MAC sends unsolicited replies claiming 20 addresses incl. the gateway",
             _sweep, expect={"ARP_SPOOFING"}, forbid={"DUPLICATE_IP", "ARP_MAPPING_CHANGED"},
             expect_assessment={"ARP_SPOOFING": "attack"}),
    Scenario("arp_spoofing_mac_mismatch",
             "Crafted replies: Ethernet source is the attacker, ARP sender MAC is forged, claiming the server",
             _mismatch, expect={"ARP_SPOOFING"}, forbid={"DUPLICATE_IP", "ARP_MAPPING_CHANGED"},
             expect_assessment={"ARP_SPOOFING": "attack"}),
    Scenario("arp_spoofing_workstation_threshold",
             "Exactly arp_unsolicited_min (5) false replies for a workstation while it re-asserts (boundary)",
             _workstation_poison(5), expect={"ARP_SPOOFING"}, forbid={"DUPLICATE_IP"},
             expect_assessment={"ARP_SPOOFING": "attack"}),
    Scenario("arp_unsolicited_below_threshold",
             "Same as the threshold case with only 4 false replies: conflict, not a confirmed attack",
             _workstation_poison(4), expect={"ARP_CONFLICT"}, forbid={"ARP_SPOOFING", "DUPLICATE_IP"},
             expect_assessment={"ARP_CONFLICT": "inconclusive"}, forbid_attacks=True),
    Scenario("arp_duplicate_ip", "Two workstations configured with the same static IP answer ARP alternately",
             _duplicate, expect={"DUPLICATE_IP"}, forbid={"ARP_SPOOFING", "ARP_MAPPING_CHANGED"},
             expect_assessment={"DUPLICATE_IP": "fault"}, forbid_attacks=True, sample="fault_duplicate_ip.pcap"),
    Scenario("arp_duplicate_probe_defended",
             "DHCP offers a printer's static IP; the client's RFC 5227 probe is defended, it declines",
             _probe_defended, expect={"DUPLICATE_IP"}, forbid={"ARP_SPOOFING", "ARP_MAPPING_CHANGED"},
             expect_assessment={"DUPLICATE_IP": "fault"}, forbid_attacks=True),
    Scenario("arp_duplicate_gateway_ip",
             "A laptop statically configured with the gateway address: a fault, not spoofing",
             _gateway_duplicate, expect={"DUPLICATE_IP"}, forbid={"ARP_SPOOFING"},
             expect_assessment={"DUPLICATE_IP": "fault"}, forbid_attacks=True),
    Scenario("arp_device_replacement", "A NAS is replaced: old MAC goes silent, new MAC announces itself once",
             _replacement, expect={"ARP_MAPPING_CHANGED"},
             forbid={"ARP_SPOOFING", "DUPLICATE_IP", "ARP_CONFLICT"},
             expect_assessment={"ARP_MAPPING_CHANGED": "benign"}, forbid_attacks=True),
    Scenario("arp_vrrp_failover", "Standby router takes over the gateway IP with one gratuitous ARP",
             _failover, expect={"ARP_MAPPING_CHANGED"}, forbid={"ARP_SPOOFING", "DUPLICATE_IP", "ARP_CONFLICT"},
             expect_assessment={"ARP_MAPPING_CHANGED": "benign"}, forbid_attacks=True),
    Scenario("arp_normal_chatter", "Busy but normal ARP: requests/replies, unicast refreshes, boot announcement",
             _normal_chatter, forbid=ARP_KINDS, forbid_attacks=True),
    Scenario("arp_legit_special_cases", "Proxy ARP, same IP on two VLANs, Microsoft NLB unicast, IPv6 noise",
             _special_cases, forbid=ARP_KINDS, forbid_attacks=True),
    Scenario("arp_probe_unanswered", "DHCP clients probe (RFC 5227), nobody answers, they announce and use it",
             _probe_unanswered, forbid=ARP_KINDS, forbid_attacks=True),
    Scenario("arp_malformed_records", "Truncated / unsupported / invalid ARP frames among normal traffic",
             _malformed, forbid=ARP_KINDS, forbid_attacks=True),
]
