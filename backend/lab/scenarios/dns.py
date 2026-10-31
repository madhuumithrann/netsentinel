"""Ground-truth scenarios for the DNS detector (faults, forged answers and their look-alikes).

Every scenario contains ``office_background`` noise: the gateway resolver (192.168.1.1)
answering normal lookups with IP TTL 64 from the gateway MAC. Background lookups use
txids 1000+ and client ports 50000+; the scenarios below use txids >= 20000 and client
ports 33000-39999 so they never collide with it.
"""
from __future__ import annotations

import random

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP, IPerror, UDPerror
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from ..packets import (ATTACKER, CLIENT, CLIENT2, CLIENT3, GATEWAY, PUBLIC_DNS, SERVER, Host, Timeline, dhcp_dora,
                       dns_lookup, dns_response, host, icmp_port_unreachable, office_background, tcp_session)
from . import Scenario

DNS_KINDS = {"DNS_SERVER_UNRESPONSIVE", "DNS_SERVER_FAILURE", "DNS_NXDOMAIN", "DNS_SLOW_RESPONSES",
             "DNS_DGA_PATTERN", "DNS_HIJACK_SUSPECTED"}
FAULT_KINDS = DNS_KINDS - {"DNS_DGA_PATTERN", "DNS_HIJACK_SUSPECTED"}

QUAD9 = Host("9.9.9.9", GATEWAY.mac)                  # a second public resolver, via the router
PHISH = Host(ATTACKER.ip, ATTACKER.mac)               # attacker's fake web server on the LAN
BANK_REAL = "93.184.216.80"


# --- local builders (explicit MACs everywhere; nothing is ever sent) ---------------------

def _query(tl: Timeline, t: float, client: Host, server: Host, name: str, txid: int, sport: int,
           qtype: str = "A", l2: Host | None = None) -> None:
    tl.add(t, Ether(src=client.mac, dst=(l2 or server).mac) / IP(src=client.ip, dst=server.ip) /
           UDP(sport=sport, dport=53) / DNS(id=txid, rd=1, qd=DNSQR(qname=name, qtype=qtype)))


def _injection_race(tl: Timeline, t: float, victim: Host, name: str, txid: int, sport: int) -> None:
    """Victim asks the gateway; an on-LAN injector answers first (TTL 128, its own MAC); the real
    answer arrives later and is rejected with ICMP port unreachable; the victim then connects
    to the forged address."""
    _query(tl, t, victim, GATEWAY, name, txid, sport)
    dns_response(tl, t + 0.004, GATEWAY.ip, ATTACKER.mac, victim, name, [PHISH.ip], txid, sport, ttl=128)
    dns_response(tl, t + 0.031, GATEWAY.ip, GATEWAY.mac, victim, name, [BANK_REAL], txid, sport, ttl=64)
    icmp_port_unreachable(tl, t + 0.0312, victim, GATEWAY, 53, sport)
    tcp_session(tl, t + 0.06, victim, PHISH, sport + 1, 443, exchanges=[(400, 2500)], rtt=0.002,
                isn_c=3_000_000 + txid, isn_s=4_000_000 + txid)


def _dns6(tl: Timeline, t: float, src_ip: str, src_mac: str, dst_ip: str, dst_mac: str, sport: int,
          dport: int, msg: DNS) -> None:
    tl.add(t, Ether(src=src_mac, dst=dst_mac) / IPv6(src=src_ip, dst=dst_ip) / UDP(sport=sport, dport=dport) / msg)


def _icmp_quoting_dns(tl: Timeline, t: float, client: Host, server: Host, sport: int, msg: DNS) -> None:
    """ICMP port unreachable that quotes a whole DNS response (the decoder must not count it)."""
    tl.add(t, Ether(src=client.mac, dst=server.mac) / IP(src=client.ip, dst=server.ip) / ICMP(type=3, code=3) /
           IPerror(src=server.ip, dst=client.ip, proto=17) / UDPerror(sport=53, dport=sport) / msg)


def _end(tl: Timeline) -> float:
    return max(t for t, _, _ in tl.items)


# --- positive scenarios ------------------------------------------------------------------

def _hijack_race() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=60)
    _injection_race(tl, 20.0, CLIENT, "bank.example.com", 20001, 33001)
    _injection_race(tl, 35.0, CLIENT2, "login.bank.example.com", 20002, 33011)
    return tl


def _unsolicited_flood() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=60)
    rng = random.Random(4242)
    txids = rng.sample(range(1, 65535), 41)
    txids = [x for x in txids if x != 20500][:40]
    # Blind spoofing: 40 answers for bank.example.com with guessed txids, spoofing the gateway's IP.
    for i, txid in enumerate(txids):
        dns_response(tl, 30.0 + i * 0.01, GATEWAY.ip, ATTACKER.mac, CLIENT, "bank.example.com", [PHISH.ip],
                     txid, 33100, ttl=64)
    dns_lookup(tl, 31.0, CLIENT, GATEWAY, "bank.example.com", answers=[BANK_REAL], txid=20500, sport=33100)
    return tl


def _dns_outage() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=60)
    names = ["fileserver.corp.example.com", "intranet.corp.example.com", "print.corp.example.com",
             "erp.corp.example.com"]
    for i in range(4):   # the internal DNS server (SERVER) works at first ...
        dns_lookup(tl, 2 + i * 2, CLIENT, SERVER, names[i], answers=["192.168.1.20"], txid=21000 + i, sport=33200 + i)
    clients = [CLIENT, CLIENT2, CLIENT3]
    for i in range(12):  # ... then stops answering; clients retry the same txid at +1 s and +3 s
        c, t = clients[i % 3], 14.0 + i * 3
        for delay in (0.0, 1.0, 3.0):
            _query(tl, t + delay, c, SERVER, names[i % 4], 21100 + i, 33300 + i)
    return tl


def _servfail() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=40)
    names = ["news.example.org", "shop.example.net", "api.vendor.io", "status.vendor.io", "files.example.org",
             "video.example.net"]
    for i, name in enumerate(names):
        dns_lookup(tl, 5 + i * 4, CLIENT if i % 2 else CLIENT2, GATEWAY, name, rcode=2, txid=22000 + i,
                   sport=33400 + i, delay=0.9)
    return tl


def _servfail_single_domain() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=40)
    for i in range(4):   # a DNSSEC-broken domain; everything else resolves fine
        dns_lookup(tl, 6 + i * 6, CLIENT, GATEWAY, "dnssec-failed.org", rcode=2, txid=22100 + i, sport=33450 + i)
    return tl


def _refused() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=40)
    # CLIENT3 was given the file server's address as its DNS server; it does not recurse for it.
    for i, name in enumerate(["example.com", "mail.example.org", "updates.vendor.com", "docs.example.com"]):
        dns_lookup(tl, 4 + i * 5, CLIENT3, SERVER, name, rcode=5, txid=22200 + i, sport=33500 + i)
    # edge case: a REFUSED answer without a question section still matches its query
    _query(tl, 30.0, CLIENT3, SERVER, "cdn.example.net", 22210, 33510)
    tl.add(30.01, Ether(src=SERVER.mac, dst=CLIENT3.mac) / IP(src=SERVER.ip, dst=CLIENT3.ip) /
           UDP(sport=53, dport=33510) / DNS(id=22210, qr=1, rcode=5, qd=None))
    return tl


def _nxdomain_typos() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=40)
    typos = ["exmaple.com", "docs.exmaple.com", "mail.exmaple.org", "updates.vendro.com", "cdn.exmaple.net",
             "exampel.com"]
    for i, name in enumerate(typos):
        dns_lookup(tl, 3 + i * 5, CLIENT2, GATEWAY, name, rcode=3, txid=23000 + i, sport=33600 + i)
    return tl


def _nxdomain_search_suffix() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=40)
    names = []
    for short in ("printer", "nas", "scanner"):
        names += [f"{short}.corp.example.com", f"{short}.example.com"]
    for i, name in enumerate(names):
        dns_lookup(tl, 4 + i * 4, CLIENT3, GATEWAY, name, rcode=3, txid=23100 + i, sport=33700 + i)
    return tl


def _dga() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=60)
    rng = random.Random(1337)
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    for i in range(30):
        label = "".join(rng.choice(alphabet) for _ in range(rng.randint(14, 20)))
        dns_lookup(tl, 5 + i * 1.5, CLIENT3, GATEWAY, f"{label}.com", rcode=3, txid=24000 + i, sport=34000 + i)
    # one generated name is registered: the command-and-control server
    dns_lookup(tl, 52.0, CLIENT3, GATEWAY, "q7x2kd9vbm4hz8rt.com", answers=["185.199.110.50"], txid=24100,
               sport=34100)
    return tl


def _slow_resolver() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=60)
    for i, name in enumerate(["example.com", "mail.example.org", "docs.example.com", "news.example.org",
                              "shop.example.net", "api.vendor.io", "cdn.example.net", "status.vendor.io"]):
        dns_lookup(tl, 4 + i * 6, CLIENT2, PUBLIC_DNS, name, answers=["93.184.216.34"], delay=1.5,
                   txid=25000 + i, sport=34200 + i, l2server=GATEWAY)
    return tl


def _wrong_source_answers() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=40)
    # CLIENT asks 8.8.8.8; besides the real answer, 9.9.9.9 also answers with the right txid/port.
    for i, name in enumerate(["example.com", "docs.example.com", "mail.example.org"]):
        t = 5 + i * 8
        dns_lookup(tl, t, CLIENT, PUBLIC_DNS, name, answers=["93.184.216.34"], txid=25100 + i, sport=34300 + i,
                   l2server=GATEWAY, delay=0.03)
        dns_response(tl, t + 0.02, QUAD9.ip, GATEWAY.mac, CLIENT, name, ["93.184.216.34"], 25100 + i, 34300 + i)
    return tl


V6_CLIENT, V6_DNS = "2001:db8:1::10", "2001:db8:1::53"


def _ipv6_outage() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=40)
    for i in range(5):
        for delay in (0.0, 1.0):
            _dns6(tl, 5 + i * 5 + delay, V6_CLIENT, CLIENT.mac, V6_DNS, SERVER.mac, 34400 + i, 53,
                  DNS(id=26000 + i, rd=1, qd=DNSQR(qname="intranet.corp.example.com", qtype="AAAA")))
    return tl


# --- negative scenarios (must stay silent) -----------------------------------------------

def _normal() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=90)
    return tl


def _nxdomain_below() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=40)
    for i in range(4):   # threshold is 5
        dns_lookup(tl, 5 + i * 5, CLIENT2, GATEWAY, f"old-host{i}.corp.example.com", rcode=3, txid=27000 + i,
                   sport=34500 + i)
    return tl


def _split_horizon() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=40)
    records = [("intranet.local", "10.20.0.5"), ("vpn.example.com", "10.8.0.1"), ("wiki.corp", "10.20.0.7")]
    for i in range(9):
        name, addr = records[i % 3]
        dns_lookup(tl, 3 + i * 4, [CLIENT, CLIENT2, CLIENT3][i % 3], GATEWAY, name, answers=[addr],
                   txid=27100 + i, sport=34600 + i)
    return tl


def _cdn_rotation() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=50)
    dhcp_dora(tl, 0.5, GATEWAY, CLIENT2.mac, 0xABCD, CLIENT2.ip, GATEWAY.ip, [GATEWAY.ip])
    sets = [["151.101.1.69"], ["151.101.65.69"], ["151.101.129.69"], ["151.101.193.69"]]
    for i, answers in enumerate(sets):   # different answers at different times: normal CDN behaviour
        dns_lookup(tl, 4 + i * 9, CLIENT, GATEWAY, "cdn.example.net", answers=answers, txid=27200 + i,
                   sport=34700 + i)
    # a retried query (same txid) answered twice with the same set in rotated order
    _query(tl, 12.0, CLIENT3, GATEWAY, "www.cdn-shop.com", 27210, 34710)
    _query(tl, 13.0, CLIENT3, GATEWAY, "www.cdn-shop.com", 27210, 34710)
    dns_response(tl, 13.02, GATEWAY.ip, GATEWAY.mac, CLIENT3, "www.cdn-shop.com", ["151.101.2.1", "151.101.66.1"],
                 27210, 34710)
    dns_response(tl, 13.05, GATEWAY.ip, GATEWAY.mac, CLIENT3, "www.cdn-shop.com", ["151.101.66.1", "151.101.2.1"],
                 27210, 34710)
    # CLIENT2 uses a public resolver that is not the DHCP one and gets a different (geo) CDN node
    for i in range(3):
        dns_lookup(tl, 20 + i * 6, CLIENT2, PUBLIC_DNS, "cdn.example.net", answers=["146.75.1.69"],
                   txid=27220 + i, sport=34720 + i, l2server=GATEWAY)
    return tl


def _multi_client_single_nx() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=40)
    for i, c in enumerate([CLIENT, CLIENT2, CLIENT3, host(13), host(14), host(15)]):
        dns_lookup(tl, 4 + i * 4, c, GATEWAY, f"wpad.site{i}.example.com", rcode=3, txid=27300 + i, sport=34800 + i)
    return tl


def _queries_at_end() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=30)
    end = _end(tl)
    for i, c in enumerate([CLIENT, CLIENT2, CLIENT3, CLIENT, CLIENT2, CLIENT3]):
        _query(tl, end + 0.1 + i * 0.2, c, GATEWAY, f"late{i}.example.com", 27400 + i, 34900 + i)
    return tl


def _icmp_quoted() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=40)
    for i in range(6):   # NXDOMAIN answers quoted inside ICMP errors must not count as DNS traffic
        msg = DNS(id=27500 + i, qr=1, rcode=3, qd=DNSQR(qname=f"gone{i}.example.com"))
        _icmp_quoting_dns(tl, 5 + i * 3, CLIENT, GATEWAY, 35000 + i, msg)
        icmp_port_unreachable(tl, 5.5 + i * 3, CLIENT2, GATEWAY, 53, 35100 + i)
    return tl


def _below_thresholds() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=50)
    dns21, dns22 = host(21), host(22)
    for i in range(2):   # 2 timeouts (threshold 3)
        _query(tl, 5 + i * 4, CLIENT, dns21, "erp.corp.example.com", 27600 + i, 35200 + i)
    for i in range(2):   # 2 SERVFAIL (threshold 3)
        dns_lookup(tl, 6 + i * 4, CLIENT2, dns22, f"svc{i}.example.org", rcode=2, txid=27610 + i, sport=35210 + i)
    for i in range(8):   # 2 slow of 8 answers (threshold 3)
        dns_lookup(tl, 4 + i * 5, CLIENT3, PUBLIC_DNS, f"n{i}.example.com", answers=["93.184.216.34"],
                   delay=0.9 if i < 2 else 0.03, txid=27620 + i, sport=35220 + i, l2server=GATEWAY)
    for i in range(2):   # 2 unsolicited answers (indicator needs 3)
        dns_response(tl, 20 + i, GATEWAY.ip, GATEWAY.mac, CLIENT, "stray.example.com", ["93.184.216.34"],
                     27640 + i, 35240)
    return tl


def _malformed() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=40)
    for i in range(4):
        tl.add(5 + i, Ether(src=CLIENT.mac, dst=GATEWAY.mac) / IP(src=CLIENT.ip, dst=GATEWAY.ip) /
               UDP(sport=35300 + i, dport=53) / Raw(b"\x12\x34\x01"))                  # too short for DNS
        tl.add(5.5 + i, Ether(src=GATEWAY.mac, dst=CLIENT.mac) / IP(src=GATEWAY.ip, dst=CLIENT.ip) /
               UDP(sport=53, dport=35300 + i) /
               Raw(b"\x12\x34\x81\x83\x00\x01\x00\x00\x00\x00\x00\x00\x07trunc"))      # truncated question
        tl.add(6.0 + i, Ether(src=GATEWAY.mac, dst=CLIENT.mac) / IP(src=GATEWAY.ip, dst=CLIENT.ip) /
               UDP(sport=53, dport=35310 + i) / Raw(bytes(range(i, i + 40))))           # garbage on port 53
        tl.add(6.2 + i, Ether(src=CLIENT.mac, dst=SERVER.mac) / IP(src=CLIENT.ip, dst=SERVER.ip) /
               TCP(sport=35320 + i, dport=53, flags="PA", seq=1, ack=1) / Raw(b"\x00\x05junk!"))
    # responses carrying only TXT / unusual rcodes, matched to real queries
    for i in range(3):
        _query(tl, 20 + i, CLIENT2, GATEWAY, "txt.example.com", 27700 + i, 35330 + i, qtype="TXT")
        tl.add(20.02 + i, Ether(src=GATEWAY.mac, dst=CLIENT2.mac) / IP(src=GATEWAY.ip, dst=CLIENT2.ip) /
               UDP(sport=53, dport=35330 + i) /
               DNS(id=27700 + i, qr=1, rcode=4 if i == 2 else 0, qd=DNSQR(qname="txt.example.com", qtype="TXT"),
                   an=DNSRR(rrname="txt.example.com", type="TXT", rdata="v=spf1 -all") if i < 2 else None))
    return tl


def _mdns_noise() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=40)
    for i in range(12):  # multicast DNS announcements are unsolicited by design
        tl.add(3 + i * 2, Ether(src=CLIENT3.mac, dst="01:00:5e:00:00:fb") / IP(src=CLIENT3.ip, dst="224.0.0.251") /
               UDP(sport=5353, dport=5353) /
               DNS(id=0, qr=1, aa=1, qd=None, an=DNSRR(rrname="printer.local", rdata="192.168.1.50")))
        tl.add(3.5 + i * 2, Ether(src=CLIENT.mac, dst="01:00:5e:00:00:fc") / IP(src=CLIENT.ip, dst="224.0.0.252") /
               UDP(sport=35400 + i, dport=5355) / DNS(id=27800 + i, qd=DNSQR(qname="fileshare")))
    return tl


def _capture_starts_mid_lookup() -> Timeline:
    tl = Timeline()
    # answers to queries sent before the capture started
    for i in range(4):
        dns_response(tl, i * 0.1, GATEWAY.ip, GATEWAY.mac, CLIENT, f"early{i}.example.com", ["93.184.216.34"],
                     27900 + i, 35500 + i)
    office_background(tl, t0=0.5, duration=40)
    return tl


SCENARIOS = [
    # attacks
    Scenario("dns_hijack_race", "On-LAN injector races the gateway resolver for bank.example.com (TTL 128 vs 64); "
             "the victim rejects the real answer and connects to the forged address",
             _hijack_race, expect={"DNS_HIJACK_SUSPECTED"}, forbid=FAULT_KINDS,
             expect_assessment={"DNS_HIJACK_SUSPECTED": "attack"}, sample="attack_dns_hijack.pcap"),
    Scenario("dns_unsolicited_flood", "40 spoofed answers with guessed txids for one name (blind cache poisoning)",
             _unsolicited_flood, expect={"DNS_HIJACK_SUSPECTED"}, forbid=FAULT_KINDS,
             expect_assessment={"DNS_HIJACK_SUSPECTED": "attack"}),
    Scenario("dns_dga", "Client looks up 30 random .com names (NXDOMAIN) and one that resolves",
             _dga, expect={"DNS_DGA_PATTERN"}, forbid={"DNS_HIJACK_SUSPECTED", "DNS_NXDOMAIN"},
             expect_assessment={"DNS_DGA_PATTERN": "attack"}),
    Scenario("dns_wrong_source_answers", "Answers with the right txid arrive from 9.9.9.9 for queries sent to "
             "8.8.8.8 (inconclusive: multi-homed resolver or on-path sender)",
             _wrong_source_answers, expect={"DNS_HIJACK_SUSPECTED"},
             expect_assessment={"DNS_HIJACK_SUSPECTED": "inconclusive"}, forbid_attacks=True),
    # faults
    Scenario("dns_server_outage", "Internal DNS server answers 4 lookups, then all lookups time out with retries",
             _dns_outage, expect={"DNS_SERVER_UNRESPONSIVE"}, forbid={"DNS_HIJACK_SUSPECTED"},
             expect_assessment={"DNS_SERVER_UNRESPONSIVE": "fault"}, forbid_attacks=True,
             sample="fault_dns_outage.pcap"),
    Scenario("dns_ipv6_outage", "IPv6 resolver never answers AAAA lookups (retried)",
             _ipv6_outage, expect={"DNS_SERVER_UNRESPONSIVE"}, forbid={"DNS_HIJACK_SUSPECTED"},
             expect_assessment={"DNS_SERVER_UNRESPONSIVE": "fault"}, forbid_attacks=True),
    Scenario("dns_servfail", "Gateway resolver returns SERVFAIL for 6 uncached names (upstream broken)",
             _servfail, expect={"DNS_SERVER_FAILURE"}, forbid={"DNS_HIJACK_SUSPECTED", "DNS_SERVER_UNRESPONSIVE"},
             expect_assessment={"DNS_SERVER_FAILURE": "fault"}, forbid_attacks=True),
    Scenario("dns_servfail_single_domain", "SERVFAIL only for one DNSSEC-broken domain",
             _servfail_single_domain, expect={"DNS_SERVER_FAILURE"}, forbid={"DNS_HIJACK_SUSPECTED"},
             expect_assessment={"DNS_SERVER_FAILURE": "fault"}, forbid_attacks=True),
    Scenario("dns_refused", "Client configured with a non-recursive DNS server gets REFUSED",
             _refused, expect={"DNS_SERVER_FAILURE"}, forbid={"DNS_HIJACK_SUSPECTED", "DNS_SERVER_UNRESPONSIVE"},
             expect_assessment={"DNS_SERVER_FAILURE": "fault"}, forbid_attacks=True),
    Scenario("dns_nxdomain_typos", "One client repeatedly looks up misspelled names",
             _nxdomain_typos, expect={"DNS_NXDOMAIN"}, forbid={"DNS_DGA_PATTERN", "DNS_HIJACK_SUSPECTED"},
             expect_assessment={"DNS_NXDOMAIN": "fault"}, forbid_attacks=True),
    Scenario("dns_nxdomain_search_suffix", "Short names expanded with non-existent search suffixes",
             _nxdomain_search_suffix, expect={"DNS_NXDOMAIN"}, forbid={"DNS_DGA_PATTERN", "DNS_HIJACK_SUSPECTED"},
             expect_assessment={"DNS_NXDOMAIN": "fault"}, forbid_attacks=True),
    Scenario("dns_slow_resolver", "Public resolver answers in 1.5 s while the gateway answers in 20 ms",
             _slow_resolver, expect={"DNS_SLOW_RESPONSES"},
             forbid={"DNS_SERVER_UNRESPONSIVE", "DNS_HIJACK_SUSPECTED"},
             expect_assessment={"DNS_SLOW_RESPONSES": "fault"}, forbid_attacks=True),
    # negatives / edge cases
    Scenario("dns_normal_office", "Normal office DNS traffic only", _normal, forbid=DNS_KINDS, forbid_attacks=True),
    Scenario("dns_nxdomain_below_threshold", "4 NXDOMAIN answers for one client (threshold 5)",
             _nxdomain_below, forbid=DNS_KINDS, forbid_attacks=True),
    Scenario("dns_split_horizon", "Internal and public-looking names resolve to private addresses (legitimate)",
             _split_horizon, forbid=DNS_KINDS, forbid_attacks=True),
    Scenario("dns_cdn_rotation", "CDN answers change over time, a retry is answered twice in rotated order, and a "
             "non-DHCP public resolver returns another CDN node", _cdn_rotation, forbid=DNS_KINDS,
             forbid_attacks=True),
    Scenario("dns_multi_client_single_nxdomain", "Six clients with one NXDOMAIN each", _multi_client_single_nx,
             forbid=DNS_KINDS, forbid_attacks=True),
    Scenario("dns_queries_at_capture_end", "Unanswered queries in the last second of the capture",
             _queries_at_end, forbid=DNS_KINDS, forbid_attacks=True),
    Scenario("dns_icmp_quoted", "ICMP port unreachable errors quoting DNS (NXDOMAIN) responses",
             _icmp_quoted, forbid=DNS_KINDS, forbid_attacks=True),
    Scenario("dns_failures_below_threshold", "2 timeouts, 2 SERVFAIL, 2 slow answers, 2 unsolicited answers",
             _below_thresholds, forbid=DNS_KINDS, forbid_attacks=True),
    Scenario("dns_malformed_packets", "Truncated / garbage payloads on port 53, TXT-only and NOTIMP answers",
             _malformed, forbid=DNS_KINDS, forbid_attacks=True),
    Scenario("dns_mdns_llmnr_noise", "Multicast DNS announcements and LLMNR queries", _mdns_noise,
             forbid=DNS_KINDS, forbid_attacks=True),
    Scenario("dns_capture_starts_mid_lookup", "Answers at capture start to queries sent before it began",
             _capture_starts_mid_lookup, forbid=DNS_KINDS, forbid_attacks=True),
]
