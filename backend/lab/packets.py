"""Deterministic builders for synthetic, protocol-correct lab traffic.

All traffic is generated offline with Scapy and written with ``wrpcap``; nothing is ever
sent on a network interface. Every Ethernet header uses explicit MAC addresses (Scapy would
otherwise try to resolve a local interface).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP, IPerror, TCPerror, UDPerror
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet, Raw
from scapy.utils import wrpcap

BROADCAST = "ff:ff:ff:ff:ff:ff"
BASE_TIME = 1_793_000_000.0   # fixed epoch so generated files are reproducible


@dataclass(frozen=True)
class Host:
    ip: str
    mac: str


def host(n: int, net: str = "192.168.1", prefix: str = "02:00:00:00:00") -> Host:
    """Convenience: host(10) -> 192.168.1.10 with MAC 02:00:00:00:00:0a."""
    return Host(f"{net}.{n}", f"{prefix}:{n:02x}")


# A typical small office: router, DNS on the router, a server and some clients.
GATEWAY = host(1)
SERVER = host(20)
CLIENT = host(10)
CLIENT2 = host(11)
CLIENT3 = host(12)
ATTACKER = Host("192.168.1.66", "02:00:00:00:00:66")
PUBLIC_DNS = Host("8.8.8.8", GATEWAY.mac)          # reached through the router
WEB = Host("93.184.216.34", GATEWAY.mac)           # public web server, via the router
WEB2 = Host("151.101.1.69", GATEWAY.mac)


@dataclass
class Timeline:
    """Collects packets with explicit timestamps; ``packets()`` returns them in time order."""

    items: list[tuple[float, int, Packet]] = field(default_factory=list)
    _seq: int = 0

    def add(self, t: float, pkt: Packet) -> Packet:
        self._seq += 1
        self.items.append((t, self._seq, pkt))
        return pkt

    def packets(self) -> list[Packet]:
        out = []
        for t, _, pkt in sorted(self.items, key=lambda x: (x[0], x[1])):
            pkt.time = BASE_TIME + t
            out.append(pkt)
        return out

    def write(self, path: str) -> None:
        wrpcap(path, self.packets())


def _eth(src: Host | str, dst: Host | str) -> Ether:
    s = src.mac if isinstance(src, Host) else src
    d = dst.mac if isinstance(dst, Host) else dst
    return Ether(src=s, dst=d)


# --- TCP ---------------------------------------------------------------------------------

@dataclass
class TcpSide:
    host: Host
    port: int
    seq: int


def tcp_session(tl: Timeline, t: float, client: Host, server: Host, sport: int, dport: int,
                exchanges: Iterable[tuple[int, int]] = ((200, 1200),), rtt: float = 0.02,
                server_delay: float = 0.01, close: str = "fin", isn_c: int = 1000,
                isn_s: int = 50000, mss: int = 1460, ttl_c: int = 64, ttl_s: int = 64,
                syn_ack_delay: float | None = None, client_mac: str | None = None,
                server_mac: str | None = None) -> float:
    """Build a complete, well-formed TCP connection. Returns the time of the last packet.

    ``exchanges`` is a list of (request_bytes, response_bytes). Responses larger than
    ``mss`` are split into segments, and the client ACKs every second segment, which is how
    real stacks behave (and what the old detector misread as retransmissions).
    """
    cm, sm = client_mac or client.mac, server_mac or server.mac
    c_seq, s_seq = isn_c, isn_s
    half = rtt / 2
    hs = syn_ack_delay if syn_ack_delay is not None else rtt

    def c2s(when: float, flags: str, payload: int = 0, opts=None):
        nonlocal c_seq
        pkt = Ether(src=cm, dst=sm) / IP(src=client.ip, dst=server.ip, ttl=ttl_c, flags="DF") / \
            TCP(sport=sport, dport=dport, flags=flags, seq=c_seq, ack=s_seq if "A" in flags else 0,
                window=64240, options=opts or [])
        if payload:
            pkt = pkt / Raw(b"q" * payload)
        tl.add(when, pkt)
        c_seq += payload + (1 if ("S" in flags or "F" in flags) else 0)
        return pkt

    def s2c(when: float, flags: str, payload: int = 0, opts=None):
        nonlocal s_seq
        pkt = Ether(src=sm, dst=cm) / IP(src=server.ip, dst=client.ip, ttl=ttl_s, flags="DF") / \
            TCP(sport=dport, dport=sport, flags=flags, seq=s_seq, ack=c_seq, window=65160,
                options=opts or [])
        if payload:
            pkt = pkt / Raw(b"r" * payload)
        tl.add(when, pkt)
        s_seq += payload + (1 if ("S" in flags or "F" in flags) else 0)
        return pkt

    now = t
    c2s(now, "S", opts=[("MSS", mss)])
    now += hs
    s2c(now, "SA", opts=[("MSS", mss)])
    now += half
    c2s(now, "A")
    for req, resp in exchanges:
        now += 0.001
        if req:
            c2s(now, "PA", req)
        now += half + server_delay
        segments = []
        remaining = resp
        while remaining > 0:
            size = min(mss, remaining)
            segments.append(size)
            remaining -= size
        for i, size in enumerate(segments):
            s2c(now, "PA" if i == len(segments) - 1 else "A", size)
            now += 0.0005
            if i % 2 == 1 or i == len(segments) - 1:
                c2s(now + half, "A")
        now += half
    now += 0.05
    if close == "fin":
        c2s(now, "FA")
        now += half
        s2c(now, "FA")
        now += half
        c2s(now, "A")
    elif close == "rst":
        c2s(now, "RA")
    return now


def tcp_refused(tl: Timeline, t: float, client: Host, server: Host, sport: int, dport: int,
                isn: int = 7000, rtt: float = 0.01) -> float:
    """SYN answered by RST/ACK: nothing listens on the port."""
    tl.add(t, _eth(client, server) / IP(src=client.ip, dst=server.ip) /
           TCP(sport=sport, dport=dport, flags="S", seq=isn))
    tl.add(t + rtt, _eth(server, client) / IP(src=server.ip, dst=client.ip) /
           TCP(sport=dport, dport=sport, flags="RA", seq=0, ack=isn + 1))
    return t + rtt


def syn_probe(tl: Timeline, t: float, src: Host, dst: Host, sport: int, dport: int,
              answer: str | None = "rst", isn: int = 9000, rtt: float = 0.002,
              l2dst: Host | None = None) -> None:
    """A half-open scan probe; ``answer`` is "rst" (closed), "synack" (open) or None (filtered)."""
    tl.add(t, _eth(src, l2dst or dst) / IP(src=src.ip, dst=dst.ip) /
           TCP(sport=sport, dport=dport, flags="S", seq=isn))
    if answer == "rst":
        tl.add(t + rtt, _eth(l2dst or dst, src) / IP(src=dst.ip, dst=src.ip) /
               TCP(sport=dport, dport=sport, flags="RA", seq=0, ack=isn + 1))
    elif answer == "synack":
        tl.add(t + rtt, _eth(l2dst or dst, src) / IP(src=dst.ip, dst=src.ip) /
               TCP(sport=dport, dport=sport, flags="SA", seq=77000, ack=isn + 1))
        tl.add(t + 2 * rtt, _eth(src, l2dst or dst) / IP(src=src.ip, dst=dst.ip) /
               TCP(sport=sport, dport=dport, flags="R", seq=isn + 1))


# --- DNS ---------------------------------------------------------------------------------

def dns_lookup(tl: Timeline, t: float, client: Host, server: Host, name: str,
               answers: Iterable[str] = ("93.184.216.34",), rcode: int = 0, delay: float = 0.02,
               txid: int = 1, sport: int = 53000, qtype: str = "A", respond: bool = True,
               l2server: Host | None = None, resp_ttl: int = 64) -> float:
    """A DNS query and (optionally) its response. Returns the response time."""
    gw = l2server or server
    tl.add(t, _eth(client, gw) / IP(src=client.ip, dst=server.ip) / UDP(sport=sport, dport=53) /
           DNS(id=txid, rd=1, qd=DNSQR(qname=name, qtype=qtype)))
    if not respond:
        return t
    an = [DNSRR(rrname=name, type=qtype, rdata=a, ttl=300) for a in answers] if rcode == 0 else []
    tl.add(t + delay, _eth(gw, client) / IP(src=server.ip, dst=client.ip, ttl=resp_ttl) /
           UDP(sport=53, dport=sport) /
           DNS(id=txid, qr=1, ra=1, rd=1, rcode=rcode, qd=DNSQR(qname=name, qtype=qtype), an=an or None))
    return t + delay


def dns_response(tl: Timeline, t: float, server_ip: str, server_mac: str, client: Host,
                 name: str, answers: Iterable[str], txid: int, dport: int, ttl: int = 64,
                 rcode: int = 0) -> None:
    """A standalone DNS response (used to model injected / spoofed answers)."""
    an = [DNSRR(rrname=name, type="A", rdata=a, ttl=300) for a in answers]
    tl.add(t, Ether(src=server_mac, dst=client.mac) / IP(src=server_ip, dst=client.ip, ttl=ttl) /
           UDP(sport=53, dport=dport) /
           DNS(id=txid, qr=1, ra=1, rd=1, rcode=rcode, qd=DNSQR(qname=name), an=an or None))


# --- ARP ---------------------------------------------------------------------------------

def arp_request(tl: Timeline, t: float, sender: Host, target_ip: str) -> None:
    tl.add(t, Ether(src=sender.mac, dst=BROADCAST) /
           ARP(op=1, hwsrc=sender.mac, psrc=sender.ip, hwdst="00:00:00:00:00:00", pdst=target_ip))


def arp_reply(tl: Timeline, t: float, claimed_ip: str, claimed_mac: str, target: Host,
              eth_src: str | None = None) -> None:
    tl.add(t, Ether(src=eth_src or claimed_mac, dst=target.mac) /
           ARP(op=2, hwsrc=claimed_mac, psrc=claimed_ip, hwdst=target.mac, pdst=target.ip))


def arp_exchange(tl: Timeline, t: float, asker: Host, owner: Host, rtt: float = 0.001) -> None:
    arp_request(tl, t, asker, owner.ip)
    arp_reply(tl, t + rtt, owner.ip, owner.mac, asker)


def gratuitous_arp(tl: Timeline, t: float, claimer_ip: str, claimer_mac: str) -> None:
    tl.add(t, Ether(src=claimer_mac, dst=BROADCAST) /
           ARP(op=2, hwsrc=claimer_mac, psrc=claimer_ip, hwdst=BROADCAST, pdst=claimer_ip))


def arp_probe(tl: Timeline, t: float, prober_mac: str, wanted_ip: str) -> None:
    """RFC 5227 probe: sender IP 0.0.0.0 asking whether anybody owns ``wanted_ip``."""
    tl.add(t, Ether(src=prober_mac, dst=BROADCAST) /
           ARP(op=1, hwsrc=prober_mac, psrc="0.0.0.0", hwdst="00:00:00:00:00:00", pdst=wanted_ip))


# --- DHCP --------------------------------------------------------------------------------

def _dhcp(src_ip: str, src_mac: str, dst_ip: str, dst_mac: str, op: int, xid: int, chaddr: str,
          options: list, yiaddr: str = "0.0.0.0", sport: int = 67, dport: int = 68,
          giaddr: str = "0.0.0.0") -> Packet:
    mac_bytes = bytes(int(x, 16) for x in chaddr.split(":"))
    return (Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip) / UDP(sport=sport, dport=dport) /
            BOOTP(op=op, xid=xid, chaddr=mac_bytes + b"\x00" * 10, yiaddr=yiaddr, giaddr=giaddr) /
            DHCP(options=options + ["end"]))


def dhcp_discover(tl: Timeline, t: float, client_mac: str, xid: int) -> None:
    tl.add(t, _dhcp("0.0.0.0", client_mac, "255.255.255.255", BROADCAST, 1, xid, client_mac,
                    [("message-type", "discover")], sport=68, dport=67))


def dhcp_offer(tl: Timeline, t: float, server: Host, client_mac: str, xid: int, offer_ip: str,
               router: str, dns: list[str], msg: str = "offer", lease: int = 86400) -> None:
    tl.add(t, _dhcp(server.ip, server.mac, "255.255.255.255", BROADCAST, 2, xid, client_mac,
                    [("message-type", msg), ("server_id", server.ip), ("router", router),
                     ("name_server", *dns), ("lease_time", lease),
                     ("subnet_mask", "255.255.255.0")], yiaddr=offer_ip))


def dhcp_request(tl: Timeline, t: float, client_mac: str, xid: int, server_ip: str,
                 requested: str) -> None:
    tl.add(t, _dhcp("0.0.0.0", client_mac, "255.255.255.255", BROADCAST, 1, xid, client_mac,
                    [("message-type", "request"), ("server_id", server_ip),
                     ("requested_addr", requested)], sport=68, dport=67))


def dhcp_dora(tl: Timeline, t: float, server: Host, client_mac: str, xid: int, offer_ip: str,
              router: str, dns: list[str]) -> float:
    dhcp_discover(tl, t, client_mac, xid)
    dhcp_offer(tl, t + 0.01, server, client_mac, xid, offer_ip, router, dns)
    dhcp_request(tl, t + 0.02, client_mac, xid, server.ip, offer_ip)
    dhcp_offer(tl, t + 0.03, server, client_mac, xid, offer_ip, router, dns, msg="ack")
    return t + 0.03


# --- ICMP --------------------------------------------------------------------------------

def icmp_frag_needed(tl: Timeline, t: float, router: Host, victim: Host, orig_src: str,
                     orig_dst: str, sport: int, dport: int, mtu: int, orig_len: int = 1500,
                     seq: int = 0) -> None:
    tl.add(t, Ether(src=router.mac, dst=victim.mac) / IP(src=router.ip, dst=victim.ip) /
           ICMP(type=3, code=4, nexthopmtu=mtu) /
           IPerror(src=orig_src, dst=orig_dst, len=orig_len, flags="DF") /
           TCPerror(sport=sport, dport=dport, seq=seq))


def icmp_port_unreachable(tl: Timeline, t: float, src: Host, dst: Host, orig_sport: int,
                          orig_dport: int) -> None:
    tl.add(t, _eth(src, dst) / IP(src=src.ip, dst=dst.ip) / ICMP(type=3, code=3) /
           IPerror(src=dst.ip, dst=src.ip, proto=17) / UDPerror(sport=orig_sport, dport=orig_dport))


def udp_packet(tl: Timeline, t: float, src: Host, dst: Host, sport: int, dport: int,
               size: int = 32) -> None:
    tl.add(t, _eth(src, dst) / IP(src=src.ip, dst=dst.ip) / UDP(sport=sport, dport=dport) /
           Raw(b"u" * size))


# --- background traffic ------------------------------------------------------------------

def office_background(tl: Timeline, t0: float = 0.0, duration: float = 60.0,
                      clients: Iterable[Host] = (CLIENT, CLIENT2, CLIENT3), seed: int = 0) -> None:
    """Normal browsing: ARP for the gateway, successful DNS lookups and HTTPS sessions.

    Every benign scenario and every attack scenario includes this, so detectors are always
    evaluated against realistic noise rather than an empty capture.
    """
    names = ["example.com", "intranet.local", "updates.vendor.com", "mail.example.org",
             "cdn.example.net", "docs.example.com"]
    clients = list(clients)
    for i, c in enumerate(clients):
        arp_exchange(tl, t0 + 0.1 * i, c, GATEWAY)
    t = t0 + 1.0
    k = seed
    while t < t0 + duration:
        c = clients[k % len(clients)]
        name = names[k % len(names)]
        sport = 40000 + (k * 7) % 20000
        dns_lookup(tl, t, c, GATEWAY, name, answers=["93.184.216.34"], txid=1000 + k,
                   sport=50000 + k % 10000)
        tcp_session(tl, t + 0.05, c, WEB if k % 2 == 0 else WEB2, sport, 443,
                    exchanges=[(300, 4200), (250, 1800)], rtt=0.03, isn_c=10_000 * (k + 1),
                    isn_s=900_000 + 10_000 * k, server_mac=GATEWAY.mac)
        t += 2.5
        k += 1
