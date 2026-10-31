"""Shared indexes built once per analysis and reused by every detector.

Detectors receive an :class:`AnalysisContext`. Expensive structures (TCP connection
reconstruction, network role inference) are computed lazily and cached.
"""
from __future__ import annotations

import ipaddress
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from functools import cached_property

from .config import Settings
from .model import ACK, FIN, RST, SYN, PacketRecord

Endpoint = tuple[str, int]


class AnalysisTimeout(Exception):
    """Raised when the analysis deadline is exceeded."""


@dataclass
class TcpConnection:
    """One TCP connection reconstructed from the capture.

    ``client`` is the endpoint that sent the first SYN. When the capture starts mid-stream
    (no SYN seen) the first observed sender is used and ``handshake_seen`` is False.
    """

    client: Endpoint
    server: Endpoint
    packets: list[PacketRecord] = field(default_factory=list)
    handshake_seen: bool = False
    syns: list[PacketRecord] = field(default_factory=list)
    synacks: list[PacketRecord] = field(default_factory=list)
    resets: list[PacketRecord] = field(default_factory=list)
    fins: list[PacketRecord] = field(default_factory=list)
    client_bytes: int = 0
    server_bytes: int = 0
    closed: bool = False

    def from_client(self, rec: PacketRecord) -> bool:
        return (rec.ip_src, rec.sport) == self.client

    @property
    def established(self) -> bool:
        """True when the three-way handshake completed or data flowed both ways."""
        if self.synacks and any(self.from_client(p) and p.tcp_flags & ACK and not p.tcp_flags & SYN
                                for p in self.packets):
            return True
        return self.client_bytes > 0 and self.server_bytes > 0

    @property
    def first_ts(self) -> float:
        return self.packets[0].ts

    @property
    def last_ts(self) -> float:
        return self.packets[-1].ts

    @property
    def label(self) -> str:
        return f"{self.client[0]}:{self.client[1]} -> {self.server[0]}:{self.server[1]}"


def is_private(ip: str | None) -> bool:
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_private or addr.is_link_local


def is_special(ip: str | None) -> bool:
    """Loopback, unspecified, multicast or broadcast addresses."""
    if not ip:
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return (addr.is_loopback or addr.is_unspecified or addr.is_multicast
            or ip == "255.255.255.255" or ip.endswith(".255"))


class AnalysisContext:
    def __init__(self, records: list[PacketRecord], settings: Settings,
                 deadline: float | None = None) -> None:
        self.records = records
        self.settings = settings
        self.thresholds = settings.thresholds
        self.deadline = deadline
        self.by_number = {r.n: r for r in records}

    # -- resource guard ---------------------------------------------------------------------
    def check_deadline(self) -> None:
        if self.deadline is not None and time.monotonic() > self.deadline:
            raise AnalysisTimeout()

    # -- convenience views ------------------------------------------------------------------
    @cached_property
    def tcp(self) -> list[PacketRecord]:
        return [r for r in self.records if r.l4 == "TCP"]

    @cached_property
    def udp(self) -> list[PacketRecord]:
        return [r for r in self.records if r.l4 == "UDP"]

    @cached_property
    def arp(self) -> list[PacketRecord]:
        return [r for r in self.records if r.arp_op is not None]

    @cached_property
    def dns(self) -> list[PacketRecord]:
        return [r for r in self.records if r.dns is not None]

    @cached_property
    def dhcp(self) -> list[PacketRecord]:
        return [r for r in self.records if r.dhcp is not None]

    @cached_property
    def icmp(self) -> list[PacketRecord]:
        return [r for r in self.records if r.l4 in ("ICMP", "ICMPv6")]

    @cached_property
    def start_ts(self) -> float:
        return self.records[0].ts if self.records else 0.0

    @cached_property
    def end_ts(self) -> float:
        return max((r.ts for r in self.records), default=0.0)

    # -- TCP connection reconstruction ------------------------------------------------------
    @cached_property
    def connections(self) -> list[TcpConnection]:
        """Group TCP segments into connections, splitting on port reuse.

        A new connection starts when a SYN (without ACK) arrives for a 4-tuple whose current
        connection has already closed (FIN/RST) or uses a different initial sequence number
        after more than 30 seconds of silence.
        """
        active: dict[tuple, TcpConnection] = {}
        finished: list[TcpConnection] = []
        for i, rec in enumerate(self.tcp):
            if i % 5000 == 0:
                self.check_deadline()
            a, b = (rec.ip_src, rec.sport), (rec.ip_dst, rec.dport)
            key = (a, b) if a <= b else (b, a)
            flags = rec.tcp_flags or 0
            is_syn = bool(flags & SYN) and not flags & ACK
            conn = active.get(key)
            if conn is not None and is_syn:
                same_attempt = any(s.seq == rec.seq for s in conn.syns)
                stale = rec.ts - conn.last_ts > 30
                if not same_attempt and (conn.closed or stale or conn.established):
                    finished.append(conn)
                    conn = None
            if conn is None:
                if is_syn:
                    conn = TcpConnection(client=a, server=b, handshake_seen=True)
                elif flags & SYN and flags & ACK:
                    conn = TcpConnection(client=b, server=a, handshake_seen=True)
                else:
                    conn = TcpConnection(client=a, server=b)
                active[key] = conn
            conn.packets.append(rec)
            if is_syn:
                conn.syns.append(rec)
            elif flags & SYN and flags & ACK:
                conn.synacks.append(rec)
            if flags & RST:
                conn.resets.append(rec)
                conn.closed = True
            if flags & FIN:
                conn.fins.append(rec)
                if len({(p.ip_src, p.sport) for p in conn.fins}) == 2:
                    conn.closed = True
            if rec.payload_len:
                if conn.from_client(rec):
                    conn.client_bytes += rec.payload_len
                else:
                    conn.server_bytes += rec.payload_len
        finished.extend(active.values())
        finished.sort(key=lambda c: c.first_ts)
        return finished

    # -- network role inference -------------------------------------------------------------
    @cached_property
    def dhcp_offered(self) -> dict[str, set[str]]:
        """Routers and DNS servers handed out in DHCP OFFER / ACK messages."""
        out: dict[str, set[str]] = {"router": set(), "dns": set(), "server": set()}
        for r in self.dhcp:
            d = r.dhcp or {}
            if d.get("msg_type") in ("OFFER", "ACK"):
                out["router"].update(d.get("router") or [])
                out["dns"].update(d.get("dns") or [])
                if d.get("server_id"):
                    out["server"].add(d["server_id"])
        return out

    @cached_property
    def ip_macs(self) -> dict[str, Counter]:
        """IP -> Counter of Ethernet source MACs seen sending with that IP (local hosts only)."""
        out: dict[str, Counter] = defaultdict(Counter)
        for r in self.records:
            if r.eth_src and r.ip_src and is_private(r.ip_src):
                out[r.ip_src][r.eth_src] += 1
        return out

    @cached_property
    def mac_ips(self) -> dict[str, set[str]]:
        """MAC -> set of source IPs it sent. Routers forward for many IPs."""
        out: dict[str, set[str]] = defaultdict(set)
        for r in self.records:
            if r.eth_src and r.ip_src:
                out[r.eth_src].add(r.ip_src)
        return out

    @cached_property
    def router_macs(self) -> set[str]:
        """MACs that behave like routers: they source traffic for public IP addresses.

        A host only sends with its own address; a router forwards traffic from many remote
        (public) addresses, so its MAC appears with several public source IPs.
        """
        out = set()
        for mac, ips in self.mac_ips.items():
            public = [ip for ip in ips if not is_private(ip) and not is_special(ip)]
            if len(public) >= 2:
                out.add(mac)
        return out

    @cached_property
    def gateway_ips(self) -> set[str]:
        """Likely default gateway IPs: DHCP-offered routers plus IPs ARP-resolved to a router MAC."""
        gws = set(self.dhcp_offered["router"])
        for r in self.arp:
            if r.arp_op == 2 and r.arp_hwsrc in self.router_macs and r.arp_psrc:
                gws.add(r.arp_psrc)
        return gws

    @cached_property
    def dns_servers(self) -> set[str]:
        servers = set(self.dhcp_offered["dns"])
        for r in self.dns:
            if r.dns and r.dns["qr"] == 0 and r.dport in (53, 5353) and r.ip_dst:
                servers.add(r.ip_dst)
        return servers
