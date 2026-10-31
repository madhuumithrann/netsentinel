"""Ground-truth scenarios for the latency detector (slow handshakes, slow applications, gaps).

``Conn`` is a small stateful TCP builder (IPv4 or IPv6) that lets a scenario place every
segment explicitly: handshakes with a chosen server-side / client-side delay, SYN retries,
server ACKs before a delayed response, keepalive probes, pushes and sequence jumps.
All frames carry explicit MACs; nothing is ever sent.
"""
from __future__ import annotations

from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from ..packets import (CLIENT, CLIENT2, CLIENT3, GATEWAY, SERVER, WEB, WEB2, Host, Timeline, arp_exchange,
                       dns_lookup, office_background, tcp_session, udp_packet)
from . import Scenario

MASK = 0xFFFFFFFF
WEB3 = Host("104.16.85.20", GATEWAY.mac)


class Conn:
    """One TCP connection whose segments are added explicitly to a timeline."""

    def __init__(self, tl: Timeline, client: Host, server: Host, sport: int, dport: int,
                 isn_c: int = 1000, isn_s: int = 500_000, mss: int = 1460,
                 server_mac: str | None = None, v6: bool = False) -> None:
        self.tl, self.client, self.server = tl, client, server
        self.sport, self.dport, self.mss, self.v6 = sport, dport, mss, v6
        self.cm, self.sm = client.mac, server_mac or server.mac
        self.c_seq, self.s_seq = isn_c, isn_s

    def _send(self, t: float, from_client: bool, flags: str, payload: int = 0, seq: int | None = None,
              opts=None) -> None:
        if from_client:
            src, dst, l2s, l2d, sp, dp = self.client, self.server, self.cm, self.sm, self.sport, self.dport
            own, other = self.c_seq, self.s_seq
        else:
            src, dst, l2s, l2d, sp, dp = self.server, self.client, self.sm, self.cm, self.dport, self.sport
            own, other = self.s_seq, self.c_seq
        l3 = IPv6(src=src.ip, dst=dst.ip) if self.v6 else IP(src=src.ip, dst=dst.ip, flags="DF")
        pkt = Ether(src=l2s, dst=l2d) / l3 / TCP(sport=sp, dport=dp, flags=flags,
                                                 seq=(own if seq is None else seq) & MASK,
                                                 ack=other & MASK if "A" in flags else 0,
                                                 window=64240, options=opts or [])
        if payload:
            pkt = pkt / Raw(b"x" * payload)
        self.tl.add(t, pkt)
        if seq is None:
            advance = payload + (1 if ("S" in flags or "F" in flags) else 0)
            if from_client:
                self.c_seq += advance
            else:
                self.s_seq += advance

    def handshake(self, t: float, server_leg: float = 0.01, client_leg: float = 0.01,
                  syn_retries: tuple[float, ...] = ()) -> float:
        isn = self.c_seq
        self._send(t, True, "S", opts=[("MSS", self.mss)])
        for r in syn_retries:
            self._send(t + r, True, "S", seq=isn, opts=[("MSS", self.mss)])
        self._send(t + server_leg, False, "SA", opts=[("MSS", self.mss)])
        self._send(t + server_leg + client_leg, True, "A")
        return t + server_leg + client_leg

    def request(self, t: float, nbytes: int, seg_gap: float = 0.0) -> float:
        while nbytes > 0:
            size = min(self.mss, nbytes)
            nbytes -= size
            self._send(t, True, "PA" if nbytes == 0 else "A", size)
            if nbytes:
                t += seg_gap
        return t

    def respond(self, t: float, nbytes: int, client_leg: float = 0.01) -> float:
        i = 0
        while nbytes > 0:
            size = min(self.mss, nbytes)
            nbytes -= size
            self._send(t, False, "PA" if nbytes == 0 else "A", size)
            if i % 2 == 1 or nbytes == 0:
                self._send(t + client_leg, True, "A")
            t += 0.0005
            i += 1
        return t + client_leg

    def s_ack(self, t: float) -> None:
        self._send(t, False, "A")

    def c_ack(self, t: float) -> None:
        self._send(t, True, "A")

    def keepalive(self, t: float, rtt: float = 0.01) -> None:
        """Windows-style keepalive: one garbage byte at snd.nxt - 1, answered by a pure ACK."""
        self._send(t, True, "A", 1, seq=self.c_seq - 1)
        self.s_ack(t + rtt)

    def resend_last_client(self, t: float, nbytes: int) -> None:
        self._send(t, True, "PA", nbytes, seq=self.c_seq - nbytes)

    def skip(self, from_client: bool, nbytes: int) -> None:
        """Advance a sequence number without emitting packets (bytes the capture missed)."""
        if from_client:
            self.c_seq += nbytes
        else:
            self.s_seq += nbytes

    def close(self, t: float, rtt: float = 0.02) -> float:
        self._send(t, True, "FA")
        self._send(t + rtt / 2, False, "FA")
        self._send(t + rtt, True, "A")
        return t + rtt


def http(tl: Timeline, t: float, client: Host, server: Host, sport: int, dport: int, *, server_leg=0.01,
         client_leg=0.01, req=400, resp=3000, wait=0.03, server_ack: float | None = None, isn=0,
         server_mac=None, v6=False, syn_retries=()) -> float:
    c = Conn(tl, client, server, sport, dport, isn_c=10_000 + isn, isn_s=7_000_000 + isn,
             server_mac=server_mac, v6=v6)
    now = c.handshake(t, server_leg, client_leg, syn_retries)
    last = c.request(now + 0.001, req)
    if server_ack is not None:
        c.s_ack(last + server_ack)
    end = c.respond(last + wait, resp, client_leg)
    return c.close(end + 0.05)


# --- positive scenarios ------------------------------------------------------------------

def _slow_handshake_server() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=40)
    # The intranet server's accept queue is overloaded: SYN/ACK takes 3 s (no SYN retry, so
    # it is delay, not loss). Other servers in the capture answer in ~45 ms.
    for i in range(4):
        c = (CLIENT, CLIENT2)[i % 2]
        http(tl, 4 + i * 7, c, SERVER, 47000 + i, 8443, server_leg=3.0, client_leg=0.001, isn=i * 100_000)
    return tl


def _slow_application() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=45)
    # 20 ms handshake, the server's TCP stack ACKs the request at once, the application needs 4 s.
    for i in range(5):
        c = (CLIENT, CLIENT2, CLIENT3)[i % 3]
        http(tl, 3 + i * 7, c, SERVER, 48000 + i, 8080, server_leg=0.018, client_leg=0.002, req=520,
             resp=6000, wait=4.0 + 0.1 * i, server_ack=0.02, isn=i * 100_000)
    # Some requests to the same application are fast (cached pages).
    for i in range(3):
        http(tl, 6 + i * 9, CLIENT, SERVER, 48100 + i, 8080, server_leg=0.018, client_leg=0.002,
             wait=0.05, isn=900_000 + i * 100_000)
    return tl


def _satellite_background(tl: Timeline, duration: float, rtt: float) -> None:
    """Like office_background, but every path has ``rtt`` of latency (satellite uplink)."""
    clients = (CLIENT, CLIENT2, CLIENT3)
    for i, c in enumerate(clients):
        arp_exchange(tl, 0.1 * i, c, GATEWAY)
    t, k = 1.0, 0
    servers = (WEB, WEB2, WEB3)
    while t < duration:
        c = clients[k % 3]
        dns_lookup(tl, t, c, GATEWAY, "example.com", txid=2000 + k, sport=51000 + k, delay=rtt)
        tcp_session(tl, t + rtt + 0.05, c, servers[k % 3], 42000 + k, 443, exchanges=[(300, 4200)],
                    rtt=rtt, isn_c=20_000 * (k + 1), isn_s=800_000 + 20_000 * k, server_mac=GATEWAY.mac)
        t += 3.0
        k += 1


def _whole_path_slow() -> Timeline:
    # office_background is deliberately NOT used: its 30 ms sessions would contradict a link
    # whose every path has 800 ms latency. The equivalent background is built with that RTT.
    tl = Timeline()
    _satellite_background(tl, 45, rtt=0.8)
    return tl


def _internet_slow_lan_fast() -> Timeline:
    # office_background is not used: its Internet sessions are fast by construction.
    tl = Timeline()
    _satellite_background(tl, 40, rtt=0.6)
    for i in range(8):
        tcp_session(tl, 2 + i * 4.5, (CLIENT, CLIENT2)[i % 2], SERVER, 49000 + i, 445,
                    exchanges=[(200, 3000)], rtt=0.002, isn_c=30_000 * (i + 1), isn_s=600_000 + 30_000 * i)
    return tl


def _slow_client_link() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=40, clients=(CLIENT, CLIENT2))
    # CLIENT3 is on bad Wi-Fi. Captured at the gateway: the server side answers at once,
    # the delay is on the client's side of the capture point (SYN/ACK -> ACK).
    for i, srv in enumerate((WEB, WEB2, SERVER, WEB, WEB2)):
        http(tl, 3 + i * 6, CLIENT3, srv, 47500 + i, 443, server_leg=0.03, client_leg=0.9,
             isn=i * 100_000, server_mac=GATEWAY.mac if srv is not SERVER else None)
    return tl


V6_CLIENT = Host("2001:db8:1::10", CLIENT.mac)
V6_SERVER = Host("2001:db8:2::20", "02:00:00:00:00:21")


def _ipv6_slow_handshake() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=30)
    for i in range(3):
        http(tl, 4 + i * 7, V6_CLIENT, V6_SERVER, 47700 + i, 443, server_leg=1.5, client_leg=0.001,
             isn=i * 100_000, v6=True)
    for i in range(3):
        http(tl, 6 + i * 7, V6_CLIENT, Host("2001:db8:3::30", "02:00:00:00:00:22"), 47800 + i, 443,
             server_leg=0.02, client_leg=0.001, isn=500_000 + i * 100_000, v6=True)
    return tl


def _gap(dropped: bool) -> Timeline:
    tl = Timeline()
    office_background(tl, duration=25)
    ssh = Conn(tl, CLIENT, SERVER, 50022, 22, isn_c=111_000, isn_s=222_000)
    now = ssh.handshake(1.0, 0.002, 0.002)
    t = now + 0.5
    while t < 23.5:
        ssh.request(t, 64)
        ssh.respond(t + 0.01, 120, 0.002)
        t += 1.0
    ssh.request(24.0, 64)               # last packet before the silence, never acknowledged
    if dropped:
        # Traffic continued but the capture missed 16 s of it: the sequence numbers jump.
        ssh.skip(True, 64 * 15)
        ssh.skip(False, 120 * 15)
        ssh.request(40.05, 64)
        ssh.respond(40.06, 120, 0.002)
    else:
        # A real outage: the client re-sends the unacknowledged segment once the path is back.
        ssh.resend_last_client(40.05, 64)
        ssh.respond(40.06, 120, 0.002)
    office_background(tl, t0=40.0, duration=20, seed=50)
    return tl


# --- negative scenarios ------------------------------------------------------------------

def _normal() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=60)
    return tl


def _single_slow() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=40)
    http(tl, 10, CLIENT, SERVER, 47000, 8443, server_leg=3.0, client_leg=0.001)
    for i in range(5):
        http(tl, 15 + i * 4, CLIENT2, SERVER, 47100 + i, 8443, server_leg=0.01, isn=(i + 1) * 100_000)
    return tl


def _boundary() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=40)
    # 0.48 s + 0.01 s = 0.49 s: just below the 0.5 s threshold on every connection.
    for i in range(4):
        http(tl, 4 + i * 7, CLIENT, SERVER, 47200 + i, 8443, server_leg=0.48, client_leg=0.01, isn=i * 100_000)
    # Responses at 1.9 s: just below the 2 s slow-response threshold.
    for i in range(4):
        http(tl, 6 + i * 7, CLIENT2, SERVER, 47300 + i, 8080, wait=1.9, isn=600_000 + i * 100_000)
    return tl


def _retried_syn() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=40)
    # SYN lost and re-sent after 1 s: the 3 s "delay" is packet loss, reported elsewhere.
    for i in range(4):
        http(tl, 4 + i * 7, CLIENT, SERVER, 47400 + i, 8443, server_leg=3.0, client_leg=0.001,
             syn_retries=(1.0,), isn=i * 100_000)
    return tl


def _idle_keepalive() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=60)
    for j in range(3):
        c = Conn(tl, (CLIENT, CLIENT2, CLIENT3)[j], SERVER, 50100 + j, 5432, isn_c=40_000 * (j + 1),
                 isn_s=4_000_000 + 40_000 * j)
        now = c.handshake(2 + j, 0.002, 0.002)
        last = c.request(now + 0.01, 300)
        c.respond(last + 0.02, 900, 0.002)
        # Idle database connection kept alive with keepalive probes (1 byte at snd.nxt-1)...
        for k in range(4):
            c.keepalive(12 + j + k * 10)
        # ...then the server sends an unsolicited notification (LISTEN/NOTIFY) after the idle time.
        c.respond(50 + j, 200, 0.002)
        # A real query after the idle period is answered quickly.
        last = c.request(54 + j, 200)
        c.respond(last + 0.03, 800, 0.002)
    return tl


def _server_push() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=60)
    for j in range(3):
        c = Conn(tl, (CLIENT, CLIENT2, CLIENT3)[j], SERVER, 50200 + j, 8883, isn_c=50_000 * (j + 1),
                 isn_s=5_000_000 + 50_000 * j)
        now = c.handshake(2 + j, 0.002, 0.002)
        last = c.request(now + 0.01, 120)           # subscribe
        c.respond(last + 0.02, 60, 0.002)           # subscription confirmed
        # The client sends an application heartbeat every 10 s that the server does not answer,
        # while the server pushes events every 5 s on its own schedule.
        for k in range(10):
            c.respond(5 + j + k * 5, 300, 0.002)
            if k % 2 == 0:
                c.request(7.5 + j + k * 5, 16)
    return tl


def _long_poll() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=80)
    for j in range(3):
        c = Conn(tl, (CLIENT, CLIENT2, CLIENT3)[j], SERVER, 50300 + j, 8080, isn_c=60_000 * (j + 1),
                 isn_s=6_000_000 + 60_000 * j)
        now = c.handshake(2 + j, 0.002, 0.002)
        for k in range(2):
            last = c.request(now + 0.01 + k * 32, 350)
            c.s_ack(last + 0.002)
            c.respond(last + 30.0, 400, 0.002)       # server holds the poll for 30 s
    return tl


def _slow_upload() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=40)
    # 3 MB uploads taking ~3 s on the wire; the server answers 50 ms after the last byte.
    for i in range(3):
        c = Conn(tl, CLIENT, SERVER, 50400 + i, 443, isn_c=70_000 * (i + 1), isn_s=7_000_000 + 70_000 * i)
        now = c.handshake(3 + i * 10, 0.002, 0.002)
        last = c.request(now + 0.01, 1460 * 2000, seg_gap=0.0015)
        c.respond(last + 0.05, 500, 0.002)
        c.close(last + 0.2)
    return tl


def _quiet_network() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=10)
    # Night time: an idle SSH session and a sensor sending one UDP reading every 15 s.
    ssh = Conn(tl, CLIENT, SERVER, 50500, 22, isn_c=90_000, isn_s=9_000_000)
    now = ssh.handshake(2.0, 0.002, 0.002)
    last = ssh.request(now + 0.1, 64)
    ssh.respond(last + 0.01, 128, 0.002)
    for k in range(6):
        udp_packet(tl, 20 + k * 15, CLIENT2, SERVER, 40123, 9999)
    last = ssh.request(100.0, 64)
    ssh.respond(last + 0.01, 128, 0.002)
    return tl


LATENCY_KINDS = {"SLOW_TCP_HANDSHAKE", "SLOW_SERVER_RESPONSE", "CAPTURE_GAP"}

SCENARIOS = [
    Scenario("delay_slow_handshake_server", "One intranet server answers SYNs after 3 s; others are fast",
             _slow_handshake_server, expect={"SLOW_TCP_HANDSHAKE"}, forbid={"SLOW_SERVER_RESPONSE", "CAPTURE_GAP"},
             expect_assessment={"SLOW_TCP_HANDSHAKE": "fault"}, forbid_attacks=True),
    Scenario("delay_slow_application", "20 ms handshake but the application needs 4 s to answer",
             _slow_application, expect={"SLOW_SERVER_RESPONSE"}, forbid={"SLOW_TCP_HANDSHAKE", "CAPTURE_GAP"},
             expect_assessment={"SLOW_SERVER_RESPONSE": "fault"}, forbid_attacks=True,
             sample="fault_slow_server.pcap"),
    Scenario("delay_whole_path_slow", "Satellite-like link: every server has ~800 ms latency",
             _whole_path_slow, expect={"SLOW_TCP_HANDSHAKE"}, forbid={"SLOW_SERVER_RESPONSE"},
             expect_assessment={"SLOW_TCP_HANDSHAKE": "fault"}, forbid_attacks=True),
    Scenario("delay_internet_slow_lan_fast", "Internet servers slow (600 ms), LAN file server fast",
             _internet_slow_lan_fast, expect={"SLOW_TCP_HANDSHAKE"}, forbid={"SLOW_SERVER_RESPONSE"},
             forbid_attacks=True),
    Scenario("delay_slow_client_link", "One client on bad Wi-Fi is slow to every server", _slow_client_link,
             expect={"SLOW_TCP_HANDSHAKE"}, forbid={"SLOW_SERVER_RESPONSE"}, forbid_attacks=True),
    Scenario("delay_ipv6_slow_handshake", "IPv6 server with 1.5 s SYN/ACK delay", _ipv6_slow_handshake,
             expect={"SLOW_TCP_HANDSHAKE"}, forbid_attacks=True),
    Scenario("delay_capture_gap_outage", "16 s total outage; the SSH client re-sends unacknowledged data",
             lambda: _gap(False), expect={"CAPTURE_GAP"}, expect_assessment={"CAPTURE_GAP": "fault"},
             forbid_attacks=True),
    Scenario("delay_capture_gap_dropped", "16 s missing from the capture; sequence numbers jump",
             lambda: _gap(True), expect={"CAPTURE_GAP"}, expect_assessment={"CAPTURE_GAP": "inconclusive"},
             forbid_attacks=True),
    Scenario("delay_normal_office", "Normal office traffic (benign)", _normal, forbid=LATENCY_KINDS,
             forbid_attacks=True),
    Scenario("delay_single_slow_handshake", "A single slow handshake among fast ones (below min count)",
             _single_slow, forbid=LATENCY_KINDS, forbid_attacks=True),
    Scenario("delay_threshold_boundary", "Handshakes of 0.49 s and responses of 1.9 s (just below thresholds)",
             _boundary, forbid=LATENCY_KINDS, forbid_attacks=True),
    Scenario("delay_retried_syn", "SYN retried after 1 s: loss, not delay", _retried_syn,
             forbid=LATENCY_KINDS, forbid_attacks=True),
    Scenario("delay_idle_keepalive", "Idle DB connections with keepalives and an unsolicited notification",
             _idle_keepalive, forbid=LATENCY_KINDS, forbid_attacks=True),
    Scenario("delay_server_push", "Server pushes events; client heartbeats are not requests", _server_push,
             forbid=LATENCY_KINDS, forbid_attacks=True),
    Scenario("delay_long_poll", "HTTP long-poll held 30 s by the server", _long_poll,
             forbid=LATENCY_KINDS, forbid_attacks=True),
    Scenario("delay_slow_upload", "3 MB uploads take 3 s; server answers 50 ms after the last byte",
             _slow_upload, forbid=LATENCY_KINDS, forbid_attacks=True),
    Scenario("delay_quiet_network", "Quiet night-time network with long idle periods", _quiet_network,
             forbid=LATENCY_KINDS, forbid_attacks=True),
]
