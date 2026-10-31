"""Unusual delays: slow handshakes, slow applications and capture gaps.

Objective
    Tell users *where* a delay comes from - the network path, one server's network, the
    client's own link, or the server application - instead of just saying "it is slow".

Algorithm
    Handshake RTT (per connection in ``ctx.connections`` with a visible handshake)
        total      = client ACK - SYN           (the full round trip, at ANY capture point)
        server leg = SYN/ACK - SYN              (capture point <-> server, plus accept time)
        client leg = client ACK - SYN/ACK       (capture point <-> client)
        Captured on the client, the server leg is the whole RTT; captured on the server, the
        client leg is. Splitting the two tells which side of the capture point is slow.
        Connections whose SYN or SYN/ACK was retransmitted are skipped: that is packet loss
        (reported by the retransmission detectors), not delay.

    SLOW_TCP_HANDSHAKE
        A server endpoint (IP, port) is slow when >= ``handshake_min_slow`` handshakes take
        >= ``handshake_slow_seconds`` and they are >= ``SLOW_SHARE_MIN`` of its handshakes.
        Before reporting per server the scope is decided from all handshakes:
          client   - one client is slow to >= 2 servers while other clients are fast
                     (its Wi-Fi / VPN / access link);
          path     - >= ``PATH_WIDE_SHARE`` of all handshakes are slow across >= 2 server IPs
                     (e.g. satellite or congested uplink: the whole path is slow);
          internet - Internet servers are slow while LAN servers are fast (the uplink);
          server   - otherwise, per server endpoint, compared with the median handshake of
                     all OTHER servers (a relative outlier: that server or its network).

    SLOW_SERVER_RESPONSE (network fine, application slow)
        Only connections whose handshake total is < ``NORMAL_HANDSHAKE_MAX`` are used, so the
        network is demonstrably fast. Each request/response turn is measured from the LAST
        client data segment of the request (not the first: an upload must not count as server
        time) to the first server data byte. TCP keepalive probes (<= 1 byte at snd.nxt-1) and
        retransmitted requests are ignored (a retransmitted request means loss). A connection
        on which the server sends data unprompted after >= ``PUSH_IDLE_SECONDS`` of silence is
        a push / streaming / long-poll protocol, so none of its turns are used. Waits
        >= ``LONG_POLL_SECONDS`` are treated as deliberate holds (long-poll) and not used.
        A server endpoint is reported with >= ``RESPONSE_MIN_SLOW`` slow turns (>=
        ``response_slow_seconds``) that are >= ``RESPONSE_SLOW_SHARE_MIN`` of its turns. A
        quick pure TCP ACK from the server for the request is shown as proof that the request
        arrived and only the application was late.

    CAPTURE_GAP
        Total silence >= ``capture_gap_seconds`` with >= ``GAP_MIN_PACKETS_AROUND`` packets in
        the ``GAP_CONTEXT_SECONDS`` before AND after, and at least one TCP connection active
        right before the gap and continuing after it. Sequence numbers across the gap tell the
        two explanations apart: data re-sent after the gap = a real outage (senders got no
        ACKs); a sequence jump = bytes were exchanged but not recorded (the capture dropped).

Indicators
    SLOW_TCP_HANDSHAKE   FAULT strong   - repeated slow handshakes to the endpoint / scope
                         FAULT moderate - relative outlier versus the other servers
    SLOW_SERVER_RESPONSE FAULT strong   - repeated slow responses with a normal handshake
                         FAULT moderate - server ACKed the request quickly, data came late
    CAPTURE_GAP          FAULT moderate - data retransmitted after the gap (outage)
                         BENIGN moderate- sequence jump across the gap (capture dropped)

Limitations
    * All times are measured at the capture point. Captured on the client, SYN -> SYN/ACK is
      the full network RTT plus the server's accept time; the two cannot be separated.
    * TLS hides application messages, so a "turn" is inferred from TCP payload direction.
    * A slow first response caused by a lost response segment that was retransmitted before
      the capture point looks like server delay when captured on the client side.
    * Jitter (RTT variance) is not analysed separately.
"""
from __future__ import annotations

import bisect
from collections import defaultdict
from dataclasses import dataclass
from statistics import median

from ..context import AnalysisContext, TcpConnection, is_private
from ..model import ACK, BENIGN, FAULT, FIN, RST, SYN, Evidence, Finding, Indicator, PacketRecord, assess

NAME = "latency"

# A handshake below this is "normal network" for the slow-application diagnosis.
NORMAL_HANDSHAKE_MAX = 0.2
# Share of an endpoint's handshakes that must be slow (one slow outlier among many is noise).
SLOW_SHARE_MIN = 0.3
# Share of ALL handshakes that must be slow to call the whole path slow.
PATH_WIDE_SHARE = 0.6
# For the "internet" / "client" scopes: the comparison group must be mostly fast.
FAST_GROUP_MAX_SLOW_SHARE = 0.2
# Slow server responses needed per server endpoint, and their minimum share of turns.
RESPONSE_MIN_SLOW = 2
RESPONSE_SLOW_SHARE_MIN = 0.2
# Waits this long are deliberate holds (long-poll / streaming), not slowness.
LONG_POLL_SECONDS = 25.0
# Unprompted server data after this much silence marks a push / streaming connection.
PUSH_IDLE_SECONDS = 1.0
# Capture-gap context: traffic needed on both sides of a gap for it to be meaningful.
GAP_CONTEXT_SECONDS = 10.0
GAP_MIN_PACKETS_AROUND = 20
MAX_GAPS = 10
MAX_EVIDENCE = 90

MASK = 0xFFFFFFFF


def _seq_after(a: int, b: int) -> bool:
    """True when sequence number a is strictly after b (RFC 1982 serial arithmetic)."""
    d = (a - b) & MASK
    return 0 < d < 0x80000000


def _ms(seconds: float) -> str:
    return f"{seconds * 1000:.0f} ms" if seconds < 1 else f"{seconds:.2f} s"


def _listed(items, limit: int = 8) -> str:
    items = list(items)
    if not items:
        return "none"
    return ", ".join(str(i) for i in items[:limit]) + (f" (+{len(items) - limit} more)" if len(items) > limit else "")


@dataclass
class _Handshake:
    conn: TcpConnection
    syn: PacketRecord
    synack: PacketRecord
    ack: PacketRecord | None
    server_leg: float
    client_leg: float | None

    @property
    def total(self) -> float:
        return self.server_leg + (self.client_leg or 0.0)

    @property
    def server(self) -> tuple[str, int]:
        return self.conn.server

    @property
    def client_ip(self) -> str:
        return self.conn.client[0]


def _handshake(conn: TcpConnection) -> _Handshake | None:
    if not conn.handshake_seen or len(conn.syns) != 1 or len(conn.synacks) != 1:
        return None                      # no handshake, or SYN / SYN-ACK retried (loss)
    syn, synack = conn.syns[0], conn.synacks[0]
    if not conn.from_client(syn) or synack.ts < syn.ts:
        return None
    ack = None
    for p in conn.packets:
        if p.n <= synack.n or not conn.from_client(p):
            continue
        flags = p.tcp_flags or 0
        if flags & ACK and not flags & (SYN | RST):
            ack = p
        break
    client_leg = ack.ts - synack.ts if ack is not None and ack.ts >= synack.ts else None
    return _Handshake(conn, syn, synack, ack, synack.ts - syn.ts, client_leg)


@dataclass
class _Turn:
    conn: TcpConnection
    first_req: PacketRecord
    last_req: PacketRecord
    server_ack: PacketRecord | None
    response: PacketRecord

    @property
    def wait(self) -> float:
        return self.response.ts - self.last_req.ts


def _turns(hs: _Handshake) -> tuple[list[_Turn], bool, int]:
    """Request/response turns of one connection -> (turns, is_push_connection, retransmitted)."""
    conn = hs.conn
    start = hs.ack or hs.synack
    c_next = (hs.syn.seq + 1) & MASK if hs.syn.seq is not None else None
    first = last = server_ack = None
    retrans = False
    retrans_turns = 0
    push = False
    last_ts = start.ts
    turns: list[_Turn] = []
    for p in conn.packets:
        if p.n <= start.n:
            continue
        flags = p.tcp_flags or 0
        if conn.from_client(p):
            if p.payload_len > 0 and p.seq is not None and c_next is not None:
                end = (p.seq + p.payload_len) & MASK
                if p.payload_len <= 1 and p.seq == (c_next - 1) & MASK:
                    pass                                    # TCP keepalive probe
                elif not _seq_after(end, c_next):
                    if first is not None:
                        retrans = True                      # request re-sent: loss, not server time
                else:
                    if first is None:
                        first, server_ack, retrans = p, None, False
                    last = p
                    c_next = end
        else:
            if p.payload_len > 0:
                if first is not None:
                    if retrans:
                        retrans_turns += 1
                    else:
                        turns.append(_Turn(conn, first, last, server_ack, p))
                    first = last = None
                elif p.ts - last_ts >= PUSH_IDLE_SECONDS:
                    push = True                             # unprompted server data
            elif first is not None and server_ack is None and p.ack is not None and c_next is not None \
                    and not _seq_after(c_next, p.ack) and flags & ACK:
                server_ack = p
            if flags & (FIN | RST) and first is not None:
                first = last = None                         # closed without answering
        last_ts = p.ts
    return turns, push, retrans_turns


# --- SLOW_TCP_HANDSHAKE --------------------------------------------------------------------

def _leg_text(slow: list[_Handshake]) -> tuple[str, str]:
    """Which side of the capture point holds the delay -> (short tag, explanation)."""
    with_client = [h for h in slow if h.client_leg is not None]
    if not with_client:
        return "unknown", "The client's final ACK was not captured, so the delay cannot be split by side."
    s = median(h.server_leg for h in with_client)
    c = median(h.client_leg for h in with_client)
    total = s + c
    if total <= 0:
        return "unknown", ""
    if s >= 0.75 * total:
        return "server_side", (f"Almost all of the delay ({_ms(s)} of {_ms(total)}) is between the capture point "
                               "and the server (SYN -> SYN/ACK). If this capture was taken on the client, that is "
                               "the full network round trip plus the time the server takes to accept the "
                               "connection.")
    if c >= 0.75 * total:
        return "client_side", (f"Almost all of the delay ({_ms(c)} of {_ms(total)}) is between the capture point "
                               "and the client (SYN/ACK -> ACK): the client's own link (Wi-Fi, VPN, access line) "
                               "is slow, not the server.")
    return "both", (f"The delay is split between both sides of the capture point (server side {_ms(s)}, "
                    f"client side {_ms(c)}).")


def _handshake_evidence(items: list[_Handshake], limit: int = MAX_EVIDENCE) -> list[Evidence]:
    ev: list[Evidence] = []
    for h in items:
        if len(ev) >= limit:
            break
        ev.append(Evidence(h.syn.n, f"SYN to {h.server[0]}:{h.server[1]} (handshake start)"))
        ev.append(Evidence(h.synack.n, f"SYN/ACK after {_ms(h.server_leg)}"))
        if h.ack is not None:
            ev.append(Evidence(h.ack.n, f"client ACK completing the handshake ({_ms(h.total)} in total)"))
    return ev[:limit]


def _scope_finding(ctx: AnalysisContext, scope: str, slow: list[_Handshake], all_hs: list[_Handshake],
                   fast_ref: list[_Handshake], subject: str) -> Finding:
    th = ctx.thresholds
    leg, leg_text = _leg_text(slow)
    med = median(h.total for h in slow)
    servers = sorted({h.server[0] for h in slow})
    clients = sorted({h.client_ip for h in slow})
    ref_med = median(h.total for h in fast_ref) if fast_ref else None
    indicators = [Indicator(f"{len(slow)} of {len(all_hs)} handshakes took >= {_ms(th.handshake_slow_seconds)} "
                            f"(median {_ms(med)})", FAULT, "strong")]
    if ref_med is not None:
        indicators.append(Indicator(f"The comparison group is fast (median {_ms(ref_med)}), which localises "
                                    "the delay", FAULT, "moderate"))
    if scope == "path":
        title = f"Whole network path is slow (median handshake {_ms(med)})"
        summary = (f"Connections to every server are slow: {len(slow)} of {len(all_hs)} TCP handshakes, to "
                   f"{len(servers)} different servers, took a median of {_ms(med)}. Because all destinations are "
                   "equally slow, the problem is the shared path (the uplink or the local network), not any "
                   "single server.")
        cause = ("A high-latency or congested shared link: satellite / mobile uplink, a saturated Internet line "
                 "(bufferbloat), an overloaded router or firewall, or all traffic being sent through a distant "
                 "VPN / proxy.")
        recs = ["Run a ping / traceroute to the default gateway and to an Internet host to see at which hop the "
                "delay starts.",
                "Check the uplink utilisation; enable QoS / smart queue management if it is saturated.",
                "If the link is satellite or a remote VPN, this latency may be inherent - consider local caching."]
        hosts = {"server": servers, "client": clients}
    elif scope == "internet":
        title = f"Internet path is slow, local network is fast (median {_ms(med)})"
        summary = (f"Handshakes to Internet servers took a median of {_ms(med)} ({len(slow)} slow), while servers "
                   f"on the local network answered in a median of {_ms(ref_med or 0)}. The LAN is healthy; the delay "
                   "is on the Internet uplink or beyond.")
        cause = ("A congested or high-latency Internet connection (ISP problem, saturated uplink, satellite link) "
                 "or an overloaded edge router / firewall doing inspection.")
        recs = ["Test the Internet line speed and latency directly at the router.",
                "Check the edge router / firewall CPU and the uplink utilisation.",
                "Contact the ISP if latency to the first ISP hop is already high."]
        hosts = {"server": servers, "client": clients}
    elif scope == "client":
        title = f"Client {subject} has a slow connection to every server"
        summary = (f"Every connection made by {subject} is slow ({len(slow)} handshakes, median {_ms(med)}, to "
                   f"{len(servers)} servers), while other clients reach the same network quickly "
                   f"(median {_ms(ref_med or 0)}). The problem is this client's own link.")
        cause = ("Poor Wi-Fi signal or interference, a congested access port, a VPN client on that machine, or "
                 "local software (security suite, proxy) delaying connections.")
        recs = [f"Check the Wi-Fi signal / cable and switch port of {subject}.",
                "Disable VPN / proxy / security software temporarily to see whether the delay disappears.",
                "Compare with a wired connection from the same location."]
        hosts = {"client": [subject], "server": servers}
    else:
        title = f"Slow TCP handshakes to {subject}"
        summary = (f"{len(slow)} of {len(all_hs)} connections to {subject} took a median of {_ms(med)} just to "
                   "establish the TCP connection"
                   + (f", while other servers in this capture answer in a median of {_ms(ref_med)}. Only this "
                      "server (or its part of the network) is slow." if ref_med is not None else "."))
        cause = ("The server is overloaded (full accept / SYN queue, CPU), or the path to it is congested or "
                 "long (remote site, overloaded firewall in front of it).")
        recs = [f"Check CPU, memory and connection counts on {subject.split(':')[0]} at the times shown.",
                "Check the listen backlog / SYN queue (e.g. 'netstat -s' for listen overflows).",
                "Run a traceroute to the server to see whether a specific hop adds the delay."]
        hosts = {"server": [subject.split(":")[0]], "client": clients}
    if leg == "client_side" and scope != "client":
        cause += " The split by capture point suggests the client side of the path holds the delay."
    times = [h.syn.ts for h in slow]
    facts = [f"Slow handshakes: {len(slow)} of {len(all_hs)}; median {_ms(med)}, worst {_ms(max(h.total for h in slow))}.",
             f"Servers affected: {_listed(sorted({f'{h.server[0]}:{h.server[1]}' for h in slow}))}.",
             f"Clients affected: {_listed(clients)}."]
    if ref_med is not None:
        facts.append(f"Comparison group median handshake: {_ms(ref_med)} over {len(fast_ref)} connections.")
    if leg_text:
        facts.append(leg_text)
    return Finding(
        detector=NAME, kind="SLOW_TCP_HANDSHAKE", title=title, category="fault",
        assessment=assess(indicators), severity="medium" if med >= 2 * th.handshake_slow_seconds else "low",
        evidence_strength="strong" if len(slow) >= 2 * th.handshake_min_slow else "moderate",
        summary=summary,
        impact="Every new connection (web page, API call, login) waits this long before any data can flow, so "
               "applications feel sluggish and may time out.",
        likely_cause=cause, recommendations=recs, facts=facts,
        alternatives=["Retransmitted SYNs are excluded here; if the retransmission detector also reports this "
                      "server, packet loss adds to the delay."],
        limitations=["Delays are measured at the capture point. Captured on the client, SYN -> SYN/ACK is the full "
                     "network round trip plus the server's accept time and the two cannot be separated.",
                     "Connections whose handshake was not captured or was retried are not measured."],
        indicators=indicators, hosts=hosts, time_start=min(times), time_end=max(h.synack.ts for h in slow),
        evidence=_handshake_evidence(sorted(slow, key=lambda h: -h.total)),
        metrics={"scope": scope, "slow_handshakes": len(slow), "handshakes": len(all_hs),
                 "median_handshake_ms": round(med * 1000, 1),
                 "max_handshake_ms": round(max(h.total for h in slow) * 1000, 1),
                 "reference_median_ms": round(ref_med * 1000, 1) if ref_med is not None else None,
                 "delay_side": leg, "servers": len(servers), "clients": len(clients)},
        rule=(f"handshake (SYN -> client ACK) >= {th.handshake_slow_seconds} s on >= {th.handshake_min_slow} "
              f"connections and >= {int(SLOW_SHARE_MIN * 100)}% of them; scope chosen by comparing with other "
              "servers / clients"))


def _handshake_findings(ctx: AnalysisContext, handshakes: list[_Handshake]) -> list[Finding]:
    th = ctx.thresholds
    if not handshakes:
        return []
    limit = th.handshake_slow_seconds

    def is_slow(h: _Handshake) -> bool:
        return h.total >= limit

    slow_all = [h for h in handshakes if is_slow(h)]
    if len(slow_all) < th.handshake_min_slow:
        return []

    # Scope 1: one client slow to several servers while other clients are fast.
    by_client: dict[str, list[_Handshake]] = defaultdict(list)
    for h in handshakes:
        by_client[h.client_ip].append(h)
    if len(by_client) >= 2:
        for client, hs in by_client.items():
            slow = [h for h in hs if is_slow(h)]
            others = [h for h in handshakes if h.client_ip != client]
            other_slow = sum(is_slow(h) for h in others)
            if (len(slow) >= th.handshake_min_slow and len({h.server[0] for h in slow}) >= 2
                    and len(slow) / len(hs) >= PATH_WIDE_SHARE and others
                    and other_slow / len(others) <= FAST_GROUP_MAX_SLOW_SHARE
                    and len(slow) >= 0.8 * len(slow_all)):
                return [_scope_finding(ctx, "client", slow, hs, others, client)]

    # Scope 2: the whole path is slow.
    slow_ips = {h.server[0] for h in slow_all}
    if len(slow_all) / len(handshakes) >= PATH_WIDE_SHARE and len(slow_ips) >= 2:
        return [_scope_finding(ctx, "path", slow_all, handshakes, [], "")]

    # Scope 3: Internet servers slow, LAN servers fast.
    public = [h for h in handshakes if not is_private(h.server[0])]
    local = [h for h in handshakes if is_private(h.server[0])]
    pub_slow = [h for h in public if is_slow(h)]
    if (public and local and len(pub_slow) >= th.handshake_min_slow and len({h.server[0] for h in pub_slow}) >= 2
            and len(pub_slow) / len(public) >= PATH_WIDE_SHARE
            and sum(is_slow(h) for h in local) / len(local) <= FAST_GROUP_MAX_SLOW_SHARE):
        return [_scope_finding(ctx, "internet", pub_slow, public, local, "")]

    # Scope 4: individual server endpoints, compared with everybody else.
    by_server: dict[tuple[str, int], list[_Handshake]] = defaultdict(list)
    for h in handshakes:
        by_server[h.server].append(h)
    findings = []
    for (ip, port), hs in sorted(by_server.items()):
        slow = [h for h in hs if is_slow(h)]
        if len(slow) < th.handshake_min_slow or len(slow) / len(hs) < SLOW_SHARE_MIN:
            continue
        others = [h for h in handshakes if h.server[0] != ip]
        findings.append(_scope_finding(ctx, "server", slow, hs, others, f"{ip}:{port}"))
    return findings


# --- SLOW_SERVER_RESPONSE ------------------------------------------------------------------

def _response_findings(ctx: AnalysisContext, handshakes: list[_Handshake]) -> list[Finding]:
    th = ctx.thresholds
    by_server: dict[tuple[str, int], dict] = defaultdict(lambda: {"turns": [], "push": 0, "long": 0,
                                                                  "retrans": 0, "hs": {}})
    for i, h in enumerate(handshakes):
        if i % 2000 == 0:
            ctx.check_deadline()
        if h.total >= NORMAL_HANDSHAKE_MAX:
            continue                     # the network itself is slow here: not an application diagnosis
        turns, push, retrans = _turns(h)
        entry = by_server[h.server]
        entry["retrans"] += retrans
        if push:
            entry["push"] += 1
            continue
        for t in turns:
            if t.wait >= LONG_POLL_SECONDS:
                entry["long"] += 1
            else:
                entry["turns"].append(t)
                entry["hs"][id(t.conn)] = h
    findings = []
    for (ip, port), entry in sorted(by_server.items()):
        turns: list[_Turn] = entry["turns"]
        slow = [t for t in turns if t.wait >= th.response_slow_seconds]
        if len(slow) < RESPONSE_MIN_SLOW or len(slow) / len(turns) < RESPONSE_SLOW_SHARE_MIN:
            continue
        hs_of = entry["hs"]
        rtt = median(hs_of[id(t.conn)].total for t in slow)
        wait = median(t.wait for t in slow)
        fast = [t for t in turns if t.wait < th.response_slow_seconds]
        acked = [t for t in slow if t.server_ack is not None]
        ack_delay = median(t.server_ack.ts - t.last_req.ts for t in acked) if acked else None
        clients = sorted({t.conn.client[0] for t in slow})
        indicators = [Indicator(f"{len(slow)} request(s) waited >= {_ms(th.response_slow_seconds)} for the first "
                                f"response byte (median {_ms(wait)}) although the TCP handshake took only "
                                f"{_ms(rtt)}", FAULT, "strong")]
        if acked:
            indicators.append(Indicator(f"The server's TCP stack acknowledged {len(acked)} of these requests within "
                                        f"{_ms(ack_delay)}: the request arrived, the application was late",
                                        FAULT, "moderate"))
        evidence: list[Evidence] = []
        for t in sorted(slow, key=lambda t: -t.wait):
            if len(evidence) >= MAX_EVIDENCE:
                break
            h = hs_of[id(t.conn)]
            evidence.append(Evidence(h.syn.n, f"SYN (handshake completed in {_ms(h.total)}: network is fast)"))
            evidence.append(Evidence(t.last_req.n, "client request (last request segment)"))
            if t.server_ack is not None:
                evidence.append(Evidence(t.server_ack.n, f"server TCP ACK of the request after "
                                                         f"{_ms(t.server_ack.ts - t.last_req.ts)}"))
            evidence.append(Evidence(t.response.n, f"first response byte after {_ms(t.wait)}"))
        think = max(wait - rtt, 0.0)
        facts = [f"Slow responses: {len(slow)} of {len(turns)} measured request/response turns; median wait "
                 f"{_ms(wait)}, worst {_ms(max(t.wait for t in slow))}.",
                 f"Median TCP handshake of those connections: {_ms(rtt)} (network round trip).",
                 f"Estimated server processing time: about {_ms(think)} per slow request.",
                 f"Fast turns on the same service: {len(fast)}"
                 + (f" (median {_ms(median(t.wait for t in fast))})." if fast else ".")]
        if acked:
            facts.append(f"Server TCP acknowledged the request in a median of {_ms(ack_delay)} before answering.")
        if entry["push"] or entry["long"]:
            facts.append(f"Not counted: {entry['push']} push/streaming connection(s) and {entry['long']} wait(s) "
                         f">= {LONG_POLL_SECONDS:.0f} s treated as long-poll.")
        findings.append(Finding(
            detector=NAME, kind="SLOW_SERVER_RESPONSE",
            title=f"Application on {ip}:{port} is slow to respond (network is fine)",
            category="fault", assessment=assess(indicators),
            severity="medium" if wait >= 2 * th.response_slow_seconds or len(slow) >= 5 else "low",
            evidence_strength="strong" if acked or len(slow) >= 2 * RESPONSE_MIN_SLOW else "moderate",
            summary=(f"The network is fine, the server is slow. Connections to {ip}:{port} are set up in {_ms(rtt)}, "
                     f"but after receiving a request the server takes a median of {_ms(wait)} to start answering "
                     f"({len(slow)} slow requests from {len(clients)} client(s))."),
            impact="Users wait several seconds for pages, API calls or queries on this service; the delay is "
                   "inside the server, so faster network links will not help.",
            likely_cause=("The application or something it depends on is slow: an overloaded server (CPU, memory, "
                          "thread pool), slow database queries or locks, a slow back-end API, or a timeout on a "
                          "dependency such as DNS or authentication on the server side."),
            recommendations=[f"Check the application and web-server logs on {ip} for slow requests at the times shown.",
                             "Check server CPU, memory, disk I/O and worker/thread-pool saturation.",
                             "Check database query times and any back-end services the application calls.",
                             "Use application performance monitoring to find the slow function or query."],
            facts=facts,
            alternatives=["A deliberately slow operation (large report, search) can legitimately take this long.",
                          "If captured on the client, a response packet lost and retransmitted before the capture "
                          "point would also look like server delay."],
            limitations=["The capture shows when the first response byte arrived, not what the server was doing.",
                         "With TLS the request boundaries are inferred from TCP payload direction.",
                         f"Push / streaming connections and waits >= {LONG_POLL_SECONDS:.0f} s are excluded to "
                         "avoid misreading long-polls."],
            indicators=indicators, hosts={"server": [ip], "client": clients},
            time_start=min(t.last_req.ts for t in slow), time_end=max(t.response.ts for t in slow),
            evidence=evidence,
            metrics={"slow_responses": len(slow), "measured_turns": len(turns), "port": port,
                     "median_wait_ms": round(wait * 1000, 1),
                     "max_wait_ms": round(max(t.wait for t in slow) * 1000, 1),
                     "median_handshake_ms": round(rtt * 1000, 1),
                     "server_ack_ms": round(ack_delay * 1000, 1) if ack_delay is not None else None,
                     "push_connections_excluded": entry["push"], "long_poll_waits_excluded": entry["long"],
                     "retransmitted_requests_excluded": entry["retrans"]},
            rule=(f"first server data >= {th.response_slow_seconds} s after the last request segment, on >= "
                  f"{RESPONSE_MIN_SLOW} turns of one service, with handshake < {NORMAL_HANDSHAKE_MAX} s")))
    return findings


# --- CAPTURE_GAP ---------------------------------------------------------------------------

def _gap_findings(ctx: AnalysisContext) -> list[Finding]:
    th = ctx.thresholds
    gaps: list[tuple[PacketRecord, PacketRecord]] = []
    prev: PacketRecord | None = None
    for i, r in enumerate(ctx.records):
        if i % 5000 == 0:
            ctx.check_deadline()
        if prev is not None and r.ts - prev.ts >= th.capture_gap_seconds:
            gaps.append((prev, r))
        if prev is None or r.ts > prev.ts:
            prev = r
    if not gaps:
        return []
    times = sorted(r.ts for r in ctx.records)
    findings = []
    for before, after in gaps[:MAX_GAPS]:
        g0, g1 = before.ts, after.ts
        n_before = bisect.bisect_right(times, g0) - bisect.bisect_left(times, g0 - GAP_CONTEXT_SECONDS)
        n_after = bisect.bisect_right(times, g1 + GAP_CONTEXT_SECONDS) - bisect.bisect_left(times, g1)
        if n_before < GAP_MIN_PACKETS_AROUND or n_after < GAP_MIN_PACKETS_AROUND:
            continue
        spanning, resent, jumped = [], [], []
        evidence = [Evidence(before.n, "last packet before the silence"),
                    Evidence(after.n, f"first packet after {g1 - g0:.1f} s of silence")]
        for conn in ctx.connections:
            if conn.first_ts > g0 or conn.last_ts < g1:
                continue
            pre = [p for p in conn.packets if p.ts <= g0]
            post = [p for p in conn.packets if p.ts >= g1]
            if not pre or not post or pre[-1].ts < g0 - GAP_CONTEXT_SECONDS:
                continue                 # idle before the gap: proves nothing
            if any((p.tcp_flags or 0) & (FIN | RST) for p in pre):
                continue
            spanning.append(conn)
            for side_is_client in (True, False):
                sent = [p for p in pre if conn.from_client(p) == side_is_client and p.payload_len and p.seq is not None]
                nxt = next((p for p in post if conn.from_client(p) == side_is_client and p.payload_len
                            and p.seq is not None), None)
                if not sent or nxt is None:
                    continue
                high = sent[0]
                high_end = (high.seq + high.payload_len) & MASK
                for p in sent[1:]:
                    end = (p.seq + p.payload_len) & MASK
                    if _seq_after(end, high_end):
                        high, high_end = p, end
                if not _seq_after((nxt.seq + nxt.payload_len) & MASK, high_end):
                    resent.append((conn, nxt))
                    evidence.append(Evidence(nxt.n, "data re-sent after the gap (it was never acknowledged)"))
                elif _seq_after(nxt.seq, high_end):
                    jumped.append((conn, nxt, (nxt.seq - high_end) & MASK))
                    evidence.append(Evidence(nxt.n, f"sequence jump: {(nxt.seq - high_end) & MASK} bytes missing "
                                                    "from the capture"))
        if not spanning:
            continue
        indicators: list[Indicator] = []
        if resent:
            indicators.append(Indicator(f"{len(resent)} sender(s) re-sent unacknowledged data after the silence: "
                                        "nothing got through during the gap (real outage)", FAULT, "moderate"))
        if jumped:
            missing = sum(j[2] for j in jumped)
            indicators.append(Indicator(f"{len(jumped)} flow(s) continue with a sequence jump ({missing} bytes never "
                                        "captured): traffic flowed but was not recorded", BENIGN, "moderate"))
        assessment = assess(indicators)
        if resent and not jumped:
            summary = (f"All traffic stopped for {g1 - g0:.1f} s while {len(spanning)} connection(s) were active, and "
                       "afterwards senders had to re-send data that was never acknowledged. The network was "
                       "really down for that period.")
            cause = ("A short outage: link flap, switch/router reboot or spanning-tree reconvergence, Wi-Fi "
                     "disconnection, or an upstream failure.")
        elif jumped and not resent:
            summary = (f"The capture contains no packets for {g1 - g0:.1f} s, but the connections continue afterwards "
                       "as if data had been exchanged in between. The network was probably fine and the capture "
                       "tool missed packets.")
            cause = "The capture was interrupted or dropped packets (overloaded capture host, SPAN port oversubscription)."
        else:
            summary = (f"No packets at all were captured for {g1 - g0:.1f} s although {len(spanning)} connection(s) "
                       "were active before and after. This is either a network outage or an interruption of the "
                       "capture; the capture does not show which.")
            cause = "A brief network outage, or the capture was paused / dropped packets."
        findings.append(Finding(
            detector=NAME, kind="CAPTURE_GAP", title=f"{g1 - g0:.1f} s of complete silence in the capture",
            category="fault", assessment=assessment, severity="low" if assessment == FAULT else "info",
            evidence_strength="moderate" if indicators else "weak",
            summary=summary,
            impact=("Users would have seen everything freeze for this period." if resent else
                    "Analysis results for this period are incomplete."),
            likely_cause=cause,
            recommendations=["Check switch / router / Wi-Fi controller logs for link or reboot events at this time.",
                             "Check the capture host for dropped-packet counters (e.g. 'dropped by kernel').",
                             "If it repeats, run a continuous ping to the gateway to confirm outages."],
            facts=[f"Silence from {g0 - ctx.start_ts:.3f} s to {g1 - ctx.start_ts:.3f} s into the capture "
                   f"({g1 - g0:.1f} s).",
                   f"Packets in the {GAP_CONTEXT_SECONDS:.0f} s before: {n_before}; after: {n_after}.",
                   f"Connections active across the gap: {len(spanning)} "
                   f"({_listed([c.label for c in spanning], 4)}).",
                   f"Senders that re-sent data afterwards: {len(resent)}; flows with a sequence jump: {len(jumped)}."],
            alternatives=["The capture filter or a capture-ring rollover can also create gaps."],
            limitations=["A capture cannot record what it did not see; outage versus capture loss is inferred from "
                         "TCP sequence numbers only."],
            indicators=indicators,
            hosts={"client": sorted({c.client[0] for c in spanning}), "server": sorted({c.server[0] for c in spanning})},
            time_start=g0, time_end=g1, evidence=evidence[:MAX_EVIDENCE],
            metrics={"gap_seconds": round(g1 - g0, 3), "packets_before": n_before, "packets_after": n_after,
                     "spanning_connections": len(spanning), "resent_after_gap": len(resent),
                     "sequence_jumps": len(jumped)},
            rule=(f"no packets for >= {th.capture_gap_seconds} s, >= {GAP_MIN_PACKETS_AROUND} packets within "
                  f"{GAP_CONTEXT_SECONDS:.0f} s on both sides, and an active TCP connection spanning it")))
    return findings


def detect(ctx: AnalysisContext) -> list[Finding]:
    handshakes = []
    for i, conn in enumerate(ctx.connections):
        if i % 2000 == 0:
            ctx.check_deadline()
        h = _handshake(conn)
        if h is not None:
            handshakes.append(h)
    return _handshake_findings(ctx, handshakes) + _response_findings(ctx, handshakes) + _gap_findings(ctx)
