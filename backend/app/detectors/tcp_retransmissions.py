"""TCP retransmission and SYN-retry analysis.

Objective
    Measure how much TCP data had to be sent twice, explain *why* (loss detected by duplicate
    ACKs, loss detected by a timeout, or a spurious resend caused by delay) and *where* the loss
    most likely happened relative to the capture point. Separately, report services whose
    connection attempts need SYN retransmissions or are never answered.

Why the old approach was wrong
    Counting repeated (flow, seq) pairs flags every healthy capture: pure ACKs, the handshake
    ACK and delayed ACKs all carry the same sequence number as the data that follows them.
    Only segments that *occupy sequence space* (payload, SYN or FIN) can be retransmitted.

Algorithm (per reconstructed connection, per direction; one linear pass, O(n log n))
    1. Sequence numbers are unwrapped with 32-bit serial arithmetic (RFC 1982):
       diff = (a - b) & 0xFFFFFFFF, negative when diff >= 2**31. Every sequence number becomes
       a signed offset from the first one seen, so wrap-around in long flows is handled.
    2. ``hi`` = highest sequence end already sent. A segment starting at or above ``hi`` is new
       data. A segment starting below ``hi`` overlaps data already sent (fully or partially)
       and is a retransmission candidate. Sent ranges are kept in a sorted interval list so the
       original transmission is found with a binary search.
    3. Exclusions (never counted as loss):
       * capture duplicates - same direction, same seq / ack / flags / length and the same IP ID
         within ``Thresholds.duplicate_capture_window`` (a SPAN port or capture on two
         interfaces seeing the frame twice). Counted separately.
       * keep-alives - 0 or 1 byte at ``hi - 1`` (RFC 1122 4.2.3.6).
       * zero-window probes - at most 1 byte while the receiver advertises window 0.
       * out-of-order - a segment filling a hole whose original was never captured, arriving
         within ``REORDER_WINDOW_SECONDS`` of the segment that jumped ahead (reordering, not
         loss), unless the receiver already sent 3 duplicate ACKs for it.
       * PMTUD resends - the original was larger than an ICMP "fragmentation needed" /
         ICMPv6 "packet too big" received for that flow before the resend. The MTU detector
         reports those.
       * MTU black-hole resends - large segments the MTU detector attributes to a black hole.
    4. Classification of each retransmission:
       * fast retransmit - the receiver sent >= 3 duplicate ACKs (pure ACK, same ack number,
         same window, data outstanding) asking for this data before it was resent;
       * timeout (RTO) - no duplicate ACKs and >= ``RTO_MIN_SECONDS`` since the previous
         transmission of the same data;
       * other - early retransmit / tail-loss probe (resent sooner, without 3 dup ACKs);
       * spurious - the receiver had already acknowledged the whole segment before it was
         resent: the network delivered the data, the sender's timer fired too early.
       * original not captured - the retransmission filled a gap; the original was lost
         *before* reaching the capture point. When the original was captured but never
         acknowledged, the loss happened *after* the capture point (or the ACK was lost).
    5. A direction (flow) is reported when it has >= ``retrans_min_per_flow`` counted
       retransmissions AND they are >= ``retrans_min_ratio`` of its data segments. Flows are
       aggregated into one finding per server IP, or per client when one client has bad flows
       to >= ``PER_CLIENT_MIN_SERVERS`` different servers (the problem follows the client).

SYN retries (TCP_SYN_RETRIES)
    Each connection attempt (one ISN) whose SYN had to be retransmitted, or that was never
    answered at all (no SYN/ACK, no RST, no ICMP unreachable), is "troubled". A service
    (server IP + port) is reported when >= ``SYN_RETRY_MIN_ATTEMPTS`` troubled attempts were made
    to it. Clients that sent SYNs to many ports or many hosts (port-scan thresholds) are
    excluded, so one probe per port from a scanner is never reported here.

Indicators (all documented in the finding)
    FAULT  strong/moderate - high retransmission ratio on one path (congestion / loss)
    FAULT  moderate        - duplicate ACKs prove the receiver saw a gap (real loss)
    FAULT  moderate        - several clients affected on the same server path
    BENIGN strong          - every retransmission was spurious (delay, not loss)
    BENIGN weak            - capture duplicates were present and were not counted as loss
    No attack indicator exists: retransmissions alone cannot show malicious intent.

Limitations
    * The capture point decides what is visible: a capture at the receiver never sees an
      original lost upstream; a capture at the sender cannot tell a lost segment from a lost ACK.
    * SACK blocks are not decoded, so selective-ACK-driven recovery is classified only from
      cumulative ACKs.
    * RTO_MIN is the common 200 ms floor; stacks with other timers may be classified "other".
"""
from __future__ import annotations

import weakref
from bisect import bisect_left, bisect_right
from collections import defaultdict
from dataclasses import dataclass, field
from statistics import median

from ..context import AnalysisContext, Endpoint, TcpConnection
from ..model import ACK, BENIGN, FAULT, FIN, RST, SYN, Evidence, Finding, Indicator, PacketRecord, assess

NAME = "tcp_retransmissions"

# --- documented constants (not in config.Thresholds) -----------------------------------------
# Minimum retransmission timeout used by Linux/Windows/macOS (RFC 6298 recommends 1 s, real
# stacks use 200-300 ms). A resend at least this long after the previous copy is a timeout.
RTO_MIN_SECONDS = 0.2
# RFC 5681: three duplicate ACKs trigger fast retransmit.
FAST_RETRANSMIT_DUPACKS = 3
# A hole filled this quickly after the segment that jumped ahead is reordering, not loss
# (same 3 ms heuristic Wireshark uses for "TCP Out-Of-Order").
REORDER_WINDOW_SECONDS = 0.003
# An unanswered SYN this close to the end of the capture may simply not have had its answer
# captured yet; it is not counted as "never answered".
SYN_ANSWER_GRACE_SECONDS = 1.0
# Troubled connection attempts to one service before TCP_SYN_RETRIES is reported.
SYN_RETRY_MIN_ATTEMPTS = 3
# A client with bad flows to this many different servers gets one per-client finding.
PER_CLIENT_MIN_SERVERS = 3
# Evidence caps (true totals always go to facts / metrics).
MAX_EVIDENCE_RETRANS = 25
MAX_EVIDENCE_ATTEMPTS = 30

MASK = 0xFFFFFFFF
HALF = 1 << 31


def sdiff(a: int, b: int) -> int:
    """Signed 32-bit serial difference a - b (RFC 1982)."""
    d = (a - b) & MASK
    return d - (1 << 32) if d >= HALF else d


def seq_lt(a: int, b: int) -> bool:
    return sdiff(a, b) < 0


def is_frag_needed(rec: PacketRecord) -> bool:
    """ICMP type 3 code 4 (IPv4) or ICMPv6 type 2 "Packet Too Big"."""
    if rec.l4 == "ICMP":
        return rec.icmp_type == 3 and rec.icmp_code == 4
    if rec.l4 == "ICMPv6":
        return rec.icmp_type == 2
    return False


FlowKey = tuple  # (src ip, src port, dst ip, dst port)


@dataclass(eq=False)
class Interval:
    """A range of sequence space [start, end) and every transmission that started inside it."""

    start: int
    end: int
    first: PacketRecord
    sends: list[PacketRecord]
    original_seen: bool = True


@dataclass(eq=False)
class Retransmission:
    rec: PacketRecord
    interval: Interval
    original: PacketRecord | None     # None when the original was never captured
    delay: float                      # seconds since the original (or since the gap opened)
    since_prev: float                 # seconds since the previous copy of the same data
    mode: str                         # "fast", "timeout" or "other"
    spurious: bool
    dup_acks: list[PacketRecord]
    pmtud: bool = False

    @property
    def upstream(self) -> bool:
        return self.original is None


@dataclass(eq=False)
class Direction:
    """Sequence-space state and results for the data one endpoint sends in one connection."""

    conn: TcpConnection
    from_client: bool
    sender: Endpoint
    receiver: Endpoint
    base: int | None = None
    hi: int = 0
    isn: int | None = None
    intervals: list[Interval] = field(default_factory=list)
    starts: list[int] = field(default_factory=list)
    data_segments: int = 0
    retrans: list[Retransmission] = field(default_factory=list)
    handshake_retries: list[PacketRecord] = field(default_factory=list)
    capture_duplicates: list[PacketRecord] = field(default_factory=list)
    keepalives: int = 0
    window_probes: int = 0
    out_of_order: int = 0
    gaps: int = 0
    acks: list[tuple[int, float]] = field(default_factory=list)   # cumulative ACK advances
    ack_values: list[int] = field(default_factory=list)
    max_ack: int | None = None
    last_ack: int | None = None
    last_win: int | None = None
    dup_count: int = 0
    dup_recs: list[PacketRecord] = field(default_factory=list)
    rcv_win: int | None = None
    mss: int | None = None

    @property
    def key(self) -> FlowKey:
        return (self.sender[0], self.sender[1], self.receiver[0], self.receiver[1])

    @property
    def label(self) -> str:
        return f"{self.sender[0]}:{self.sender[1]} -> {self.receiver[0]}:{self.receiver[1]}"

    def rel(self, seq: int) -> int:
        """Unwrapped offset of ``seq`` from the first sequence number, near ``hi``."""
        return self.hi + sdiff(seq, (self.base + self.hi) & MASK)

    def acked_at(self, end: int) -> float | None:
        """Capture time of the first cumulative ACK covering ``end``, or None."""
        i = bisect_left(self.ack_values, end)
        return self.acks[i][1] if i < len(self.acks) else None

    def restart(self, isn: int) -> None:
        """A SYN with a new ISN starts a new sequence space for this direction."""
        self.base, self.hi, self.isn = isn, 0, isn
        self.intervals, self.starts = [], []
        self.acks, self.ack_values = [], []
        self.max_ack = self.last_ack = self.last_win = None
        self.dup_count, self.dup_recs = 0, []

    def add_interval(self, iv: Interval) -> None:
        i = bisect_right(self.starts, iv.start)
        self.starts.insert(i, iv.start)
        self.intervals.insert(i, iv)


@dataclass
class TcpAnalysis:
    pairs: list[tuple[TcpConnection, Direction, Direction]]
    by_key: dict[FlowKey, list[Direction]]
    frag_index: dict[FlowKey, list[PacketRecord]]
    frag_messages: list[PacketRecord]


_CACHE: "weakref.WeakKeyDictionary[AnalysisContext, TcpAnalysis]" = weakref.WeakKeyDictionary()


def frag_needed_messages(ctx: AnalysisContext) -> list[PacketRecord]:
    return [r for r in ctx.icmp if is_frag_needed(r)]


def _flow_key_from_inner(inner: dict | None) -> FlowKey | None:
    if not isinstance(inner, dict):
        return None
    src, dst, sport, dport = inner.get("src"), inner.get("dst"), inner.get("sport"), inner.get("dport")
    if src is None or dst is None or sport is None or dport is None:
        return None
    return (src, sport, dst, dport)


def _is_capture_duplicate(prev: PacketRecord, rec: PacketRecord, window: float) -> bool:
    return (0 <= rec.ts - prev.ts <= window and prev.seq == rec.seq and prev.ack == rec.ack
            and prev.tcp_flags == rec.tcp_flags and prev.payload_len == rec.payload_len
            and prev.ip_id == rec.ip_id)


def _on_ack(d: Direction, rec: PacketRecord) -> None:
    """``rec`` was sent by d's receiver: update d's view of what has been acknowledged."""
    d.rcv_win = rec.win
    if d.base is None or rec.ack is None:
        return
    a = d.rel(rec.ack)
    if d.max_ack is None or a > d.max_ack:
        d.max_ack = a
        d.acks.append((a, rec.ts))
        d.ack_values.append(a)
    flags = rec.tcp_flags or 0
    pure = rec.payload_len == 0 and not flags & (SYN | FIN | RST)
    if pure and d.last_ack == a and rec.win == d.last_win and a < d.hi:
        d.dup_count += 1
        if len(d.dup_recs) < 8:
            d.dup_recs.append(rec)
    elif pure or a != d.last_ack:
        d.last_ack, d.last_win, d.dup_count, d.dup_recs = a, rec.win, 0, []


def _pmtud_related(rec: PacketRecord, original: PacketRecord | None,
                   frag_index: dict[FlowKey, list[PacketRecord]]) -> bool:
    icmps = frag_index.get((rec.ip_src, rec.sport, rec.ip_dst, rec.dport))
    if not icmps:
        return False
    earlier = [i for i in icmps if i.ts <= rec.ts and (original is None or i.ts >= original.ts - 0.001)]
    if not earlier:
        return False
    if original is None or original.ip_len is None:
        return True
    mtus = [i.icmp_mtu for i in earlier if i.icmp_mtu]
    return not mtus or original.ip_len > min(mtus)


def _on_segment(d: Direction, rec: PacketRecord, frag_index: dict) -> None:
    flags = rec.tcp_flags or 0
    syn, fin = bool(flags & SYN), bool(flags & FIN)
    length = rec.payload_len + (1 if syn else 0) + (1 if fin else 0)
    if length <= 0:
        return
    if syn and (d.isn is None or rec.seq != d.isn):
        d.restart(rec.seq)
    if d.base is None:
        d.base, d.hi = rec.seq, 0
    s = d.rel(rec.seq)
    e = s + length
    if s >= d.hi:
        if s > d.hi:
            d.gaps += 1
        d.add_interval(Interval(s, e, rec, [rec]))
        d.hi = e
        if not syn:
            d.data_segments += 1
        return
    if not syn and not fin and rec.payload_len <= 1:
        if s == d.hi - 1:
            d.keepalives += 1
            return
        if d.rcv_win == 0:
            d.window_probes += 1
            return
    idx = bisect_right(d.starts, s) - 1
    covered = idx >= 0 and d.intervals[idx].end > s
    dup_ok = (d.dup_count >= FAST_RETRANSMIT_DUPACKS and d.last_ack is not None and d.last_ack <= s)
    dups = list(d.dup_recs) if dup_ok else []
    if covered:
        iv = d.intervals[idx]
        original: PacketRecord | None = iv.first if iv.original_seen else None
        prev = iv.sends[-1]
        iv.sends.append(rec)
        delay = rec.ts - iv.first.ts
        since_prev = rec.ts - prev.ts
        if e > d.hi:  # partial overlap: the tail is new data
            d.add_interval(Interval(d.hi, e, rec, [rec]))
            d.hi = e
    else:
        if idx + 1 >= len(d.intervals):   # defensive: should not happen while s < hi
            d.add_interval(Interval(s, e, rec, [rec]))
            d.hi = max(d.hi, e)
            d.data_segments += 1
            return
        nxt = d.intervals[idx + 1]
        since_gap = rec.ts - nxt.first.ts
        iv = Interval(s, min(e, nxt.start), rec, [rec], original_seen=False)
        d.add_interval(iv)
        if not dup_ok and since_gap <= REORDER_WINDOW_SECONDS:
            d.out_of_order += 1
            d.data_segments += 1
            return
        original, delay, since_prev = None, since_gap, since_gap
    if syn:
        d.handshake_retries.append(rec)
        return
    d.data_segments += 1
    mode = "fast" if dup_ok else ("timeout" if since_prev >= RTO_MIN_SECONDS else "other")
    spurious = d.max_ack is not None and d.max_ack >= e
    d.retrans.append(Retransmission(rec, iv, original, max(delay, 0.0), max(since_prev, 0.0), mode,
                                    spurious, dups, _pmtud_related(rec, original, frag_index)))


def analyze_tcp(ctx: AnalysisContext) -> TcpAnalysis:
    """Run the per-direction sequence analysis once per capture (shared with the MTU detector)."""
    cached = _CACHE.get(ctx)
    if cached is not None:
        return cached
    window = ctx.thresholds.duplicate_capture_window
    messages = frag_needed_messages(ctx)
    frag_index: dict[FlowKey, list[PacketRecord]] = defaultdict(list)
    for m in messages:
        inner = m.icmp_inner or {}
        key = _flow_key_from_inner(inner)
        if key is not None and inner.get("proto") == 6:
            frag_index[key].append(m)
    pairs: list[tuple[TcpConnection, Direction, Direction]] = []
    by_key: dict[FlowKey, list[Direction]] = defaultdict(list)
    processed = 0
    for conn in ctx.connections:
        c2s = Direction(conn, True, conn.client, conn.server)
        s2c = Direction(conn, False, conn.server, conn.client)
        last: dict[bool, PacketRecord | None] = {True: None, False: None}
        for rec in conn.packets:
            processed += 1
            if processed % 5000 == 0:
                ctx.check_deadline()
            if rec.seq is None or rec.tcp_flags is None or rec.sport is None:
                continue
            fc = conn.from_client(rec)
            mine, peer = (c2s, s2c) if fc else (s2c, c2s)
            prev = last[fc]
            if prev is not None and _is_capture_duplicate(prev, rec, window):
                mine.capture_duplicates.append(rec)
                continue
            last[fc] = rec
            flags = rec.tcp_flags
            if flags & RST:
                continue
            if flags & SYN and rec.mss:
                mine.mss = rec.mss
            if flags & ACK:
                _on_ack(peer, rec)
            _on_segment(mine, rec, frag_index)
        pairs.append((conn, c2s, s2c))
        by_key[c2s.key].append(c2s)
        by_key[s2c.key].append(s2c)
    result = TcpAnalysis(pairs, dict(by_key), dict(frag_index), messages)
    _CACHE[ctx] = result
    return result


# --- SYN retry analysis ----------------------------------------------------------------------

@dataclass(eq=False)
class Attempt:
    conn: TcpConnection
    isn: int
    syns: list[PacketRecord]
    answer: PacketRecord | None
    answer_kind: str | None          # "synack", "rst", "icmp" or None

    @property
    def retried(self) -> bool:
        return len(self.syns) > 1


def _unreachable_index(ctx: AnalysisContext) -> dict[FlowKey, list[PacketRecord]]:
    out: dict[FlowKey, list[PacketRecord]] = defaultdict(list)
    for r in ctx.icmp:
        if (r.l4 == "ICMP" and r.icmp_type == 3) or (r.l4 == "ICMPv6" and r.icmp_type == 1):
            key = _flow_key_from_inner(r.icmp_inner)
            if key is not None:
                out[key].append(r)
    return out


def _attempts(ctx: AnalysisContext, conn: TcpConnection,
              unreachable: dict[FlowKey, list[PacketRecord]]) -> list[Attempt]:
    window = ctx.thresholds.duplicate_capture_window
    groups: dict[int, list[PacketRecord]] = {}
    for s in conn.syns:
        if s.seq is None:
            continue
        g = groups.setdefault(s.seq, [])
        if g and _is_capture_duplicate(g[-1], s, window):
            continue
        g.append(s)
    out = []
    key = (conn.client[0], conn.client[1], conn.server[0], conn.server[1])
    for isn, syns in groups.items():
        want = (isn + 1) & MASK
        answer, kind = None, None
        for p in conn.synacks:
            if p.ack == want and p.ts >= syns[0].ts:
                answer, kind = p, "synack"
                break
        if answer is None:
            for p in conn.resets:
                if not conn.from_client(p) and p.ts >= syns[0].ts and \
                        (p.ack == want or not (p.tcp_flags or 0) & ACK):
                    answer, kind = p, "rst"
                    break
        if answer is None:
            for p in unreachable.get(key, []):
                if p.ts >= syns[0].ts:
                    answer, kind = p, "icmp"
                    break
        out.append(Attempt(conn, isn, syns, answer, kind))
    return out


def _scanners(ctx: AnalysisContext) -> set[tuple[str, str | None, int | None]]:
    """(client, server, None) / (client, None, port) / (client, None, None) pairs that look like scans."""
    th = ctx.thresholds
    ports: dict[tuple[str, str], set[int]] = defaultdict(set)
    hosts: dict[tuple[str, int], set[str]] = defaultdict(set)
    pairs: dict[str, set[tuple[str, int]]] = defaultdict(set)
    for conn in ctx.connections:
        if not conn.syns:
            continue
        c, (s, p) = conn.client[0], conn.server
        ports[(c, s)].add(p)
        hosts[(c, p)].add(s)
        pairs[c].add((s, p))
    out: set[tuple[str, str | None, int | None]] = set()
    for (c, s), ps in ports.items():
        if len(ps) >= th.scan_vertical_ports:
            out.add((c, s, None))
    for (c, p), hs in hosts.items():
        if len(hs) >= th.scan_horizontal_hosts:
            out.add((c, None, p))
    for c, ps in pairs.items():
        if len(ps) >= th.scan_slow_total_ports:
            out.add((c, None, None))
    return out


def _syn_retry_findings(ctx: AnalysisContext) -> list[Finding]:
    unreachable = _unreachable_index(ctx)
    scanners = _scanners(ctx)
    end_ts = ctx.end_ts
    troubled: dict[tuple[str, int], list[Attempt]] = defaultdict(list)
    answered_hosts: set[str] = set()
    for i, conn in enumerate(ctx.connections):
        if i % 2000 == 0:
            ctx.check_deadline()
        if conn.synacks:
            answered_hosts.add(conn.server[0])
        if not conn.syns:
            continue
        c, (s, p) = conn.client[0], conn.server
        if (c, s, None) in scanners or (c, None, p) in scanners or (c, None, None) in scanners:
            continue
        for att in _attempts(ctx, conn, unreachable):
            unanswered = att.answer is None and att.syns[-1].ts < end_ts - SYN_ANSWER_GRACE_SECONDS
            if att.retried or unanswered:
                troubled[conn.server].append(att)

    findings = []
    for (server_ip, port), atts in sorted(troubled.items()):
        if len(atts) < SYN_RETRY_MIN_ATTEMPTS:
            continue
        never = [a for a in atts if a.answer is None]
        late_ok = [a for a in atts if a.answer_kind == "synack" and a.retried]
        late_rst = [a for a in atts if a.answer_kind in ("rst", "icmp")]
        syn_rtx = sum(len(a.syns) - 1 for a in atts)
        clients = sorted({a.conn.client[0] for a in atts})
        waits = [a.answer.ts - a.syns[0].ts for a in late_ok]
        host_up = server_ip in answered_hosts
        other_ports_ok = host_up and any(
            conn.server[0] == server_ip and conn.server[1] != port and conn.synacks
            for conn in ctx.connections)
        mostly_silent = len(never) * 2 >= len(atts)

        indicators = [
            Indicator(f"{len(atts)} connection attempts to {server_ip}:{port} needed SYN "
                      f"retransmissions or were never answered", FAULT, "moderate"),
            Indicator("The same service was requested repeatedly by ordinary clients "
                      "(clients probing many ports or hosts were excluded)", FAULT, "moderate")]
        if len(clients) >= 2:
            indicators.append(Indicator(f"{len(clients)} different clients were affected, so the problem "
                                        "is on the server side or its path", FAULT, "moderate"))
        if mostly_silent:
            if other_ports_ok:
                title = f"{server_ip}:{port} silently drops connection attempts"
                summary = (f"{len(never)} of {len(atts)} attempts to open a connection to port {port} on "
                           f"{server_ip} were never answered at all - not accepted, not refused - even "
                           f"though the same server answered on other ports. Something is silently "
                           "discarding these packets.")
                cause = ("A firewall rule that DROPs (instead of rejecting) traffic to this port, on the "
                         "server or on the path; or the service is bound behind a filter.")
            elif host_up:
                title = f"{server_ip}:{port} is not responding to connection attempts"
                summary = (f"{len(never)} of {len(atts)} attempts to connect to {server_ip}:{port} got no "
                           "reply, although the server answered other connections in this capture.")
                cause = ("The service stopped accepting connections (overloaded or hung listener), or a "
                         "firewall silently drops the traffic.")
            else:
                title = f"{server_ip} is not answering connection attempts on port {port}"
                summary = (f"{len(never)} of {len(atts)} attempts to connect to {server_ip}:{port} got no "
                           f"reply of any kind, and {server_ip} answered no TCP connection at all in this "
                           "capture.")
                cause = ("The server is down or unreachable, the route to it is broken, or a firewall "
                         "silently drops all traffic to it.")
        else:
            title = f"Connections to {server_ip}:{port} only succeed after retrying"
            summary = (f"{len(late_ok)} of {len(atts)} connection attempts to {server_ip}:{port} had their "
                       "first SYN lost or ignored and only succeeded after the client re-sent it"
                       + (f" (median wait {median(waits):.1f} s)." if waits else "."))
            cause = ("Packet loss on the path to the server, or a server whose listen queue is full "
                     "(it drops new SYNs when overloaded).")
        evidence: list[Evidence] = []
        for a in atts[:MAX_EVIDENCE_ATTEMPTS]:
            evidence.append(Evidence(a.syns[0].n, "connection attempt (SYN)"))
            for k, s in enumerate(a.syns[1:4], start=1):
                evidence.append(Evidence(s.n, f"SYN retransmission #{k} after {s.ts - a.syns[0].ts:.2f} s "
                                              "(same initial sequence number)"))
            if a.answer is not None:
                label = {"synack": "SYN/ACK finally received", "rst": "attempt refused (RST)",
                         "icmp": "ICMP unreachable answering the attempt"}[a.answer_kind or "synack"]
                evidence.append(Evidence(a.answer.n, f"{label} after {a.answer.ts - a.syns[0].ts:.2f} s"))
        times = [s.ts for a in atts for s in a.syns]
        facts = [f"{len(atts)} connection attempts from {len(clients)} client(s) were affected; "
                 f"{syn_rtx} SYN retransmissions were sent in total.",
                 f"Never answered: {len(never)}; succeeded only after retrying: {len(late_ok)}; "
                 f"refused after retrying: {len(late_rst)}.",
                 f"Clients: {', '.join(clients[:10])}" + (" ..." if len(clients) > 10 else "")]
        if waits:
            facts.append(f"Successful attempts waited {min(waits):.2f}-{max(waits):.2f} s for the SYN/ACK.")
        facts.append(f"{server_ip} answered other TCP connections in this capture: "
                     f"{'yes' if host_up else 'no'}.")
        findings.append(Finding(
            detector=NAME, kind="TCP_SYN_RETRIES", title=title, category="fault",
            assessment=assess(indicators), severity="medium",
            evidence_strength="strong" if len(atts) >= 2 * SYN_RETRY_MIN_ATTEMPTS else "moderate",
            summary=summary,
            impact="Applications hang for seconds and then report a connection timeout.",
            likely_cause=cause,
            recommendations=[
                f"Check whether a firewall (host or network) drops traffic to {server_ip}:{port}; a REJECT "
                "rule would at least fail fast.",
                f"Confirm the service on port {port} is running and its listen backlog is not exhausted "
                "('ss -ltn' shows Recv-Q on Linux; 'netstat -ano' on Windows).",
                f"Test reachability from a client: 'Test-NetConnection {server_ip} -Port {port}' (Windows) "
                f"or 'nc -vz {server_ip} {port}' (Linux)."],
            facts=facts,
            alternatives=["The capture point may miss the SYN/ACK if the return traffic takes another path "
                          "(asymmetric routing)."],
            limitations=["The capture cannot show where the SYN was dropped, only that no answer came back "
                         "to the capture point.",
                         f"Attempts within {SYN_ANSWER_GRACE_SECONDS:.0f} s of the end of the capture are not "
                         "counted as unanswered."],
            indicators=indicators,
            hosts={"server": [server_ip], "client": clients},
            time_start=min(times), time_end=max(times), evidence=evidence,
            metrics={"attempts_affected": len(atts), "never_answered": len(never),
                     "succeeded_after_retry": len(late_ok), "refused_after_retry": len(late_rst),
                     "syn_retransmissions": syn_rtx, "clients": len(clients), "port": port,
                     "median_wait_seconds": round(median(waits), 3) if waits else None},
            rule=(f">= {SYN_RETRY_MIN_ATTEMPTS} connection attempts to one service with a retransmitted SYN "
                  "(same ISN) or no answer at all; scanning clients excluded")))
    return findings


# --- retransmission findings -----------------------------------------------------------------

@dataclass(eq=False)
class FlowStat:
    d: Direction
    counted: list[Retransmission]

    @property
    def ratio(self) -> float:
        return len(self.counted) / self.d.data_segments if self.d.data_segments else 0.0


def _pct(x: float) -> str:
    return f"{x * 100:.1f}%"


def _retrans_finding(flows: list[FlowStat], scope: str, scope_ip: str, th) -> Finding:
    retx = [r for f in flows for r in f.counted]
    segs = sum(f.d.data_segments for f in flows)
    ratio = len(retx) / segs if segs else 0.0
    fast = sum(r.mode == "fast" for r in retx)
    timeout = sum(r.mode == "timeout" for r in retx)
    other = len(retx) - fast - timeout
    spurious = sum(r.spurious for r in retx)
    upstream = sum(r.upstream for r in retx)
    downstream = sum(not r.upstream and not r.spurious for r in retx)
    delays = [r.delay for r in retx]
    med = median(delays) if delays else 0.0
    syn_rtx = sum(len(f.d.handshake_retries) for f in flows)
    cap_dups = sum(len(f.d.capture_duplicates) for f in flows)
    dup_ack_total = sum(len(r.dup_acks) for r in retx)
    senders = sorted({f.d.sender[0] for f in flows})
    receivers = sorted({f.d.receiver[0] for f in flows})
    servers = sorted({f.d.conn.server[0] for f in flows})
    clients = sorted({f.d.conn.client[0] for f in flows})
    conns = {id(f.d.conn) for f in flows}
    worst = sorted(flows, key=lambda f: (-len(f.counted), -f.ratio, f.d.conn.first_ts))
    all_spurious = spurious == len(retx)

    indicators: list[Indicator] = []
    if all_spurious:
        indicators.append(Indicator(f"All {len(retx)} resent segments had already been acknowledged by the "
                                    "receiver before they were resent: the data was delivered", BENIGN, "strong"))
        indicators.append(Indicator("The sender's retransmission timer fired early, which means "
                                    "acknowledgements were delayed (latency spikes)", FAULT, "weak"))
    else:
        strong = ratio >= 0.05 and len(retx) >= 10
        indicators.append(Indicator(f"{_pct(ratio)} of {segs} data segments on this path were retransmitted "
                                    f"({len(retx)} resends)", FAULT, "strong" if strong else "moderate"))
        if fast:
            indicators.append(Indicator(f"{fast} resends followed >= {FAST_RETRANSMIT_DUPACKS} duplicate ACKs: "
                                        "the receiver itself reported missing data", FAULT, "moderate"))
        if timeout and timeout >= fast:
            indicators.append(Indicator(f"{timeout} resends happened only after a timeout with no feedback, "
                                        "typical of packets dropped by a congested or faulty link",
                                        FAULT, "moderate"))
        other_side = clients if scope == "server" else servers
        if len(other_side) >= 2:
            indicators.append(Indicator(f"{len(other_side)} different {'clients' if scope == 'server' else 'servers'}"
                                        f" are affected on paths through {scope_ip}", FAULT, "moderate"))
    if cap_dups:
        indicators.append(Indicator(f"{cap_dups} frames were exact capture duplicates (same IP ID within "
                                    f"{th.duplicate_capture_window * 1e6:.0f} us) and were not counted as loss",
                                    BENIGN, "weak"))
    assessment = assess(indicators)

    if scope == "server":
        where = f"traffic exchanged with {scope_ip}"
        title = (f"Spurious TCP retransmissions on connections with {scope_ip}" if all_spurious else
                 f"TCP packet loss on connections with {scope_ip}")
    else:
        where = f"traffic of client {scope_ip} to {len(servers)} different servers"
        title = (f"Spurious TCP retransmissions from client {scope_ip}" if all_spurious else
                 f"TCP packet loss affecting client {scope_ip}")

    if all_spurious:
        summary = (f"In {where}, {len(retx)} segments ({_pct(ratio)} of the data) were sent twice although the "
                   "receiver had already acknowledged them. Nothing was actually lost: the sender gave up "
                   f"waiting too early because acknowledgements arrived late (median {med:.2f} s after the "
                   "original).")
        cause = ("Delay spikes (bufferbloat, a busy wireless link or an overloaded device) made the "
                 "acknowledgements arrive after the sender's retransmission timer expired.")
        severity = "info"
    else:
        summary = (f"{_pct(ratio)} of the TCP data in {where} had to be resent ({len(retx)} of {segs} data "
                   f"segments in {len(conns)} connection(s)). Each resend means a packet was lost and the "
                   f"sender waited (median {med:.2f} s) before trying again.")
        if timeout >= fast:
            cause = ("Packets are being dropped on this path: a congested link or overloaded router queue, "
                     "a faulty cable / port (CRC errors) or a weak wireless signal.")
        else:
            cause = ("Packets are being lost on this path while the connection stays busy (the receiver "
                     "keeps reporting gaps): typically congestion or a link with errors.")
        severity = "medium" if (ratio >= 0.05 or len(conns) >= 3 or med >= 1.0) else "low"

    facts = [f"{len(retx)} of {segs} data segments ({_pct(ratio)}) were retransmissions, across "
             f"{len(flows)} flow(s) in {len(conns)} connection(s).",
             f"Fast retransmissions (after >= {FAST_RETRANSMIT_DUPACKS} duplicate ACKs): {fast}; timeout "
             f"retransmissions (>= {RTO_MIN_SECONDS * 1000:.0f} ms without feedback): {timeout}; other (early / "
             f"tail-loss probe): {other}.",
             f"Delay before resending: median {med:.3f} s, max {max(delays):.3f} s." if delays else "",
             f"Spurious (data already acknowledged): {spurious}."]
    if upstream:
        facts.append(f"{upstream} resends filled gaps whose original was never captured: those packets were "
                     "lost before they reached the capture point (between the sender and here).")
    if downstream:
        facts.append(f"{downstream} resends repeat a segment that WAS captured but never acknowledged: it was "
                     "lost after passing the capture point, or its acknowledgement was lost.")
    if syn_rtx:
        facts.append(f"{syn_rtx} handshake (SYN or SYN/ACK) retransmissions occurred in these connections.")
    if cap_dups:
        facts.append(f"{cap_dups} capture-duplicate frames were ignored (not loss).")
    excluded_ka = sum(f.d.keepalives + f.d.window_probes for f in flows)
    if excluded_ka:
        facts.append(f"{excluded_ka} keep-alive / zero-window probes were excluded.")
    for f in worst[:5]:
        facts.append(f"{f.d.label}: {len(f.counted)} of {f.d.data_segments} segments resent "
                     f"({_pct(f.ratio)}).")
    facts = [x for x in facts if x]

    evidence: list[Evidence] = []
    budget = MAX_EVIDENCE_RETRANS
    for f in worst:
        for r in f.counted:
            if budget <= 0:
                break
            budget -= 1
            if r.original is not None:
                evidence.append(Evidence(r.original.n, f"original segment (seq {r.original.seq}, "
                                                       f"{r.original.payload_len} bytes)"))
            else:
                evidence.append(Evidence(r.rec.n, f"retransmission after {r.delay:.2f} s of a segment whose "
                                                  "original was never captured (lost before the capture "
                                                  "point)"))
            for k, dack in enumerate(r.dup_acks[:3], start=1):
                evidence.append(Evidence(dack.n, f"duplicate ACK #{k} (receiver still waiting for seq "
                                                 f"{dack.ack})"))
            if r.original is not None:
                why = {"fast": "fast retransmit after duplicate ACKs",
                       "timeout": "timeout, no acknowledgement",
                       "other": "early retransmit"}[r.mode]
                if r.spurious:
                    why = "spurious: already acknowledged"
                evidence.append(Evidence(r.rec.n, f"retransmission after {r.delay:.2f} s ({why})"))
    times = [r.rec.ts for r in retx] + [r.original.ts for r in retx if r.original is not None]

    if all_spurious:
        recs = ["Look for latency spikes on this path (the 'Unusual delays' findings, ping with a long "
                "series, or the router's queue statistics).",
                "Enable modern loss recovery on servers (Linux: RACK/TLP are default; avoid very low RTO "
                "settings) so delay spikes do not trigger resends.",
                "Reduce bufferbloat with smart queue management (fq_codel / CAKE) on the router."]
    else:
        recs = [f"Check the interface counters (errors, drops, CRC) on every device between "
                f"{', '.join(senders[:3])} and {', '.join(receivers[:3])}.",
                "If the client is on Wi-Fi, test the same transfer over a cable to rule out radio "
                "interference.",
                "Check link utilisation on the uplink: sustained near-100% use causes queue drops; apply "
                "QoS or increase capacity.",
                "Replace suspect cables / switch ports and confirm both ends agree on speed and duplex."]
    if upstream and downstream:
        alt = "Loss was seen both before and after the capture point, so more than one segment may be lossy."
    elif upstream:
        alt = "Because the originals never reached the capture point, the loss is between the sender and here."
    else:
        alt = "A capture taken at the sender cannot tell a lost data segment from a lost acknowledgement."

    rule = (f"seq-space segment below the highest sequence already sent (serial arithmetic), excluding "
            f"keep-alives, window probes, capture duplicates and PMTUD resends; flow reported when "
            f">= {th.retrans_min_per_flow} resends and >= {_pct(th.retrans_min_ratio)} of data segments")
    hosts = {"server": servers, "client": clients, "data sender": senders, "data receiver": receivers}
    return Finding(
        detector=NAME, kind="TCP_RETRANSMISSIONS", title=title, category="fault", assessment=assessment,
        severity=severity, evidence_strength="strong" if len(retx) >= 10 else "moderate",
        summary=summary,
        impact=("No user impact beyond some wasted bandwidth, but it is an early sign of latency problems."
                if all_spurious else
                "Downloads and pages load slowly, video and calls stutter; at high loss connections stall."),
        likely_cause=cause, recommendations=recs, facts=facts,
        alternatives=[alt, "A capture point that drops frames itself (overloaded capture host) can make "
                           "originals look missing; check the capture tool's drop counter."],
        limitations=["The capture shows where packets were seen, not where they were dropped; the location "
                     "is inferred from which copies were captured.",
                     "SACK options are not decoded; classification relies on cumulative ACKs.",
                     "Keep-alives, window probes and capture duplicates are excluded by rule and could hide "
                     "a very unusual stack behaviour."],
        indicators=indicators, hosts=hosts,
        time_start=min(times) if times else None, time_end=max(times) if times else None,
        evidence=evidence,
        metrics={"retransmissions": len(retx), "data_segments": segs, "ratio": round(ratio, 4),
                 "fast_retransmissions": fast, "timeout_retransmissions": timeout,
                 "other_retransmissions": other, "spurious": spurious,
                 "original_not_captured": upstream, "syn_retries": syn_rtx,
                 "median_delay_seconds": round(med, 3),
                 "max_delay_seconds": round(max(delays), 3) if delays else 0.0,
                 "duplicate_acks": dup_ack_total, "capture_duplicates": cap_dups,
                 "flows": len(flows), "connections": len(conns), "scope": scope},
        rule=rule)


def detect(ctx: AnalysisContext) -> list[Finding]:
    th = ctx.thresholds
    analysis = analyze_tcp(ctx)
    try:
        from .mtu import blackhole_intervals  # lazy import: mtu imports this module
        excluded = blackhole_intervals(ctx)
    except Exception:  # the MTU detector failing must not hide retransmission findings
        excluded = set()

    flagged: list[FlowStat] = []
    for _conn, c2s, s2c in analysis.pairs:
        for d in (c2s, s2c):
            if not d.retrans or not d.data_segments:
                continue
            counted = [r for r in d.retrans if not r.pmtud and id(r.interval) not in excluded]
            fs = FlowStat(d, counted)
            if len(counted) >= th.retrans_min_per_flow and fs.ratio >= th.retrans_min_ratio:
                flagged.append(fs)

    findings: list[Finding] = []
    by_client: dict[str, list[FlowStat]] = defaultdict(list)
    for fs in flagged:
        by_client[fs.d.conn.client[0]].append(fs)
    used: set[int] = set()
    for client, flows in sorted(by_client.items()):
        if len({f.d.conn.server[0] for f in flows}) >= PER_CLIENT_MIN_SERVERS:
            findings.append(_retrans_finding(flows, "client", client, th))
            used.update(id(f) for f in flows)
    by_server: dict[str, list[FlowStat]] = defaultdict(list)
    for fs in flagged:
        if id(fs) not in used:
            by_server[fs.d.conn.server[0]].append(fs)
    for server, flows in sorted(by_server.items()):
        findings.append(_retrans_finding(flows, "server", server, th))

    findings.extend(_syn_retry_findings(ctx))
    return findings
