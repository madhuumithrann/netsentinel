"""MTU mismatch analysis: explicit "fragmentation needed" signals and inferred PMTUD black holes.

Objective
    Find paths whose maximum packet size (MTU) is smaller than the packets the endpoints send,
    which makes large transfers stall while small requests still work.

MTU_ICMP_FRAG_NEEDED (direct evidence)
    A router that must forward a packet bigger than its next link, with Don't Fragment set,
    drops it and returns ICMP type 3 code 4 (IPv4) or ICMPv6 type 2 "Packet Too Big", carrying
    the next-hop MTU and the header of the dropped packet. Messages are grouped per reporting
    router. For every affected flow (taken from the quoted header) we report:
      * the next-hop MTU value(s) and the size of the packet that was too big;
      * the MSS each endpoint advertised in its SYN (e.g. MSS 1460 means 1500-byte packets);
      * whether Path MTU Discovery took effect: if the same flow keeps sending packets larger
        than the reported MTU more than ``PMTUD_GRACE_SECONDS`` after the ICMP
        (>= ``PMTUD_IGNORED_MIN_PACKETS`` times), PMTUD is not working for that sender.
    Forgery checks (an ICMP "too big" message is a known way to degrade TCP):
      * ATTACK moderate - MTU below any real link (IPv4 < 552, IPv6 < 1280 which RFC 8200 forbids);
      * ATTACK moderate - the quoted TCP sequence number was never sent by that flow (the
        capture saw the flow, so a genuine router would quote a real packet);
      * ATTACK weak     - the quoted packet is not even larger than the claimed MTU.
    Two moderate attack indicators are needed for an ATTACK assessment (see model.assess).

MTU_BLACKHOLE_SUSPECTED (inferred)
    When ICMP is blocked, oversize packets vanish silently. Per TCP connection direction
    (shared sequence analysis from ``tcp_retransmissions``):
      * a segment with payload >= ``Thresholds.mtu_large_segment_bytes`` and DF set (IPv6 is
        always DF) was retransmitted at that size >= ``Thresholds.mtu_blackhole_min_retrans``
        times and never acknowledged (or only after the sender re-sent it in smaller pieces);
      * smaller segments of the same connection WERE acknowledged (data, or at least the
        handshake);
      * no ICMP fragmentation-needed message was seen for the flow;
      * the path still worked for small packets after the large ones started failing: the
        receiver kept sending packets (e.g. duplicate ACKs), or a smaller resend got through.
    Re-sending the same data in smaller segments and having it acknowledged is a strong
    indicator (the sender's own black-hole detection / PLPMTUD proving size is the problem).

Limitations
    * A capture cannot measure the true path MTU; the black hole is inferred from sizes that
      failed and sizes that worked (the reported bracket is an estimate).
    * The black-hole rule needs a capture point on the sender's side of the drop; a capture at
      the receiver never sees the oversize packets.
    * MSS clamping by middleboxes is only visible if the capture sits on both sides of it.
"""
from __future__ import annotations

import weakref
from bisect import bisect_right
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from ..context import AnalysisContext, TcpConnection
from ..model import ATTACK, BENIGN, FAULT, Evidence, Finding, Indicator, PacketRecord, assess
from .tcp_retransmissions import Direction, Interval, analyze_tcp

NAME = "mtu"

# --- documented constants --------------------------------------------------------------------
# Packets the sender emits this soon after the ICMP may already have been queued; ignore them.
PMTUD_GRACE_SECONDS = 0.05
# Oversize packets after the ICMP before we say PMTUD is not taking effect.
PMTUD_IGNORED_MIN_PACKETS = 2
# Smallest plausible next-hop MTU. Linux refuses to lower the path MTU below 552 (min_pmtu);
# IPv6 links must support 1280 bytes (RFC 8200), so a smaller value is protocol-invalid.
MIN_PLAUSIBLE_MTU_V4 = 552
MIN_PLAUSIBLE_MTU_V6 = 1280
MAX_EVIDENCE_FLOWS = 20


def _is_v6(rec: PacketRecord) -> bool:
    return rec.l3 == "IPv6"


def _syn_mss(conn: TcpConnection, from_client: bool) -> int | None:
    pkts = conn.syns if from_client else conn.synacks
    for p in pkts:
        if p.mss:
            return p.mss
    return None


# --- black-hole inference ----------------------------------------------------------------

@dataclass(eq=False)
class Blackhole:
    conn: TcpConnection
    d: Direction
    stuck: list[Interval]
    affected: list[Interval]
    onset: float
    resized_ok: list[tuple[Interval, PacketRecord, float]]
    receiver_after: int
    dupacks_after: list[PacketRecord]
    small_acked: list[Interval]
    handshake_only: bool
    largest_ok: int | None
    smallest_bad: int | None
    big_retrans: int = 0
    mss: int | None = None


_BH_CACHE: "weakref.WeakKeyDictionary[AnalysisContext, list[Blackhole]]" = weakref.WeakKeyDictionary()


def _small_acked(d: Direction, thr: int) -> list[Interval]:
    out = []
    for iv in d.intervals:
        size = iv.first.payload_len
        if 0 < size < thr and d.acked_at(iv.end) is not None:
            out.append(iv)
    return out


def find_blackholes(ctx: AnalysisContext) -> list[Blackhole]:
    cached = _BH_CACHE.get(ctx)
    if cached is not None:
        return cached
    th = ctx.thresholds
    thr = th.mtu_large_segment_bytes
    analysis = analyze_tcp(ctx)
    out: list[Blackhole] = []
    for i, (conn, c2s, s2c) in enumerate(analysis.pairs):
        if i % 2000 == 0:
            ctx.check_deadline()
        for d, other in ((c2s, s2c), (s2c, c2s)):
            if not d.retrans:
                continue
            stuck, affected, resized = [], [], []
            big_retrans = 0
            for iv in d.intervals:
                first = iv.first
                if first.payload_len < thr or not (first.df or _is_v6(first)):
                    continue
                big = [s for s in iv.sends if s.payload_len >= thr]
                small = [s for s in iv.sends if s.payload_len < thr and s.ts > first.ts]
                acked = d.acked_at(iv.end)
                if acked is not None and not (small and acked >= small[0].ts):
                    continue            # acknowledged at full size: ordinary loss at most
                affected.append(iv)
                if acked is not None and small:
                    resized.append((iv, small[0], acked))
                if len(big) - 1 >= th.mtu_blackhole_min_retrans:
                    stuck.append(iv)
                    big_retrans += len(big) - 1
            if not stuck:
                continue
            if analysis.frag_index.get(d.key):
                continue                # ICMP was seen: explicit MTU problem, reported separately
            small_ok = _small_acked(d, thr) + _small_acked(other, thr)
            handshake_ok = bool(conn.synacks) and conn.established
            if not small_ok and not handshake_ok:
                continue
            onset = min(iv.first.ts for iv in stuck)
            stuck_start = stuck[0].start
            receiver_after, dupacks = 0, []
            for p in conn.packets:
                if p.ts <= onset or conn.from_client(p) == d.from_client:
                    continue
                receiver_after += 1
                if (p.payload_len == 0 and p.ack is not None and d.base is not None
                        and d.rel(p.ack) == stuck_start and len(dupacks) < 20):
                    dupacks.append(p)
            if not receiver_after and not resized:
                continue                # receiver silent: could be a dead host, not MTU
            ok_sizes = [s.ip_len for _, s, _ in resized if s.ip_len]
            affected_ids = {id(iv) for iv in affected}
            ok_sizes += [iv.first.ip_len for iv in d.intervals
                         if id(iv) not in affected_ids and iv.first.ip_len and iv.first.payload_len > 0
                         and d.acked_at(iv.end) is not None]
            bad_sizes = [iv.first.ip_len for iv in stuck if iv.first.ip_len]
            out.append(Blackhole(conn, d, stuck, affected, onset, resized, receiver_after, dupacks,
                                 small_ok, not small_ok, max(ok_sizes) if ok_sizes else None,
                                 min(bad_sizes) if bad_sizes else None, big_retrans,
                                 _syn_mss(conn, d.from_client)))
    _BH_CACHE[ctx] = out
    return out


def blackhole_intervals(ctx: AnalysisContext) -> set[int]:
    """ids of intervals whose resends are explained by a black hole (used by tcp_retransmissions)."""
    return {id(iv) for bh in find_blackholes(ctx) for iv in bh.affected}


def _blackhole_finding(sender: str, holes: list[Blackhole], th) -> Finding:
    receivers = sorted({bh.d.receiver[0] for bh in holes})
    stuck_total = sum(len(bh.stuck) for bh in holes)
    retrans_total = sum(bh.big_retrans for bh in holes)
    resized = [r for bh in holes for r in bh.resized_ok]
    dupacks = sum(len(bh.dupacks_after) for bh in holes)
    alive = sum(1 for bh in holes if bh.receiver_after)
    handshake_only = all(bh.handshake_only for bh in holes)
    ok = [bh.largest_ok for bh in holes if bh.largest_ok]
    bad = [bh.smallest_bad for bh in holes if bh.smallest_bad]
    largest_ok, smallest_bad = (max(ok) if ok else None), (min(bad) if bad else None)
    mss = sorted({bh.mss for bh in holes if bh.mss})

    indicators = [
        Indicator(f"{stuck_total} large segment(s) (>= {th.mtu_large_segment_bytes} bytes, DF set) were "
                  f"retransmitted {retrans_total} times at full size and never acknowledged", FAULT, "moderate"),
        Indicator("Smaller segments of the same connection(s) were acknowledged" if not handshake_only else
                  "The handshake (small packets) completed normally", FAULT, "moderate" if not handshake_only
                  else "weak"),
        Indicator("No ICMP 'fragmentation needed' / 'packet too big' message arrived for these flows, as "
                  "happens when a firewall blocks ICMP", FAULT, "weak")]
    if alive:
        indicators.append(Indicator(f"The receiver kept sending packets after the large segments vanished"
                                    + (f" ({dupacks} duplicate ACKs asking for the missing data)" if dupacks
                                       else "") + ", so the host and link were up", FAULT, "moderate"))
    if resized:
        indicators.append(Indicator(f"{len(resized)} time(s) the same data got through as soon as the sender "
                                    "re-sent it in smaller segments: size is the problem", FAULT, "strong"))
    bracket = ""
    if largest_ok and smallest_bad and largest_ok < smallest_bad:
        bracket = (f" Packets of {largest_ok} bytes got through and packets of {smallest_bad} bytes did not, "
                   f"so the path MTU is probably between {largest_ok} and {smallest_bad - 1} bytes.")
    facts = [f"{len(holes)} connection(s) from {sender} to {', '.join(receivers[:5])} stalled on large "
             f"segments; {stuck_total} distinct segment(s) were resent {retrans_total} times at full size.",
             f"No ICMP fragmentation-needed / packet-too-big message was captured for these flows."]
    if mss:
        facts.append(f"MSS advertised by {sender} in its SYN: {', '.join(map(str, mss))} bytes "
                     f"(=> {mss[-1] + 40}-byte IPv4 packets).")
    if dupacks:
        facts.append(f"The receiver sent {dupacks} duplicate ACKs after the stall began, still asking for the "
                     "first missing large segment.")
    if resized:
        facts.append(f"{len(resized)} stalled segment(s) were acknowledged only after being re-sent at "
                     f"{min(s.payload_len for _, s, _ in resized)}-"
                     f"{max(s.payload_len for _, s, _ in resized)} bytes.")
    if bracket:
        facts.append(bracket.strip())
    for bh in holes[:5]:
        facts.append(f"{bh.d.label}: {len(bh.stuck)} large segment(s) stuck, first at "
                     f"{bh.stuck[0].first.payload_len} bytes payload.")

    evidence: list[Evidence] = []
    for bh in holes[:MAX_EVIDENCE_FLOWS]:
        for p in bh.small_acked[:1]:
            evidence.append(Evidence(p.first.n, f"small segment ({p.first.payload_len} bytes) that was "
                                                "acknowledged"))
        for iv in bh.stuck[:2]:
            evidence.append(Evidence(iv.first.n, f"large segment ({iv.first.payload_len} bytes, DF) never "
                                                 "acknowledged"))
            for k, s in enumerate([s for s in iv.sends[1:] if s.payload_len >= th.mtu_large_segment_bytes][:5],
                                  start=1):
                evidence.append(Evidence(s.n, f"retransmission #{k} of the large segment after "
                                              f"{s.ts - iv.first.ts:.2f} s (same size, still not acknowledged)"))
        for p in bh.dupacks_after[:3]:
            evidence.append(Evidence(p.n, "duplicate ACK from the receiver (alive, still missing the large "
                                          "segment)"))
        for iv, s, _acked in bh.resized_ok[:2]:
            evidence.append(Evidence(s.n, f"same data re-sent in a smaller segment ({s.payload_len} bytes) - "
                                          "this one was acknowledged"))
    times = [iv.first.ts for bh in holes for iv in bh.stuck] + \
            [s.ts for bh in holes for iv in bh.stuck for s in iv.sends]
    return Finding(
        detector=NAME, kind="MTU_BLACKHOLE_SUSPECTED",
        title=f"Large packets from {sender} disappear (suspected MTU black hole)",
        category="fault", assessment=assess(indicators), severity="medium",
        evidence_strength="strong" if resized else "moderate",
        summary=(f"Connections from {sender} work for small packets but every large packet "
                 f"(>= {th.mtu_large_segment_bytes} bytes) is silently lost, even after repeated resends, and "
                 "no router reported the problem." + bracket),
        impact=("Logins and small pages work, but uploads, downloads, e-mail attachments or VPN sessions hang "
                "as soon as data gets large."),
        likely_cause=("A link on the path has a smaller MTU than the endpoints assume (VPN, PPPoE, GRE / IPsec "
                      "tunnel) and a firewall blocks the ICMP messages that would tell the sender to send "
                      "smaller packets (Path MTU Discovery black hole)."),
        recommendations=[
            "Allow ICMP type 3 code 4 (IPv4) and ICMPv6 type 2 through every firewall on the path; blocking "
            "them breaks Path MTU Discovery.",
            "Clamp the TCP MSS on the router / VPN gateway (e.g. 'iptables -t mangle -A FORWARD -p tcp "
            "--tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu', or 'ip tcp adjust-mss 1360' on Cisco).",
            "Find the real path MTU: 'ping -f -l 1472 <host>' (Windows) or 'ping -M do -s 1472 <host>' "
            "(Linux), lowering the size until it succeeds; then lower the interface / tunnel MTU.",
            "On Linux senders, 'net.ipv4.tcp_mtu_probing=1' lets TCP recover from black holes by itself."],
        facts=facts,
        alternatives=["Heavy loss that hits only large packets (a faulty link corrupting long frames) looks "
                      "similar; check interface CRC counters.",
                      "A middlebox dropping specific traffic after the handshake (DPI / IPS) can also stall "
                      "connections."],
        limitations=["The capture cannot measure the true path MTU; the black hole is inferred from which "
                     "packet sizes were and were not acknowledged.",
                     "Detection needs the capture on the sender's side of the drop.",
                     "ICMP messages may have been sent but filtered before the capture point."],
        indicators=indicators,
        hosts={"data sender": [sender], "data receiver": receivers},
        time_start=min(times), time_end=max(times), evidence=evidence,
        metrics={"connections": len(holes), "stuck_segments": stuck_total,
                 "large_segment_retransmissions": retrans_total, "resized_and_acknowledged": len(resized),
                 "duplicate_acks_after_stall": dupacks, "largest_acknowledged_packet": largest_ok,
                 "smallest_failed_packet": smallest_bad, "advertised_mss": mss,
                 "large_segment_bytes": th.mtu_large_segment_bytes},
        rule=(f"DF segment >= {th.mtu_large_segment_bytes} B resent >= {th.mtu_blackhole_min_retrans} times at "
              "full size and never acknowledged, smaller segments acknowledged, no ICMP frag-needed, path "
              "still alive for small packets"))


# --- ICMP fragmentation needed -----------------------------------------------------------

@dataclass(eq=False)
class FlowReport:
    key: tuple
    proto: int | None
    icmps: list[PacketRecord]
    mtu: int | None
    trigger: PacketRecord | None = None
    largest_before: int | None = None
    oversize_after: list[PacketRecord] = field(default_factory=list)
    adapted: PacketRecord | None = None
    sender_mss: int | None = None
    receiver_mss: int | None = None
    never_sent: bool = False
    quoted_len: int | None = None


def _udp_index(ctx: AnalysisContext, wanted: set[tuple]) -> dict[tuple, list[PacketRecord]]:
    out: dict[tuple, list[PacketRecord]] = defaultdict(list)
    if not wanted:
        return out
    for i, r in enumerate(ctx.udp):
        if i % 5000 == 0:
            ctx.check_deadline()
        key = (r.ip_src, r.sport, r.ip_dst, r.dport)
        if key in wanted:
            out[key].append(r)
    return out


def _interval_of(d: Direction, seq: int) -> Interval | None:
    if d.base is None or not d.intervals:
        return None
    rel = d.rel(seq)
    i = bisect_right(d.starts, rel) - 1
    if i >= 0 and d.intervals[i].end > rel:
        return d.intervals[i]
    return None


def _evaluate_flow(ctx, analysis, key, proto, icmps, udp_idx) -> FlowReport:
    mtus = [i.icmp_mtu for i in icmps if i.icmp_mtu]
    rep = FlowReport(key, proto, icmps, min(mtus) if mtus else None)
    first = icmps[0]
    inner = first.icmp_inner or {}
    rep.quoted_len = inner.get("len")
    sent: list[PacketRecord] = []
    if proto == 6:
        dirs = analysis.by_key.get(key, [])
        # The connection active when the ICMP arrived.
        dirs = [d for d in dirs if d.conn.first_ts - 1 <= first.ts <= d.conn.last_ts + 1] or dirs
        if dirs:
            d = dirs[0]
            sent = [p for p in d.conn.packets if d.conn.from_client(p) == d.from_client]
            rep.sender_mss = _syn_mss(d.conn, d.from_client)
            rep.receiver_mss = _syn_mss(d.conn, not d.from_client)
            seq = inner.get("seq")
            if seq is not None and d.base is not None and d.intervals:
                iv = _interval_of(d, seq)
                if iv is not None:
                    before = [s for s in iv.sends if s.ts <= first.ts + 0.001]
                    rep.trigger = before[-1] if before else None
                    if rep.trigger is None:
                        rep.never_sent = True
                elif d.isn is not None or d.rel(seq) >= 0:
                    rep.never_sent = True
    elif proto == 17:
        sent = udp_idx.get(key, [])
    before = [p for p in sent if p.ts <= first.ts and p.ip_len]
    rep.largest_before = max((p.ip_len for p in before), default=None)
    if rep.trigger is None and rep.mtu:
        over = [p for p in before if p.ip_len > rep.mtu]
        rep.trigger = over[-1] if over else None
    if rep.mtu:
        for p in sent:
            if p.ts <= first.ts or not p.ip_len:
                continue
            if p.ip_len > rep.mtu and p.ts > first.ts + PMTUD_GRACE_SECONDS:
                rep.oversize_after.append(p)
            elif p.ip_len <= rep.mtu and p.payload_len > 0 and rep.adapted is None:
                rep.adapted = p
    return rep


def _frag_findings(ctx: AnalysisContext) -> list[Finding]:
    analysis = analyze_tcp(ctx)
    msgs = analysis.frag_messages
    if not msgs:
        return []
    by_router: dict[str, list[PacketRecord]] = defaultdict(list)
    for m in msgs:
        by_router[m.ip_src or "unknown"].append(m)
    udp_wanted = set()
    for m in msgs:
        inner = m.icmp_inner or {}
        if inner.get("proto") == 17 and inner.get("sport") is not None:
            udp_wanted.add((inner.get("src"), inner.get("sport"), inner.get("dst"), inner.get("dport")))
    udp_idx = _udp_index(ctx, udp_wanted)

    findings = []
    for router, recs in sorted(by_router.items()):
        flows: dict[tuple, list[PacketRecord]] = defaultdict(list)
        for r in recs:
            inner = r.icmp_inner or {}
            key = (inner.get("src"), inner.get("sport"), inner.get("dst"), inner.get("dport"))
            flows[(key, inner.get("proto"))].append(r)
        reports = [_evaluate_flow(ctx, analysis, key, proto, icmps, udp_idx)
                   for (key, proto), icmps in flows.items()]
        mtu_counts = Counter(r.icmp_mtu for r in recs)
        mtu_values = sorted(m for m in mtu_counts if m)
        v6 = any(r.l4 == "ICMPv6" for r in recs)
        ignored = [rp for rp in reports if len(rp.oversize_after) >= PMTUD_IGNORED_MIN_PACKETS]
        adapted = [rp for rp in reports if rp.adapted is not None and rp not in ignored]
        tiny = [m for m in mtu_values if m < (MIN_PLAUSIBLE_MTU_V6 if v6 else MIN_PLAUSIBLE_MTU_V4)]
        never_sent = [rp for rp in reports if rp.never_sent]
        self_inconsistent = [rp for rp in reports if rp.quoted_len and rp.mtu and rp.quoted_len <= rp.mtu]
        sizes = sorted({rp.quoted_len or rp.largest_before for rp in reports if rp.quoted_len or rp.largest_before})
        mtu_text = ", ".join(map(str, mtu_values)) if mtu_values else "not stated"
        msg_name = "ICMPv6 'packet too big'" if v6 else "ICMP 'fragmentation needed'"

        indicators = [Indicator(f"Router {router} reported next-hop MTU {mtu_text}"
                                + (f", smaller than the {sizes[-1]}-byte packets being sent" if sizes else ""),
                                FAULT, "moderate")]
        if ignored:
            indicators.append(Indicator(f"{len(ignored)} flow(s) kept sending packets larger than the reported "
                                        f"MTU after the message: Path MTU Discovery is not taking effect",
                                        FAULT, "strong"))
        if adapted:
            indicators.append(Indicator(f"{len(adapted)} flow(s) switched to smaller packets afterwards "
                                        "(Path MTU Discovery worked)", BENIGN, "weak"))
        if tiny:
            indicators.append(Indicator(f"Reported MTU {tiny[0]} is below any real link "
                                        f"(minimum {MIN_PLAUSIBLE_MTU_V6 if v6 else MIN_PLAUSIBLE_MTU_V4}); "
                                        "forged 'too big' messages are used to degrade TCP", ATTACK, "moderate"))
        if never_sent:
            indicators.append(Indicator(f"{len(never_sent)} message(s) quote a TCP segment the flow never sent, "
                                        "although the capture saw that flow: a real router quotes the packet "
                                        "it dropped", ATTACK, "moderate"))
        if self_inconsistent:
            indicators.append(Indicator("The quoted packet is not larger than the claimed MTU, so it could not "
                                        "have been too big", ATTACK, "weak"))
        assessment = assess(indicators)
        severity = "high" if assessment == ATTACK else "medium" if (ignored or assessment != FAULT) else "low"

        senders = sorted({rp.key[0] for rp in reports if rp.key[0]})
        dests = sorted({rp.key[2] for rp in reports if rp.key[2]})
        mss = sorted({rp.sender_mss for rp in reports if rp.sender_mss})
        facts = [f"{len(recs)} {msg_name} message(s) from {router}, next-hop MTU: {mtu_text}"
                 + (f" (counts: {', '.join(f'{m}: {c}' for m, c in sorted(mtu_counts.items(), key=lambda x: str(x[0])))})"
                    if len(mtu_counts) > 1 else "") + ".",
                 f"Affected flows: {len(reports)}."]
        for rp in reports[:8]:
            src, sport, dst, dport = rp.key
            proto = {6: "TCP", 17: "UDP"}.get(rp.proto, f"protocol {rp.proto}")
            if src is None or dst is None:
                text = "Flow unknown (the router quoted too little of the dropped packet)"
            elif sport is None:
                text = f"{proto} {src} -> {dst}"
            else:
                text = f"{proto} {src}:{sport} -> {dst}:{dport}"
            if rp.quoted_len:
                text += f": a {rp.quoted_len}-byte packet did not fit MTU {rp.mtu or '?'}"
            if rp.sender_mss:
                text += f"; sender advertised MSS {rp.sender_mss} (=> {rp.sender_mss + (60 if v6 else 40)}-byte packets)"
            if rp.oversize_after:
                text += f"; {len(rp.oversize_after)} oversize packet(s) sent after the ICMP"
            elif rp.adapted is not None:
                text += f"; next data packet was {rp.adapted.ip_len} bytes (adapted)"
            facts.append(text + ".")
        if mss and mtu_values:
            facts.append(f"Suggested MSS for this path: {mtu_values[0] - (60 if v6 else 40)} bytes "
                         f"(MTU {mtu_values[0]} minus IP and TCP headers).")

        evidence: list[Evidence] = []
        for rp in reports[:MAX_EVIDENCE_FLOWS]:
            if rp.trigger is not None:
                evidence.append(Evidence(rp.trigger.n, f"oversize packet ({rp.trigger.ip_len} bytes"
                                                       f"{', DF' if rp.trigger.df else ''}) that the router "
                                                       "could not forward"))
            for i in rp.icmps[:5]:
                evidence.append(Evidence(i.n, f"{msg_name} from {router} (next-hop MTU {i.icmp_mtu or '?'})"))
            for p in rp.oversize_after[:5]:
                evidence.append(Evidence(p.n, f"oversize packet ({p.ip_len} bytes) sent after the ICMP "
                                              "(PMTUD not taking effect)"))
            if rp.adapted is not None and not rp.oversize_after:
                evidence.append(Evidence(rp.adapted.n, f"first smaller packet after the ICMP ({rp.adapted.ip_len} "
                                                       "bytes, sender adapted)"))
        times = [r.ts for r in recs] + [p.ts for rp in reports for p in rp.oversize_after]

        if assessment == ATTACK:
            title = f"Suspicious {msg_name} messages claiming to be from {router}"
            summary = (f"{len(recs)} message(s) told {', '.join(senders[:3]) or 'a host'} to shrink its packets "
                       f"to {mtu_text} bytes, but they do not match the traffic actually sent. They are probably "
                       "forged to slow down or disrupt these connections.")
            cause = "Forged ICMP 'too big' messages (an ICMP-based denial-of-service / degradation attack)."
        elif ignored:
            title = f"Path MTU {mtu_text} reported by {router} is being ignored"
            summary = (f"The router {router} cannot forward packets larger than {mtu_text} bytes and said so, "
                       f"but {len(ignored)} flow(s) kept sending larger packets anyway, so those packets keep "
                       "being dropped and the transfer stalls.")
            cause = ("The sender ignores ICMP 'too big' messages (PMTUD disabled, or a host firewall drops the "
                     "ICMP before TCP sees it) while the path has a smaller MTU (VPN / PPPoE / tunnel).")
        else:
            title = f"MTU mismatch: {router} can only forward {mtu_text}-byte packets"
            summary = (f"Packets of up to {sizes[-1] if sizes else 'more than ' + mtu_text} bytes were too big for "
                       f"the next link at {router} (MTU {mtu_text}). The router told the sender, which "
                       + ("then sent smaller packets, so the connection recovered after a delay."
                          if adapted else "may or may not have adapted (not visible in this capture)."))
            cause = ("A link on the path (VPN, PPPoE, tunnel, or a misconfigured interface) has a smaller MTU "
                     "than the 1500 bytes the endpoints assume.")
        hosts = {"reporting router": [router], "sender": senders, "destination": dests}
        findings.append(Finding(
            detector=NAME, kind="MTU_ICMP_FRAG_NEEDED", title=title, category="fault",
            assessment=assessment, severity=severity,
            evidence_strength="strong" if (ignored or len(recs) >= 3) else "moderate",
            summary=summary,
            impact=("Large transfers start slowly or stall; small requests work. Every oversize packet costs a "
                    "round trip and a resend."),
            likely_cause=cause,
            recommendations=(
                ["Verify the source of these ICMP messages: is the router address real and on the path?",
                 "Rate-limit or validate inbound ICMP 'too big' messages at the firewall (accept only those "
                 "quoting real connections).",
                 "Set a sane minimum path MTU on hosts (Linux: net.ipv4.route.min_pmtu)."]
                if assessment == ATTACK else
                [f"Clamp TCP MSS to {mtu_values[0] - (60 if v6 else 40) if mtu_values else 1360} bytes on the "
                 "router / VPN gateway so endpoints never send oversize packets.",
                 "Make the tunnel / interface MTU consistent on both ends of the link.",
                 "Do not block ICMP 'fragmentation needed' / ICMPv6 'packet too big' on host firewalls; PMTUD "
                 "depends on them."]),
            facts=facts,
            alternatives=(["A misbehaving router could also produce these values."] if assessment == ATTACK else
                          ["Occasional messages are normal Path MTU Discovery; they matter when they repeat or "
                           "the sender does not adapt."]),
            limitations=["The capture cannot measure the true path MTU; it shows only what the router reported.",
                         "Whether the sender adapted is judged from packets visible at the capture point."],
            indicators=indicators, hosts=hosts,
            time_start=min(times), time_end=max(times), evidence=evidence,
            metrics={"messages": len(recs), "mtu_values": mtu_values, "flows": len(reports),
                     "flows_ignoring_pmtud": len(ignored), "flows_adapted": len(adapted),
                     "oversize_after_icmp": sum(len(rp.oversize_after) for rp in reports),
                     "advertised_mss": mss, "quoted_never_sent": len(never_sent),
                     "implausible_mtu": bool(tiny), "ipv6": v6},
            rule=("ICMP type 3 code 4 / ICMPv6 type 2 grouped per reporting router; PMTUD ignored when >= "
                  f"{PMTUD_IGNORED_MIN_PACKETS} packets above the MTU follow after {PMTUD_GRACE_SECONDS} s")))
    return findings


def detect(ctx: AnalysisContext) -> list[Finding]:
    th = ctx.thresholds
    findings = _frag_findings(ctx)
    by_sender: dict[str, list[Blackhole]] = defaultdict(list)
    for bh in find_blackholes(ctx):
        by_sender[bh.d.sender[0]].append(bh)
    for sender, holes in sorted(by_sender.items()):
        findings.append(_blackhole_finding(sender, holes, th))
    return findings
