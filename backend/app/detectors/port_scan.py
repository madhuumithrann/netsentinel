"""Port scan and host sweep detection.

Objective
    Recognise a host that is *mapping* other hosts' services (reconnaissance) and tell it apart
    from a host that simply *uses* many services. Report the true scope of the scan (every
    probe, port and target, not just the part that crossed a threshold) and what it discovered.

Algorithm
    1. Probe extraction (one probe = one attempt to reach one host:port):
       * TCP SYN probes - every reconstructed connection (``ctx.connections``) whose client sent a
         SYN. Its outcome comes from the target's answer:
           open      SYN/ACK came back (or the prober completed the handshake),
           closed    the target answered with RST,
           filtered  no answer, or an ICMP unreachable / administratively-prohibited message
                     quoting the probe,
           session   the handshake completed AND application data flowed: legitimate use.
         Whether the prober completed the handshake (ACK) or tore it down with a bare RST tells
         a "connect" scan from a "SYN half-open" scan.
       * TCP stealth probes - connections in which every segment the prober sent has none of
         SYN / ACK / RST set: FIN-only, NULL (no flags) and XMAS (FIN+PSH+URG). RFC 793 stacks
         set ACK on every segment after the SYN, so these have no legitimate use; they exist to
         slip past stateless filters and to fingerprint operating systems.
       * UDP probes - UDP has no handshake, so a probe is only recognised when the target
         answered it with an ICMP port-unreachable (closed) or admin-prohibited (filtered), whose
         quoted header (``icmp_inner``) names the original destination port. Once a src->target
         pair has at least ``UDP_MIN_UNREACHABLE`` such answers, all of the src's datagrams to
         that target are treated as probes (replied = open, no answer = open|filtered).
    2. False-positive controls (applied before counting):
       * A probe that led to a data-carrying session counts as *success*; the failure ratio
         (ports that never carried data / ports probed) must be >= ``scan_min_failure_ratio``.
         A client legitimately using 20 services completes 20 sessions, ratio ~0.
       * Sessions to ephemeral ports (>= 1024) that completed are dropped entirely (FTP passive
         data, RPC dynamic ports, P2P); connections from source port 20 (active FTP data) are
         dropped; failed ephemeral-port attempts toward a host the source has a working FTP (21)
         or MS-RPC (135) control session with are dropped (blocked passive-FTP data is a fault).
       * Horizontal counting ignores targets the source looked up in DNS first: scanners do not
         resolve a name per target, while a client whose uplink is down retries many resolved
         sites on 443.
       * UDP datagrams that answer an earlier datagram (reverse flow seen first, or service port
         -> ephemeral port) are responses, not probes: late DNS answers to closed client sockets
         produce port-unreachables but no scan. Pairs that also produced ICMP time-exceeded
         (traceroute / mtr) are ignored.
    3. Triggers per source, with sliding windows of ``scan_window_seconds`` (two pointers, O(n)):
       vertical    >= ``scan_vertical_ports`` distinct ports on one target within a window,
       horizontal  >= ``scan_horizontal_hosts`` distinct targets on one port within a window,
       stealth     >= ``scan_stealth_min_ports`` distinct host:ports probed with FIN/NULL/XMAS,
       slow        >= ``scan_slow_total_ports`` distinct host:port pairs over the whole capture,
                   structured like a scan (many ports on a host or one port on many hosts),
                   when no window fired. Window triggers also require the failure ratio inside
                   the window.
    4. ONE finding per scanning source. Kind ``HOST_SWEEP`` when only horizontal behaviour fired
       (one service checked across many hosts), otherwise ``PORT_SCAN``. Probes separated by more
       than one window are reported as separate bursts of the same finding.

Indicators (all documented in the finding)
    ATTACK strong    vertical window hit with high failure ratio
    ATTACK strong    horizontal window hit with high failure ratio
    ATTACK strong    stealth TCP flag combinations (no legitimate use)
    ATTACK moderate  slow scan (many host:ports over the capture, below the window rate)
    ATTACK moderate  half-open technique: SYN/ACKs answered by a bare RST from the prober
    ATTACK moderate  crafted SYNs: >= 80 % of >= 10 SYN probes carry no MSS option, which every
                     operating-system TCP stack sends (raw-packet scanning tool)
    ATTACK weak      one fixed source port reused for >= 10 different targets/ports
    ATTACK weak      ports probed in strictly ascending order

Severity
    high for an ATTACK assessment, critical when the scan found open services on
    ``CRITICAL_OPEN_HOSTS`` or more hosts (reconnaissance that succeeded broadly), medium when
    the assessment stays inconclusive.

Limitations
    * The capture vantage point limits what is visible: a scan whose answers are dropped before
      the capture point looks fully "filtered".
    * UDP probes are only recognised through ICMP answers; hosts rate-limit ICMP, and a UDP
      scan of a host that sends no ICMP at all is invisible here.
    * ACK / window / Maimon scans look like mid-stream TCP and are not detected.
    * A scan slower than the capture duration allows (a few probes per hour) is invisible, and
      spoofed decoy sources (nmap -D) appear as several scanners.
    * Authorisation cannot be read from packets: an approved vulnerability scanner looks exactly
      like an attacker.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass

from ..context import AnalysisContext, TcpConnection, is_special
from ..model import ACK, ATTACK, FIN, PSH, RST, SYN, URG, Evidence, Finding, Indicator, PacketRecord, assess

NAME = "port_scan"

# --- detector-local thresholds (shared ones come from ctx.thresholds) --------------------------
UDP_MIN_UNREACHABLE = 3       # ICMP unreachables needed before a src->target pair counts as UDP probing
CRAFTED_MIN_PROBES = 10       # SYN probes needed before judging the "no MSS option" signal
CRAFTED_MIN_RATIO = 0.8       # share of SYN probes without an MSS option for the crafted indicator
FIXED_SPORT_MIN = 10          # distinct host:ports probed from one source port for that indicator
SEQUENTIAL_MIN_PORTS = 10     # ports needed before judging ascending probe order
SEQUENTIAL_MIN_RATIO = 0.9    # share of ascending steps for the sequential indicator
CRITICAL_OPEN_HOSTS = 5       # open services found on this many hosts -> critical
EPHEMERAL_MIN = 1024          # ports at or above this are dynamic / ephemeral
FTP_DATA_PORT = 20            # active-mode FTP data connections originate here
DYNAMIC_PORT_CONTROL = {21: "FTP", 135: "MS-RPC endpoint mapper"}  # control channels -> dynamic data ports
OPEN_EVIDENCE_PROBES = 25     # open-port probes put in evidence (up to 3 packets each)
FAILED_EVIDENCE_PROBES = 50   # failed probes put in evidence, sampled evenly across the scan
EVIDENCE_PER_OUTCOME = 5      # failed probes guaranteed per answer type (closed / filtered / no answer)
LIST_CAP = 12                 # items listed inline in plain-language text
HOSTS_CAP = 50                # targets listed in the hosts dict (true total in metrics)

STEALTH = {"FIN", "NULL", "XMAS", "FLAGS"}
TECHNIQUE_LABEL = {"FIN": "TCP FIN", "NULL": "TCP NULL (no flags)", "XMAS": "TCP XMAS (FIN+PSH+URG)",
                   "FLAGS": "TCP unusual-flag", "UDP": "UDP"}
ICMP4_CODES = {0: "network unreachable", 1: "host unreachable", 2: "protocol unreachable",
               3: "port unreachable", 9: "network administratively prohibited",
               10: "host administratively prohibited", 13: "administratively prohibited"}
ICMP6_CODES = {0: "no route", 1: "administratively prohibited", 3: "address unreachable",
               4: "port unreachable", 5: "source policy failed", 6: "reject route"}


@dataclass
class _Probe:
    ts: float
    src: str
    target: str
    proto: str                 # "tcp" or "udp"
    port: int
    technique: str             # "SYN", "FIN", "NULL", "XMAS", "FLAGS" or "UDP"
    outcome: str               # "open", "closed", "filtered", "open|filtered" or "session"
    used: bool                 # application data was exchanged (legitimate use)
    probe: PacketRecord
    sport: int | None = None
    reply: PacketRecord | None = None
    reply_text: str = ""
    followup: PacketRecord | None = None   # the prober's own packet after an "open" answer
    completed: bool = False    # prober completed the TCP handshake (connect scan)
    has_mss: bool = False

    @property
    def service(self) -> str:
        return f"{self.port}/{self.proto}"


# --- helpers -----------------------------------------------------------------------------------

def _flags(rec: PacketRecord) -> int:
    return rec.tcp_flags or 0


def _icmp_text(rec: PacketRecord) -> str:
    codes = ICMP6_CODES if rec.l4 == "ICMPv6" else ICMP4_CODES
    return f"ICMP {codes.get(rec.icmp_code, f'unreachable code {rec.icmp_code}')}"


def _fmt_duration(seconds: float) -> str:
    seconds = max(seconds, 0.0)
    if seconds < 1:
        return f"{seconds * 1000:.0f} ms"
    if seconds < 120:
        return f"{seconds:.1f} seconds"
    minutes, sec = divmod(int(round(seconds)), 60)
    if minutes < 120:
        return f"{minutes} min {sec} s"
    return f"{minutes // 60} h {minutes % 60} min"


def _join(items: list[str], cap: int = LIST_CAP) -> str:
    shown = ", ".join(items[:cap])
    return shown + (f" and {len(items) - cap} more" if len(items) > cap else "")


def _sample(items: list, cap: int) -> list:
    """Deterministic, evenly spread selection that always keeps the first and last item."""
    if len(items) <= cap:
        return list(items)
    if cap <= 1:
        return items[:cap]
    return [items[round(k * (len(items) - 1) / (cap - 1))] for k in range(cap)]


def _window(events: list[tuple[float, object, bool]], width: float,
            min_ratio: float) -> tuple[tuple[int, float, float, float] | None, int]:
    """Sliding window over (ts, key, used) events sorted by time.

    Returns (best qualifying window, peak distinct keys in any window). A window qualifies when
    the share of its distinct keys that never saw a successful session is >= ``min_ratio``;
    the best one has the most distinct keys: (distinct, failure_ratio, start_ts, end_ts).
    """
    counts: Counter = Counter()
    used_counts: Counter = Counter()
    used_keys = 0
    best: tuple[int, float, float, float] | None = None
    peak = 0
    i = 0
    for j, (ts, key, used) in enumerate(events):
        counts[key] += 1
        if used:
            used_counts[key] += 1
            if used_counts[key] == 1:
                used_keys += 1
        while ts - events[i][0] > width:
            old_ts, old_key, old_used = events[i]
            counts[old_key] -= 1
            if counts[old_key] == 0:
                del counts[old_key]
            if old_used:
                used_counts[old_key] -= 1
                if used_counts[old_key] == 0:
                    del used_counts[old_key]
                    used_keys -= 1
            i += 1
        distinct = len(counts)
        peak = max(peak, distinct)
        ratio = 1 - used_keys / distinct
        if ratio >= min_ratio and (best is None or distinct > best[0]):
            best = (distinct, ratio, events[i][0], ts)
    return best, peak


# --- probe extraction --------------------------------------------------------------------------

def _index_icmp(ctx: AnalysisContext):
    """ICMP errors keyed by the flow they quote: (src, sport, dst, dport)."""
    tcp_err: dict[tuple, tuple[PacketRecord, bool]] = {}
    udp_err: dict[tuple, tuple[PacketRecord, bool]] = {}
    te_pairs: set[tuple[str, str]] = set()
    for i, r in enumerate(ctx.icmp):
        if i % 5000 == 0:
            ctx.check_deadline()
        inner = r.icmp_inner
        if not isinstance(inner, dict):
            continue
        isrc, idst, proto = inner.get("src"), inner.get("dst"), inner.get("proto")
        if not isrc or not idst:
            continue
        v6 = r.l4 == "ICMPv6"
        if (not v6 and r.icmp_type == 11) or (v6 and r.icmp_type == 3):
            te_pairs.add((isrc, idst))          # traceroute / mtr hop answer
            continue
        if not ((not v6 and r.icmp_type == 3) or (v6 and r.icmp_type == 1)):
            continue
        if not v6 and r.icmp_code == 4:
            continue                            # fragmentation needed: an MTU signal, not reachability
        sport, dport = inner.get("sport"), inner.get("dport")
        if not isinstance(sport, int) or not isinstance(dport, int):
            continue
        port_unreach = r.icmp_code == (4 if v6 else 3)
        key = (isrc, sport, idst, dport)
        if proto == 6:
            tcp_err.setdefault(key, (r, port_unreach))
        elif proto == 17:
            udp_err.setdefault(key, (r, port_unreach))
    return tcp_err, udp_err, te_pairs


def _syn_probe(conn: TcpConnection, tcp_err: dict) -> _Probe | None:
    (src, sport), (target, port) = conn.client, conn.server
    if not src or not target or sport is None or port is None or src == target:
        return None
    syn = conn.syns[0]
    synack = conn.synacks[0] if conn.synacks else None
    after = [q for q in conn.packets if conn.from_client(q) and q.n > syn.n and not _flags(q) & SYN]
    completed = any(_flags(q) & ACK and not _flags(q) & RST for q in after)
    data = conn.client_bytes + conn.server_bytes > 0
    used = data and (synack is not None or completed)
    probe = _Probe(ts=syn.ts, src=src, target=target, proto="tcp", port=port, technique="SYN",
                   outcome="filtered", used=used, probe=syn, sport=sport, completed=completed,
                   has_mss=any(s.mss for s in conn.syns))
    if used:
        probe.outcome, probe.reply = "session", synack
        probe.reply_text = f"SYN/ACK: port {port} open (a real session followed)"
    elif synack is not None or completed:
        probe.outcome, probe.reply = "open", synack
        if synack is not None:
            probe.reply_text = f"SYN/ACK: port {port} open on {target}"
        follow = next((q for q in after if synack is None or q.n > synack.n), None)
        if follow is not None:
            probe.followup = follow
    else:
        rst = next((q for q in conn.packets if not conn.from_client(q) and _flags(q) & RST), None)
        if rst is not None:
            probe.outcome, probe.reply = "closed", rst
            probe.reply_text = f"RST: port {port} closed on {target}"
        else:
            err = tcp_err.get((src, sport, target, port))
            if err is not None:
                probe.reply = err[0]
                probe.outcome = "closed" if err[1] else "filtered"
                probe.reply_text = f"{_icmp_text(err[0])}: port {port} {probe.outcome}"
    return probe


def _stealth_probe(conn: TcpConnection, tcp_err: dict) -> _Probe | None:
    first = conn.packets[0]
    if first.tcp_flags is None or _flags(first) & (SYN | ACK | RST):
        return None
    src, sport, target, port = first.ip_src, first.sport, first.ip_dst, first.dport
    if not src or not target or sport is None or port is None or src == target:
        return None
    mine = [q for q in conn.packets if (q.ip_src, q.sport) == (src, sport)]
    # Every segment the prober sent must be flag-anomalous; otherwise this is a mid-stream
    # capture of an ordinary connection, not a probe.
    if any(q.tcp_flags is None or q.tcp_flags & (SYN | ACK | RST) for q in mine):
        return None
    base = first.tcp_flags & 0x3F
    technique = ("NULL" if base == 0 else "XMAS" if base & (FIN | PSH | URG) == FIN | PSH | URG
                 else "FIN" if base == FIN else "FLAGS")
    probe = _Probe(ts=first.ts, src=src, target=target, proto="tcp", port=port, technique=technique,
                   outcome="open|filtered", used=False, probe=first, sport=sport)
    rst = next((q for q in conn.packets if (q.ip_src, q.sport) == (target, port) and _flags(q) & RST), None)
    if rst is not None:
        probe.outcome, probe.reply = "closed", rst
        probe.reply_text = f"RST: port {port} closed on {target}"
    else:
        err = tcp_err.get((src, sport, target, port))
        if err is not None:
            probe.outcome, probe.reply = "filtered", err[0]
            probe.reply_text = f"{_icmp_text(err[0])}: port {port} filtered"
    return probe


def _tcp_probes(ctx: AnalysisContext, tcp_err: dict) -> list[_Probe]:
    out = []
    for i, conn in enumerate(ctx.connections):
        if i % 5000 == 0:
            ctx.check_deadline()
        if not conn.packets:
            continue
        probe = _syn_probe(conn, tcp_err) if conn.syns else _stealth_probe(conn, tcp_err)
        if probe is not None:
            out.append(probe)
    return out


def _is_response(key: tuple, first_seen: dict, ts: float) -> bool:
    src, sport, dst, dport = key
    reverse = first_seen.get((dst, dport, src, sport))
    if reverse is not None and reverse.ts <= ts:
        return True                      # the other side spoke first: this answers it
    return sport < EPHEMERAL_MIN <= dport  # service port -> ephemeral client port


def _udp_probes(ctx: AnalysisContext, udp_err: dict, te_pairs: set) -> list[_Probe]:
    if not udp_err:
        return []
    first_seen: dict[tuple, PacketRecord] = {}
    for i, r in enumerate(ctx.udp):
        if i % 5000 == 0:
            ctx.check_deadline()
        if r.ip_src and r.ip_dst and r.sport is not None and r.dport is not None:
            first_seen.setdefault((r.ip_src, r.sport, r.ip_dst, r.dport), r)
    answered: dict[tuple[str, str], set[int]] = defaultdict(set)
    for key, (rec, _) in udp_err.items():
        if not _is_response(key, first_seen, rec.ts):
            answered[(key[0], key[2])].add(key[3])
    pairs = {p for p, ports in answered.items()
             if len(ports) >= UDP_MIN_UNREACHABLE and p not in te_pairs and p[0] != p[1]}
    if not pairs:
        return []
    out: list[_Probe] = []
    for key, rec in first_seen.items():
        src, sport, dst, dport = key
        if (src, dst) not in pairs or _is_response(key, first_seen, rec.ts):
            continue
        probe = _Probe(ts=rec.ts, src=src, target=dst, proto="udp", port=dport, technique="UDP",
                       outcome="open|filtered", used=False, probe=rec, sport=sport)
        reply = first_seen.get((dst, dport, src, sport))
        err = udp_err.get(key)
        if reply is not None and reply.ts >= rec.ts:
            probe.outcome, probe.used, probe.reply = "open", True, reply
            probe.reply_text = f"UDP reply from port {dport}: open on {dst}"
        elif err is not None:
            probe.reply = err[0]
            probe.outcome = "closed" if err[1] else "filtered"
            probe.reply_text = f"{_icmp_text(err[0])}: UDP port {dport} {probe.outcome}"
        out.append(probe)
    # ICMP answers whose original datagram was not captured (asymmetric capture point).
    for key, (rec, port_unreach) in udp_err.items():
        src, sport, dst, dport = key
        if (src, dst) in pairs and key not in first_seen and not _is_response(key, first_seen, rec.ts):
            out.append(_Probe(ts=rec.ts, src=src, target=dst, proto="udp", port=dport, technique="UDP",
                              outcome="closed" if port_unreach else "filtered", used=False, probe=rec,
                              sport=sport, reply_text=f"{_icmp_text(rec)}: UDP port {dport} "
                                                      "(the probe itself was not captured)"))
    return out


def _exclude(probes: list[_Probe]) -> list[_Probe]:
    control = {(p.src, p.target) for p in probes
               if p.proto == "tcp" and p.port in DYNAMIC_PORT_CONTROL and p.used}
    kept = []
    for p in probes:
        if is_special(p.src) or is_special(p.target):
            continue
        if p.proto == "tcp" and p.sport == FTP_DATA_PORT:
            continue                         # active FTP data connection from the server
        if p.port >= EPHEMERAL_MIN and p.used:
            continue                         # completed dynamic-port session (FTP passive, RPC, P2P)
        if p.proto == "tcp" and p.port >= EPHEMERAL_MIN and (p.src, p.target) in control:
            continue                         # data port negotiated over a working control channel
        kept.append(p)
    return kept


def _resolved(ctx: AnalysisContext) -> dict[str, set[str]]:
    """Client IP -> addresses it received in DNS answers."""
    out: dict[str, set[str]] = defaultdict(set)
    for r in ctx.dns:
        d = r.dns or {}
        if d.get("qr") != 1 or not r.ip_dst:
            continue
        for a in d.get("answers") or []:
            if isinstance(a, dict) and a.get("type") in ("A", "AAAA") and a.get("value"):
                out[r.ip_dst].add(a["value"])
    return out


# --- per-source analysis -----------------------------------------------------------------------

def _analyse(ctx: AnalysisContext, src: str, probes: list[_Probe], resolved: set[str]) -> Finding | None:
    th = ctx.thresholds
    width, min_ratio = th.scan_window_seconds, th.scan_min_failure_ratio

    by_target: dict[str, list] = defaultdict(list)
    by_port: dict[tuple[str, int], list] = defaultdict(list)
    for p in probes:
        by_target[p.target].append((p.ts, (p.proto, p.port), p.used))
        if p.target not in resolved:
            by_port[(p.proto, p.port)].append((p.ts, p.target, p.used))

    vertical: dict[str, tuple] = {}
    peak_ports = 0
    for target, events in by_target.items():
        best, peak = _window(events, width, min_ratio)
        peak_ports = max(peak_ports, peak)
        if best and best[0] >= th.scan_vertical_ports:
            vertical[target] = best
    horizontal: dict[tuple[str, int], tuple] = {}
    peak_hosts = 0
    for key, events in by_port.items():
        best, peak = _window(events, width, min_ratio)
        peak_hosts = max(peak_hosts, peak)
        if best and best[0] >= th.scan_horizontal_hosts:
            horizontal[key] = best

    stealth_probes = [p for p in probes if p.technique in STEALTH]
    stealth_pairs = {(p.target, p.port) for p in stealth_probes}
    stealth = len(stealth_pairs) >= th.scan_stealth_min_ports

    pair_used: dict[tuple, bool] = {}
    for p in probes:
        k = (p.target, p.proto, p.port)
        pair_used[k] = pair_used.get(k, False) or p.used
    failed_pairs = [k for k, u in pair_used.items() if not u]
    failed_ports_per_target = Counter(t for t, _, _ in failed_pairs)
    failed_hosts_per_port = Counter((pr, po) for t, pr, po in failed_pairs if t not in resolved)
    slow = (not vertical and not horizontal and len(pair_used) >= th.scan_slow_total_ports
            and len(failed_pairs) / len(pair_used) >= min_ratio
            and (max(failed_ports_per_target.values(), default=0) >= th.scan_vertical_ports
                 or max(failed_hosts_per_port.values(), default=0) >= th.scan_horizontal_hosts))

    if not (vertical or horizontal or stealth or slow):
        return None

    # Scope: every probe that belongs to the scanning behaviour (not the source's normal use).
    scan_targets = {t for t, n in failed_ports_per_target.items() if n >= 2}
    scan_ports = {k for k, n in failed_hosts_per_port.items() if n >= 2}

    def in_scope(p: _Probe) -> bool:
        if p.target in vertical or (stealth and p.technique in STEALTH):
            return True
        if (p.proto, p.port) in horizontal and p.target not in resolved:
            return True
        return slow and (p.target in scan_targets
                         or ((p.proto, p.port) in scan_ports and p.target not in resolved))

    scope = [p for p in probes if in_scope(p)]
    if not scope:
        return None
    scope.sort(key=lambda p: (p.ts, p.probe.n))

    pairs: dict[tuple, bool] = {}
    for p in scope:
        k = (p.target, p.proto, p.port)
        pairs[k] = pairs.get(k, False) or p.used
    per_target = Counter(k[0] for k in pairs)
    targets = sorted(per_target, key=lambda t: (-per_target[t], t))
    services = sorted({(p.proto, p.port) for p in scope}, key=lambda s: (s[0] != "tcp", s[1]))
    failure_ratio = sum(not u for u in pairs.values()) / len(pairs)
    start, end = scope[0].ts, scope[-1].ts
    duration = end - start
    rate = len(scope) / duration if duration > 0 else float(len(scope))
    outcomes = Counter(p.outcome for p in scope)

    bursts: list[dict] = []
    for p in scope:
        if bursts and p.ts - bursts[-1]["end"] <= width:
            bursts[-1]["end"] = p.ts
            bursts[-1]["probes"] += 1
        else:
            bursts.append({"start": p.ts, "end": p.ts, "probes": 1})

    found: dict[str, set[tuple[str, int]]] = defaultdict(set)
    for p in scope:
        if p.outcome in ("open", "session"):
            found[p.target].add((p.proto, p.port))
    open_ports = {t: [f"{po}/{pr}" for pr, po in sorted(found[t], key=lambda s: (s[0] != "tcp", s[1]))]
                  for t in sorted(found)}

    syn_probes = [p for p in scope if p.technique == "SYN"]
    half_open = [p for p in syn_probes if p.outcome == "open" and not p.completed and p.followup is not None
                 and _flags(p.followup) & RST]
    connect = [p for p in syn_probes if p.outcome == "open" and p.completed]
    types: list[str] = []
    if half_open:
        types.append("TCP SYN half-open")
    if connect:
        types.append("TCP connect")
    if syn_probes and not half_open and not connect:
        types.append("TCP SYN")
    for tech in ("FIN", "NULL", "XMAS", "FLAGS", "UDP"):
        if any(p.technique == tech for p in scope):
            types.append(TECHNIQUE_LABEL[tech])

    # --- indicators ----------------------------------------------------------------------
    indicators: list[Indicator] = []
    facts: list[str] = []
    triggers: list[str] = []
    if vertical:
        triggers.append("vertical")
        t, (n, r, ws, we) = max(vertical.items(), key=lambda kv: (kv[1][0], kv[0]))
        indicators.append(Indicator(
            f"{n} different ports on {t} were probed within {_fmt_duration(we - ws)} and {r:.0%} of them "
            "never carried any data (normal clients use the services they connect to)", ATTACK, "strong"))
        facts.append(f"Peak rate: {n} distinct ports on {t} inside one {width:.0f}-second window "
                     f"(threshold {th.scan_vertical_ports}).")
    if horizontal:
        triggers.append("horizontal")
        (pr, po), (n, r, ws, we) = max(horizontal.items(), key=lambda kv: (kv[1][0], -kv[0][1]))
        indicators.append(Indicator(
            f"Port {po}/{pr} was probed on {n} different hosts within {_fmt_duration(we - ws)} and {r:.0%} "
            "of those attempts never carried data, and none of the hosts had been looked up in DNS",
            ATTACK, "strong"))
        facts.append(f"Peak rate: port {po}/{pr} on {n} distinct hosts inside one {width:.0f}-second "
                     f"window (threshold {th.scan_horizontal_hosts}).")
    if stealth:
        triggers.append("stealth")
        kinds = Counter(p.technique for p in stealth_probes)
        label = ", ".join(f"{c} {TECHNIQUE_LABEL[k]}" for k, c in sorted(kinds.items()))
        indicators.append(Indicator(
            f"{len(stealth_probes)} probes ({label}) used TCP flag combinations that no normal TCP stack "
            "sends; they are only used to slip past firewalls and fingerprint hosts", ATTACK, "strong"))
        facts.append(f"Stealth probes: {label} to {len(stealth_pairs)} distinct host:port combinations.")
    if slow:
        triggers.append("slow")
        indicators.append(Indicator(
            f"{len(pairs)} host:port combinations were probed over {_fmt_duration(duration)}: too slowly to "
            f"cross the {width:.0f}-second window threshold, but a scan in scope and structure "
            "(classic 'slow scan' to stay below IDS rate limits)", ATTACK, "moderate"))
        facts.append(f"Slow scan: never more than {peak_ports} ports on one host or {peak_hosts} hosts on one "
                     f"port per {width:.0f} s, yet {len(pairs)} host:port combinations overall "
                     f"(threshold {th.scan_slow_total_ports}).")
    if half_open:
        indicators.append(Indicator(
            f"{len(half_open)} SYN/ACK answer(s) were immediately reset by the source instead of completing "
            "the handshake: the SYN 'half-open' scanning technique, which avoids application logs",
            ATTACK, "moderate"))
    no_mss = [p for p in syn_probes if not p.has_mss]
    if len(syn_probes) >= CRAFTED_MIN_PROBES and len(no_mss) / len(syn_probes) >= CRAFTED_MIN_RATIO:
        indicators.append(Indicator(
            f"{len(no_mss)} of {len(syn_probes)} SYN probes carry no MSS option, which every operating-system "
            "TCP stack sends: the packets were crafted by a raw-packet scanning tool", ATTACK, "moderate"))
        facts.append(f"{len(no_mss)} of {len(syn_probes)} SYN probes have no TCP MSS option.")
    sport_targets: dict[int, set] = defaultdict(set)
    for p in scope:
        if p.proto == "tcp" and p.sport is not None:
            sport_targets[p.sport].add((p.target, p.port))
    if sport_targets:
        sp, used_by = max(sport_targets.items(), key=lambda kv: (len(kv[1]), -kv[0]))
        if len(used_by) >= FIXED_SPORT_MIN:
            indicators.append(Indicator(
                f"Source port {sp} was reused for {len(used_by)} different host:port probes; operating systems "
                "pick a new ephemeral port per connection", ATTACK, "weak"))
    ascending = total_steps = 0
    orders: dict[str, list[int]] = defaultdict(list)
    seen_ports: set[tuple[str, int]] = set()
    for p in scope:
        if p.proto == "tcp" and (p.target, p.port) not in seen_ports:
            seen_ports.add((p.target, p.port))
            orders[p.target].append(p.port)
    for order in orders.values():
        if len(order) >= SEQUENTIAL_MIN_PORTS:
            total_steps += len(order) - 1
            ascending += sum(b > a for a, b in zip(order, order[1:]))
    if total_steps and ascending / total_steps >= SEQUENTIAL_MIN_RATIO:
        indicators.append(Indicator("Ports were probed in ascending numerical order, typical of a scanning "
                                    "script", ATTACK, "weak"))

    assessment = assess(indicators)
    open_hosts = len(open_ports)
    severity = ("critical" if open_hosts >= CRITICAL_OPEN_HOSTS else "high") if assessment == ATTACK else "medium"
    sweep = "horizontal" in triggers and set(triggers) <= {"horizontal", "slow"}
    kind = "HOST_SWEEP" if sweep else "PORT_SCAN"

    # --- plain-language text -------------------------------------------------------------
    service_list = [f"{po}/{pr}" for pr, po in services]
    type_text = " + ".join(types) if types else "TCP"
    open_text = ("; ".join(f"{', '.join(v)} on {t}" for t, v in list(open_ports.items())[:LIST_CAP])
                 + (f"; and {open_hosts - LIST_CAP} more hosts" if open_hosts > LIST_CAP else ""))
    if kind == "HOST_SWEEP":
        (pr, po) = max(horizontal, key=lambda k: (horizontal[k][0], -k[1]))
        hosts_on = sorted({p.target for p in scope if (p.proto, p.port) == (pr, po)})
        title = f"Host sweep from {src}: port {po}/{pr} probed on {len(hosts_on)} hosts"
        summary = (f"{src} checked whether port {po}/{pr} is open on {len(hosts_on)} different hosts "
                   f"({len(scope)} probes in {_fmt_duration(duration)}, {rate:.1f} per second). ")
    else:
        title = (f"Port scan from {src}: {len(services)} ports on {len(targets)} host"
                 f"{'s' if len(targets) != 1 else ''}")
        summary = (f"{src} sent {len(scope)} probes to {len(pairs)} host:port combinations - "
                   f"{len(services)} different port(s) on {len(targets)} host(s) - over "
                   f"{_fmt_duration(duration)} ({rate:.1f} probes per second). ")
    summary += (f"Technique: {type_text}. {failure_ratio:.0%} of the probed ports never carried any data, so "
                "these were not real connections: the source was checking which services exist. ")
    summary += (f"The scan found open services: {open_text}." if open_ports else
                "No open service was found (every probe was refused or went unanswered).")
    if len(bursts) > 1:
        summary += f" The probing came in {len(bursts)} separate bursts."

    facts.insert(0, f"{len(scope)} probes from {src} to {len(pairs)} host:port combinations: "
                    f"{len(services)} distinct ports ({_join(service_list)}) on {len(targets)} host(s) "
                    f"({_join(targets)}).")
    facts.insert(1, f"Answers: {outcomes.get('open', 0)} open (SYN/ACK or UDP reply), "
                    f"{outcomes.get('closed', 0)} closed (RST or ICMP port unreachable), "
                    f"{outcomes.get('filtered', 0)} filtered (no answer or ICMP prohibited), "
                    f"{outcomes.get('open|filtered', 0)} unanswered stealth/UDP probes (open or filtered), "
                    f"{outcomes.get('session', 0)} followed by a real data session.")
    facts.insert(2, f"Duration {_fmt_duration(duration)}, average {rate:.1f} probes per second; "
                    f"{failure_ratio:.0%} of probed host:ports never carried data "
                    f"(threshold {min_ratio:.0%}).")
    if len(bursts) > 1:
        facts.append("Bursts: " + "; ".join(
            f"{b['probes']} probes at +{b['start'] - ctx.start_ts:.1f}s for {_fmt_duration(b['end'] - b['start'])}"
            for b in bursts[:LIST_CAP]))
    for t, v in list(open_ports.items())[:LIST_CAP]:
        facts.append(f"Open on {t}: {', '.join(v)}.")

    recommendations = [
        f"Ask IT / the security team whether {src} is an approved scanner or inventory tool and whether a "
        "scan was scheduled at this time.",
        f"If it is not approved, locate the device (its MAC address and switch port) and isolate it; check it "
        "for malware or an unauthorised user.",
    ]
    if open_ports:
        recommendations.append(f"Review the services the scan found ({open_text}): disable the ones not needed, "
                               "patch the rest and restrict who may reach them with firewall rules.")
    recommendations.append(f"Check the logs of the scanned hosts for login attempts or exploits from {src} "
                           "after the scan ended - scans usually precede an attack.")
    recommendations.append("Enable scan detection / rate limiting on the firewall or IDS so future scans "
                           "raise an alert automatically.")

    # --- evidence ------------------------------------------------------------------------
    evidence: list[Evidence] = []
    open_probes = [p for p in scope if p.outcome in ("open", "session")]
    for p in _sample(open_probes, OPEN_EVIDENCE_PROBES):
        if p.outcome == "session":
            if p.reply is not None:
                evidence.append(Evidence(p.reply.n, p.reply_text))
            continue
        evidence.append(Evidence(p.probe.n, f"probe to {p.target} port {p.service} (open)"))
        if p.reply is not None:
            evidence.append(Evidence(p.reply.n, p.reply_text))
        if p.followup is not None:
            role = ("scanner completed the handshake, then dropped it (connect scan)" if p.completed else
                    f"scanner reset port {p.port} without completing the handshake (half-open scan)")
            evidence.append(Evidence(p.followup.n, role))
    failed = [p for p in scope if p.outcome not in ("open", "session")]
    # Every kind of answer (closed / filtered / unanswered) is represented, then the rest of the
    # budget is spread evenly over the scan so the evidence shows its whole time span.
    chosen: dict[int, _Probe] = {}
    for outcome in ("closed", "filtered", "open|filtered"):
        for p in _sample([q for q in failed if q.outcome == outcome], EVIDENCE_PER_OUTCOME):
            chosen[p.probe.n] = p
    rest = [p for p in failed if p.probe.n not in chosen]
    for p in _sample(rest, max(FAILED_EVIDENCE_PROBES - len(chosen), 0)):
        chosen[p.probe.n] = p
    for p in sorted(chosen.values(), key=lambda q: q.probe.n):
        label = TECHNIQUE_LABEL.get(p.technique, "SYN")
        note = {"closed": "closed", "filtered": "filtered, no answer" if p.reply is None else "filtered",
                "open|filtered": "no answer: open or filtered"}.get(p.outcome, p.outcome)
        evidence.append(Evidence(p.probe.n, f"{label} probe to {p.target} port {p.service} ({note})"))
        if p.reply is not None and p.reply is not p.probe:
            evidence.append(Evidence(p.reply.n, p.reply_text))

    hosts: dict[str, list[str]] = {"scanner": [src], "target": targets[:HOSTS_CAP]}
    macs = ctx.ip_macs.get(src)
    if macs:
        mac = macs.most_common(1)[0][0]
        if mac not in ctx.router_macs:
            hosts["scanner_mac"] = [mac]

    alternatives = [f"An authorised vulnerability scanner, asset-inventory or network-monitoring tool running on "
                    f"{src} produces exactly this traffic - confirm with IT before treating it as hostile."]
    if kind == "HOST_SWEEP":
        alternatives.append(f"A management or backup tool that checks port {services[0][1]} on every host can "
                            "look like a sweep; such tools usually complete their sessions.")
    limitations = [
        "Packets cannot show whether the scan was authorised.",
        "Answers dropped before the capture point make ports look filtered; only what this capture point "
        "saw is counted.",
    ]
    if any(p.proto == "udp" for p in scope):
        limitations.append("UDP probes are recognised through ICMP answers, which hosts rate-limit, so the "
                           "real number of UDP ports probed may be higher.")
    if stealth:
        limitations.append("Unanswered FIN/NULL/XMAS probes cannot distinguish an open port from a filtered "
                           "one (that is why attackers use them).")

    rule = (f"Probes from one source (SYN / FIN / NULL / XMAS / UDP answered by ICMP): >= {th.scan_vertical_ports} "
            f"ports on one host or >= {th.scan_horizontal_hosts} hosts on one port within "
            f"{width:.0f} s, or >= {th.scan_slow_total_ports} host:ports overall, with >= {min_ratio:.0%} never "
            f"carrying data; or >= {th.scan_stealth_min_ports} stealth-flag probes")

    return Finding(
        detector=NAME, kind=kind, title=title, category="attack", assessment=assessment,
        severity=severity,
        evidence_strength="strong" if any(i.strength == "strong" for i in indicators) else "moderate",
        summary=summary,
        impact=("The scanning host now knows which services are reachable" +
                (f" ({open_text})" if open_ports else "") +
                ". A scan does no damage by itself, but it is normally the reconnaissance step before "
                "an attack on the services it found."),
        likely_cause=(f"A port-scanning tool (for example nmap or masscan) running on {src}: either an "
                      "authorised security or inventory scan, or an unauthorised / compromised device mapping "
                      "the network."),
        recommendations=recommendations, facts=facts, alternatives=alternatives, limitations=limitations,
        indicators=indicators, hosts=hosts, time_start=start, time_end=end, evidence=evidence,
        metrics={
            "probes": len(scope), "distinct_ports": len(services), "distinct_targets": len(targets),
            "host_port_pairs": len(pairs), "duration_seconds": round(duration, 3),
            "probes_per_second": round(rate, 2), "failure_ratio": round(failure_ratio, 3),
            "outcomes": {k: outcomes.get(k, 0) for k in ("open", "closed", "filtered", "open|filtered", "session")},
            "scan_types": types, "open_ports": open_ports, "open_hosts": open_hosts,
            "triggers": triggers, "bursts": len(bursts),
            "burst_detail": [{"start": b["start"], "end": b["end"], "probes": b["probes"]} for b in bursts],
            "peak_ports_in_window": peak_ports, "peak_hosts_in_window": peak_hosts,
            "window_seconds": width, "stealth_probes": len(stealth_probes),
        },
        rule=rule)


def detect(ctx: AnalysisContext) -> list[Finding]:
    tcp_err, udp_err, te_pairs = _index_icmp(ctx)
    probes = _exclude(_tcp_probes(ctx, tcp_err) + _udp_probes(ctx, udp_err, te_pairs))
    by_src: dict[str, list[_Probe]] = defaultdict(list)
    for p in probes:
        by_src[p.src].append(p)
    resolved = _resolved(ctx)
    findings = []
    for src in sorted(by_src):
        ctx.check_deadline()
        items = sorted(by_src[src], key=lambda p: (p.ts, p.probe.n))
        finding = _analyse(ctx, src, items, resolved.get(src, set()))
        if finding is not None:
            findings.append(finding)
    return findings
