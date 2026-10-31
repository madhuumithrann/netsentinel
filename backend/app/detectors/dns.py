"""DNS fault and attack analysis.

Objective
    Explain why name resolution fails or is slow, and spot forged DNS answers, while blaming
    the right party: a failed lookup is attributed to the *client* that asked (NXDOMAIN) or
    to the *server* that failed to answer (timeouts, SERVFAIL, REFUSED, slowness).

Algorithm
    1. Transaction matching (single pass in capture order, O(n)).
       A query opens a transaction keyed by (client IP, client port, server IP, txid) with
       its question name. A response matches when (response dst, dst port, response src,
       txid) equals that key and its question name agrees (a response without a question
       section, which some servers send with REFUSED / FORMERR, matches on the key alone).
       Re-sent queries with the same key and name within ``RETRY_WINDOW`` seconds are
       retries of the same transaction. A response that matches (client, port, txid, name)
       but comes from a *different* source address is an "answer from a server the client
       did not query". Anything else is unmatched. Only records the decoder parsed as DNS
       on UDP/TCP are used; ICMP errors that quote a DNS packet are never decoded as DNS,
       and multicast DNS / LLMNR (ports 5353 / 5355, multicast destinations) is excluded
       because it is unsolicited by design. Capture duplicates (same packet seen twice
       within ``duplicate_capture_window`` with the same IP ID) are dropped.
    2. Fault rules (category "fault")
       * DNS_SERVER_UNRESPONSIVE - per server: >= ``dns_min_failures`` transactions with no
         answer at all, counting only queries that have >= ``dns_timeout_seconds`` of capture
         after them, and either a majority of that server's eligible transactions
         unanswered or a run of >= ``OUTAGE_RUN_MIN`` consecutive unanswered transactions
         (an outage window inside an otherwise healthy capture).
       * DNS_SERVER_FAILURE - per (server, rcode): >= ``dns_min_failures`` transactions
         answered SERVFAIL (upstream resolution / DNSSEC broken) or REFUSED (the server
         will not recurse for this client: wrong DNS server configured). When the failures
         concern <= ``NAME_SPECIFIC_MAX`` names while the same server resolves others, the
         problem is reported as domain-specific.
       * DNS_NXDOMAIN - per *client* (the query sender): >= ``dns_nxdomain_min`` lookups
         answered NXDOMAIN (reverse ``.arpa`` lookups excluded). The names are classified as
         search-domain expansion (same first label tried with several suffixes, or
         single-label names), typos (Damerau distance <= 2 from a name that resolved in this
         capture) or repeated lookups of one broken name.
       * DNS_SLOW_RESPONSES - per server: >= ``dns_min_slow`` answers slower than
         ``dns_slow_seconds`` that are also >= ``SLOW_MIN_SHARE`` of its answers, compared
         with the other resolvers in the capture (median / p95 / max).
    3. Attack rules (category "attack")
       * DNS_DGA_PATTERN - one client receives NXDOMAIN for >= ``DGA_MIN_UNIQUE`` unique
         random-looking names (first label >= ``DGA_MIN_LEN`` characters with Shannon
         entropy >= ``dns_random_name_entropy`` bits/char) spread over >= ``DGA_MIN_DOMAINS``
         different registrable domains. Domain-generation-algorithm malware does exactly
         this while looking for its command-and-control server.
       * DNS_HIJACK_SUSPECTED - grouped per claimed server address, built from indicators:
           strong   conflicting duplicate answers: one transaction answered twice with
                    disjoint address sets (or an address vs NXDOMAIN). Strong when the
                    answers outnumber the queries or their IP TTL / source MAC differ;
                    moderate when every retry got its own answer (load-balanced server).
           strong   IP-TTL anomaly: a suspect response (conflicting, unsolicited, from an
                    unqueried server or contradicting the server's earlier answer for the
                    name) whose IP TTL differs by >= ``TTL_DELTA`` from the median TTL of
                    that server's normal answers (needs >= ``BASELINE_MIN`` of them).
           strong   transaction-ID brute force: >= ``BRUTE_FORCE_TXIDS`` unsolicited answers
                    for one name to one client with different txids (blind spoofing).
           moderate >= ``UNSOLICITED_MIN`` unsolicited answers (no matching query).
           moderate answers from a server the client did not query, carrying the right
                    txid and port (the sender can see the queries).
           moderate a suspect response arriving from a different Ethernet source MAC than
                    the server's normal answers.
           moderate the resolver is not in the DHCP-offered DNS list (when DHCP was seen)
                    and gives disjoint answers from the offered resolver for the same name.
           weak     a public-looking name answered with a private / loopback address in a
                    suspect response (split-horizon DNS does this legitimately).
         ``assess()`` turns these into a verdict; the finding is only emitted when the
         verdict is ATTACK, or INCONCLUSIVE with a moderate+ indicator that is not the
         DHCP-list one (different public resolvers legitimately return different CDN
         addresses, so that indicator never stands alone).

Limitations
    Only what the capture point sees: queries answered from a client's local cache never
    appear, responses lost on the return path look like server silence, and an on-path
    attacker who drops the genuine answer (full man-in-the-middle) leaves no race to see.
    DNS over HTTPS / TLS / QUIC is encrypted and invisible here. The random-name test is
    deliberately conservative: short DGA names (< 10 characters) are not flagged.
"""
from __future__ import annotations

import ipaddress
import math
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from statistics import median

from ..context import AnalysisContext
from ..model import ATTACK, BENIGN, FAULT, INCONCLUSIVE, Evidence, Finding, Indicator, PacketRecord, assess

NAME = "dns"

# --- detector-local thresholds (documented; global ones come from ctx.thresholds) -----------
EVIDENCE_CAP = 80            # packets of evidence per finding (true totals go in metrics)
RETRY_WINDOW = 10.0          # same key + name re-sent within this many seconds is a retry
REUSE_AFTER_ANSWER = 1.0     # same key queried again > this long after an answer = new lookup
TTL_DELTA = 5                # IP TTL difference that suggests a different sending device
BASELINE_MIN = 3             # normal answers needed before a server's TTL / MAC is trusted
UNSOLICITED_MIN = 3          # unsolicited answers before they count as an indicator
BRUTE_FORCE_TXIDS = 10       # distinct txids for one name to one client = blind spoofing
SLOW_MIN_SHARE = 0.2         # slow answers must also be this share of a server's answers
OUTAGE_RUN_MIN = 5           # consecutive unanswered lookups that form an outage window
NAME_SPECIFIC_MAX = 2        # SERVFAIL/REFUSED for at most this many names = domain-specific
DGA_MIN_LEN = 10             # first-label length for the random-name test
DGA_MIN_UNIQUE = 10          # unique random-looking NXDOMAIN names per client
DGA_MIN_DOMAINS = 5          # ... spread over at least this many registrable domains
TYPO_MAX_DISTANCE = 2        # Damerau-Levenshtein distance for "looks like a typo"
TYPO_MIN_LEN = 6             # shorter names are too ambiguous for typo matching
TYPO_MAX_NAMES = 300         # bound the typo search (unique NXDOMAIN names compared)
REPEAT_NAME_MEDIUM = 5       # one name failing this often = an application in a retry loop
LOCAL_SUFFIXES = (".local", ".lan", ".home", ".internal", ".corp", ".arpa", ".localdomain",
                  ".intranet", ".private", ".test", ".invalid", ".localhost")
MDNS_PORTS = {5353, 5355}
RCODE_NAMES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
SECOND_LEVEL = {"co", "com", "net", "org", "gov", "ac", "edu", "ne", "or", "go"}


# --- small helpers -------------------------------------------------------------------------

def _ip(value: str | None):
    try:
        return ipaddress.ip_address(value) if value else None
    except ValueError:
        return None


def _multicast_or_broadcast(ip: str | None) -> bool:
    addr = _ip(ip)
    if addr is None:
        return True
    return addr.is_multicast or addr.is_unspecified or ip == "255.255.255.255"


def _private_answer(value: str) -> bool:
    """Private, loopback or link-local address. 0.0.0.0 / :: are sinkhole answers, not private."""
    addr = _ip(value)
    if addr is None or addr.is_unspecified:
        return False
    return addr.is_private or addr.is_loopback or addr.is_link_local


def _public_looking(name: str | None) -> bool:
    if not name or "." not in name:
        return False
    return not name.endswith(LOCAL_SUFFIXES)


def _registrable(name: str) -> str:
    labels = [x for x in name.split(".") if x]
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in SECOND_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def _random_looking(name: str, min_entropy: float) -> bool:
    if "." not in name:
        return False          # single-label probes (e.g. browser intranet checks) are excluded
    first = name.split(".", 1)[0]
    return len(first) >= DGA_MIN_LEN and _entropy(first) >= min_entropy


def _osa_distance(a: str, b: str, limit: int) -> int:
    """Optimal-string-alignment (Damerau) distance, abandoned early once it exceeds ``limit``."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev2: list[int] | None = None
    prev = list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        cur = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if prev2 is not None and i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        if min(cur) > limit:
            return limit + 1
        prev2, prev = prev, cur
    return prev[-1]


def _rcode(rec: PacketRecord) -> int | None:
    rc = (rec.dns or {}).get("rcode")
    return rc if isinstance(rc, int) else None


def _addresses(rec: PacketRecord) -> frozenset[str]:
    """A/AAAA values of a response; CNAME targets when it carries no addresses."""
    answers = (rec.dns or {}).get("answers") or []
    addrs = frozenset(a.get("value") for a in answers if a.get("type") in ("A", "AAAA") and a.get("value"))
    if addrs:
        return addrs
    return frozenset(a.get("value") for a in answers if a.get("type") == "CNAME" and a.get("value"))


def _describe_answer(rec: PacketRecord) -> str:
    rc = _rcode(rec)
    if rc != 0:
        return RCODE_NAMES.get(rc, f"rcode {rc}")
    addrs = sorted(_addresses(rec))
    return ", ".join(addrs[:4]) + (" ..." if len(addrs) > 4 else "") if addrs else "no addresses"


def _conflict(a: PacketRecord, b: PacketRecord) -> bool:
    """Two answers to the same question that cannot both be true.

    Overlapping address sets (round-robin rotation, subsets from a load-balanced server) and
    SERVFAIL / REFUSED mixes (a forwarder that failed then succeeded) are not conflicts.
    """
    ra, rb = _rcode(a), _rcode(b)
    if ra not in (0, 3) or rb not in (0, 3) or ra == rb == 3:
        return False
    aa, ab = _addresses(a), _addresses(b)
    if ra == rb == 0:
        return bool(aa) and bool(ab) and aa.isdisjoint(ab)
    return bool(aa if ra == 0 else ab)


def _pct(values: list[float], q: float) -> float:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(round(q * (len(ordered) - 1))))]


def _ms(seconds: float) -> str:
    return f"{seconds * 1000:.0f} ms" if seconds < 10 else f"{seconds:.1f} s"


def _short_list(items, limit: int = 10) -> str:
    items = list(items)
    return ", ".join(str(i) for i in items[:limit]) + (f" ... (+{len(items) - limit} more)" if len(items) > limit else "")


# --- transaction reconstruction ------------------------------------------------------------

@dataclass(eq=False)
class _Txn:
    client: str
    port: int
    server: str
    txid: int
    qname: str | None
    qtype: str | None
    queries: list[PacketRecord] = field(default_factory=list)
    responses: list[PacketRecord] = field(default_factory=list)   # from the queried server
    foreign: list[PacketRecord] = field(default_factory=list)     # same txid/port, other source

    @property
    def answer(self) -> PacketRecord | None:
        return self.responses[0] if self.responses else None

    def latency(self) -> float | None:
        resp = self.answer
        if resp is None:
            return None
        prior = [q for q in self.queries if q.n < resp.n]
        query = prior[-1] if prior else self.queries[0]
        return max(0.0, resp.ts - query.ts)

    @property
    def label(self) -> str:
        return f"{self.qname or '?'} (txid {self.txid})"


@dataclass
class _State:
    txns: list[_Txn]
    unsolicited: list[PacketRecord]
    foreign: list[tuple[PacketRecord, _Txn]]
    ignored_unmatched: int
    duplicates: int


def _match(cands: list[_Txn] | None, qname: str | None) -> _Txn | None:
    for txn in reversed(cands or []):
        if qname is None or txn.qname is None or txn.qname == qname:
            return txn
    return None


def _build(ctx: AnalysisContext) -> _State:
    th = ctx.thresholds
    txns: list[_Txn] = []
    by_key: dict[tuple, list[_Txn]] = {}
    by_alt: dict[tuple, list[_Txn]] = {}
    unmatched: list[PacketRecord] = []
    foreign: list[tuple[PacketRecord, _Txn]] = []
    query_clients: set[str] = set()
    last_seen: dict[tuple, tuple[float, int | None]] = {}
    duplicates = 0
    for i, rec in enumerate(ctx.dns):
        if i % 2000 == 0:
            ctx.check_deadline()
        d = rec.dns
        if not d or rec.l4 not in ("UDP", "TCP") or not rec.ip_src or not rec.ip_dst:
            continue
        if rec.sport is None or rec.dport is None or rec.sport in MDNS_PORTS or rec.dport in MDNS_PORTS:
            continue
        if _multicast_or_broadcast(rec.ip_dst):
            continue
        txid, qr = d.get("id"), d.get("qr")
        if not isinstance(txid, int) or qr not in (0, 1):
            continue
        qname = d.get("qname") or None
        sig = (rec.ip_src, rec.sport, rec.ip_dst, rec.dport, txid, qr, qname)
        prev = last_seen.get(sig)
        last_seen[sig] = (rec.ts, rec.ip_id)
        if prev is not None and rec.ts - prev[0] <= th.duplicate_capture_window and prev[1] == rec.ip_id:
            duplicates += 1
            continue
        if qr == 0:
            key = (rec.ip_src, rec.sport, rec.ip_dst, txid)
            query_clients.add(rec.ip_src)
            txn = None
            cands = by_key.get(key)
            if cands:
                last = cands[-1]
                answered_long_ago = bool(last.responses) and rec.ts - last.responses[-1].ts > REUSE_AFTER_ANSWER
                if last.qname == qname and rec.ts - last.queries[-1].ts <= RETRY_WINDOW and not answered_long_ago:
                    txn = last
            if txn is None:
                txn = _Txn(rec.ip_src, rec.sport, rec.ip_dst, txid, qname, d.get("qtype"))
                txns.append(txn)
                by_key.setdefault(key, []).append(txn)
                by_alt.setdefault((rec.ip_src, rec.sport, txid, qname), []).append(txn)
            txn.queries.append(rec)
            continue
        txn = _match(by_key.get((rec.ip_dst, rec.dport, rec.ip_src, txid)), qname)
        if txn is not None:
            txn.responses.append(rec)
            continue
        alt = by_alt.get((rec.ip_dst, rec.dport, txid, qname)) if qname else None
        if alt:
            alt[-1].foreign.append(rec)
            foreign.append((rec, alt[-1]))
            continue
        unmatched.append(rec)
    # An unmatched answer only counts as "unsolicited" when we can see that client's queries
    # (otherwise the capture may simply miss one direction), it arrives after the first
    # timeout period (earlier ones may answer queries sent before the capture started) and it
    # actually carries answer records (garbage on port 53 does not).
    unsolicited = [r for r in unmatched
                   if r.ip_dst in query_clients and r.ts - ctx.start_ts >= th.dns_timeout_seconds
                   and _addresses(r) and (r.dns or {}).get("qname")]
    return _State(txns, unsolicited, foreign, len(unmatched) - len(unsolicited), duplicates)


# --- fault: unresponsive server ------------------------------------------------------------

def _unresponsive(ctx: AnalysisContext, st: _State, by_client_name: dict) -> list[Finding]:
    th = ctx.thresholds
    per_server: dict[str, list[_Txn]] = defaultdict(list)
    for t in st.txns:
        per_server[t.server].append(t)
    findings: list[Finding] = []
    sources: set[str] | None = None
    for server, items in per_server.items():
        eligible = [t for t in items
                    if t.responses or t.foreign or ctx.end_ts - t.queries[0].ts >= th.dns_timeout_seconds]
        unanswered = [t for t in eligible if not t.responses and not t.foreign]
        if len(unanswered) < th.dns_min_failures:
            continue
        majority = len(unanswered) / len(eligible) > 0.5
        run, best, best_run = [], 0, []
        for t in eligible:
            if not t.responses and not t.foreign:
                run.append(t)
                if len(run) > best:
                    best, best_run = len(run), list(run)
            else:
                run = []
        if not majority and best < OUTAGE_RUN_MIN:
            continue
        window = unanswered if majority else best_run
        ctx.check_deadline()
        if sources is None:
            sources = {r.ip_src for r in ctx.records if r.ip_src}
        start, end = window[0].queries[0].ts, window[-1].queries[-1].ts
        answered = [t for t in eligible if t.responses]
        before = [t for t in answered if t.answer.ts < start]
        after = [t for t in answered if t.answer.ts > end]
        clients = sorted({t.client for t in window})
        queries = sum(len(t.queries) for t in window)
        retries = queries - len(window)
        names = Counter(t.qname or "?" for t in window)
        reasks = sum(1 for (c, n), v in Counter((t.client, t.qname) for t in window).items() if v > 1)
        fallback = set()
        for t in window:
            for other in by_client_name.get((t.client, t.qname), []):
                if other.server != server and other.responses and other.queries[0].ts >= t.queries[0].ts:
                    fallback.add(other.server)
        never_seen = server not in sources
        rel = lambda ts: f"+{ts - ctx.start_ts:.1f}s"  # noqa: E731

        indicators = [Indicator(f"{len(window)} lookups sent to {server} got no answer within "
                                f"{th.dns_timeout_seconds:g} s ({len(unanswered)} of {len(eligible)} "
                                "eligible lookups overall)", FAULT,
                                "strong" if majority and len(unanswered) >= 2 * th.dns_min_failures else "moderate")]
        if retries or reasks:
            what = " and ".join(x for x in (f"re-sent {retries} queries" if retries else "",
                                            f"asked again for {reasks} name(s)" if reasks else "") if x)
            indicators.append(Indicator(f"Clients {what} - normal resolver behaviour when a server stays silent",
                                        FAULT, "moderate"))
        if before:
            indicators.append(Indicator(f"The same server answered {len(before)} lookups earlier in the capture, so "
                                        "it worked and then stopped", FAULT, "moderate"))
        facts = [f"{len(window)} DNS lookups ({queries} query packets) to {server} between {rel(start)} and "
                 f"{rel(end)} received no response at all.",
                 f"{len(unanswered)} of {len(eligible)} lookups to this server that had at least "
                 f"{th.dns_timeout_seconds:g} s of capture after them went unanswered.",
                 f"Affected clients: {_short_list(clients)}.",
                 f"Names that failed: {_short_list(f'{n} (x{c})' for n, c in names.most_common())}."]
        if retries:
            facts.append(f"{retries} retransmitted queries (same txid) show the clients waiting and retrying.")
        if before:
            facts.append(f"Last successful answer before the outage: {rel(before[-1].answer.ts)} "
                         f"(packet {before[-1].answer.n}).")
        if after:
            facts.append(f"The server answered again {len(after)} time(s) after the outage window, first at "
                         f"{rel(after[0].answer.ts)}.")
        if fallback:
            facts.append(f"Clients fell back to other resolver(s) that did answer: {', '.join(sorted(fallback))}.")
        limitations = ["The capture cannot show whether the queries reached the server and the answers were lost "
                       "on the way back, or whether the server never received them."]
        if never_seen:
            limitations.append(f"No packet from {server} appears anywhere in the capture. If the capture point only "
                               "sees outbound traffic (asymmetric routing / one-way SPAN), answers may exist but were "
                               "not captured.")
        evidence: list[Evidence] = []
        for t in window:
            evidence.append(Evidence(t.queries[0].n, f"query to {server} with no answer: {t.label}"))
            evidence.extend(Evidence(q.n, f"retry of the same query (still unanswered): {t.label}")
                            for q in t.queries[1:3])
        evidence = evidence[:EVIDENCE_CAP - 1]
        if before:
            evidence.append(Evidence(before[-1].answer.n, f"last answer from {server} before it went silent"))
        assessment = assess(indicators)
        findings.append(Finding(
            detector=NAME, kind="DNS_SERVER_UNRESPONSIVE",
            title=f"DNS server {server} is not answering",
            category="fault", assessment=assessment, severity="medium",
            evidence_strength="strong" if majority and before else "moderate",
            summary=(f"{len(clients)} client(s) sent {len(window)} DNS lookups to {server} and none of them got an "
                     f"answer, even after {retries} retries. "
                     + ("The server had been answering normally before that. " if before else "")
                     + "Name resolution through this server is down."),
            impact=("Websites, e-mail and internal applications fail to open or take many seconds before failing "
                    "('server not found', 'DNS_PROBE_FINISHED_NO_INTERNET'), even though the network link is up."),
            likely_cause=("The DNS service on that host stopped or crashed, the host is down, or a firewall / ACL "
                          "between the clients and the server drops DNS (UDP/TCP 53)."),
            recommendations=[f"Check that the DNS service on {server} is running and listening on port 53 "
                             "(e.g. 'nslookup example.com " + server + "' from a client).",
                             "Check firewall rules and ACLs for UDP and TCP port 53 on the path to the server.",
                             "Make sure clients have a working secondary DNS server configured (DHCP option 6).",
                             "If the server is upstream (ISP / public resolver), check the router's WAN link "
                             "and the router's DNS forwarder settings."],
            facts=facts,
            alternatives=["Return traffic lost on an asymmetric path or not mirrored to the capture point.",
                          "Rate limiting on the server dropping a client that sends too many queries."],
            limitations=limitations, indicators=indicators,
            hosts={"dns_server": [server], "client": clients},
            time_start=start, time_end=end, evidence=evidence,
            metrics={"unanswered_lookups": len(unanswered), "window_lookups": len(window),
                     "eligible_lookups": len(eligible), "query_packets": queries, "retries": retries,
                     "answered_before": len(before), "answered_after": len(after), "clients": len(clients),
                     "fallback_servers": sorted(fallback), "server_seen_sending": not never_seen},
            rule=(f"no response within {th.dns_timeout_seconds:g} s for >= {th.dns_min_failures} lookups and "
                  f"(majority of the server's lookups or >= {OUTAGE_RUN_MIN} consecutive)")))
    return findings


# --- fault: SERVFAIL / REFUSED -------------------------------------------------------------

def _server_failures(ctx: AnalysisContext, st: _State) -> list[Finding]:
    th = ctx.thresholds
    groups: dict[tuple[str, int], list[tuple[_Txn, PacketRecord]]] = defaultdict(list)
    ok_names: dict[str, set[str]] = defaultdict(set)
    ok_clients: dict[str, set[str]] = defaultdict(set)
    for t in st.txns:
        for r in t.responses:
            rc = _rcode(r)
            if rc in (2, 5):
                groups[(t.server, rc)].append((t, r))
                break
        else:
            if t.answer is not None and _rcode(t.answer) in (0, 3):
                ok_names[t.server].add(t.qname or "?")
                ok_clients[t.server].add(t.client)
    findings: list[Finding] = []
    for (server, rc), items in groups.items():
        if len(items) < th.dns_min_failures:
            continue
        names = Counter(t.qname or "?" for t, _ in items)
        clients = sorted({t.client for t, _ in items})
        other_ok = ok_names[server] - set(names)
        specific = len(names) <= NAME_SPECIFIC_MAX and len(other_ok) >= 3
        served_others = sorted(ok_clients[server] - set(clients))
        rel = lambda ts: f"+{ts - ctx.start_ts:.1f}s"  # noqa: E731
        indicators = [Indicator(f"{server} answered {len(items)} lookups with {RCODE_NAMES[rc]}", FAULT, "moderate"),
                      Indicator("The server responds (it is up) but reports an error, which is a configuration "
                                "or upstream problem, not an attack signature", FAULT, "moderate")]
        if rc == 2:
            title = (f"DNS server {server} cannot resolve {_short_list(names, 2)}" if specific
                     else f"DNS server {server} returns SERVFAIL")
            summary = (f"{server} returned SERVFAIL ('server failure') for {len(items)} lookups covering "
                       f"{len(names)} name(s). " +
                       (f"It still resolved {len(other_ok)} other names, so the problem is specific to these domains."
                        if specific else
                        "The server is reachable but could not complete the resolution for the clients."))
            cause = ("The domain's own authoritative servers are unreachable or its DNSSEC signatures are broken / "
                     "expired, so a validating resolver refuses to answer." if specific else
                     "The resolver cannot reach its upstream / root servers (WAN or forwarder failure), its "
                     "forwarder is down, or DNSSEC validation fails (e.g. wrong system clock on the resolver).")
            recs = ([f"Test the names directly against another resolver (e.g. 'nslookup {names.most_common(1)[0][0]} "
                     "1.1.1.1'); if they fail everywhere the domain itself is broken - contact its owner.",
                     "Check the domain with a DNSSEC analyser (expired RRSIG / wrong DS record)."] if specific else
                    [f"Check the forwarder / upstream configuration and WAN connectivity of {server}.",
                     "Check the resolver's logs and its clock (DNSSEC validation fails when the time is wrong).",
                     "Restart the DNS service if its cache or upstream connections are stuck."])
            impact = ("Those specific websites or services fail to open with 'server not found'." if specific else
                      "Most new (uncached) names fail to resolve, so websites and applications fail to connect.")
        else:
            title = f"DNS server {server} refuses queries"
            summary = (f"{server} returned REFUSED for {len(items)} lookups from {len(clients)} client(s). The server "
                       "is reachable but will not answer (resolve) for these clients.")
            cause = ("The clients are pointed at a DNS server that does not offer recursion to them: an "
                     "authoritative-only server, a resolver whose ACL excludes their subnet, or a stale / wrong "
                     "DNS server address in the client or DHCP configuration.")
            recs = ["Check which DNS server the affected clients use (ipconfig /all, resolvectl status) and correct "
                    "it, or fix the DHCP option 6 that hands it out.",
                    f"If {server} should serve these clients, allow their subnet in its recursion ACL "
                    "(e.g. 'allow-recursion' in BIND, 'access-control' in Unbound)."]
            impact = "Every lookup from the affected clients fails immediately; nothing that needs DNS works."
        facts = [f"{len(items)} lookups answered {RCODE_NAMES[rc]} by {server} between {rel(items[0][1].ts)} and "
                 f"{rel(items[-1][1].ts)}.",
                 f"Names: {_short_list(f'{n} (x{c})' for n, c in names.most_common())}.",
                 f"Clients: {_short_list(clients)}.",
                 f"The same server answered {len(other_ok)} other name(s) normally in this capture."]
        if rc == 5 and served_others:
            facts.append(f"It answered other clients normally ({_short_list(served_others, 5)}), which points to a "
                         "per-client ACL or a misconfigured client.")
        evidence: list[Evidence] = []
        for t, r in items[:EVIDENCE_CAP // 2]:
            evidence.append(Evidence(t.queries[0].n, f"query from {t.client}: {t.label}"))
            evidence.append(Evidence(r.n, f"{RCODE_NAMES[rc]} answer from {server}"))
        times = [r.ts for _, r in items]
        findings.append(Finding(
            detector=NAME, kind="DNS_SERVER_FAILURE", title=title,
            category="fault", assessment=assess(indicators),
            severity="low" if specific else "medium",
            evidence_strength="strong" if len(items) >= 2 * th.dns_min_failures else "moderate",
            summary=summary, impact=impact, likely_cause=cause, recommendations=recs, facts=facts,
            alternatives=(["Deliberate filtering: some resolvers answer REFUSED for blocked domains."] if rc == 5 else
                          ["A temporary upstream outage that resolves itself; repeat the test later."]),
            limitations=["The capture shows the error code but not the resolver's internal reason; its logs do."],
            indicators=indicators, hosts={"dns_server": [server], "client": clients},
            time_start=min(times), time_end=max(times), evidence=evidence,
            metrics={"rcode": RCODE_NAMES[rc], "failed_lookups": len(items), "names": len(names),
                     "clients": len(clients), "other_names_resolved": len(other_ok), "domain_specific": specific},
            rule=f"rcode {RCODE_NAMES[rc]} for >= {th.dns_min_failures} lookups from one server"))
    return findings


# --- fault / attack: NXDOMAIN and DGA ------------------------------------------------------

def _nxdomain(ctx: AnalysisContext, st: _State) -> list[Finding]:
    th = ctx.thresholds
    per_client: dict[str, list[_Txn]] = defaultdict(list)
    resolved_names: set[str] = set()
    resolved_random: dict[str, list[_Txn]] = defaultdict(list)
    for t in st.txns:
        ans = t.answer
        if ans is None or not t.qname:
            continue
        rc = _rcode(ans)
        if rc == 3 and not t.qname.endswith(".arpa"):
            per_client[t.client].append(t)
        elif rc == 0 and _addresses(ans):
            if len(resolved_names) < 5000:
                resolved_names.add(t.qname)
            if _random_looking(t.qname, th.dns_random_name_entropy):
                resolved_random[t.client].append(t)
    by_len: dict[int, list[str]] = defaultdict(list)
    for name in resolved_names:
        by_len[len(name)].append(name)

    findings: list[Finding] = []
    for client, items in per_client.items():
        if len(items) < th.dns_nxdomain_min:
            continue
        ctx.check_deadline()
        random_items = [t for t in items if _random_looking(t.qname, th.dns_random_name_entropy)]
        random_names = sorted({t.qname for t in random_items})
        domains = {_registrable(n) for n in random_names}
        rest = items
        if len(random_names) >= DGA_MIN_UNIQUE and len(domains) >= DGA_MIN_DOMAINS:
            # Generated names whose entropy happens to fall just below the threshold belong to the
            # same generator when they have the same shape (label count, TLD, alphanumeric first
            # label of similar length containing a digit or nearly random).
            flagged = set(random_names)
            shapes = {(n.count("."), n.rsplit(".", 1)[-1]) for n in random_names}
            lens = [len(n.split(".", 1)[0]) for n in random_names]
            lo, hi = min(lens), max(lens)
            siblings = []
            for t in items:
                if t.qname in flagged or "." not in t.qname:
                    continue
                first = t.qname.split(".", 1)[0]
                if ((t.qname.count("."), t.qname.rsplit(".", 1)[-1]) in shapes and first.isalnum()
                        and lo <= len(first) <= hi and len(first) >= DGA_MIN_LEN
                        and (any(ch.isdigit() for ch in first)
                             or _entropy(first) >= th.dns_random_name_entropy - 0.4)):
                    siblings.append(t)
            findings.append(_dga_finding(ctx, client, random_items, random_names, domains,
                                         resolved_random.get(client, []), siblings))
            absorbed = flagged | {t.qname for t in siblings}
            rest = [t for t in items if t.qname not in absorbed]
            if len(rest) < th.dns_nxdomain_min:
                continue
        findings.append(_nxdomain_finding(ctx, client, rest, by_len, random_names if rest is items else []))
    return findings


def _nxdomain_finding(ctx, client: str, items: list[_Txn], by_len: dict[int, list[str]],
                      random_names: list[str]) -> Finding:
    th = ctx.thresholds
    names = Counter(t.qname for t in items)
    unique = list(names)
    servers = sorted({t.server for t in items})
    # search-domain expansion: one first label tried with several suffixes, or bare names
    suffixes: dict[str, set[str]] = defaultdict(set)
    single_label = [n for n in unique if "." not in n]
    for n in unique:
        if "." in n:
            first, rest = n.split(".", 1)
            suffixes[first].add(rest)
    expanded = {f: s for f, s in suffixes.items() if len(s) >= 2}
    search_pattern = len(expanded) >= 2 or any(len(s) >= 3 for s in expanded.values())
    common_suffix = Counter(n.split(".", 1)[1] for n in unique if "." in n).most_common(1)
    # typos of names that did resolve in this capture
    typos: dict[str, str] = {}
    for n in unique[:TYPO_MAX_NAMES]:
        if len(n) < TYPO_MIN_LEN:
            continue
        for length in range(len(n) - TYPO_MAX_DISTANCE, len(n) + TYPO_MAX_DISTANCE + 1):
            hit = next((good for good in by_len.get(length, ())
                        if good != n and _osa_distance(n, good, TYPO_MAX_DISTANCE) <= TYPO_MAX_DISTANCE), None)
            if hit:
                typos[n] = hit
                break
    top_name, top_count = names.most_common(1)[0]
    indicators = [Indicator(f"{len(items)} lookups by {client} for {len(unique)} name(s) were answered "
                            "'name does not exist'", FAULT, "moderate")]
    causes = []
    if search_pattern or single_label:
        indicators.append(Indicator("The same host names were tried with several domain suffixes (or with no suffix "
                                    "at all): the client's DNS search-domain list is appending suffixes that do not "
                                    "exist", FAULT, "moderate"))
        causes.append("a wrong or stale DNS search-domain / connection-specific suffix on the client "
                      "(each short name is tried with every suffix in the list)")
    if typos:
        indicators.append(Indicator(f"{len(typos)} failed name(s) are near-misspellings of names that resolved "
                                    "(e.g. " + ", ".join(f"{a} vs {b}" for a, b in list(typos.items())[:3]) + ")",
                                    FAULT, "moderate"))
        causes.append("misspelled host names in an application setting, script, bookmark or mapped drive")
    if top_count >= REPEAT_NAME_MEDIUM:
        indicators.append(Indicator(f"'{top_name}' failed {top_count} times: an application keeps retrying a name "
                                    "that no longer exists", FAULT, "moderate"))
        causes.append(f"an application configured with the removed / renamed host '{top_name}'")
    if random_names:
        indicators.append(Indicator(f"{len(random_names)} random-looking names, but under only a few parent domains "
                                    "(could be tokenised telemetry / anti-virus lookups, DNS tunnelling or a "
                                    "random-subdomain flood)", ATTACK, "weak"))
    if not causes:
        causes.append("a removed or renamed host, a mistyped name, or a stale configuration entry on the client")
    facts = [f"{len(items)} NXDOMAIN answers to lookups sent by {client} (resolver(s): {', '.join(servers)}).",
             f"Distinct names: {len(unique)}; most frequent: {_short_list(f'{n} (x{c})' for n, c in names.most_common(8))}."]
    if expanded:
        facts.append("Names tried with several suffixes: " +
                     "; ".join(f"{f} -> {', '.join(sorted(s)[:4])}" for f, s in list(expanded.items())[:5]) + ".")
    if common_suffix:
        facts.append(f"Most common failing suffix: '{common_suffix[0][0]}' ({common_suffix[0][1]} names).")
    if typos:
        facts.append("Near-misspellings of resolvable names: " +
                     ", ".join(f"{a} (did you mean {b}?)" for a, b in list(typos.items())[:6]) + ".")
    evidence: list[Evidence] = []
    for t in items[:EVIDENCE_CAP // 2]:
        evidence.append(Evidence(t.queries[0].n, f"lookup by {client}: {t.label}"))
        evidence.append(Evidence(t.answer.n, f"NXDOMAIN answer from {t.server}"
                                 + (f" (typo of {typos[t.qname]})" if t.qname in typos else "")))
    times = [t.answer.ts for t in items]
    return Finding(
        detector=NAME, kind="DNS_NXDOMAIN",
        title=f"{client} keeps looking up names that do not exist",
        category="fault", assessment=assess(indicators),
        severity="medium" if top_count >= REPEAT_NAME_MEDIUM else "low",
        evidence_strength="strong" if len(indicators) >= 2 else "moderate",
        summary=(f"The client {client} asked for {len(unique)} different name(s) {len(items)} times and the DNS server "
                 "answered every time that the name does not exist (NXDOMAIN). The DNS server is working correctly; "
                 "the names being requested are wrong."),
        impact=("The application or user on that client cannot reach the intended service, and each failed lookup "
                "adds delay before a fallback is tried."),
        likely_cause="Most likely " + "; or ".join(causes) + ".",
        recommendations=["On the client, check the DNS suffix search list (ipconfig /all, /etc/resolv.conf 'search') "
                         "and DHCP option 15/119.",
                         f"Find the process that resolves '{top_name}' (e.g. Sysmon event 22, 'Get-DnsClientCache') "
                         "and correct its configuration.",
                         "If the names were removed on purpose, update scripts, mapped drives and bookmarks."],
        facts=facts,
        alternatives=["Software probing for optional services (WPAD, printers) produces some NXDOMAIN noise.",
                      "A recently deleted DNS record that clients still reference."],
        limitations=["NXDOMAIN is the server's honest answer; the capture cannot show which program asked.",
                     "This is not evidence of DNS hijacking: forged answers are detected separately."],
        indicators=indicators, hosts={"client": [client], "dns_server": servers},
        time_start=min(times), time_end=max(times), evidence=evidence,
        metrics={"nxdomain_answers": len(items), "unique_names": len(unique), "search_suffix_pattern": search_pattern,
                 "typo_names": len(typos), "single_label_names": len(single_label), "top_name_count": top_count},
        rule=f">= {th.dns_nxdomain_min} NXDOMAIN answers to lookups sent by one client")


def _dga_finding(ctx, client: str, items: list[_Txn], names: list[str], domains: set[str],
                 resolved: list[_Txn], siblings: list[_Txn]) -> Finding:
    th = ctx.thresholds
    flagged_count = len(names)
    names = sorted(set(names) | {t.qname for t in siblings})
    items = sorted(items + siblings, key=lambda t: t.queries[0].n)
    domains = {_registrable(n) for n in names}
    entropies = [_entropy(n.split(".", 1)[0]) for n in names]
    tlds = Counter(n.rsplit(".", 1)[-1] for n in names)
    resolved_names = sorted({t.qname for t in resolved})
    contacted = sorted({a for t in resolved for a in _addresses(t.answer)})
    indicators = [Indicator(f"{flagged_count} unique random-looking names (first label >= {DGA_MIN_LEN} characters, "
                            f"entropy >= {th.dns_random_name_entropy:g} bits/char) failed with NXDOMAIN"
                            + (f", plus {len(siblings)} more of the same generated shape" if siblings else "")
                            + ": domain-generation-algorithm malware pattern", ATTACK, "moderate"),
                  Indicator(f"The names belong to {len(domains)} different registrable domains, unlike legitimate "
                            "random sub-domain lookups which stay under one vendor domain", ATTACK, "moderate")]
    if resolved_names:
        indicators.append(Indicator(f"{len(resolved_names)} name(s) with the same random pattern DID resolve - "
                                    "candidate command-and-control servers", ATTACK, "moderate"))
    evidence: list[Evidence] = []
    for t in items[:EVIDENCE_CAP // 2]:
        evidence.append(Evidence(t.queries[0].n, f"random-looking lookup: {t.label}"))
        evidence.append(Evidence(t.answer.n, "NXDOMAIN (generated name not registered)"))
    for t in resolved[:10]:
        evidence.append(Evidence(t.answer.n, f"random-looking name that resolved: {t.qname} -> {_describe_answer(t.answer)}"))
    times = [t.answer.ts for t in items]
    assessment = assess(indicators)
    return Finding(
        detector=NAME, kind="DNS_DGA_PATTERN",
        title=f"{client} is querying algorithmically generated domain names",
        category="attack", assessment=assessment, severity="high" if assessment == ATTACK else "medium",
        evidence_strength="strong" if resolved_names else "moderate",
        summary=(f"{client} looked up {len(names)} different random-looking domain names (for example "
                 f"{', '.join(names[:3])}) across {len(domains)} domains, and almost none of them exist. "
                 "Malware that uses a domain generation algorithm (DGA) behaves exactly like this: it tries many "
                 "generated names until it finds the one its operator registered."),
        impact=("The client is probably infected and trying to reach its controller; if one of the names resolves, "
                "the attacker can send it commands or receive stolen data."),
        likely_cause="Malware with a domain generation algorithm running on the client.",
        recommendations=[f"Isolate {client} from the network and run a full endpoint / EDR scan.",
                         "Find the process issuing the lookups (Sysmon event 22, EDR DNS telemetry).",
                         "Block the resolved candidate addresses at the firewall and search other hosts' DNS logs "
                         "for the same names.",
                         "Enable DNS filtering / RPZ that blocks newly registered and DGA domains."],
        facts=[f"{len(items)} NXDOMAIN answers for {len(names)} unique random-looking names from {client}: "
               f"{flagged_count} above the entropy threshold, {len(siblings)} of identical shape just below it.",
               f"Entropy of the first label: min {min(entropies):.2f}, mean {sum(entropies) / len(entropies):.2f}, "
               f"max {max(entropies):.2f} bits/char (threshold {th.dns_random_name_entropy:g}).",
               f"Top-level domains used: {_short_list(f'.{t} (x{c})' for t, c in tlds.most_common())}.",
               f"Examples: {_short_list(names, 8)}."]
              + ([f"Random-looking names that resolved: {_short_list(resolved_names, 5)} -> "
                  f"{_short_list(contacted, 5)}."] if resolved_names else []),
        alternatives=["Some security products and browsers generate random lookups, but they normally use a single "
                      "vendor domain or single-label names (both excluded here)."],
        limitations=["Randomness of a name is a statistical hint, not proof; confirm on the endpoint.",
                     f"Short generated names (< {DGA_MIN_LEN} characters) and dictionary-word DGAs are not detected."],
        indicators=indicators, hosts={"infected_client": [client], "dns_server": sorted({t.server for t in items}),
                                      "candidate_c2": contacted},
        time_start=min(times), time_end=max(times), evidence=evidence,
        metrics={"random_nxdomain_names": len(names), "entropy_flagged_names": flagged_count,
                 "same_shape_names": len(siblings), "nxdomain_answers": len(items),
                 "registrable_domains": len(domains), "resolved_random_names": len(resolved_names)},
        rule=(f">= {DGA_MIN_UNIQUE} unique NXDOMAIN names with first-label entropy >= {th.dns_random_name_entropy:g} "
              f"and length >= {DGA_MIN_LEN} over >= {DGA_MIN_DOMAINS} registrable domains, per client"))


# --- fault: slow responses -----------------------------------------------------------------

def _slow(ctx: AnalysisContext, st: _State) -> list[Finding]:
    th = ctx.thresholds
    per_server: dict[str, list[tuple[_Txn, float]]] = defaultdict(list)
    for t in st.txns:
        lat = t.latency()
        # SERVFAIL / REFUSED delays are part of that failure (reported by DNS_SERVER_FAILURE)
        if lat is not None and _rcode(t.answer) in (0, 3):
            per_server[t.server].append((t, lat))
    stats = {s: (median([l for _, l in v]), len(v)) for s, v in per_server.items()}
    findings: list[Finding] = []
    for server, items in per_server.items():
        slow = [(t, l) for t, l in items if l > th.dns_slow_seconds]
        if len(slow) < th.dns_min_slow or len(slow) / len(items) < SLOW_MIN_SHARE:
            continue
        lats = [l for _, l in items]
        med, p95, mx = median(lats), _pct(lats, 0.95), max(lats)
        others = {s: m for s, (m, n) in stats.items() if s != server and n >= 3}
        fast_others = {s: m for s, m in others.items() if m <= th.dns_slow_seconds / 2}
        late = [t for t, l in slow if l >= th.dns_timeout_seconds]
        clients = sorted({t.client for t, _ in slow})
        indicators = [Indicator(f"{len(slow)} of {len(items)} answers from {server} took longer than "
                                f"{_ms(th.dns_slow_seconds)} (median {_ms(med)})", FAULT, "moderate")]
        if fast_others:
            indicators.append(Indicator("Other resolvers in the same capture answered quickly (" +
                                        ", ".join(f"{s} median {_ms(m)}" for s, m in list(fast_others.items())[:3]) +
                                        "), so the delay is specific to this server or its path", FAULT, "moderate"))
            cause = (f"{server} is overloaded, far away, or its upstream / forwarder is slow (cache misses must be "
                     "resolved recursively); or the path to it is congested.")
        elif others:
            indicators.append(Indicator("Every resolver in the capture is slow, which points to the shared uplink "
                                        "or the client side", FAULT, "moderate"))
            cause = "The shared Internet uplink is congested or lossy, or the client side is overloaded."
        else:
            cause = (f"{server} or the path to it is slow (overloaded resolver, slow upstream forwarder, or a "
                     "congested link).")
        facts = [f"{len(slow)} of {len(items)} answers from {server} were slower than {_ms(th.dns_slow_seconds)}.",
                 f"Latency for {server}: median {_ms(med)}, p95 {_ms(p95)}, max {_ms(mx)}.",
                 f"Clients affected: {_short_list(clients)}."]
        if others:
            facts.append("Other resolvers: " + ", ".join(f"{s} median {_ms(m)} ({stats[s][1]} answers)"
                                                         for s, m in sorted(others.items())[:5]) + ".")
        if late:
            facts.append(f"{len(late)} answer(s) arrived after {th.dns_timeout_seconds:g} s, by which time many "
                         "clients have already retried or given up.")
        evidence: list[Evidence] = []
        for t, l in sorted(slow, key=lambda x: -x[1])[:EVIDENCE_CAP // 2]:
            q = [x for x in t.queries if x.n < t.answer.n][-1:] or t.queries[:1]
            evidence.append(Evidence(q[0].n, f"query to {server}: {t.label}"))
            evidence.append(Evidence(t.answer.n, f"answer after {_ms(l)}"))
        times = [t.answer.ts for t, _ in slow]
        findings.append(Finding(
            detector=NAME, kind="DNS_SLOW_RESPONSES",
            title=f"DNS server {server} answers slowly",
            category="fault", assessment=assess(indicators), severity="low" if p95 < 1.0 else "medium",
            evidence_strength="strong" if len(slow) >= 2 * th.dns_min_slow else "moderate",
            summary=(f"{len(slow)} of the {len(items)} DNS answers from {server} took longer than "
                     f"{_ms(th.dns_slow_seconds)}; the median was {_ms(med)} and the slowest {_ms(mx)}. Every "
                     "connection to a new name waits for this before it can even start."),
            impact="Web pages and applications feel sluggish to start ('waiting for host'), even with good bandwidth.",
            likely_cause=cause,
            recommendations=[f"Measure {server} directly (e.g. 'nslookup' / 'dig' timing) and compare with another "
                             "resolver.",
                             "Check the resolver's CPU, cache size and upstream forwarder health.",
                             "Configure a closer or faster resolver as primary, and check the uplink for congestion."],
            facts=facts,
            alternatives=["Uncached names that require full recursion are legitimately slower; persistent slowness "
                          "for common names is not."],
            limitations=["Latency is measured at the capture point; if it is far from the client, client-side delay "
                         "is not included."],
            indicators=indicators, hosts={"dns_server": [server], "client": clients},
            time_start=min(times), time_end=max(times), evidence=evidence,
            metrics={"slow_answers": len(slow), "answers": len(items), "median_ms": round(med * 1000, 1),
                     "p95_ms": round(p95 * 1000, 1), "max_ms": round(mx * 1000, 1), "late_answers": len(late),
                     "other_servers_median_ms": {s: round(m * 1000, 1) for s, m in sorted(others.items())}},
            rule=(f">= {th.dns_min_slow} answers slower than {th.dns_slow_seconds:g} s and >= "
                  f"{SLOW_MIN_SHARE:.0%} of the server's answers")))
    return findings


# --- attack: forged answers ----------------------------------------------------------------

@dataclass
class _Suspect:
    server: str
    conflicts: list[tuple[_Txn, list[PacketRecord], str]] = field(default_factory=list)
    unsolicited: list[PacketRecord] = field(default_factory=list)
    foreign: list[tuple[PacketRecord, _Txn]] = field(default_factory=list)
    contradicts: list[PacketRecord] = field(default_factory=list)
    dhcp_mismatch: list[tuple[str, frozenset, frozenset]] = field(default_factory=list)


def _hijack(ctx: AnalysisContext, st: _State) -> list[Finding]:
    # Baseline per server: solicited, uncontested answers (median IP TTL, usual source MAC,
    # addresses per name). Forged packets in a race or a flood are excluded by construction.
    conflict_txns: dict[int, tuple[_Txn, list[PacketRecord], str]] = {}
    for t in st.txns:
        if len(t.responses) < 2:
            continue
        rs = t.responses
        bad = [(a, b) for i, a in enumerate(rs) for b in rs[i + 1:] if _conflict(a, b)]
        if bad:
            a, b = bad[0]
            differs = (a.ttl is not None and b.ttl is not None and abs(a.ttl - b.ttl) >= TTL_DELTA) or \
                (a.eth_src and b.eth_src and a.eth_src != b.eth_src)
            strength = "strong" if len(rs) > len(t.queries) or differs else "moderate"
            conflict_txns[id(t)] = (t, [a, b], strength)
    base_ttl: dict[str, list[int]] = defaultdict(list)
    base_mac: dict[str, Counter] = defaultdict(Counter)
    answers_per_name: Counter = Counter()                     # (server, name) -> uncontested answers
    addr_count: dict[tuple[str, str], Counter] = defaultdict(Counter)
    name_addr_by_server: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    for t in st.txns:
        if id(t) in conflict_txns or t.answer is None:
            continue
        r = t.answer
        if r.ttl is not None:
            base_ttl[t.server].append(r.ttl)
        if r.eth_src:
            base_mac[t.server][r.eth_src] += 1
        addrs = _addresses(r) if _rcode(r) == 0 else frozenset()
        if t.qname and addrs:
            answers_per_name[(t.server, t.qname)] += 1
            addr_count[(t.server, t.qname)].update(addrs)
            name_addr_by_server[t.server][t.qname].update(addrs)
    ttl_ref = {s: int(median(v)) for s, v in base_ttl.items() if len(v) >= BASELINE_MIN}
    mac_ref = {}
    for s, c in base_mac.items():
        mac, n = c.most_common(1)[0]
        if sum(c.values()) >= BASELINE_MIN and n / sum(c.values()) >= 0.9:
            mac_ref[s] = mac

    suspects: dict[str, _Suspect] = {}

    def get(server: str) -> _Suspect:
        if server not in suspects:
            suspects[server] = _Suspect(server)
        return suspects[server]

    for t, pair, strength in conflict_txns.values():
        get(t.server).conflicts.append((t, pair, strength))
    for r in st.unsolicited:
        get(r.ip_src).unsolicited.append(r)
    for r, t in st.foreign:
        get(r.ip_src).foreign.append((r, t))
    # A matched answer that contradicts what the same server answered for the same name
    # earlier is only suspicious together with a TTL or MAC anomaly (CDNs rotate addresses).
    for t in st.txns:
        r = t.answer
        if r is None or id(t) in conflict_txns or not t.qname or _rcode(r) != 0:
            continue
        ttl_bad = t.server in ttl_ref and r.ttl is not None and abs(r.ttl - ttl_ref[t.server]) >= TTL_DELTA
        mac_bad = t.server in mac_ref and r.eth_src and r.eth_src != mac_ref[t.server]
        if not (ttl_bad or mac_bad):
            continue
        key = (t.server, t.qname)
        addrs = _addresses(r)
        # contradicts = the server answered this name in other lookups too, and none of this
        # answer's addresses ever appeared in those other answers
        if addrs and answers_per_name[key] > 1 and all(addr_count[key][a] == 1 for a in addrs):
            get(t.server).contradicts.append(r)
    offered = ctx.dhcp_offered.get("dns") or set()
    if offered:
        legit_names: dict[str, set[str]] = defaultdict(set)
        for s in offered:
            for n, a in name_addr_by_server.get(s, {}).items():
                legit_names[n].update(a)
        for s, names in name_addr_by_server.items():
            if s in offered:
                continue
            for n, a in names.items():
                if n in legit_names and a.isdisjoint(legit_names[n]):
                    get(s).dhcp_mismatch.append((n, frozenset(a), frozenset(legit_names[n])))

    if not suspects:
        return []
    icmp_reject: dict[tuple, list[PacketRecord]] = defaultdict(list)
    for r in ctx.icmp:
        inner = r.icmp_inner or {}
        if r.icmp_type in (3, 1) and inner.get("proto") == 17 and inner.get("sport") == 53:
            icmp_reject[(inner.get("src"), inner.get("dst"), inner.get("dport"))].append(r)
    conns_by_pair: dict[tuple[str, str], list] = defaultdict(list)
    if any(s.conflicts for s in suspects.values()):
        for c in ctx.connections:
            conns_by_pair[(c.client[0], c.server[0])].append(c)

    findings = []
    for server, s in suspects.items():
        ctx.check_deadline()
        f = _hijack_finding(ctx, s, ttl_ref.get(server), mac_ref.get(server), icmp_reject, conns_by_pair,
                            offered)
        if f is not None:
            findings.append(f)
    return findings


def _hijack_finding(ctx, s: _Suspect, ttl_ref: int | None, mac_ref: str | None, icmp_reject, conns_by_pair,
                    offered: set[str]) -> Finding | None:
    server = s.server
    rel = lambda ts: f"+{ts - ctx.start_ts:.1f}s"  # noqa: E731

    def ttl_bad(r: PacketRecord) -> bool:
        return ttl_ref is not None and r.ttl is not None and abs(r.ttl - ttl_ref) >= TTL_DELTA

    def mac_bad(r: PacketRecord) -> bool:
        return mac_ref is not None and bool(r.eth_src) and r.eth_src != mac_ref

    suspect_resps: list[PacketRecord] = []
    for _, pair, _ in s.conflicts:
        suspect_resps.extend(pair)
    suspect_resps += s.unsolicited + [r for r, _ in s.foreign] + s.contradicts
    ttl_anom = [r for r in suspect_resps if ttl_bad(r)]
    mac_anom = [r for r in suspect_resps if mac_bad(r)]
    brute: dict[tuple[str, str], set[int]] = defaultdict(set)
    for r in s.unsolicited:
        brute[(r.ip_dst, r.dns.get("qname"))].add(r.dns.get("id"))
    brute_hits = {k: v for k, v in brute.items() if len(v) >= BRUTE_FORCE_TXIDS}
    private_hits = []
    for r in suspect_resps:
        name = (r.dns or {}).get("qname")
        if _public_looking(name) and any(_private_answer(a) for a in _addresses(r)):
            private_hits.append(r)

    indicators: list[Indicator] = []
    strong_conflicts = [c for c in s.conflicts if c[2] == "strong"]
    if s.conflicts:
        indicators.append(Indicator(
            f"{len(s.conflicts)} lookup(s) were answered twice with contradicting answers (same client, port, txid "
            "and name) - the signature of an injected answer racing the real one",
            ATTACK, "strong" if strong_conflicts else "moderate"))
    if ttl_anom:
        indicators.append(Indicator(
            f"{len(ttl_anom)} suspicious answer(s) claiming to come from {server} carry IP TTL "
            f"{_short_list(sorted({r.ttl for r in ttl_anom}), 4)} while its normal answers arrive with TTL {ttl_ref}: "
            "they were sent by a different device", ATTACK, "strong"))
    if brute_hits:
        (victim, qname), ids = next(iter(brute_hits.items()))
        indicators.append(Indicator(
            f"{len(ids)} unsolicited answers for '{qname}' to {victim} with different transaction IDs: blind "
            "spoofing that guesses the txid (Kaminsky-style cache poisoning)", ATTACK, "strong"))
    if len(s.unsolicited) >= UNSOLICITED_MIN:
        indicators.append(Indicator(f"{len(s.unsolicited)} answers from {server} match no query the client sent",
                                    ATTACK, "moderate"))
    if s.foreign:
        indicators.append(Indicator(
            f"{len(s.foreign)} answer(s) came from {server} although the client had asked a different server - "
            "with the correct txid and port, so the sender could see the queries", ATTACK, "moderate"))
    if mac_anom:
        indicators.append(Indicator(
            f"{len(mac_anom)} suspicious answer(s) arrived from Ethernet source "
            f"{_short_list(sorted({r.eth_src for r in mac_anom}), 3)} instead of {mac_ref}, the MAC that carries "
            f"{server}'s normal answers", ATTACK, "moderate"))
    dhcp_indicator = None
    if s.dhcp_mismatch:
        dhcp_indicator = Indicator(
            f"{server} is not a DNS server handed out by DHCP ({', '.join(sorted(offered))}) and answered "
            f"{len(s.dhcp_mismatch)} name(s) with addresses the DHCP-provided resolver never returned", ATTACK,
            "moderate")
        indicators.append(dhcp_indicator)
    if private_hits:
        indicators.append(Indicator(
            f"{len(private_hits)} suspicious answer(s) point a public-looking name to a private address (alone "
            "this is normal split-horizon DNS)", ATTACK, "weak"))
    if s.foreign:
        agree = contradict = 0
        for r, t in s.foreign:
            real = set().union(*(_addresses(x) for x in t.responses)) if t.responses else set()
            mine = _addresses(r)
            if real and mine:
                if mine & real:
                    agree += 1
                else:
                    contradict += 1
        if contradict:
            indicators.append(Indicator(f"{contradict} of the answers from the unqueried server contradict the "
                                        "queried server's own answer", ATTACK, "moderate"))
        elif agree == len(s.foreign):
            indicators.append(Indicator("The unexpected answers agree with what the queried server answered, so "
                                        "they did not redirect anyone", BENIGN, "moderate"))
        if not (s.conflicts or ttl_anom or brute_hits):
            indicators.append(Indicator("A resolver with several addresses can legitimately answer from a different "
                                        "address than the one queried", BENIGN, "weak"))

    assessment = assess(indicators)
    # The DHCP-list indicator never stands alone: public resolvers legitimately differ (CDN geo answers).
    reportable = any(i.points_to == ATTACK and i.strength in ("strong", "moderate") and i is not dhcp_indicator
                     for i in indicators)
    if assessment != ATTACK and not (assessment == INCONCLUSIVE and reportable):
        return None

    evidence: list[Evidence] = []
    facts: list[str] = []
    clients: set[str] = set()
    forged_addrs: set[str] = set()
    attacker_macs: set[str] = set()
    first_wins = False
    client_used = []
    for t, (a, b), _ in s.conflicts:
        clients.add(t.client)
        forged = None
        if ttl_bad(a) != ttl_bad(b):
            forged = a if ttl_bad(a) else b
        elif mac_bad(a) != mac_bad(b):
            forged = a if mac_bad(a) else b
        genuine = None if forged is None else (b if forged is a else a)
        evidence.append(Evidence(t.queries[0].n, f"client query from {t.client}: {t.label}"))
        for idx, r in enumerate((a, b), start=1):
            order = "arrived first" if idx == 1 else "arrived second"
            if forged is None:
                role = f"conflicting answer #{idx} ({order}): {_describe_answer(r)}, IP TTL {r.ttl}"
            elif r is forged:
                role = f"forged answer ({order}): {_describe_answer(r)}, IP TTL {r.ttl}, MAC {r.eth_src}"
            else:
                role = f"genuine answer ({order}): {_describe_answer(r)}, IP TTL {r.ttl}"
            evidence.append(Evidence(r.n, role))
        q0 = t.queries[0].ts
        facts.append(f"{t.label} asked by {t.client} at {rel(q0)}: answer 1 (packet {a.n}, {_ms(a.ts - q0)} after "
                     f"the query, IP TTL {a.ttl}, MAC {a.eth_src}) said {_describe_answer(a)}; answer 2 (packet "
                     f"{b.n}, {_ms(b.ts - q0)} after the query, IP TTL {b.ttl}, MAC {b.eth_src}) said "
                     f"{_describe_answer(b)}.")
        if forged is not None:
            forged_addrs.update(_addresses(forged))
            if forged.eth_src and mac_bad(forged):
                attacker_macs.add(forged.eth_src)
            if forged is a:
                first_wins = True
            later = b if forged is a else a
            for icmp in icmp_reject.get((later.ip_src, later.ip_dst, later.dport), []):
                if 0 <= icmp.ts - later.ts <= 1.0:
                    evidence.append(Evidence(icmp.n, "client rejected the later answer (ICMP port unreachable): it "
                                                     "had already accepted the first one"))
                    facts.append(f"The client answered the later reply with ICMP port unreachable (packet {icmp.n}), "
                                 "so it had already accepted the earlier one.")
                    break
            for addr in _addresses(forged):
                for c in conns_by_pair.get((t.client, addr), []):
                    if c.first_ts >= forged.ts:
                        client_used.append(c)
                        evidence.append(Evidence(c.packets[0].n, f"client connects to the forged address {addr} "
                                                                 f"(port {c.server[1]})"))
                        facts.append(f"After the forged answer, {t.client} opened a TCP connection to {addr}:"
                                     f"{c.server[1]} (packet {c.packets[0].n}) - it used the forged address.")
                        break
            if genuine is not None:
                facts.append(f"The genuine answer for {t.qname} is probably {_describe_answer(genuine)}.")
    for r in s.unsolicited[:EVIDENCE_CAP // 3]:
        clients.add(r.ip_dst)
        evidence.append(Evidence(r.n, f"unsolicited answer (no matching query) to {r.ip_dst}:{r.dport}: "
                                      f"{r.dns.get('qname')} -> {_describe_answer(r)}, txid {r.dns.get('id')}"))
    if s.unsolicited:
        forged_addrs.update(a for r in s.unsolicited for a in _addresses(r))
        attacker_macs.update(r.eth_src for r in s.unsolicited if mac_bad(r) and r.eth_src)
        facts.append(f"{len(s.unsolicited)} answers from {server} between {rel(s.unsolicited[0].ts)} and "
                     f"{rel(s.unsolicited[-1].ts)} match no query (names: "
                     f"{_short_list(sorted({r.dns.get('qname') for r in s.unsolicited}), 4)}; "
                     f"{len({r.dns.get('id') for r in s.unsolicited})} distinct txids).")
    for r, t in s.foreign[:EVIDENCE_CAP // 4]:
        clients.add(t.client)
        evidence.append(Evidence(t.queries[0].n, f"query sent to {t.server}: {t.label}"))
        evidence.append(Evidence(r.n, f"answer from {server}, which was not queried: {_describe_answer(r)}"))
    if s.foreign:
        forged_addrs.update(a for r, _ in s.foreign for a in _addresses(r))
        facts.append(f"{len(s.foreign)} answer(s) came from {server} for queries sent to "
                     f"{', '.join(sorted({t.server for _, t in s.foreign}))}.")
    for r in s.contradicts[:10]:
        clients.add(r.ip_dst)
        evidence.append(Evidence(r.n, f"answer contradicting {server}'s earlier answers: {_describe_answer(r)}, "
                                      f"IP TTL {r.ttl}"))
    for n, got, legit in s.dhcp_mismatch[:5]:
        facts.append(f"{server} answered {n} -> {_short_list(sorted(got), 3)}; the DHCP-provided resolver answered "
                     f"{_short_list(sorted(legit), 3)}.")
    if ttl_ref is not None:
        facts.append(f"Normal answers from {server} arrive with IP TTL {ttl_ref}"
                     + (f" from MAC {mac_ref}." if mac_ref else "."))
    evidence = evidence[:EVIDENCE_CAP]
    all_times = [r.ts for r in suspect_resps]
    critical = assessment == ATTACK and (first_wins or client_used) and strong_conflicts
    confirmed = assessment == ATTACK
    opening = (f"Answers that claim to come from the DNS server {server} do not match its real behaviour. "
               if confirmed else f"DNS answers from {server} look unusual, but the capture does not prove forgery. ")
    summary = (opening +
               (f"{len(s.conflicts)} lookup(s) got two contradicting answers; " if s.conflicts else "") +
               (f"{len(s.unsolicited)} answers arrived for queries nobody sent; " if s.unsolicited else "") +
               (f"{len(s.foreign)} answer(s) came from a server the client never asked; " if s.foreign else "") +
               ("the suspicious answers point to " + _short_list(sorted(forged_addrs), 4) + ". " if forged_addrs else "") +
               ("The forged answer arrived first, so the client most likely used it." if first_wins else ""))
    return Finding(
        detector=NAME, kind="DNS_HIJACK_SUSPECTED",
        title=f"Forged DNS answers impersonating {server}" if confirmed else f"Unexpected DNS answers from {server}",
        category="attack", assessment=assessment,
        severity=("critical" if critical else "high") if assessment == ATTACK else "low",
        evidence_strength="strong" if any(i.strength == "strong" and i.points_to == ATTACK for i in indicators)
        else "moderate",
        summary=summary.strip(),
        impact=("Clients can be sent to an attacker-controlled address instead of the real website (phishing, "
                "credential theft, malware downloads) while the address bar still shows the right name."),
        likely_cause=("A device on the path (or on the local network after ARP / DHCP spoofing) is injecting forged "
                      "DNS responses that race or replace the genuine resolver's answers." if confirmed else
                      "Either a misconfigured resolver / load balancer (several addresses, answering from the wrong "
                      "one) or a device that can see the queries and injects its own answers; more evidence is "
                      "needed to tell them apart."),
        recommendations=["Flush the DNS cache on affected clients ('ipconfig /flushdns') and on the resolver.",
                         "Verify each client's configured DNS servers and the router's DNS / DHCP settings for "
                         "tampering (a changed upstream resolver is a common router compromise).",
                         "Check for ARP spoofing or a rogue DHCP server on the same segment (see related findings); "
                         + (f"locate the device with MAC {_short_list(sorted(attacker_macs), 3)} via the switch "
                            "MAC table." if attacker_macs else "trace the device by its TTL / MAC."),
                         "Enable DNSSEC validation on the resolver and DNS-over-HTTPS / DNS-over-TLS on clients so "
                         "forged answers are rejected.",
                         "Treat any credentials entered on the affected sites since the first forged answer as "
                         "compromised."],
        facts=facts,
        alternatives=["A misconfigured resolver with several addresses or a load balancer can produce mismatched "
                      "source addresses or TTLs; this alone is not proof of an attack.",
                      "Split-horizon DNS legitimately returns private addresses for public-looking names."],
        limitations=["The capture cannot show which answer a client finally used unless it rejects the other one "
                     "(ICMP) or connects to one of the addresses.",
                     "An attacker who blocks the genuine answer entirely leaves no conflicting pair to observe."],
        indicators=indicators,
        hosts={"dns_server": [server], "client": sorted(clients),
               ("forged_answer_address" if confirmed else "suspicious_answer_address"): sorted(forged_addrs),
               "suspected_attacker_mac": sorted(attacker_macs)},
        time_start=min(all_times) if all_times else None, time_end=max(all_times) if all_times else None,
        evidence=evidence,
        metrics={"conflicting_lookups": len(s.conflicts), "unsolicited_answers": len(s.unsolicited),
                 "answers_from_unqueried_server": len(s.foreign), "ttl_anomalies": len(ttl_anom),
                 "mac_anomalies": len(mac_anom), "bruteforce_targets": len(brute_hits),
                 "private_answers_for_public_names": len(private_hits), "dhcp_resolver_mismatches": len(s.dhcp_mismatch),
                 "baseline_ip_ttl": ttl_ref, "baseline_mac": mac_ref,
                 "client_connected_to_forged_address": len(client_used)},
        rule="assess() over documented DNS forgery indicators (conflicting answers, IP TTL / MAC anomalies, "
             "unsolicited answers, answers from unqueried servers)")


# --- entry point ---------------------------------------------------------------------------

def detect(ctx: AnalysisContext) -> list[Finding]:
    if not ctx.dns:
        return []
    st = _build(ctx)
    by_client_name: dict[tuple, list[_Txn]] = defaultdict(list)
    for t in st.txns:
        by_client_name[(t.client, t.qname)].append(t)
    findings: list[Finding] = []
    findings += _unresponsive(ctx, st, by_client_name)
    findings += _server_failures(ctx, st)
    findings += _nxdomain(ctx, st)
    findings += _slow(ctx, st)
    findings += _hijack(ctx, st)
    return findings
