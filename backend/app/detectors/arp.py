"""ARP spoofing, duplicate IP addresses and ARP conflicts.

Objective
    Two different MAC addresses claiming the same IPv4 address is a symptom, not a diagnosis.
    It happens when a device is replaced, when a high-availability pair fails over, when two
    devices are configured with the same address (a fault) and when an attacker poisons ARP
    caches to intercept traffic (an attack). This detector reconstructs *who claimed what, when,
    and whether anybody asked*, and only calls something an attack when several independent
    behaviours that legitimate devices do not show are present together.

Algorithm
    1. ARP pass (sort by time: O(n log n); then one O(n) walk). Every ARP request or reply is a
       *claim* "sender IP is at sender MAC" (that is how receivers update their caches). Claims
       are keyed by (VLAN, IP) so the same private address re-used on two VLANs is not a
       conflict. Each claim is classified:
         * request      - op 1 asking for another address (the sender claims its own IP)
         * reply        - op 2 *solicited*: a request for that IP from the reply's recipient
                          (matched by recipient IP or MAC) was seen within ``arp_reply_window``
         * unsolicited  - op 2 unicast reply that nobody asked for (poisoning tools send these
                          periodically so victims' caches never expire)
         * unverified   - a reply in the first ``arp_reply_window`` seconds of the capture whose
                          request may simply have been sent before the capture started
         * gratuitous   - announcement (sender IP == target IP, or a broadcast reply); this is
                          how devices legitimately announce themselves at boot or on failover
       RFC 5227 probes (sender IP 0.0.0.0) are not claims. They open a short conflict window:
       any ARP packet whose *sender* IP is the probed address from another MAC (a defence), or
       a simultaneous probe from another MAC, is an address conflict.
       The pass also records one-MAC-many-IPs claims and frames whose Ethernet source MAC differs
       from the ARP sender MAC (known legitimate cases are excluded: VRRP/HSRP/GLBP virtual MACs,
       Microsoft NLB unicast and multicast cluster MACs).
    2. For every contested (VLAN, IP) - two or more MACs - an *owner* is chosen (not suspicious,
       not a mere prober, preferably the router MAC, earliest claim) and every other MAC is a
       *challenger* (capped at ARP_MAX_CHALLENGERS per address).
    3. One pass over IPv4 frames (only when something is contested): per (IP, MAC) originating
       traffic intervals, frames *redirected* to a challenger MAC (addressed to the contested IP,
       or - when the contested IP is the gateway - to an off-link destination), and frames the
       challenger *relays* onward (same IP src/dst/ID/protocol plus L4 ports, sequence and length
       within ARP_RELAY_WINDOW). Relayed copies are not counted as the challenger "using" the IP.
    4. Indicators are weighed with ``assess()`` per (owner, challenger) pair; the result chooses
       the finding kind. Attack pairs are grouped per sending device into one ARP_SPOOFING finding.

Indicators
    ATTACK
      A1 unsolicited replies for the IP: >= arp_unsolicited_min moderate, fewer weak
      A2 the IP is the default gateway / DNS server: strong when the challenger also shows active
         poisoning behaviour (A1, A5, A6 or A8), otherwise moderate (a laptop mis-configured with
         the gateway address is a fault)
      A3 the challenger also claims other IP(s): strong with active poisoning, otherwise weak
         (proxy ARP routers legitimately answer for many addresses)
      A4 flip-flop (>= arp_flip_min_transitions transitions, owner re-asserting) while the
         challenger's replies are mostly unsolicited: moderate
      A5 unexplained Ethernet-source / ARP-sender MAC mismatch: strong when the transmitting MAC
         is itself known to use a different IP, otherwise moderate
      A6 traffic relay (man-in-the-middle): frames redirected to the challenger are re-sent by it
         to another MAC: strong. Redirection without relay: weak (the duplicate device of a
         fault also receives traffic)
      A7 >= arp_unsolicited_min gratuitous announcements spread over > ARP_GARP_PERSIST_SECONDS
         while the owner keeps re-asserting: moderate (failover sends one short burst)
      A8 the MAC claimed >= ARP_SWEEP_MIN_IPS different IPs through unsolicited replies: strong
    FAULT
      F1 both MACs answered ARP requests for the IP, interleaved, without unsolicited replies:
         moderate
      F2 both MACs originated IPv4 traffic from the IP during overlapping periods: moderate
      F3 RFC 5227 probe for the IP answered by another MAC (or simultaneous probes): strong
      F4 both MACs announced the IP with gratuitous ARP: weak
    BENIGN
      B1 exactly one clean hand-over (owner -> challenger, no reversion, no unsolicited
         replies, no MAC mismatch): moderate
      B2 the old MAC fell silent (no ARP and no IP traffic) before the new MAC appeared: moderate
      B3 the new MAC announced itself with a gratuitous ARP: weak
      B4 the new MAC is a VRRP/HSRP/GLBP virtual-router MAC: moderate

Kinds
    ARP_SPOOFING        (attack)  pair assessed ATTACK, or A8 alone (one MAC poisoning many IPs)
    DUPLICATE_IP        (fault)   pair assessed FAULT with F1, F2 or F3
    ARP_CONFLICT        (fault)   contested mapping that is FAULT without duplicate-specific
                                  evidence, or INCONCLUSIVE
    ARP_MAPPING_CHANGED (fault list, assessment benign, severity info) one clean change

Limitations
    * The capture point decides visibility: a switch port sees ARP broadcasts but only the
      unicast replies sent to that port, so poisoning of other hosts can be invisible.
    * "Unsolicited" is relative to the requests in the capture; a request lost by the capture
      makes a legitimate reply look unsolicited (one or two such replies only produce weak
      indicators, and the first ``arp_reply_window`` seconds are never judged).
    * MAC addresses can be forged; switch port lookups locate where frames entered the network.
    * IPv6 Neighbor Discovery spoofing is out of scope (ARP is IPv4 only). Address-denial attacks
      that answer every RFC 5227 probe are reported as conflicts/duplicates per address.
    * A VRRP pair that fails over and then pre-empts back (A -> B -> A) without virtual MACs is
      reported as an inconclusive ARP_CONFLICT, not as an attack.
"""
from __future__ import annotations

from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from statistics import median, pstdev

from ..context import AnalysisContext, is_private
from ..model import ATTACK, BENIGN, FAULT, INCONCLUSIVE, Evidence, Finding, Indicator, PacketRecord, assess

NAME = "arp"

# A MAC claiming at least this many different IPs through *unsolicited* unicast replies is
# poisoning a range of addresses (proxy ARP routers answer solicited requests; MetalLB-style
# announcers use gratuitous broadcasts, so neither is counted).
ARP_SWEEP_MIN_IPS = 5
# A relayed copy of a frame must leave the challenger within this time of arriving at it.
ARP_RELAY_WINDOW = 1.0
# Gratuitous announcements spread over longer than this are persistent re-poisoning, not the
# short burst a failover sends (keepalived sends 5 + 5 within ~5 s by default).
ARP_GARP_PERSIST_SECONDS = 30.0
# Unsolicited replies whose interval coefficient of variation is below this are "periodic".
ARP_PERIODIC_CV = 0.35
# Bounds that keep pathological captures (ARP floods with random MACs) linear.
ARP_MAX_CHALLENGERS = 20
ARP_MAX_EVIDENCE = 100
ARP_MAX_PENDING_RELAY = 200_000

BROADCAST = "ff:ff:ff:ff:ff:ff"
ZERO_MAC = "00:00:00:00:00:00"
STRENGTH_RANK = {"strong": 3, "moderate": 2, "weak": 1}

KNOWN_OUIS = {"00:50:56": "VMware", "00:0c:29": "VMware", "08:00:27": "Oracle VirtualBox",
              "52:54:00": "QEMU/KVM", "00:15:5d": "Microsoft Hyper-V", "00:00:5e": "IANA VRRP",
              "00:00:0c": "Cisco", "00:07:b4": "Cisco GLBP"}


# --- small helpers ---------------------------------------------------------------------------

def _mac(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    v = value.strip().lower().replace("-", ":")
    return v if len(v) == 17 else None


def _usable_ip(ip: str | None) -> bool:
    """IPv4 unicast addresses that can legitimately be claimed in ARP."""
    if not ip or ip == "0.0.0.0" or ip == "255.255.255.255":
        return False
    try:
        first = int(ip.split(".", 1)[0])
    except ValueError:
        return False
    return first not in (0, 127) and first < 224


def _virtual_router_mac(mac: str) -> bool:
    return (mac.startswith("00:00:5e:00:01:") or mac.startswith("00:00:5e:00:02:")   # VRRP
            or mac.startswith("00:00:0c:07:ac:") or mac.startswith("00:00:0c:9f:f")  # HSRP v1/v2
            or mac.startswith("00:07:b4:00:"))                                       # GLBP


def _explained_mismatch(eth: str, hw: str) -> str | None:
    """Legitimate reasons for Ethernet source != ARP sender MAC."""
    if _virtual_router_mac(hw):
        return "virtual router MAC"
    if int(hw[:2], 16) & 1:
        return "multicast cluster MAC (e.g. Microsoft NLB multicast mode)"
    if hw.startswith("02:bf:") and eth.startswith("02:") and eth[6:] == hw[6:]:
        return "Microsoft NLB unicast mode"
    return None


def _mac_note(mac: str) -> str:
    vendor = KNOWN_OUIS.get(mac[:8])
    if vendor:
        return f"{mac}: vendor prefix {mac[:8]} belongs to {vendor}"
    if int(mac[:2], 16) & 2:
        return (f"{mac} is a locally administered address (set by software: a virtual machine, a "
                "randomised 'private' Wi-Fi address or a tool), so its vendor prefix identifies nothing")
    return f"{mac}: look up the vendor prefix {mac[:8].upper()} in the IEEE OUI registry"


def _where(key: tuple) -> str:
    vlan, ip = key
    return ip if vlan is None else f"{ip} (VLAN {vlan})"


def _flow_key(r: PacketRecord) -> tuple:
    # IP ID alone is not unique (many stacks send 0 or a constant with DF set), so the L4
    # identity is added; a relaying host forwards the datagram without changing any of these.
    return (r.ip_src, r.ip_dst, r.ip_id, r.ip_proto, r.sport, r.dport, r.seq, r.ack,
            r.payload_len, r.icmp_type)


def _strength(indicators: list[Indicator], direction: str) -> str:
    rel = [i for i in indicators if i.points_to == direction]
    if any(i.strength == "strong" for i in rel):
        return "strong"
    if sum(i.strength == "moderate" for i in rel) >= 2:
        return "moderate"
    return "weak"


@dataclass(slots=True)
class _Claim:
    rec: PacketRecord
    mac: str                    # ARP sender MAC (the claimed mapping)
    kind: str                   # request / reply / unsolicited / unverified / gratuitous
    req_n: int | None = None    # request answered by a solicited reply
    sender: str | None = None   # Ethernet source MAC (the device that physically sent it)
    mismatch: bool = False      # unexplained Ethernet-source / ARP-sender difference

    @property
    def ts(self) -> float:
        return self.rec.ts


@dataclass
class _Conflict:
    probe: PacketRecord
    prober: str
    other: PacketRecord
    other_mac: str
    how: str                    # "defence" or "simultaneous probe"


@dataclass
class _Pair:
    key: tuple
    owner: str
    chal: str
    sender: str
    verdict: str = INCONCLUSIVE
    kind: str = "ARP_CONFLICT"
    tagged: list[tuple[str, Indicator]] = field(default_factory=list)
    evidence: list[tuple[int, str]] = field(default_factory=list)
    facts: list[str] = field(default_factory=list)
    m: dict = field(default_factory=dict)     # numbers for metrics and text

    @property
    def indicators(self) -> list[Indicator]:
        return [i for _, i in self.tagged]


class _Redirect:
    __slots__ = ("count", "samples", "relays", "relay_samples", "ttl_dec", "sources")

    def __init__(self) -> None:
        self.count = 0
        self.samples: list[PacketRecord] = []
        self.relays = 0
        self.relay_samples: list[tuple[PacketRecord, PacketRecord]] = []
        self.ttl_dec = 0
        self.sources: Counter = Counter()


# --- detector --------------------------------------------------------------------------------

def detect(ctx: AnalysisContext) -> list[Finding]:
    th = ctx.thresholds
    window = th.arp_reply_window
    if not ctx.arp:
        return []
    start = ctx.start_ts

    timeline: dict[tuple, list[_Claim]] = defaultdict(list)           # (vlan, ip) -> claims
    by_mac: dict[tuple, dict[str, list[_Claim]]] = defaultdict(lambda: defaultdict(list))
    mac_ips: dict[tuple, Counter] = defaultdict(Counter)              # (vlan, mac) -> ip counts
    mac_unsol: dict[tuple, Counter] = defaultdict(Counter)            # (vlan, mac) -> ip counts
    mac_unsol_recs: dict[tuple, list[PacketRecord]] = defaultdict(list)
    conflicts: dict[tuple, list[_Conflict]] = defaultdict(list)
    open_probes: dict[tuple, list[list]] = defaultdict(list)
    last_req_ip: dict[tuple, PacketRecord] = {}
    last_req_mac: dict[tuple, PacketRecord] = {}
    skipped = explained = 0

    def live(key: tuple, now: float) -> list[list]:
        lst = open_probes.get(key)
        if not lst:
            return []
        lst[:] = [p for p in lst if 0 <= now - p[0].ts <= window]
        return lst

    # 1. ARP pass ---------------------------------------------------------------------------
    for i, r in enumerate(sorted(ctx.arp, key=lambda x: (x.ts, x.n))):
        if i % 5000 == 0:
            ctx.check_deadline()
        op = r.arp_op
        hw = _mac(r.arp_hwsrc)
        psrc, pdst, vlan = r.arp_psrc, r.arp_pdst, r.vlan
        if op not in (1, 2) or hw is None or hw in (ZERO_MAC, BROADCAST) or not pdst or not psrc:
            skipped += 1
            continue
        eth = _mac(r.eth_src)
        if psrc == "0.0.0.0":
            if op == 1 and _usable_ip(pdst):          # RFC 5227 probe
                key = (vlan, pdst)
                for p in live(key, r.ts):
                    if p[1] != hw and not p[2]:
                        p[2] = True
                        conflicts[key].append(_Conflict(p[0], p[1], r, hw, "simultaneous probe"))
                open_probes[key].append([r, hw, False])
                last_req_mac[(vlan, hw, pdst)] = r
            else:
                skipped += 1
            continue
        if not _usable_ip(psrc):
            skipped += 1
            continue
        key = (vlan, psrc)
        for p in live(key, r.ts):
            if p[1] != hw and not p[2]:
                p[2] = True
                conflicts[key].append(_Conflict(p[0], p[1], r, hw, "defence"))
        req = None
        if op == 1:
            if psrc == pdst:
                kind = "gratuitous"
            else:
                kind = "request"
                last_req_ip[(vlan, psrc, pdst)] = r
                last_req_mac[(vlan, hw, pdst)] = r
        else:
            hwdst, edst = _mac(r.arp_hwdst), _mac(r.eth_dst)
            if psrc == pdst or edst == BROADCAST or hwdst == BROADCAST:
                kind = "gratuitous"
            else:
                for cand in (last_req_ip.get((vlan, pdst, psrc)), last_req_mac.get((vlan, hwdst, psrc)),
                             last_req_mac.get((vlan, edst, psrc))):
                    if cand is not None and 0 <= r.ts - cand.ts <= window and (req is None or cand.ts > req.ts):
                        req = cand
                kind = "reply" if req else ("unverified" if r.ts - start < window else "unsolicited")
        mismatch = False
        if eth and eth != hw:
            if _explained_mismatch(eth, hw) is None:
                mismatch = True
            else:
                explained += 1
        claim = _Claim(r, hw, kind, req.n if req else None, eth or hw, mismatch)
        timeline[key].append(claim)
        by_mac[key][hw].append(claim)
        mac_ips[(vlan, hw)][psrc] += 1
        if kind == "unsolicited":
            mac_unsol[(vlan, hw)][psrc] += 1
            if len(mac_unsol_recs[(vlan, hw)]) < 40:
                mac_unsol_recs[(vlan, hw)].append(r)

    sweep_macs = {vm for vm, ips in mac_unsol.items() if len(ips) >= ARP_SWEEP_MIN_IPS}

    # 2. contested addresses: owner and challengers -----------------------------------------
    router_macs = ctx.router_macs
    contested: dict[tuple, tuple[str, list[str]]] = {}
    for key in set(by_mac) | set(conflicts):
        macs = dict(by_mac.get(key, {}))
        probers = set()
        for c in conflicts.get(key, []):
            for mac in (c.prober, c.other_mac):
                macs.setdefault(mac, [])
            probers.add(c.prober)
        if len(macs) < 2:
            continue
        vlan = key[0]

        def first_seen(mac: str) -> float:
            ts = [c.ts for c in macs[mac][:1]]
            ts += [c.probe.ts for c in conflicts.get(key, []) if c.prober == mac][:1]
            return min(ts) if ts else float("inf")

        def owner_rank(mac: str) -> tuple:
            claims = macs[mac]
            suspicious = (any(c.kind == "unsolicited" or c.mismatch for c in claims)
                          or (vlan, mac) in sweep_macs)
            only_probed = not claims
            others = len(mac_ips.get((vlan, mac), {})) - (1 if claims else 0)
            return (suspicious, only_probed, mac not in router_macs, others > 0, first_seen(mac), mac)

        ranked = sorted(macs, key=owner_rank)
        contested[key] = (ranked[0], ranked[1:1 + ARP_MAX_CHALLENGERS])
    if not contested:
        return _sweep_only_findings(ctx, sweep_macs, mac_unsol, mac_unsol_recs, mac_ips, set())

    # 3. IPv4 pass: traffic origin, redirection and relay ---------------------------------
    claimed_ips = {ip for (_, ip) in timeline}
    gateway_cache: dict[tuple, bool] = {}

    def is_gateway(key: tuple, owner: str) -> bool:
        if key not in gateway_cache:
            ip = key[1]
            gateway_cache[key] = (ip in ctx.dhcp_offered["router"]
                                  or (ip in ctx.gateway_ips and owner in router_macs))
        return gateway_cache[key]

    watch: dict[str, dict[tuple, float]] = defaultdict(dict)        # mac -> contested key -> since
    gw_watch: dict[str, list[tuple[tuple, float]]] = defaultdict(list)
    for key, (owner, chals) in contested.items():
        for chal in chals:
            claims = by_mac[key].get(chal) or []
            since = claims[0].ts if claims else None
            if since is None:
                continue
            for mac in {chal} | {c.sender for c in claims if c.sender}:
                watch[mac][key] = since
                if is_gateway(key, owner):
                    gw_watch[mac].append((key, since))
    origin: dict[tuple, list] = {}           # (vlan, ip, mac) -> [count, first_ts, last_ts, [n]]
    redirects: dict[tuple, _Redirect] = defaultdict(_Redirect)   # (mac, key)
    pending: dict[tuple, tuple[PacketRecord, tuple]] = {}
    expiry: deque = deque()
    for i, r in enumerate(ctx.records):
        if i % 5000 == 0:
            ctx.check_deadline()
        if r.l3 != "IPv4" or not r.ip_src or not r.ip_dst:
            continue
        esrc, edst = r.eth_src, r.eth_dst
        while expiry and r.ts - expiry[0][0] > ARP_RELAY_WINDOW:
            _, fk, n = expiry.popleft()
            held = pending.get(fk)
            if held is not None and held[0].n == n:
                del pending[fk]
        relayed = False
        if esrc in watch and edst != esrc:
            fk = _flow_key(r)
            held = pending.get(fk)
            if held is not None and held[0].eth_dst == esrc and held[0].eth_src != esrc:
                inbound, rkey = held
                red = redirects[(esrc, rkey)]
                red.relays += 1
                if inbound.ttl is not None and r.ttl is not None and r.ttl == inbound.ttl - 1:
                    red.ttl_dec += 1
                if len(red.relay_samples) < 15:
                    red.relay_samples.append((inbound, r))
                del pending[fk]
                relayed = True
        if edst in watch and esrc != edst:
            k = (r.vlan, r.ip_dst)
            since = watch[edst].get(k)
            target = k if since is not None and r.ts >= since else None
            if target is None and r.ip_dst not in claimed_ips and _usable_ip(r.ip_dst):
                for gkey, gsince in gw_watch.get(edst, ()):
                    if gkey[0] == r.vlan and r.ts >= gsince:
                        target = gkey
                        break
            if target is not None:
                red = redirects[(edst, target)]
                red.count += 1
                red.sources[r.ip_src] += 1
                if len(red.samples) < 15:
                    red.samples.append(r)
                if len(pending) < ARP_MAX_PENDING_RELAY:
                    fk = _flow_key(r)
                    pending[fk] = (r, target)
                    expiry.append((r.ts, fk, r.n))
        if not relayed and esrc and (r.vlan, r.ip_src) in contested:
            ok = (r.vlan, r.ip_src, esrc)
            st = origin.get(ok)
            if st is None:
                origin[ok] = [1, r.ts, r.ts, [r.n]]
            else:
                st[0] += 1
                st[2] = r.ts
                if len(st[3]) < 2:
                    st[3].append(r.n)

    # 4. per-pair indicators --------------------------------------------------------------------
    pairs: list[_Pair] = []
    for key, (owner, chals) in sorted(contested.items(), key=lambda kv: (str(kv[0][0]), kv[0][1])):
        for chal in chals:
            pairs.append(_analyse_pair(ctx, key, owner, chal, timeline[key], by_mac[key],
                                       conflicts.get(key, []), mac_ips, sweep_macs, origin,
                                       redirects, is_gateway(key, owner)))

    findings: list[Finding] = []
    attack_by_device: dict[tuple, list[_Pair]] = defaultdict(list)
    per_ip: dict[tuple, list[_Pair]] = defaultdict(list)
    for p in pairs:
        if p.verdict == ATTACK:
            attack_by_device[(p.key[0], p.sender)].append(p)
        else:
            per_ip[p.key].append(p)
    for (vlan, device), items in attack_by_device.items():
        findings.append(_spoofing_finding(ctx, vlan, device, items, mac_ips, mac_unsol,
                                          mac_unsol_recs, sweep_macs))
    rank = {"DUPLICATE_IP": 0, "ARP_CONFLICT": 1, "ARP_MAPPING_CHANGED": 2}
    for key, items in per_ip.items():
        items.sort(key=lambda p: rank[p.kind])
        findings.append(_ip_finding(ctx, key, items, origin))
    done = {(vlan, dev) for vlan, dev in attack_by_device}
    findings.extend(_sweep_only_findings(ctx, sweep_macs, mac_unsol, mac_unsol_recs, mac_ips, done))
    if skipped or explained:
        for f in findings:
            f.metrics.setdefault("arp_frames_ignored", skipped)
            f.metrics.setdefault("explained_mac_mismatches", explained)
    return findings


# --- pair analysis -----------------------------------------------------------------------------

def _analyse_pair(ctx: AnalysisContext, key: tuple, owner: str, chal: str, timeline: list[_Claim],
                  macs: dict[str, list[_Claim]], conflicts: list[_Conflict], mac_ips: dict,
                  sweep_macs: set, origin: dict, redirects: dict, gateway: bool) -> _Pair:
    th = ctx.thresholds
    vlan, ip = key
    start = ctx.start_ts
    oc, cc = macs.get(owner, []), macs.get(chal, [])
    c_unsol = [c for c in cc if c.kind == "unsolicited"]
    c_sol = [c for c in cc if c.kind == "reply"]
    o_sol = [c for c in oc if c.kind == "reply"]
    c_garp = [c for c in cc if c.kind == "gratuitous"]
    o_garp = [c for c in oc if c.kind == "gratuitous"]
    c_mis = [c for c in cc if c.mismatch]
    senders = Counter(c.sender for c in cc if c.sender)
    sender = senders.most_common(1)[0][0] if senders else chal
    c_other = sorted(set(mac_ips.get((vlan, chal), {})) - {ip})
    o_other = sorted(set(mac_ips.get((vlan, owner), {})) - {ip})
    sweep = (vlan, chal) in sweep_macs or (vlan, sender) in sweep_macs
    dns = ip in ctx.dns_servers
    pair_conf = [c for c in conflicts if {c.prober, c.other_mac} == {owner, chal}]

    # sub-timeline of the two MACs: runs, transitions, reversion
    runs: list[_Claim] = []
    for c in timeline:
        if c.mac in (owner, chal) and (not runs or runs[-1].mac != c.mac):
            runs.append(c)
    transitions = max(len(runs) - 1, 0)
    flip = transitions >= th.arp_flip_min_transitions
    reassert = next((c for idx, c in enumerate(runs) if c.mac == owner and idx > 0), None)

    # redirection / relay towards the challenger (and its transmitting MAC)
    red = _Redirect()
    for mac in {chal, sender}:
        got = redirects.get((mac, key))
        if got is not None:
            red.count += got.count
            red.relays += got.relays
            red.ttl_dec += got.ttl_dec
            red.samples.extend(got.samples)
            red.relay_samples.extend(got.relay_samples)
            red.sources.update(got.sources)
    sender_ips = sorted(set(mac_ips.get((vlan, sender), {})) - {ip}) if sender != chal else c_other
    active = bool(c_unsol or c_mis or red.relays or sweep)

    o_ip = origin.get((vlan, ip, owner))
    c_ip = origin.get((vlan, ip, chal))
    overlap = bool(o_ip and c_ip and max(o_ip[1], c_ip[1]) <= min(o_ip[2], c_ip[2]))
    c_first = min([c.ts for c in cc[:1]] + [c.probe.ts for c in pair_conf if c.prober == chal][:1] or [0.0])
    o_last = max([c.ts for c in oc[-1:]] + ([o_ip[2]] if o_ip else []) or [0.0])
    old_silent = bool(oc) and bool(cc) and o_last < c_first

    role = ("the default gateway and DNS server" if gateway and dns else "the default gateway" if gateway
            else "a DNS server" if dns else None)
    where = _where(key)
    p = _Pair(key, owner, chal, sender)
    add = p.tagged.append

    # attack indicators
    interval = None
    if len(c_unsol) >= 3:
        gaps = [b.ts - a.ts for a, b in zip(c_unsol, c_unsol[1:])]
        interval = median(gaps)
        periodic = interval > 0 and pstdev(gaps) / max(sum(gaps) / len(gaps), 1e-9) < ARP_PERIODIC_CV
    else:
        periodic = False
    if len(c_unsol) >= th.arp_unsolicited_min:
        add(("A1", Indicator(f"{chal} sent {len(c_unsol)} ARP replies claiming {where} that no device had "
                             f"asked for" + (f", regularly every ~{interval:.1f} s (the refresh pattern of "
                                             "poisoning tools)" if periodic else ""), ATTACK, "moderate")))
    elif c_unsol:
        add(("A1", Indicator(f"{chal} sent {len(c_unsol)} unsolicited ARP reply(ies) claiming {where} "
                             f"(below the pattern threshold of {th.arp_unsolicited_min})", ATTACK, "weak")))
    if role:
        add(("A2", Indicator(f"{where} is {role}; whoever answers for it receives other hosts' traffic"
                             + ("" if active else " (but the challenger shows no active poisoning behaviour)"),
                             ATTACK, "strong" if active else "moderate")))
    if c_other:
        add(("A3", Indicator(f"{chal} also claims {len(c_other)} other address(es) "
                             f"({', '.join(c_other[:5])}{' ...' if len(c_other) > 5 else ''}), i.e. one device "
                             f"answering for several IPs", ATTACK, "strong" if active else "weak")))
    if flip and c_unsol and len(c_unsol) > len(c_sol):
        add(("A4", Indicator(f"The mapping of {where} flip-flopped {transitions} times: the real owner keeps "
                             f"re-asserting and {chal} keeps overwriting it with unsolicited replies",
                             ATTACK, "moderate")))
    if c_mis:
        known = bool(sender_ips) and sender != chal
        add(("A5", Indicator(f"{len(c_mis)} ARP frame(s) claiming {where} were transmitted by Ethernet source "
                             f"{sender} but carry ARP sender MAC {chal}" +
                             (f"; {sender} is the device that uses {', '.join(sender_ips[:3])}" if known else ""),
                             ATTACK, "strong" if known else "moderate")))
    if red.relays:
        add(("A6", Indicator(f"{red.relays} frame(s) delivered to {sender} because of the false mapping were "
                             "re-sent by it to the real destination (same IP header and ports"
                             + (f", TTL decreased by one in {red.ttl_dec}" if red.ttl_dec else "")
                             + "): traffic is being relayed through it (man-in-the-middle)", ATTACK, "strong")))
    elif red.count:
        add(("A6", Indicator(f"{red.count} frame(s) for {where if not gateway else 'off-link destinations'} were "
                             f"delivered to {sender} instead of {owner}", ATTACK, "weak")))
    if (len(c_garp) >= th.arp_unsolicited_min and c_garp[-1].ts - c_garp[0].ts > ARP_GARP_PERSIST_SECONDS
            and reassert is not None and flip):
        add(("A7", Indicator(f"{chal} kept announcing {where} with {len(c_garp)} gratuitous ARPs over "
                             f"{c_garp[-1].ts - c_garp[0].ts:.0f} s while the owner re-asserted it", ATTACK,
                             "moderate")))
    if sweep:
        n_ips = max(len(mac_ips.get((vlan, chal), {})), len(mac_ips.get((vlan, sender), {})))
        add(("A8", Indicator(f"{sender} claimed {n_ips} different IP addresses, at least {ARP_SWEEP_MIN_IPS} of "
                             "them through unsolicited replies (poisoning a range of hosts)", ATTACK, "strong")))

    # fault indicators
    if o_sol and c_sol and not c_unsol and transitions >= 2:
        add(("F1", Indicator(f"Both {owner} ({len(o_sol)}x) and {chal} ({len(c_sol)}x) answered ARP requests for "
                             f"{where}, alternately - two devices that both believe they own it", FAULT,
                             "moderate")))
    if overlap:
        add(("F2", Indicator(f"Both MACs sent normal IP traffic from {where} during the same period "
                             f"({o_ip[0]} and {c_ip[0]} frames)", FAULT, "moderate")))
    if pair_conf:
        c0 = pair_conf[0]
        add(("F3", Indicator(f"RFC 5227 address conflict: {c0.prober} probed {ip} and {c0.other_mac} "
                             + ("answered that it already uses it" if c0.how == "defence"
                                else "was probing for the same address at the same time"),
                             FAULT, "moderate" if sweep else "strong")))
    if o_garp and c_garp:
        add(("F4", Indicator(f"Both MACs announced {where} as their own with gratuitous ARP", FAULT, "weak")))

    # benign indicators
    clean = (transitions == 1 and runs and runs[0].mac == owner and not c_unsol and not c_mis
             and not red.relays and not sweep and not pair_conf)
    if clean:
        add(("B1", Indicator(f"A single clean hand-over: {where} moved from {owner} to {chal} and never moved "
                             "back", BENIGN, "moderate")))
    if old_silent and not pair_conf:
        add(("B2", Indicator(f"{owner} went silent (no ARP and no IP traffic) at "
                             f"+{o_last - start:.1f} s, before {chal} first claimed {where} at "
                             f"+{c_first - start:.1f} s", BENIGN, "moderate")))
    if c_garp and not c_unsol and len(c_garp) < th.arp_unsolicited_min:
        add(("B3", Indicator(f"{chal} announced itself with {len(c_garp)} gratuitous ARP(s), as devices do after "
                             "boot or failover", BENIGN, "weak")))
    if _virtual_router_mac(chal):
        add(("B4", Indicator(f"{chal} is a VRRP/HSRP/GLBP virtual-router MAC", BENIGN, "moderate")))

    p.verdict = assess(p.indicators)
    tags = {t for t, _ in p.tagged}
    if p.verdict == ATTACK:
        p.kind = "ARP_SPOOFING"
    elif p.verdict == FAULT and tags & {"F1", "F2", "F3"}:
        p.kind = "DUPLICATE_IP"
    elif p.verdict == BENIGN:
        p.kind = "ARP_MAPPING_CHANGED"
    else:
        p.kind = "ARP_CONFLICT"

    p.m = {"ip": ip, "vlan": vlan, "owner": owner, "challenger": chal, "sender": sender, "role": role,
           "gateway": gateway, "dns": dns, "owner_claims": len(oc), "challenger_claims": len(cc),
           "unsolicited": len(c_unsol), "owner_solicited": len(o_sol), "challenger_solicited": len(c_sol),
           "challenger_gratuitous": len(c_garp), "owner_gratuitous": len(o_garp), "mismatch": len(c_mis),
           "transitions": transitions, "redirected": red.count, "relayed": red.relays, "ttl_dec": red.ttl_dec,
           "owner_ip_frames": o_ip[0] if o_ip else 0, "challenger_ip_frames": c_ip[0] if c_ip else 0,
           "overlap": overlap, "probe_conflicts": len(pair_conf), "interval": interval, "periodic": periodic,
           "challenger_other_ips": c_other, "owner_other_ips": o_other, "sender_ips": sender_ips,
           # Victims: hosts sent false mappings, plus local hosts whose traffic was diverted
           # (redirected packets from internet servers have public sources and are excluded).
           "victims": sorted(({c.rec.arp_pdst for c in c_unsol if c.rec.arp_pdst}
                              | {s for s in red.sources if is_private(s)}) - {ip}),
           "first_owner": oc[0].ts if oc else None, "first_chal": c_first, "old_silent": old_silent,
           "times": [c.ts for c in (oc[:1] + oc[-1:] + cc[:1] + cc[-1:])]
           + [x.ts for x in red.samples[:1]] + [c.probe.ts for c in pair_conf[:1]]}

    # evidence (bounded per role)
    ev = p.evidence.append
    if oc:
        ev((oc[0].rec.n, f"first claim of {where} by {owner} ({_claim_word(oc[0])}, +{oc[0].ts - start:.1f} s)"))
    for c in cc[:1]:
        ev((c.rec.n, f"first claim of {where} by {chal} ({_claim_word(c)}, +{c.ts - start:.1f} s)"))
    for c in c_unsol[:20]:
        ev((c.rec.n, f"unsolicited ARP reply: {ip} is-at {chal}, sent to {c.rec.arp_pdst} "
                     f"(no request from it in the previous {th.arp_reply_window:g} s)"))
    for c in c_mis[:8]:
        ev((c.rec.n, f"MAC mismatch: Ethernet source {c.sender} but ARP sender MAC {chal}"))
    for c in c_garp[:5]:
        ev((c.rec.n, f"gratuitous ARP from {chal} announcing {ip}"))
    for c in o_garp[:3]:
        ev((c.rec.n, f"gratuitous ARP from {owner} announcing {ip}"))
    for c in c_sol[:6]:
        ev((c.rec.n, f"ARP reply from {chal} for {ip} answering request #{c.req_n}"))
        ev((c.req_n, f"ARP request for {ip} answered by {chal}"))
    for c in o_sol[:6]:
        ev((c.rec.n, f"ARP reply from {owner} for {ip} answering request #{c.req_n}"))
        ev((c.req_n, f"ARP request for {ip} answered by {owner}"))
    if reassert is not None:
        ev((reassert.rec.n, f"{owner} re-asserts {ip} after {chal} claimed it (mapping flips back)"))
    for c in pair_conf[:6]:
        ev((c.probe.n, f"RFC 5227 ARP probe from {c.prober}: is {ip} in use?"))
        ev((c.other.n, f"{'defence: ' + ip + ' is already used by ' if c.how == 'defence' else 'simultaneous probe for ' + ip + ' from '}{c.other_mac}"))
    for r in red.samples[:10]:
        ev((r.n, f"redirected: frame {r.ip_src} -> {r.ip_dst} delivered to {r.eth_dst} instead of {owner}"))
    for inbound, out in red.relay_samples[:10]:
        ev((out.n, f"relayed: {sender} re-sent packet #{inbound.n} ({out.ip_src} -> {out.ip_dst}) to {out.eth_dst}"
                   + (f", TTL {inbound.ttl}->{out.ttl}" if inbound.ttl is not None and out.ttl is not None else "")))
    for st, mac in ((o_ip, owner), (c_ip, chal)):
        for n in (st[3] if st else []):
            ev((n, f"IP traffic sent from {ip} by {mac}"))
    return p


def _claim_word(c: _Claim) -> str:
    return {"request": "ARP request", "reply": "solicited ARP reply", "unsolicited": "unsolicited ARP reply",
            "unverified": "ARP reply", "gratuitous": "gratuitous ARP"}.get(c.kind, "ARP")


def _merge_indicators(pairs: list[_Pair]) -> list[Indicator]:
    best: dict[tuple, tuple[Indicator, int]] = {}
    for p in pairs:
        for tag, ind in p.tagged:
            k = (tag, ind.points_to)
            cur = best.get(k)
            if cur is None:
                best[k] = (ind, 1)
            else:
                stronger = ind if STRENGTH_RANK[ind.strength] > STRENGTH_RANK[cur[0].strength] else cur[0]
                best[k] = (stronger, cur[1] + 1)
    out = []
    for (tag, _), (ind, count) in sorted(best.items()):
        text = ind.text + (f" (seen for {count} addresses)" if count > 1 else "")
        out.append(Indicator(text, ind.points_to, ind.strength))
    return out


def _collect_evidence(pairs: list[_Pair], extra: list[tuple[int, str]] = ()) -> list[Evidence]:
    seen: set[int] = set()
    out: list[Evidence] = []
    # Interleave pairs so a long first pair cannot crowd out the others.
    queues = [list(extra)] + [list(p.evidence) for p in pairs]
    while any(queues) and len(out) < ARP_MAX_EVIDENCE:
        for q in queues:
            while q:
                n, role = q.pop(0)
                if n is not None and n not in seen:
                    seen.add(n)
                    out.append(Evidence(n, role))
                    break
            if len(out) >= ARP_MAX_EVIDENCE:
                break
    return out


def _rel(ctx: AnalysisContext, ts: float | None) -> str:
    return "?" if ts is None else f"+{ts - ctx.start_ts:.1f} s"


# --- finding builders --------------------------------------------------------------------------

SPOOF_RECS = [
    "Locate the attacking device: on the access switch run 'show mac address-table address {mac}' (Cisco; "
    "equivalent on other vendors) to find the port, then disconnect or isolate that port.",
    "Enable Dynamic ARP Inspection together with DHCP snooping on the access VLANs so switches drop ARP "
    "replies that do not match the DHCP binding table.",
    "Configure a static ARP entry for the default gateway on critical hosts and servers "
    "(Windows: 'netsh interface ipv4 add neighbors'; Linux: 'ip neigh replace {gw} lladdr {gw_mac} nud permanent').",
    "Treat traffic of the affected hosts since {since} as possibly intercepted: check for TLS certificate "
    "warnings, rotate credentials used over unencrypted protocols, and prefer encrypted, authenticated protocols.",
    "Flush the poisoned ARP caches on the victims ('arp -d *' on Windows, 'ip neigh flush all' on Linux) once "
    "the device is removed, and verify the gateway MAC with 'arp -a'.",
]


def _spoofing_finding(ctx: AnalysisContext, vlan, device: str, pairs: list[_Pair], mac_ips: dict,
                      mac_unsol: dict, mac_unsol_recs: dict, sweep_macs: set) -> Finding:
    th = ctx.thresholds
    indicators = _merge_indicators(pairs)
    if (vlan, device) in sweep_macs and not any(t == "A8" for p in pairs for t, _ in p.tagged):
        indicators.append(_sweep_indicator(vlan, device, mac_ips, mac_unsol))
    assessment = assess(indicators)
    own_ips = sorted(set(mac_ips.get((vlan, device), {})) - {p.key[1] for p in pairs})
    impersonated = [p.key[1] for p in pairs]
    gw_pairs = [p for p in pairs if p.m["gateway"] or p.m["dns"]]
    relays = sum(p.m["relayed"] for p in pairs)
    redirected = sum(p.m["redirected"] for p in pairs)
    unsol = sum(p.m["unsolicited"] for p in pairs)
    mism = sum(p.m["mismatch"] for p in pairs)
    flips = sum(1 for p in pairs if p.m["transitions"] >= th.arp_flip_min_transitions)
    # In two-way poisoning the client and gateway are each impersonated to the other, so a host
    # can be both impersonated and a victim; only the attacker's own addresses are excluded.
    victims = sorted({v for p in pairs for v in p.m["victims"]} - set(own_ips))
    spoofed_macs = sorted({p.chal for p in pairs if p.chal != device})
    all_claimed = sorted(set(mac_ips.get((vlan, device), {}))
                         | {ip for p in pairs for ip in mac_ips.get((vlan, p.chal), {})})
    times = [t for p in pairs for t in p.m["times"] if t is not None]
    t0 = min((p.m["first_chal"] for p in pairs), default=None)
    who = device + (f" (which itself uses {', '.join(own_ips[:3])})" if own_ips else "")
    parts = []
    for p in pairs[:6]:
        desc = f"{_where(p.key)}" + (f" ({p.m['role']})" if p.m["role"] else "") + f", really at {p.owner}"
        parts.append(desc)
    more = f" and {len(pairs) - 6} more" if len(pairs) > 6 else ""
    summary = (f"The device {who} told other machines that it is {'; '.join(parts)}{more}. ")
    if unsol:
        summary += (f"It sent {unsol} ARP replies that nobody had asked for, so that the victims' ARP caches "
                    "point to it instead of the real owner. ")
    if mism:
        summary += (f"{mism} of its ARP frames carried a different sender MAC than the Ethernet frame itself, which "
                    "normal network stacks never do. ")
    if relays:
        summary += (f"Afterwards {redirected} frames were delivered to it and it forwarded {relays} of them on to "
                    "the real destination, so it sits in the middle of the conversation and can read or alter it.")
    elif redirected:
        summary += f"Afterwards {redirected} frames meant for the impersonated address(es) were delivered to it."
    gw = next((p for p in gw_pairs if p.m["gateway"]), None)
    title = (f"ARP spoofing man-in-the-middle by {device}" if relays else
             f"ARP spoofing: {device} impersonates {gw.m['ip']} ({gw.m['role']})" if gw else
             f"ARP spoofing by {device} ({len(pairs)} address{'es' if len(pairs) != 1 else ''})")
    facts = []
    for p in pairs[:10]:
        m = p.m
        facts.append(f"{_where(p.key)}: legitimate owner {p.owner} first seen {_rel(ctx, m['first_owner'])}; "
                     f"{p.chal} claimed it {m['challenger_claims']} times from {_rel(ctx, m['first_chal'])} "
                     f"({m['unsolicited']} unsolicited, {m['challenger_solicited']} solicited, "
                     f"{m['challenger_gratuitous']} gratuitous); mapping transitions: {m['transitions']}"
                     + (f"; unsolicited replies every ~{m['interval']:.1f} s" if m["interval"] else ""))
        if m["relayed"] or m["redirected"]:
            facts.append(f"{_where(p.key)}: {m['redirected']} frames redirected to {p.sender}, {m['relayed']} "
                         f"relayed onward" + (f" with TTL decreased by one ({m['ttl_dec']})" if m["ttl_dec"] else ""))
    if len(pairs) > 10:
        facts.append(f"... and {len(pairs) - 10} more impersonated addresses.")
    facts.append(f"{device} claimed {len(all_claimed)} address(es) in ARP in total: "
                 f"{', '.join(all_claimed[:12])}{' ...' if len(all_claimed) > 12 else ''}")
    if victims:
        facts.append(f"Hosts that were sent false mappings or whose traffic was diverted: {', '.join(victims[:10])}")
    facts.append(_mac_note(device))
    gw_ip = gw.m["ip"] if gw else (ctx.dhcp_offered["router"] and sorted(ctx.dhcp_offered["router"])[0]) or "<gateway IP>"
    gw_mac = gw.owner if gw else "<gateway MAC>"
    recs = [r.format(mac=device, gw=gw_ip, gw_mac=gw_mac, since=_rel(ctx, t0) + " into the capture")
            for r in SPOOF_RECS]
    if spoofed_macs:
        recs.insert(1, f"The forged sender MAC(s) {', '.join(spoofed_macs)} may not exist; search the switch "
                       f"tables for the transmitting MAC {device}.")
    hosts = {"attacker": [device] + own_ips, "impersonated": impersonated,
             "legitimate": sorted({p.owner for p in pairs}), "victim": victims}
    if spoofed_macs:
        hosts["spoofed_mac"] = spoofed_macs
    evidence = _collect_evidence(pairs)
    return Finding(
        detector=NAME, kind="ARP_SPOOFING", title=title, category="attack", assessment=assessment,
        severity="critical" if relays or gw_pairs else "high",
        evidence_strength=_strength(indicators, ATTACK),
        summary=summary.strip(),
        impact=("Traffic of the affected hosts flows through the attacker's machine: it can be read, changed or "
                "dropped. Users may notice slowness, intermittent loss of connectivity or certificate warnings."
                if relays or redirected else
                "Victims that accept the false mapping send their traffic to the wrong device, where it can be "
                "intercepted or dropped."),
        likely_cause=("ARP cache poisoning, most likely deliberate (tools such as arpspoof, Ettercap or Bettercap "
                      "produce exactly this pattern of repeated unsolicited replies"
                      + (" and IP forwarding" if relays else "") + ")."),
        recommendations=recs,
        facts=facts,
        alternatives=["A misconfigured proxy-ARP device or a high-availability pair without a virtual MAC can "
                      "produce some of these signals, but not periodic unsolicited replies combined with "
                      "relaying or answering for several addresses at once.",
                      "A security product that intentionally intercepts traffic (some NAC / captive portal "
                      "systems use ARP poisoning) - check whether such a system is deployed."],
        limitations=["The capture only shows unicast ARP replies sent to or from the capture point; other hosts "
                     "may have been poisoned as well.",
                     "'Unsolicited' is judged against the requests visible in this capture.",
                     "MAC addresses can be forged; the switch port where the frames enter is the reliable way to "
                     "identify the device."],
        indicators=indicators, hosts=hosts,
        time_start=min(times) if times else None, time_end=max(times) if times else None,
        evidence=evidence,
        metrics={"impersonated_ips": len(pairs), "unsolicited_replies": unsol, "redirected_frames": redirected,
                 "relayed_frames": relays, "mac_mismatch_frames": mism, "claimed_ips_total": len(all_claimed),
                 "flip_flop_ips": flips, "gateway_targeted": bool(gw), "attacker_mac": device,
                 "claims": sum(p.m["challenger_claims"] for p in pairs)},
        rule=("Two MACs claim one IP and assess() of the documented indicators (unsolicited replies >= "
              f"{th.arp_unsolicited_min}, gateway/DNS target, one MAC many IPs, flip-flop >= "
              f"{th.arp_flip_min_transitions} transitions, MAC mismatch, traffic relay) returns ATTACK"))


def _sweep_indicator(vlan, mac: str, mac_ips: dict, mac_unsol: dict) -> Indicator:
    n_unsol = len(mac_unsol.get((vlan, mac), {}))
    return Indicator(f"{mac} claimed {len(mac_ips.get((vlan, mac), {}))} different IP addresses, {n_unsol} of them "
                     "through unsolicited replies (poisoning a range of hosts)", ATTACK, "strong")


def _sweep_only_findings(ctx: AnalysisContext, sweep_macs: set, mac_unsol: dict, mac_unsol_recs: dict,
                         mac_ips: dict, done: set) -> list[Finding]:
    """A MAC poisoning many addresses even when none of them is visibly contested."""
    th = ctx.thresholds
    out = []
    for vlan, mac in sorted(sweep_macs, key=lambda vm: (str(vm[0]), vm[1])):
        if (vlan, mac) in done:
            continue
        ips = sorted(mac_unsol[(vlan, mac)])
        total = sum(mac_unsol[(vlan, mac)].values())
        recs = mac_unsol_recs[(vlan, mac)]
        indicators = [_sweep_indicator(vlan, mac, mac_ips, mac_unsol)]
        if total >= th.arp_unsolicited_min:
            indicators.append(Indicator(f"{total} unsolicited ARP replies in total", ATTACK, "moderate"))
        gws = [ip for ip in ips if ip in ctx.gateway_ips or ip in ctx.dhcp_offered["router"]]
        victims = sorted({r.arp_pdst for r in recs if r.arp_pdst} - set(ips))
        out.append(Finding(
            detector=NAME, kind="ARP_SPOOFING", title=f"ARP spoofing: {mac} claims {len(ips)} addresses",
            category="attack", assessment=assess(indicators), severity="critical" if gws else "high",
            evidence_strength=_strength(indicators, ATTACK),
            summary=(f"The device {mac} sent unsolicited ARP replies claiming to be {len(ips)} different IP "
                     f"addresses ({', '.join(ips[:8])}{' ...' if len(ips) > 8 else ''}). A normal device only "
                     "answers for its own address when asked."),
            impact="Hosts that accept these replies send traffic for those addresses to this device.",
            likely_cause="ARP cache poisoning of a whole address range (for example 'arpspoof' against a subnet).",
            recommendations=[r.format(mac=mac, gw=(gws[0] if gws else "<gateway IP>"), gw_mac="<gateway MAC>",
                                      since=_rel(ctx, recs[0].ts if recs else None) + " into the capture")
                             for r in SPOOF_RECS],
            facts=[f"{total} unsolicited replies for {len(ips)} addresses between {_rel(ctx, recs[0].ts)} and "
                   f"{_rel(ctx, recs[-1].ts)}" if recs else f"{total} unsolicited replies",
                   f"Recipients of the false replies: {', '.join(victims[:10]) or 'not visible'}",
                   _mac_note(mac)],
            alternatives=["A proxy-ARP router answers for many addresses, but only when asked."],
            limitations=["None of the claimed addresses was seen being used by another device in this capture, so "
                         "the capture cannot show whether the poisoning succeeded."],
            indicators=indicators, hosts={"attacker": [mac], "impersonated": ips, "victim": victims},
            time_start=recs[0].ts if recs else None, time_end=recs[-1].ts if recs else None,
            evidence=[Evidence(r.n, f"unsolicited ARP reply: {r.arp_psrc} is-at {mac}, sent to {r.arp_pdst}")
                      for r in recs],
            metrics={"impersonated_ips": len(ips), "unsolicited_replies": total, "claimed_ips_total":
                     len(mac_ips.get((vlan, mac), {})), "attacker_mac": mac},
            rule=f"one MAC claims >= {ARP_SWEEP_MIN_IPS} IPs through unsolicited ARP replies"))
    return out


def _ip_finding(ctx: AnalysisContext, key: tuple, pairs: list[_Pair], origin: dict) -> Finding:
    main = pairs[0]
    m = main.m
    kind = main.kind
    where = _where(key)
    ip = key[1]
    owner, chal = main.owner, main.chal
    indicators = _merge_indicators(pairs)
    assessment = main.verdict if len(pairs) == 1 else assess(indicators)
    if kind == "DUPLICATE_IP" and assessment != FAULT:
        assessment = main.verdict
    devices = [owner] + [p.chal for p in pairs]
    times = [t for p in pairs for t in p.m["times"] if t is not None]
    role = m["role"]
    counts = {p.owner: p.m["owner_claims"] for p in pairs}
    counts.update({p.chal: p.m["challenger_claims"] for p in pairs})
    count_txt = ", ".join(f"{mac}: {n} ARP claim(s)" for mac, n in counts.items())
    facts = [f"{owner} claimed {where} first ({_rel(ctx, m['first_owner'])}); {chal} from {_rel(ctx, m['first_chal'])}.",
             f"Claims per MAC - {count_txt}.",
             f"Solicited ARP replies: {owner} {m['owner_solicited']}, {chal} {m['challenger_solicited']}; "
             f"gratuitous: {owner} {m['owner_gratuitous']}, {chal} {m['challenger_gratuitous']}; "
             f"unsolicited from {chal}: {m['unsolicited']}; mapping transitions: {m['transitions']}.",
             f"IP frames sent from {ip}: {owner} {m['owner_ip_frames']}, {chal} {m['challenger_ip_frames']}"
             + (" (overlapping in time)" if m["overlap"] else "") + "."]
    ip_level = ctx.ip_macs.get(ip)
    if ip_level:
        non_router = [mac for mac in ip_level if mac not in ctx.router_macs]
        if len(non_router) >= 2:
            facts.append(f"Outside ARP, {len(non_router)} non-router MACs sent IPv4 traffic with source {ip}: "
                         f"{', '.join(sorted(non_router)[:5])}.")
    if m["probe_conflicts"]:
        facts.append(f"{m['probe_conflicts']} RFC 5227 probe conflict(s) for {ip}.")
    if m["redirected"]:
        facts.append(f"{m['redirected']} frames {'for off-link destinations ' if m['gateway'] else ''}were "
                     f"delivered to {chal} instead of {owner}.")
    offered = _dhcp_offers(ctx, ip)
    if offered:
        facts.append(f"The DHCP server offered {ip} to {', '.join(offered)} even though another device already "
                     "uses it, so the DHCP pool overlaps a statically configured address.")
    facts.extend(_mac_note(mac) for mac in devices[:4])
    hosts = {"address": [ip], "device": devices}
    evidence = _collect_evidence(pairs)
    rel = {"time_start": min(times) if times else None, "time_end": max(times) if times else None}
    gw_txt = (f" Because {ip} is {role}, clients that learned {chal}'s MAC send their traffic to the wrong device "
              "and lose connectivity." if role else "")
    common = dict(detector=NAME, indicators=indicators, hosts=hosts, evidence=evidence, **rel)

    if kind == "DUPLICATE_IP":
        hosts.update({"first_owner": [owner], "second_device": [p.chal for p in pairs]})
        probe = m["probe_conflicts"] and not m["challenger_claims"]
        if probe:
            summary = (f"Device {chal} tried to start using {where}, but its RFC 5227 ARP probe was answered by "
                       f"{owner}, which already uses that address. The address is assigned twice.")
            impact = (f"The new device ({chal}) should refuse the address and may end up with no network access "
                      "or a self-assigned 169.254.x.x address; if it ignores the conflict both devices break.")
        else:
            summary = (f"Two different network cards are both using {where}. {owner} was seen with it first "
                       f"({_rel(ctx, m['first_owner'])}), {chal} appeared at {_rel(ctx, m['first_chal'])}. Both "
                       "answer ARP requests for the address and/or send traffic from it, so other devices keep "
                       "switching between them." + gw_txt)
            impact = ("Both devices suffer intermittent connection drops: replies go to whichever MAC a peer "
                      "cached last, so sessions hang, reset or time out.")
        recs = [f"Identify both devices by MAC ({', '.join(devices)}): check the switch MAC table "
                "('show mac address-table address <mac>') and the vendor prefix (OUI) of each MAC.",
                f"Change the static IP configuration of one device, or exclude {ip} from the DHCP pool if it is "
                "statically assigned.",
                "Check DHCP reservations for an overlap with manually configured addresses.",
                "After the fix, clear stale ARP entries ('arp -d' / 'ip neigh flush') on hosts that talk to it."]
        cause = ("Two devices configured with the same static IP address, a static address inside the DHCP pool, "
                 "or a DHCP reservation overlapping a manual configuration.")
        if offered:
            cause = f"The DHCP pool contains {ip}, which is also configured statically on {owner}."
        title = f"Duplicate IP address {where}: {owner} and {chal}" + (f" ({role})" if role else "")
        return Finding(kind=kind, title=title, category="fault", assessment=assessment,
                       severity="low" if probe else "medium", evidence_strength=_strength(indicators, FAULT),
                       summary=summary, impact=impact, likely_cause=cause, recommendations=recs, facts=facts,
                       alternatives=["ARP spoofing can look similar, but the second device here behaves like a "
                                     "normal host (it answers requests and claims no other address)."],
                       limitations=["The capture cannot tell which device was configured correctly.",
                                    "Only ARP and traffic visible at the capture point are considered."],
                       metrics=_ip_metrics(pairs), rule="two MACs answer for one IP; assess() returns FAULT with "
                       "interleaved solicited replies, simultaneous use or an RFC 5227 conflict", **common)

    if kind == "ARP_MAPPING_CHANGED":
        hosts.update({"old_mac": [owner], "new_mac": [chal]})
        return Finding(kind=kind, title=f"{where} moved from {owner} to {chal}", category="fault",
                       assessment=assessment, severity="info", evidence_strength=_strength(indicators, BENIGN),
                       summary=(f"The MAC address for {where} changed once, from {owner} to {chal} at "
                                f"{_rel(ctx, m['first_chal'])}, and never changed back. The old MAC stopped "
                                "communicating. This is what a device replacement, a DHCP re-assignment or a "
                                "failover to a standby device looks like."),
                       impact="None expected; hosts that still cache the old MAC recover when their entry expires.",
                       likely_cause="Planned change: replaced network card or device, failover, or new DHCP lease.",
                       recommendations=["No action needed if the change was planned.",
                                        f"If nobody replaced {where}, check that {chal} is an authorised device."],
                       facts=facts,
                       alternatives=["A single, one-off ARP poisoning attempt would also produce one change; it "
                                     "would normally be repeated and show unsolicited replies, which were not seen."],
                       limitations=["A change outside the capture window is invisible."],
                       metrics=_ip_metrics(pairs), rule="one clean MAC change without reversion; assess() BENIGN",
                       **common)

    hosts.update({"first_owner": [owner], "other_mac": [p.chal for p in pairs]})
    sev = "medium" if role or assessment == INCONCLUSIVE and any(i.points_to == ATTACK for i in indicators) else "low"
    return Finding(kind="ARP_CONFLICT", title=f"Conflicting ARP mappings for {where}", category="fault",
                   assessment=assessment, severity=sev,
                   evidence_strength=_strength(indicators, assessment if assessment in (FAULT, ATTACK, BENIGN)
                                               else ATTACK),
                   summary=(f"{where} was claimed by {len(devices)} different MACs ({', '.join(devices)}). The "
                            "evidence is not decisive between a configuration problem and a spoofing attempt."
                            + gw_txt),
                   impact="Hosts may send traffic for this address to the wrong device intermittently.",
                   likely_cause=("Possibly a duplicate address, a device changing MAC, or a short ARP poisoning "
                                 "attempt; see the indicators."),
                   recommendations=[f"Identify the devices behind {', '.join(devices)} in the switch MAC table and "
                                    "confirm which one should own the address.",
                                    "Capture for longer: repeated unsolicited replies would indicate spoofing, "
                                    "simultaneous use would indicate a duplicate address.",
                                    "Consider Dynamic ARP Inspection to block ARP replies that do not match DHCP "
                                    "bindings."],
                   facts=facts, alternatives=["Duplicate IP address (fault).", "ARP spoofing attempt (attack)."],
                   limitations=["Too few packets to separate a fault from an attack with confidence."],
                   metrics=_ip_metrics(pairs), rule="two MACs claim one IP; assess() is not decisive", **common)


def _ip_metrics(pairs: list[_Pair]) -> dict:
    m = pairs[0].m
    claims = {pairs[0].owner: m["owner_claims"]}
    solicited = {pairs[0].owner: m["owner_solicited"]}
    frames = {pairs[0].owner: m["owner_ip_frames"]}
    for p in pairs:
        claims[p.chal] = p.m["challenger_claims"]
        solicited[p.chal] = p.m["challenger_solicited"]
        frames[p.chal] = p.m["challenger_ip_frames"]
    return {"ip": m["ip"], "vlan": m["vlan"], "macs": list(claims), "first_claimer": pairs[0].owner,
            "claims_per_mac": claims, "solicited_replies_per_mac": solicited, "ip_frames_per_mac": frames,
            "transitions": m["transitions"], "unsolicited_replies": sum(p.m["unsolicited"] for p in pairs),
            "probe_conflicts": sum(p.m["probe_conflicts"] for p in pairs),
            "redirected_frames": sum(p.m["redirected"] for p in pairs), "gateway": m["gateway"]}


def _dhcp_offers(ctx: AnalysisContext, ip: str) -> list[str]:
    out = set()
    for r in ctx.dhcp:
        d = r.dhcp or {}
        if d.get("msg_type") in ("OFFER", "ACK") and d.get("yiaddr") == ip and d.get("chaddr"):
            out.add(str(d["chaddr"]))
    return sorted(out)
