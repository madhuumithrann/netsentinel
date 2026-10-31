"""DHCP analysis: rogue / multiple servers, unanswered DISCOVERs and NAK storms.

Objective
    Tell a *rogue* DHCP server (an attacker or an unauthorised device that hands clients a
    malicious gateway / DNS server) apart from legitimate DHCP topologies that look similar
    on the wire: relay agents, redundant split-scope servers and one server serving many
    subnets. Also explain DHCP faults that leave clients without an address.

Algorithm
    1. Server identity. Every OFFER / ACK is attributed to a *server entity*:
       ``identity`` = option 54 (server identifier), falling back to the IP source, plus the
       Ethernet source MAC. A reply carrying a relay address (giaddr != 0.0.0.0) travels via a
       relay agent, so its source IP / MAC belong to the relay and are NOT treated as another
       server; such replies are attributed to the identity alone (the old detector counted the
       relay as a second server).
    2. Scope. A server only competes with servers that answer the same clients. Replies are
       placed in a scope: ("local", VLAN) for replies delivered on the captured segment, or
       ("relay", giaddr) for the server -> relay leg seen at the core. Two entities compete when
       they share a scope OR answered the same transaction (xid + client MAC). One server
       handing different gateways to different relayed subnets is therefore normal.
    3. Which one is legitimate. Among competing entities the one most consistent with the
       observed traffic wins: packets with public source IPs forwarded by the MAC of the gateway
       it offers (a real router forwards Internet traffic), plus DNS responses actually served
       by the DNS servers it offers; ties are broken by reply count, then first appearance.
       Being first or fastest is deliberately the weakest signal: rogues race to answer first.
    4. Each non-legitimate entity is compared with the legitimate one *within the shared scope*:
         - different gateway / DNS offered ...................... ROGUE_DHCP_SERVER
         - same server identifier from another MAC (interleaved) .. ROGUE_DHCP_SERVER
         - identical gateway and DNS ............................. MULTIPLE_DHCP_SERVERS
       Clients that took the rogue lease (REQUEST naming the rogue / ACK from the rogue MAC)
       are listed, and their later traffic is checked for frames actually sent to the rogue
       gateway MAC or DNS queries sent to the rogue DNS server (proof of redirection).
    5. DHCP_NO_RESPONSE: per client MAC, DISCOVERs whose transaction never received an OFFER.
       DISCOVERs in the last ``DHCP_OFFER_WAIT_SECONDS`` of the capture are still pending and
       are not counted. When a relay copy and the original broadcast are both captured, only
       the original is counted.
    6. DHCP_NAK: per server identity, >= ``DHCP_NAK_MIN`` NAKs. The matching REQUEST is used to
       tell clients asking for an address from another network (moved laptops, wrong VLAN)
       from a server that NAKs everything.

Indicators (all fed to ``assess``)
    ROGUE_DHCP_SERVER
      ATTACK strong   - offered gateway differs from the legitimate server's gateway
      ATTACK strong   - offered DNS differs from the legitimate server's DNS
      ATTACK strong   - the rogue names itself (its own IP / MAC) as gateway or DNS
      ATTACK strong   - same server identifier sent from a second MAC while the first was active
      ATTACK moderate - both servers answered the same DISCOVER/REQUEST (race for the client)
      ATTACK moderate - clients accepted the rogue lease
      ATTACK strong   - accepted clients then sent traffic to the rogue gateway / DNS
      FAULT moderate  - the rogue hands out a different subnet (typical of a consumer router
                        plugged in by mistake: clients break instead of being intercepted)
      BENIGN moderate - identical options (only with a spoofed identifier, e.g. failover NICs)
    MULTIPLE_DHCP_SERVERS
      BENIGN moderate - identical gateway and DNS
      BENIGN moderate - disjoint address pools (classic 80/20 split scope)
      FAULT moderate  - both servers offered the same address to different clients
    DHCP_NO_RESPONSE
      FAULT strong    - >= dhcp_unanswered_discover_min unanswered DISCOVERs from a client
      FAULT moderate  - other clients were served meanwhile (pool / filtering / relay issue)
    DHCP_NAK
      FAULT strong    - >= DHCP_NAK_MIN NAKs from one server
      FAULT moderate  - NAKed requests are for addresses outside the server's network
      ATTACK moderate - the NAKing device never hands out leases itself while another
                        server does (possible rogue NAK denial of service)

Limitations
    * Only DHCPv4 is decoded (UDP 67/68). DHCPv6 and IPv6 Router Advertisements are not
      analysed here.
    * The subnet mask option is not decoded by the parser, so "same subnet" is a /24 heuristic.
    * On a switched network a capture port often sees only broadcast OFFERs and the client's
      own unicast traffic; a rogue answering by unicast to other clients may be invisible.
    * A rogue that also forges giaddr and its source IP like a relay is attributed by server
      identifier only; it is still caught if it offers different options or races the same
      transaction.
"""
from __future__ import annotations

import ipaddress
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from ..context import AnalysisContext, is_private, is_special
from ..model import ATTACK, BENIGN, FAULT, Evidence, Finding, Indicator, PacketRecord, assess

NAME = "dhcp"

ZERO = "0.0.0.0"
# A DISCOVER sent this close to the end of the capture may simply not have been answered yet.
DHCP_OFFER_WAIT_SECONDS = 2.0
# NAKs from one server before it is reported. A single NAK is normal when a laptop that moved
# from another network asks for its old address (INIT-REBOOT).
DHCP_NAK_MIN = 3
# Evidence caps (true totals always go to facts / metrics).
MAX_EVIDENCE = 80
MAX_LISTED = 10


def _dhcp(rec: PacketRecord) -> dict:
    d = rec.dhcp
    return d if isinstance(d, dict) else {}


def _ip_list(value) -> list[str]:
    if not isinstance(value, (list, tuple)):
        return []
    return [v for v in value if isinstance(v, str) and v and v != ZERO]


def _valid_ip(value) -> str | None:
    if not isinstance(value, str) or not value or value == ZERO:
        return None
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return None
    return value


def _net24(ip: str | None) -> str | None:
    """/24 network of an IPv4 address (the parser does not decode the subnet-mask option)."""
    ip = _valid_ip(ip)
    if ip is None or ":" in ip:
        return None
    return ip.rsplit(".", 1)[0]


def _listed(items, limit: int = MAX_LISTED) -> str:
    items = list(items)
    text = ", ".join(str(i) for i in items[:limit])
    return text + (f" (+{len(items) - limit} more)" if len(items) > limit else "") if items else "none"


@dataclass
class _Server:
    identity: str
    mac: str | None             # sender MAC for direct replies, None when only seen via relays
    replies: list[PacketRecord] = field(default_factory=list)
    scopes: set = field(default_factory=set)
    transactions: set = field(default_factory=set)     # (xid, chaddr)
    src_ips: set = field(default_factory=set)
    relays: set = field(default_factory=set)

    @property
    def key(self) -> tuple[str, str | None]:
        return (self.identity, self.mac)

    @property
    def first_ts(self) -> float:
        return self.replies[0].ts

    @property
    def last_ts(self) -> float:
        return self.replies[-1].ts

    @property
    def label(self) -> str:
        if self.mac:
            return f"{self.identity} ({self.mac})"
        return f"{self.identity} (via relay {_listed(sorted(self.relays), 3)})"

    def count(self, msg_type: str) -> int:
        return sum(_dhcp(r).get("msg_type") == msg_type for r in self.replies)


def _scope(rec: PacketRecord, d: dict) -> tuple:
    gi = _valid_ip(d.get("giaddr"))
    if gi and rec.ip_dst == gi:
        return ("relay", gi)         # server -> relay leg: serves the relay's (remote) subnet
    if gi and rec.ip_src != gi:
        return ("relay", gi)         # relayed reply seen somewhere else on the path
    return ("local", rec.vlan)       # delivered on the captured segment


def _config(replies: list[PacketRecord]) -> tuple[frozenset, frozenset]:
    routers, dns = set(), set()
    for r in replies:
        d = _dhcp(r)
        routers.update(_ip_list(d.get("router")))
        dns.update(_ip_list(d.get("dns")))
    return frozenset(routers), frozenset(dns)


def _shared_replies(a: _Server, b: _Server) -> tuple[list[PacketRecord], list[PacketRecord]]:
    """Replies of a and b in the context where they compete (shared scopes or transactions)."""
    scopes = a.scopes & b.scopes
    txs = a.transactions & b.transactions

    def pick(s: _Server) -> list[PacketRecord]:
        out = []
        for r in s.replies:
            d = _dhcp(r)
            if _scope(r, d) in scopes or (d.get("xid"), d.get("chaddr")) in txs:
                out.append(r)
        return out
    return pick(a), pick(b)


def _competes(a: _Server, b: _Server) -> bool:
    return bool(a.scopes & b.scopes) or bool(a.transactions & b.transactions)


class _TrafficIndex:
    """Lazily built, single-pass index used to judge which server matches real traffic."""

    def __init__(self, ctx: AnalysisContext) -> None:
        self.ctx = ctx
        self._public_by_mac: Counter | None = None
        self._dns_answers: Counter | None = None
        self._arp_macs: dict[str, set[str]] | None = None

    def _build(self) -> None:
        public: Counter = Counter()
        for i, r in enumerate(self.ctx.records):
            if i % 5000 == 0:
                self.ctx.check_deadline()
            if r.eth_src and r.ip_src and not is_private(r.ip_src) and not is_special(r.ip_src):
                public[r.eth_src] += 1
        self._public_by_mac = public
        dns: Counter = Counter()
        for r in self.ctx.dns:
            if r.dns and r.dns.get("qr") == 1 and r.ip_src:
                dns[r.ip_src] += 1
        self._dns_answers = dns
        arp: dict[str, set[str]] = defaultdict(set)
        for r in self.ctx.arp:
            if r.arp_op == 2 and r.arp_psrc and r.arp_hwsrc:
                arp[r.arp_psrc].add(r.arp_hwsrc)
        self._arp_macs = arp

    def macs_of(self, ip: str) -> set[str]:
        if self._arp_macs is None:
            self._build()
        out = set(self._arp_macs.get(ip, set()))
        senders = self.ctx.ip_macs.get(ip)
        if senders:
            out.add(senders.most_common(1)[0][0])
        return out

    def forwarded(self, mac: str) -> int:
        if self._public_by_mac is None:
            self._build()
        return self._public_by_mac.get(mac, 0)

    def dns_answers(self, ip: str) -> int:
        if self._dns_answers is None:
            self._build()
        return self._dns_answers.get(ip, 0)

    def consistency(self, server: _Server) -> int:
        routers, dns = _config(server.replies)
        gw = max((self.forwarded(m) for r in routers for m in self.macs_of(r)), default=0)
        resolver = max((self.dns_answers(d) for d in dns), default=0)
        return gw + resolver


def _collect_servers(ctx: AnalysisContext) -> dict[tuple, _Server]:
    servers: dict[tuple, _Server] = {}
    for r in ctx.dhcp:
        d = _dhcp(r)
        if d.get("msg_type") not in ("OFFER", "ACK"):
            continue
        identity = _valid_ip(d.get("server_id")) or _valid_ip(r.ip_src)
        if identity is None:
            continue
        gi = _valid_ip(d.get("giaddr"))
        mac = None if gi else r.eth_src
        key = (identity, mac)
        s = servers.get(key)
        if s is None:
            s = servers[key] = _Server(identity=identity, mac=mac)
        s.replies.append(r)
        s.scopes.add(_scope(r, d))
        s.transactions.add((d.get("xid"), d.get("chaddr")))
        if r.ip_src:
            s.src_ips.add(r.ip_src)
        if gi:
            s.relays.add(gi)
    return servers


def _client_requests(ctx: AnalysisContext) -> dict[str, list[PacketRecord]]:
    out: dict[str, list[PacketRecord]] = defaultdict(list)
    for r in ctx.dhcp:
        d = _dhcp(r)
        if d.get("msg_type") == "REQUEST" and d.get("chaddr"):
            out[d["chaddr"]].append(r)
    return out


def _redirected_traffic(ctx: AnalysisContext, victims: dict[str, PacketRecord], rogue_gw_macs: set[str],
                        rogue_dns: set[str]) -> list[PacketRecord]:
    """Frames from accepted victims that actually used the rogue gateway or rogue DNS."""
    if not victims or not (rogue_gw_macs or rogue_dns):
        return []
    out = []
    for i, r in enumerate(ctx.records):
        if i % 5000 == 0:
            ctx.check_deadline()
        ack = victims.get(r.eth_src or "")
        if ack is None or r.ts < ack.ts or r.dhcp is not None:
            continue
        to_gw = r.eth_dst in rogue_gw_macs and r.ip_dst and not is_private(r.ip_dst) \
            and not is_special(r.ip_dst)
        to_dns = r.dns is not None and r.dns.get("qr") == 0 and r.ip_dst in rogue_dns
        if to_gw or to_dns:
            out.append(r)
    return out


def _rogue_finding(ctx: AnalysisContext, legit: _Server, rogue: _Server, idx: _TrafficIndex,
                   requests: dict[str, list[PacketRecord]]) -> Finding | None:
    legit_shared, rogue_shared = _shared_replies(legit, rogue)
    legit_shared = legit_shared or legit.replies
    rogue_shared = rogue_shared or rogue.replies
    l_routers, l_dns = _config(legit_shared)
    r_routers, r_dns = _config(rogue_shared)
    router_diff = bool(l_routers and r_routers and l_routers != r_routers)
    dns_diff = bool(l_dns and r_dns and l_dns != r_dns)
    same_identity = legit.identity == rogue.identity and legit.mac and rogue.mac \
        and legit.mac != rogue.mac
    overlap = max(legit.first_ts, rogue.first_ts) <= min(legit.last_ts, rogue.last_ts)
    raced = sorted(legit.transactions & rogue.transactions, key=str)
    spoofed = bool(same_identity and (overlap or raced))
    if not (router_diff or dns_diff or spoofed):
        return None

    rogue_ips = set(rogue.src_ips) | {rogue.identity}
    if rogue.mac:
        # Only local addresses: public sources behind a forwarding rogue are not "itself".
        rogue_ips |= {ip for ip in ctx.mac_ips.get(rogue.mac, set()) if is_private(ip)}
    self_gateway = sorted(r for r in r_routers - l_routers
                          if r in rogue_ips or (rogue.mac and rogue.mac in idx.macs_of(r)))
    self_dns = sorted(d for d in r_dns - l_dns
                      if d in rogue_ips or (rogue.mac and rogue.mac in idx.macs_of(d)))

    # Clients that accepted the rogue lease.
    victims: dict[str, PacketRecord] = {}
    for r in rogue.replies:
        d = _dhcp(r)
        if d.get("msg_type") == "ACK" and d.get("chaddr") and d["chaddr"] not in victims:
            victims[d["chaddr"]] = r
    victim_requests: list[PacketRecord] = []
    if not same_identity:
        for chaddr, reqs in requests.items():
            for q in reqs:
                if _dhcp(q).get("server_id") == rogue.identity:
                    victim_requests.append(q)
    victim_requests.sort(key=lambda p: p.n)
    requesting = sorted({_dhcp(q).get("chaddr") for q in victim_requests} - set(victims))
    victim_ips = sorted({_dhcp(a).get("yiaddr") for a in victims.values()
                         if _valid_ip(_dhcp(a).get("yiaddr"))})

    rogue_gw_macs = set()
    for gw in r_routers - l_routers:
        rogue_gw_macs |= idx.macs_of(gw)
    legit_gw_macs = set()
    for gw in l_routers:
        legit_gw_macs |= idx.macs_of(gw)
    rogue_gw_macs -= legit_gw_macs
    redirected = _redirected_traffic(ctx, victims, rogue_gw_macs, set(r_dns - l_dns))

    l_nets = {_net24(_dhcp(r).get("yiaddr")) for r in legit_shared} | {_net24(x) for x in l_routers}
    r_nets = {_net24(_dhcp(r).get("yiaddr")) for r in rogue_shared} - {None}
    l_nets.discard(None)
    other_subnet = bool(r_nets and l_nets and not (r_nets & l_nets))

    gw_l, gw_r = _listed(sorted(l_routers)), _listed(sorted(r_routers))
    dns_l, dns_r = _listed(sorted(l_dns)), _listed(sorted(r_dns))
    indicators: list[Indicator] = []
    if router_diff:
        indicators.append(Indicator(
            f"{rogue.label} tells clients to use gateway {gw_r}, while the legitimate server "
            f"{legit.label} hands out gateway {gw_l}", ATTACK, "strong"))
    if dns_diff:
        indicators.append(Indicator(
            f"{rogue.label} hands out DNS server {dns_r} instead of the legitimate {dns_l}", ATTACK, "strong"))
    if self_gateway or self_dns:
        what = " and ".join(x for x in (f"gateway {_listed(self_gateway)}" if self_gateway else "",
                                         f"DNS {_listed(self_dns)}" if self_dns else "") if x)
        indicators.append(Indicator(
            f"The rogue server names itself as {what}, so clients that accept it send their traffic "
            "through it", ATTACK, "strong"))
    if spoofed:
        indicators.append(Indicator(
            f"Server identifier {rogue.identity} is used by two different MAC addresses "
            f"({legit.mac} and {rogue.mac}) at the same time: one of them impersonates the real server",
            ATTACK, "strong"))
    if raced:
        indicators.append(Indicator(
            f"Both servers answered the same {len(raced)} client transaction(s); clients take whichever "
            "answer arrives first", ATTACK, "moderate"))
    if victims:
        indicators.append(Indicator(
            f"{len(victims)} client(s) accepted a lease from the rogue server", ATTACK, "moderate"))
    if redirected:
        indicators.append(Indicator(
            f"{len(redirected)} packets from accepted clients were then sent to the rogue gateway/DNS: "
            "the redirection is actually happening", ATTACK, "strong"))
    if other_subnet:
        indicators.append(Indicator(
            f"The rogue hands out addresses in {_listed(sorted(r_nets))}.x, a different network from the "
            f"legitimate {_listed(sorted(l_nets))}.x; this is typical of a home router plugged in by mistake",
            FAULT, "moderate"))
    if spoofed and not router_diff and not dns_diff:
        indicators.append(Indicator("Both MACs hand out identical options (could be a failover pair "
                                    "using physical MACs)", BENIGN, "moderate"))
    assessment = assess(indicators)
    if assessment == ATTACK:
        severity = "critical" if victims else "high"
    else:
        severity = "medium"

    # Evidence
    evidence: list[Evidence] = []
    raced_set = set(raced)
    discovers = []
    for r in ctx.dhcp:
        d = _dhcp(r)
        if d.get("msg_type") == "DISCOVER" and (d.get("xid"), d.get("chaddr")) in raced_set:
            discovers.append(r)
    for r in discovers[:10]:
        evidence.append(Evidence(r.n, "client DISCOVER answered by both servers"))
    for r in rogue.replies[:40]:
        d = _dhcp(r)
        evidence.append(Evidence(r.n, f"rogue {d.get('msg_type')} from {rogue.label}: gateway "
                                      f"{_listed(_ip_list(d.get('router')), 3)}, DNS "
                                      f"{_listed(_ip_list(d.get('dns')), 3)}"))
    for r in legit_shared[:5]:
        d = _dhcp(r)
        evidence.append(Evidence(r.n, f"legitimate {d.get('msg_type')} from {legit.label} for comparison: "
                                      f"gateway {_listed(_ip_list(d.get('router')), 3)}, DNS "
                                      f"{_listed(_ip_list(d.get('dns')), 3)}"))
    for q in victim_requests[:10]:
        evidence.append(Evidence(q.n, f"client {_dhcp(q).get('chaddr')} REQUESTs the rogue lease"))
    for chaddr, ack in list(victims.items())[:10]:
        evidence.append(Evidence(ack.n, f"rogue ACK: client {chaddr} accepts {_dhcp(ack).get('yiaddr')}"))
    for p in redirected[:10]:
        if p.dns is not None:
            evidence.append(Evidence(p.n, f"victim DNS query sent to rogue DNS {p.ip_dst}"))
        else:
            evidence.append(Evidence(p.n, f"victim traffic to {p.ip_dst} sent to rogue gateway MAC {p.eth_dst}"))
    evidence = evidence[:MAX_EVIDENCE]

    times = [r.ts for r in rogue.replies] + [p.ts for p in redirected]
    victim_macs = sorted(victims)
    if spoofed:
        # The identifier belongs to the real server; attribute the rogue by MAC (and any own IP).
        own = {ip for ip in ctx.mac_ips.get(rogue.mac, set()) if is_private(ip)} - {rogue.identity}
        rogue_host = sorted(own) + [rogue.mac]
    else:
        rogue_host = sorted(set(rogue.src_ips) | {rogue.identity}) + ([rogue.mac] if rogue.mac else [])
    legit_host = [legit.identity] + ([legit.mac] if legit.mac else [])
    hosts = {"rogue_server": rogue_host, "legitimate_server": legit_host}
    if spoofed:
        hosts["impersonated_server"] = [rogue.identity]
    if victim_macs or victim_ips:
        hosts["victim"] = victim_macs + victim_ips
    if r_routers - l_routers:
        hosts["rogue_gateway"] = sorted(r_routers - l_routers)
    if r_dns - l_dns:
        hosts["rogue_dns"] = sorted(r_dns - l_dns)

    if spoofed:
        what = (f"A second device (MAC {rogue.mac}) is answering DHCP requests while pretending to be the "
                f"network's DHCP server {rogue.identity} (normally MAC {legit.mac}).")
    else:
        what = (f"A second DHCP server, {rogue.label}, is answering clients on this network alongside the "
                f"legitimate server {legit.label}.")
    redirect_text = []
    if router_diff:
        redirect_text.append(f"gateway {gw_r} instead of {gw_l}")
    if dns_diff:
        redirect_text.append(f"DNS server {dns_r} instead of {dns_l}")
    summary = what + (" It hands out " + " and ".join(redirect_text) + "." if redirect_text else
                      " It hands out the same options, but its presence means clients can be given "
                      "any configuration it chooses.")
    if victims:
        summary += f" {len(victims)} client(s) accepted its lease ({_listed(victim_macs, 5)})."
        if redirected:
            summary += (f" Those clients then sent {len(redirected)} packets to the rogue gateway/DNS, "
                        "so their traffic is being redirected.")
    impact = ("Clients that accept the rogue lease send their Internet traffic and/or DNS lookups to a device "
              "controlled by someone else, who can read, modify or block it (man-in-the-middle, phishing via "
              "fake DNS answers)." if (router_diff or dns_diff) else
              "Clients may receive addresses from an impersonating device that can change their configuration "
              "at any time.")
    if victims:
        impact += f" Affected clients: {_listed(victim_macs + victim_ips)}."
    else:
        impact += " No client was seen accepting the rogue lease in this capture yet."
    cause = ("An attacker or unauthorised device is running a DHCP server on the LAN to redirect traffic."
             if not other_subnet else
             "An unauthorised DHCP server is on the LAN. Because it hands out a different network, it is most "
             "often a consumer router or access point plugged in with its LAN port, but a deliberate rogue "
             "cannot be ruled out.")
    rec = [f"Locate the device with MAC {rogue.mac or 'shown in the evidence'} (switch MAC address table) and "
           "disconnect it.",
           "Enable DHCP snooping on the access switches and trust only the uplink/port of the legitimate server.",
           "On affected clients, release and renew the lease (ipconfig /release && ipconfig /renew) and flush "
           "the DNS cache (ipconfig /flushdns).",
           "Treat traffic from affected clients during the exposure window as possibly intercepted; change "
           "passwords entered over unencrypted connections."]
    facts = [f"Rogue server {rogue.label}: {rogue.count('OFFER')} OFFER(s) and {rogue.count('ACK')} ACK(s), "
             f"gateway {gw_r}, DNS {dns_r}.",
             f"Legitimate server {legit.label}: {legit.count('OFFER')} OFFER(s) and {legit.count('ACK')} ACK(s), "
             f"gateway {gw_l}, DNS {dns_l}.",
             f"Why {legit.identity} is treated as legitimate: its gateway/DNS carry {idx.consistency(legit)} "
             f"observed forwarded/answered packets versus {idx.consistency(rogue)} for the rogue."]
    if raced:
        facts.append(f"{len(raced)} client transaction(s) received answers from both servers.")
    if victims:
        facts.append(f"Clients that accepted the rogue lease: {_listed(victim_macs)} "
                     f"(addresses {_listed(victim_ips)}).")
    if requesting:
        facts.append(f"Clients that requested the rogue lease without a visible ACK: {_listed(requesting)}.")
    if redirected:
        facts.append(f"{len(redirected)} packets from accepted clients went to the rogue gateway MAC or rogue DNS.")
    alternatives = ["An authorised second server that was misconfigured with the wrong gateway or DNS "
                    "(verify with the network owner)."]
    if other_subnet:
        alternatives.insert(0, "A consumer router or Wi-Fi access point connected by mistake (its own DHCP "
                               "server hands out its default network).")
    if spoofed:
        alternatives.append("A DHCP failover pair that answers from physical MACs with the same identifier "
                            "(only plausible when the options are identical).")
    limitations = ["The capture shows which server answered, not who owns the device; physical location must "
                   "be found via the switch MAC table.",
                   "On a switched network unicast OFFER/ACKs to other clients may not be visible, so more "
                   "clients may be affected than listed.",
                   "The subnet mask option is not decoded; 'same network' is judged on /24 boundaries."]
    return Finding(
        detector=NAME, kind="ROGUE_DHCP_SERVER",
        title=f"Rogue DHCP server {rogue.identity}" + (f" ({rogue.mac})" if rogue.mac else "")
              + (" impersonating the real server" if spoofed else ""),
        category="attack", assessment=assessment, severity=severity,
        evidence_strength="strong" if sum(i.strength == "strong" for i in indicators) >= 2 else "moderate",
        summary=summary, impact=impact, likely_cause=cause, recommendations=rec, facts=facts,
        alternatives=alternatives, limitations=limitations, indicators=indicators, hosts=hosts,
        time_start=min(times), time_end=max(times), evidence=evidence,
        metrics={"rogue_server_id": rogue.identity, "rogue_mac": rogue.mac,
                 "legit_server_id": legit.identity, "legit_mac": legit.mac,
                 "rogue_offers": rogue.count("OFFER"), "rogue_acks": rogue.count("ACK"),
                 "legit_offers": legit.count("OFFER"), "legit_acks": legit.count("ACK"),
                 "rogue_router": sorted(r_routers), "rogue_dns": sorted(r_dns),
                 "legit_router": sorted(l_routers), "legit_dns": sorted(l_dns),
                 "spoofed_server_id": spoofed, "raced_transactions": len(raced),
                 "victims": len(victims), "victim_macs": victim_macs,
                 "redirected_packets": len(redirected)},
        rule="OFFER/ACK from >1 server identity (server-id + MAC, relays excluded) in the same scope with "
             "different gateway/DNS, or one server-id from two MACs at once")


def _multiple_finding(legit: _Server, others: list[_Server]) -> Finding:
    l_routers, l_dns = _config(legit.replies)
    indicators = [Indicator(f"All {len(others) + 1} servers hand out the same gateway "
                            f"({_listed(sorted(l_routers))}) and DNS ({_listed(sorted(l_dns))})",
                            BENIGN, "moderate")]
    pools = {s.key: {(_dhcp(r).get("yiaddr"), _dhcp(r).get("chaddr")) for r in s.replies
                     if _valid_ip(_dhcp(r).get("yiaddr"))} for s in [legit] + others}
    overlaps = []
    servers = [legit] + others
    for i, a in enumerate(servers):
        a_by_ip = defaultdict(set)
        for ip, ch in pools[a.key]:
            a_by_ip[ip].add(ch)
        for b in servers[i + 1:]:
            for ip, ch in pools[b.key]:
                if ip in a_by_ip and (a_by_ip[ip] - {ch}):
                    overlaps.append(ip)
    addr_sets = [{ip for ip, _ in pools[s.key]} for s in servers]
    disjoint = all(not (addr_sets[i] & addr_sets[j]) for i in range(len(addr_sets))
                   for j in range(i + 1, len(addr_sets)))
    if overlaps:
        indicators.append(Indicator(f"Different servers offered the same address to different clients "
                                    f"({_listed(sorted(set(overlaps)))}); their pools overlap and can create "
                                    "duplicate IP addresses", FAULT, "moderate"))
    elif disjoint:
        indicators.append(Indicator("Each server hands out its own, non-overlapping addresses (typical "
                                    "split-scope redundancy)", BENIGN, "moderate"))
    assessment = assess(indicators)
    raced = set()
    for s in others:
        raced |= legit.transactions & s.transactions
    evidence = []
    for s in servers:
        for r in s.replies[:15]:
            d = _dhcp(r)
            evidence.append(Evidence(r.n, f"{d.get('msg_type')} from {s.label} offering {d.get('yiaddr')} "
                                          f"(gateway {_listed(_ip_list(d.get('router')), 3)})"))
    times = [r.ts for s in servers for r in s.replies]
    labels = [s.label for s in servers]
    return Finding(
        detector=NAME, kind="MULTIPLE_DHCP_SERVERS",
        title=f"{len(servers)} DHCP servers with identical settings",
        category="attack", assessment=assessment, severity="low",
        evidence_strength="moderate",
        summary=(f"{len(servers)} DHCP servers answer clients on the same network: {_listed(labels)}. They hand "
                 "out identical gateway and DNS settings, which is how redundant (authorised) DHCP servers are "
                 "normally set up."),
        impact=("Nothing is wrong for clients as long as both servers are authorised"
                + ("; however both servers offered the same address to different clients, which can cause "
                   "duplicate IP conflicts." if overlaps else ".")),
        likely_cause="Redundant or failover DHCP servers (for example an 80/20 split scope).",
        recommendations=["Confirm with the network owner that every listed server is authorised.",
                         "Add the authorised servers to the DHCP-snooping trusted ports so any other "
                         "server is blocked automatically.",
                         "Make sure the address pools of the servers do not overlap."],
        facts=[f"{s.label}: {s.count('OFFER')} OFFER(s), {s.count('ACK')} ACK(s), "
               f"{len({ip for ip, _ in pools[s.key]})} distinct address(es) offered" for s in servers]
              + [f"{len(raced)} client transaction(s) were answered by more than one server."],
        alternatives=["A rogue server that copies the legitimate settings (it could change them later)."],
        limitations=["The capture cannot show whether a server is authorised; this needs the network "
                     "owner's inventory."],
        indicators=indicators,
        hosts={"dhcp_server": sorted({s.identity for s in servers}) + sorted({s.mac for s in servers if s.mac})},
        time_start=min(times), time_end=max(times), evidence=evidence[:MAX_EVIDENCE],
        metrics={"servers": len(servers), "server_ids": sorted({s.identity for s in servers}),
                 "raced_transactions": len(raced), "overlapping_addresses": sorted(set(overlaps))},
        rule="OFFER/ACK from >1 server identity in the same scope, all with identical gateway and DNS")


def _server_findings(ctx: AnalysisContext) -> list[Finding]:
    servers = _collect_servers(ctx)
    if len(servers) < 2:
        return []
    idx = _TrafficIndex(ctx)
    ranked = sorted(servers.values(),
                    key=lambda s: (-idx.consistency(s), -len(s.replies), s.first_ts))
    requests = _client_requests(ctx)
    findings: list[Finding] = []
    identical: dict[tuple, list[_Server]] = defaultdict(list)
    heads: dict[tuple, _Server] = {}
    for pos, s in enumerate(ranked):
        ref = next((r for r in ranked[:pos] if _competes(r, s)), None)
        if ref is None:
            continue                     # serves its own scope: nothing to compare with
        rogue = _rogue_finding(ctx, ref, s, idx, requests)
        if rogue is not None:
            findings.append(rogue)
            continue
        if ref.identity == s.identity:
            continue                     # same server seen via a relay path, or its NIC was replaced
        identical[ref.key].append(s)
        heads[ref.key] = ref
    for key, others in identical.items():
        findings.append(_multiple_finding(heads[key], others))
    return findings


def _no_response_findings(ctx: AnalysisContext) -> list[Finding]:
    th = ctx.thresholds
    offers: dict[tuple, float] = {}
    served_clients: dict[str, float] = {}
    any_reply = False
    for r in ctx.dhcp:
        d = _dhcp(r)
        mt = d.get("msg_type")
        if mt in ("OFFER", "ACK", "NAK"):
            any_reply = True
        if mt == "OFFER":
            key = (d.get("xid"), d.get("chaddr"))
            offers[key] = max(offers.get(key, r.ts), r.ts)
            if d.get("chaddr"):
                served_clients.setdefault(d["chaddr"], r.ts)
    direct: dict[str, list[PacketRecord]] = defaultdict(list)
    relayed: dict[str, list[PacketRecord]] = defaultdict(list)
    for r in ctx.dhcp:
        d = _dhcp(r)
        if d.get("msg_type") != "DISCOVER" or not d.get("chaddr"):
            continue
        (relayed if _valid_ip(d.get("giaddr")) else direct)[d["chaddr"]].append(r)
    cutoff = ctx.end_ts - DHCP_OFFER_WAIT_SECONDS
    affected: dict[str, tuple[list[PacketRecord], list[PacketRecord]]] = {}
    for chaddr in set(direct) | set(relayed):
        discovers = direct.get(chaddr) or relayed.get(chaddr) or []
        unanswered, pending = [], []
        for r in discovers:
            d = _dhcp(r)
            offered_at = offers.get((d.get("xid"), chaddr))
            if offered_at is not None and offered_at >= r.ts - 0.001:
                continue
            (pending if r.ts > cutoff else unanswered).append(r)
        if len(unanswered) >= th.dhcp_unanswered_discover_min:
            affected[chaddr] = (unanswered, discovers)
    if not affected:
        return []
    all_unanswered = sorted((r for u, _ in affected.values() for r in u), key=lambda p: p.n)
    t0, t1 = all_unanswered[0].ts, all_unanswered[-1].ts
    others_served = sorted(c for c, ts in served_clients.items() if c not in affected and t0 - 60 <= ts <= t1 + 60)
    recovered = sorted(c for c in affected if c in served_clients and served_clients[c] > affected[c][0][-1].ts)
    indicators = [Indicator(f"{len(all_unanswered)} DHCP DISCOVERs from {len(affected)} client(s) over "
                            f"{t1 - t0:.1f} s received no OFFER", FAULT, "strong")]
    if others_served:
        indicators.append(Indicator(f"Other clients ({len(others_served)}) were served in the same period, so "
                                    "the server is alive but ignores these clients", FAULT, "moderate"))
    clients = sorted(affected)
    if not any_reply:
        cause = ("No DHCP server answered anything in this capture: the DHCP server is down, unreachable from "
                 "this network segment, or the DHCP relay (ip helper-address) on the router is missing or broken.")
    elif others_served:
        cause = ("The DHCP server answers other clients but not these: its address pool is probably exhausted, "
                 "or MAC filtering / reservations, a port-security rule or a VLAN/relay misconfiguration "
                 "blocks these clients.")
    else:
        cause = ("The DHCP server stopped answering during the capture (service stopped, crashed, pool "
                 "exhausted) or the relay path to it broke.")
    evidence = [Evidence(r.n, f"DISCOVER from {_dhcp(r).get('chaddr')} with no OFFER (xid "
                              f"0x{int(_dhcp(r).get('xid') or 0):08x})") for r in all_unanswered[:MAX_EVIDENCE]]
    return [Finding(
        detector=NAME, kind="DHCP_NO_RESPONSE",
        title=f"DHCP server not answering {len(affected)} client(s)",
        category="fault", assessment=assess(indicators), severity="high" if len(affected) >= 3 else "medium",
        evidence_strength="strong",
        summary=(f"{len(affected)} device(s) asked for an IP address {len(all_unanswered)} times (DHCP DISCOVER) "
                 "and no DHCP server ever offered one."
                 + (f" {len(recovered)} of them eventually got an offer later." if recovered else "")),
        impact=("These devices cannot get an IP address, so they have no network access at all (Windows shows "
                "'No Internet' with a 169.254.x.x address)."),
        likely_cause=cause,
        recommendations=["Check that the DHCP service is running and reachable (and see its log for "
                         "'no free leases').",
                         "Check the address pool usage and lease time; enlarge the pool or shorten leases if full.",
                         "If the server is on another subnet, verify the router's DHCP relay (ip helper-address) "
                         "for this VLAN.",
                         "Check switch port security / DHCP snooping rules on the affected clients' ports."],
        facts=[f"Unanswered DISCOVERs per client: "
               + _listed([f"{c} x{len(affected[c][0])}" for c in clients]),
               f"DHCP replies of any kind in the capture: {'yes' if any_reply else 'none'}.",
               f"Other clients served during this period: {_listed(others_served)}."],
        alternatives=["The capture point may not see the server's replies (e.g. unicast OFFERs on a switched "
                      "network) - confirm on the client that it really has no address."],
        limitations=[f"DISCOVERs in the last {DHCP_OFFER_WAIT_SECONDS:.0f} s of the capture are not counted "
                     "because their OFFER may simply not have arrived yet.",
                     "Only DHCPv4 is analysed."],
        indicators=indicators,
        hosts={"client": clients} | ({"dhcp_server": sorted(ctx.dhcp_offered["server"])}
                                     if ctx.dhcp_offered["server"] else {}),
        time_start=t0, time_end=t1, evidence=evidence,
        metrics={"clients": len(affected), "unanswered_discovers": len(all_unanswered),
                 "per_client": {c: len(affected[c][0]) for c in clients},
                 "other_clients_served": len(others_served), "recovered_clients": recovered,
                 "any_dhcp_reply": any_reply},
        rule=f">= {th.dhcp_unanswered_discover_min} DISCOVERs from one client with no OFFER for that transaction")]


def _nak_findings(ctx: AnalysisContext) -> list[Finding]:
    naks: dict[str, list[PacketRecord]] = defaultdict(list)
    ackers: Counter = Counter()
    server_nets: dict[str, set] = defaultdict(set)
    requests: dict[tuple, PacketRecord] = {}
    for r in ctx.dhcp:
        d = _dhcp(r)
        mt = d.get("msg_type")
        identity = _valid_ip(d.get("server_id")) or _valid_ip(r.ip_src)
        if mt == "REQUEST":
            requests[(d.get("xid"), d.get("chaddr"))] = r
        elif mt == "NAK" and identity:
            naks[identity].append(r)
        elif mt in ("OFFER", "ACK") and identity:
            ackers[identity] += 1
            server_nets[identity].add(_net24(d.get("yiaddr")))
            for gw in _ip_list(d.get("router")):
                server_nets[identity].add(_net24(gw))
    findings = []
    for identity, items in naks.items():
        if len(items) < DHCP_NAK_MIN:
            continue
        nets = server_nets.get(identity, set()) - {None}
        if not nets:
            nets = {_net24(identity)} - {None}
        pairs = []
        for nak in items:
            d = _dhcp(nak)
            req = requests.get((d.get("xid"), d.get("chaddr")))
            wanted = None
            if req is not None and req.ts <= nak.ts:
                rd = _dhcp(req)
                wanted = _valid_ip(rd.get("requested_ip")) or _valid_ip(rd.get("ciaddr"))
            pairs.append((nak, req if wanted else None, wanted))
        foreign = [w for _, _, w in pairs if w and nets and _net24(w) not in nets]
        clients = Counter(_dhcp(n).get("chaddr") for n in items)
        indicators = [Indicator(f"{len(items)} DHCP NAKs from {identity} refused {len(clients)} client(s)",
                                FAULT, "strong")]
        if foreign:
            indicators.append(Indicator(f"{len(foreign)} refused request(s) were for addresses outside the "
                                        f"server's network ({_listed(sorted(set(foreign)))})", FAULT, "moderate"))
        other_ackers = [s for s in ackers if s != identity]
        if not ackers.get(identity) and other_ackers:
            indicators.append(Indicator(f"{identity} never hands out a lease itself while {_listed(other_ackers)} "
                                        "does; a device that only refuses requests may be a rogue NAK "
                                        "denial-of-service", ATTACK, "moderate"))
        looping = sorted(c for c, k in clients.items() if k >= 3)
        evidence = []
        for nak, req, wanted in pairs[:MAX_EVIDENCE // 2]:
            if req is not None:
                evidence.append(Evidence(req.n, f"client {_dhcp(req).get('chaddr')} requests {wanted}"))
            evidence.append(Evidence(nak.n, f"NAK from {identity} refusing client {_dhcp(nak).get('chaddr')}"))
        times = [n.ts for n in items]
        cause = ("Clients are asking to keep addresses from a different network (moved between offices / VLANs, "
                 "or the server's scope was renumbered), and the server correctly refuses them." if foreign else
                 "The server refuses requests it should accept: its scope/pool or lease database is "
                 "misconfigured, two servers disagree about who owns the leases, or the pool is exhausted.")
        findings.append(Finding(
            detector=NAME, kind="DHCP_NAK",
            title=f"DHCP server {identity} is refusing address requests ({len(items)} NAKs)",
            category="fault", assessment=assess(indicators), severity="medium",
            evidence_strength="strong" if len(items) >= 2 * DHCP_NAK_MIN else "moderate",
            summary=(f"The DHCP server {identity} answered {len(items)} address requests from "
                     f"{len(clients)} client(s) with NAK ('you may not use this address')."
                     + (f" Client(s) {_listed(looping)} were refused 3 or more times, so they are stuck in a "
                        "retry loop." if looping else "")),
            impact="Refused clients drop their address and have to start over; repeated refusals mean they stay "
                   "offline or keep losing connectivity.",
            likely_cause=cause,
            recommendations=["Compare the requested addresses with the server's configured scope and subnet.",
                             "Check that only one authoritative DHCP server serves this VLAN.",
                             "On a stuck client, run 'ipconfig /release' then 'ipconfig /renew' to force a fresh "
                             "DISCOVER."],
            facts=[f"NAKs: {len(items)}; clients refused: {_listed([f'{c} x{k}' for c, k in clients.most_common()])}.",
                   f"Requested addresses outside the server's network: {_listed(sorted(set(foreign)))}.",
                   f"Server's own network(s) (from its offers): {_listed(sorted(f'{n}.0/24' for n in nets))}."],
            alternatives=["A single NAK after a laptop moves between networks is normal; only repeated NAKs "
                          "indicate a problem."],
            limitations=["The capture does not show the server's configuration, only its answers."],
            indicators=indicators,
            hosts={"dhcp_server": [identity], "client": sorted(c for c in clients if c)},
            time_start=min(times), time_end=max(times), evidence=evidence,
            metrics={"naks": len(items), "clients": len(clients), "foreign_requests": len(foreign),
                     "looping_clients": looping},
            rule=f">= {DHCP_NAK_MIN} DHCP NAKs from one server"))
    return findings


def detect(ctx: AnalysisContext) -> list[Finding]:
    if not ctx.dhcp:
        return []
    return _server_findings(ctx) + _no_response_findings(ctx) + _nak_findings(ctx)
