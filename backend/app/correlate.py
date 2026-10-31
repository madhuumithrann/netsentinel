"""Incident reconstruction engine and fault-versus-attack diagnosis.

Detectors report independent *findings*. This module decides which findings describe the
same underlying problem, groups them into *incidents*, rebuilds a chronological timeline
from their packet evidence and produces a transparent verdict.

Linking rules (deterministic, documented)
    Two findings are linked only when ALL of the following hold:
      1. their kinds appear together in ``RELATIONS`` - a curated list of known
         cause/effect or attack-chain relationships, each with a written explanation;
      2. they share at least one host (IP or MAC address), unless the relation is
         explicitly marked as time-only (e.g. a DNS outage and connection failures that
         start together on the same network);
      3. their time ranges overlap or are within ``correlation_gap_seconds``.
    Being close in time is never enough on its own, so unrelated problems that happen to
    occur together stay separate incidents.

Verdict rules
    * attack       - at least one finding is assessed as an attack and every fault finding
                     in the incident is explained as a side effect of it;
    * mixed        - an attack plus at least one fault that is not explained by it;
    * fault        - fault findings only;
    * inconclusive - only inconclusive findings;
    * benign       - only benign/informational findings.
    Correlation does not prove causation: every linked incident says so in its uncertainty
    list, and each relation is shown to the user with the reason it was applied.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Any

from .context import AnalysisContext
from .evidence import describe
from .model import ATTACK, BENIGN, FAULT, INCONCLUSIVE, SEVERITIES, Finding

SCAN = {"PORT_SCAN", "HOST_SWEEP"}
ARP_ATTACK = {"ARP_SPOOFING"}
DNS_ATTACK = {"DNS_HIJACK_SUSPECTED"}
DHCP_ATTACK = {"ROGUE_DHCP_SERVER"}
CONNECTION_TROUBLE = {"TCP_RETRANSMISSIONS", "TCP_SYN_RETRIES", "TCP_CONNECTION_RESET",
                      "TCP_CONNECTION_REFUSED"}
SLOWNESS = {"SLOW_TCP_HANDSHAKE", "SLOW_SERVER_RESPONSE", "DNS_SLOW_RESPONSES"}
DNS_FAULTS = {"DNS_SERVER_UNRESPONSIVE", "DNS_SERVER_FAILURE"}
MTU = {"MTU_ICMP_FRAG_NEEDED", "MTU_BLACKHOLE_SUSPECTED"}
ADDRESS_CONFLICT = {"DUPLICATE_IP", "ARP_CONFLICT"}


@dataclass(frozen=True)
class Relation:
    left: frozenset[str]
    right: frozenset[str]
    kind: str            # "chain" (both are parts of one attack), "side_effect" (right caused by left),
                         # "cause" (left is the likely cause of right), "same_problem"
    explanation: str
    time_only: bool = False


def _rel(left, right, kind, explanation, time_only=False) -> Relation:
    return Relation(frozenset(left), frozenset(right), kind, explanation, time_only)


RELATIONS: list[Relation] = [
    # --- attack chains -------------------------------------------------------------------
    _rel(ARP_ATTACK, DNS_ATTACK, "chain",
         "ARP poisoning puts the attacker between the victim and the gateway, which is exactly the "
         "position needed to forge DNS answers."),
    _rel(DHCP_ATTACK, DNS_ATTACK, "chain",
         "A rogue DHCP server can hand clients a malicious DNS server, which then returns forged answers."),
    _rel(DHCP_ATTACK, ARP_ATTACK, "chain",
         "Both techniques redirect clients' traffic through an attacker-controlled device."),
    _rel(SCAN, ARP_ATTACK | DNS_ATTACK | DHCP_ATTACK, "chain",
         "Reconstructing the attacker's steps: reconnaissance (scanning) by the same host that later "
         "redirects traffic."),
    _rel({"DNS_DGA_PATTERN"}, SCAN, "chain",
         "A host generating random domain lookups (typical of malware) is also probing other hosts."),
    # --- attack side effects -------------------------------------------------------------
    _rel(SCAN, {"TCP_CONNECTION_REFUSED", "TCP_SYN_RETRIES", "TCP_CONNECTION_RESET"}, "side_effect",
         "Resets and unanswered connection attempts are the expected responses to a port scan, so "
         "they are explained by the scan rather than by a broken service."),
    _rel(ARP_ATTACK, CONNECTION_TROUBLE | SLOWNESS, "side_effect",
         "Traffic relayed through an attacker's machine is often delayed or dropped, so these "
         "connection problems are likely a side effect of the interception."),
    _rel(DHCP_ATTACK, CONNECTION_TROUBLE | SLOWNESS | DNS_FAULTS, "side_effect",
         "Clients configured by a rogue DHCP server send traffic to a gateway/DNS server that may "
         "not forward it properly."),
    _rel(DNS_ATTACK, {"TCP_CONNECTION_RESET", "TCP_CONNECTION_REFUSED", "TCP_SYN_RETRIES"}, "side_effect",
         "Clients that received forged DNS answers connect to the wrong server, where connections fail."),
    # --- fault causes ----------------------------------------------------------------------
    _rel(MTU, {"TCP_RETRANSMISSIONS"}, "cause",
         "Packets larger than the path MTU are dropped and resent, so the retransmissions are most "
         "likely caused by the MTU problem."),
    _rel(ADDRESS_CONFLICT, CONNECTION_TROUBLE, "cause",
         "When two devices share one IP address, replies go to the wrong device and connections "
         "break or reset."),
    _rel(DNS_FAULTS, {"TCP_SYN_RETRIES", "CAPTURE_GAP", "DHCP_NO_RESPONSE"}, "same_problem",
         "DNS and connection failures starting together usually point to one upstream outage "
         "(router, uplink or internet connection).", time_only=True),
    _rel({"DHCP_NO_RESPONSE", "DHCP_SERVER_PROBLEM"}, DNS_FAULTS | {"TCP_SYN_RETRIES"}, "same_problem",
         "Clients without a valid DHCP lease cannot reach DNS or other servers."),
    _rel({"TCP_CONNECTION_REFUSED"}, {"TCP_SYN_RETRIES", "TCP_CONNECTION_RESET", "SLOW_SERVER_RESPONSE"},
         "same_problem", "Refused, unanswered or reset connections to the same server indicate one "
         "failing service."),
    _rel({"SLOW_SERVER_RESPONSE"}, {"TCP_CONNECTION_RESET"}, "same_problem",
         "A server that answers slowly and then resets connections is usually overloaded or crashing."),
    _rel({"TCP_RETRANSMISSIONS"}, SLOWNESS | {"TCP_SYN_RETRIES"}, "same_problem",
         "Packet loss forces retransmissions, which users experience as slowness."),
    _rel({"SLOW_TCP_HANDSHAKE"}, {"DNS_SLOW_RESPONSES"}, "same_problem",
         "Slow DNS and slow connection setup together point to a congested or high-latency path.",
         time_only=True),
]

CHAINS = [
    # (required kinds, title, narrative)
    ({"ARP_SPOOFING", "DNS_HIJACK_SUSPECTED"}, "Man-in-the-middle attack: ARP poisoning with DNS forgery",
     "A device poisoned ARP caches to intercept traffic and forged DNS answers to redirect victims."),
    ({"ROGUE_DHCP_SERVER", "DNS_HIJACK_SUSPECTED"}, "Traffic redirection through a rogue DHCP server",
     "A rogue DHCP server configured clients with attacker-controlled settings, and DNS answers were forged."),
    ({"ARP_SPOOFING"}, "Man-in-the-middle attack via ARP spoofing",
     "A device impersonated another host's IP address on the local network to intercept its traffic."),
    ({"ROGUE_DHCP_SERVER"}, "Rogue DHCP server redirecting clients",
     "An unauthorised DHCP server is handing out network settings that point clients to other devices."),
    ({"DNS_HIJACK_SUSPECTED"}, "DNS answers are being tampered with",
     "Clients received DNS answers that conflict with the legitimate resolver."),
    ({"PORT_SCAN"}, "Network reconnaissance (port scanning)",
     "A host systematically probed other devices to discover which services they expose."),
    ({"HOST_SWEEP"}, "Network reconnaissance (host sweep)",
     "A host probed many devices for the same service."),
    ({"DNS_SERVER_UNRESPONSIVE", "TCP_SYN_RETRIES"}, "Upstream outage: DNS and connections failing together",
     "Name resolution and new connections failed at the same time, which points to one upstream failure."),
    ({"MTU_BLACKHOLE_SUSPECTED"}, "Path MTU problem (black hole)",
     "Large packets are silently dropped on the path while small packets get through."),
    ({"MTU_ICMP_FRAG_NEEDED"}, "Path MTU smaller than the packets being sent",
     "A router reported that packets were too large for the next link."),
    ({"DUPLICATE_IP"}, "IP address conflict",
     "Two devices are using the same IP address."),
]

STRENGTH_RANK = {"strong": 0, "moderate": 1, "weak": 2}
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}
VERDICT_LABELS = {
    "attack": "Likely attack",
    "mixed": "Attack and fault together",
    "fault": "Network fault",
    "inconclusive": "Needs investigation",
    "benign": "Expected behaviour",
}


def _relation_for(a: Finding, b: Finding) -> tuple[Relation, Finding, Finding] | None:
    for rel in RELATIONS:
        if a.kind in rel.left and b.kind in rel.right:
            return rel, a, b
        if b.kind in rel.left and a.kind in rel.right:
            return rel, b, a
    return None


def _gap(a: Finding, b: Finding) -> float:
    a0, a1 = a.time_start or 0.0, a.time_end or a.time_start or 0.0
    b0, b1 = b.time_start or 0.0, b.time_end or b.time_start or 0.0
    if a1 < b0:
        return b0 - a1
    if b1 < a0:
        return a0 - b1
    return 0.0


def _overlap(a: Finding, b: Finding) -> bool:
    return _gap(a, b) == 0.0


@dataclass
class Link:
    cause: Finding
    effect: Finding
    relation: Relation
    shared: list[str]
    gap: float

    def to_dict(self) -> dict[str, Any]:
        basis = (f"shared host{'s' if len(self.shared) > 1 else ''} {', '.join(self.shared[:4])}"
                 if self.shared else "the problems started at the same time (time-only link)")
        return {"from": self.cause.id, "to": self.effect.id, "type": self.relation.kind,
                "explanation": self.relation.explanation,
                "basis": f"{basis}; time gap {self.gap:.1f} s"}


def find_links(findings: list[Finding], gap_limit: float) -> list[Link]:
    links: list[Link] = []
    for i, a in enumerate(findings):
        for b in findings[i + 1:]:
            match = _relation_for(a, b)
            if match is None:
                continue
            rel, cause, effect = match
            gap = _gap(cause, effect)
            if gap > gap_limit:
                continue
            shared = sorted(cause.entities() & effect.entities())
            if not shared and not (rel.time_only and _overlap(cause, effect)):
                continue
            links.append(Link(cause, effect, rel, shared, gap))
    return links


def _components(findings: list[Finding], links: list[Link]) -> list[list[Finding]]:
    parent = {f.id: f.id for f in findings}

    def root(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for link in links:
        ra, rb = root(link.cause.id), root(link.effect.id)
        if ra != rb:
            parent[max(ra, rb)] = min(ra, rb)
    groups: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        groups[root(f.id)].append(f)
    return list(groups.values())


def _verdict(group: list[Finding], links: list[Link]) -> tuple[str, list[str]]:
    attacks = [f for f in group if f.assessment == ATTACK]
    faults = [f for f in group if f.assessment == FAULT]
    notes: list[str] = []
    if attacks:
        explained = {l.effect.id for l in links
                     if l.relation.kind == "side_effect" and l.cause.assessment == ATTACK}
        unexplained = [f for f in faults if f.id not in explained]
        for f in faults:
            if f.id in explained:
                notes.append(f"{f.id} ({f.title}) is treated as a side effect of the attack, not a separate fault.")
        return ("mixed" if unexplained else "attack"), notes
    if faults:
        return "fault", notes
    if any(f.assessment == INCONCLUSIVE for f in group):
        return "inconclusive", notes
    return "benign", notes


def _confidence(group: list[Finding], verdict: str) -> tuple[str, str]:
    """Evidence strength of the verdict, with the documented reason."""
    relevant = [f for f in group if
                (verdict in ("attack", "mixed") and f.assessment == ATTACK) or
                (verdict == "fault" and f.assessment == FAULT)] or group
    best = min(relevant, key=lambda f: STRENGTH_RANK.get(f.evidence_strength, 2))
    level = best.evidence_strength
    detectors = {f.detector for f in relevant}
    if len(detectors) >= 2 and level != "strong":
        level = "strong" if level == "moderate" else "moderate"
        return level, (f"Raised one level because {len(detectors)} independent detectors "
                       f"({', '.join(sorted(detectors))}) point the same way.")
    return level, f"Based on the strongest supporting finding ({best.id}: {best.evidence_strength} evidence)."


def _title(group: list[Finding], primary: Finding) -> tuple[str, str | None]:
    kinds = {f.kind for f in group}
    for required, title, narrative in CHAINS:
        if required <= kinds and (len(required) > 1 or len(group) >= 1):
            if len(required) == 1 and primary.kind not in required:
                continue
            return title, narrative
    return primary.title, None


def _timeline(group: list[Finding], ctx: AnalysisContext, limit: int = 60) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    start = ctx.start_ts
    for f in group:
        seen_roles: dict[str, int] = defaultdict(int)
        chosen = []
        for ev in sorted(f.evidence, key=lambda e: e.packet):
            # Keep the first two packets of every evidence role so each step of the story appears.
            if seen_roles[ev.role] < 2:
                seen_roles[ev.role] += 1
                chosen.append(ev)
        for ev in chosen[:12]:
            rec = ctx.by_number.get(ev.packet)
            if rec is None:
                continue
            events.append({"time": rec.ts, "relative": round(rec.ts - start, 6), "packet": rec.n,
                           "finding": f.id, "kind": f.kind, "role": ev.role,
                           "src": rec.ip_src or rec.arp_psrc or rec.eth_src,
                           "dst": rec.ip_dst or rec.arp_pdst or rec.eth_dst, "info": describe(rec)})
    events.sort(key=lambda e: (e["time"], e["packet"]))
    if len(events) > limit:
        # Keep the beginning and end of the story rather than an arbitrary prefix.
        events = events[: limit // 2] + events[-(limit // 2):]
    return events


def _hosts(group: list[Finding]) -> list[dict[str, Any]]:
    roles: dict[str, set[str]] = defaultdict(set)
    for f in group:
        for role, values in f.hosts.items():
            for v in values:
                if v:
                    roles[v].add(role)
    order = {"attacker": 0, "suspect": 0, "rogue_server": 0, "scanner": 0, "victim": 1, "client": 2}
    return sorted(({"address": a, "roles": sorted(r)} for a, r in roles.items()),
                  key=lambda h: (min(order.get(r, 3) for r in h["roles"]), h["address"]))[:40]


def _dedupe(items: list[str], limit: int) -> list[str]:
    seen, out = set(), []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            out.append(item)
    return out[:limit]


def build_incidents(findings: list[Finding], ctx: AnalysisContext) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if not findings:
        return [], {"status": "clean", "label": "No problems detected",
                    "headline": ("No faults or attacks matched NetSentinel's detection rules in this capture. "
                                 "This does not guarantee the network is healthy: problems outside the "
                                 "capture or below the detection thresholds are not visible."),
                    "counts": {}}
    links = find_links(findings, ctx.thresholds.correlation_gap_seconds)
    groups = _components(findings, links)
    incidents: list[dict[str, Any]] = []
    for group in groups:
        group.sort(key=lambda f: (f.time_start or 0, f.id))
        ids = {f.id for f in group}
        group_links = [l for l in links if l.cause.id in ids]
        verdict, verdict_notes = _verdict(group, group_links)
        # Primary finding: attacks first, then severity, then strongest evidence.
        primary = min(group, key=lambda f: (0 if f.assessment == ATTACK else 1, SEV_RANK.get(f.severity, 9),
                                            STRENGTH_RANK.get(f.evidence_strength, 2), f.time_start or 0))
        title, narrative = _title(group, primary)
        confidence, confidence_reason = _confidence(group, verdict)
        severity = min((f.severity for f in group), key=lambda s: SEV_RANK.get(s, 9))
        if verdict in ("attack", "mixed") and len({f.detector for f in group}) >= 2 \
                and SEV_RANK[severity] > SEV_RANK["high"]:
            severity = "high"
        reasoning = []
        for f in group:
            for ind in f.indicators:
                reasoning.append({"finding": f.id, **ind.to_dict()})
        uncertainty = _dedupe([lim for f in group for lim in f.limitations], 8)
        if group_links:
            uncertainty.insert(0, "The findings were linked by documented rules (shared hosts, timing and a "
                                  "known cause-and-effect relationship). Correlation does not prove causation.")
        recs: list[str] = []
        for f in sorted(group, key=lambda f: (0 if f.assessment == ATTACK else 1, SEV_RANK.get(f.severity, 9))):
            recs.extend(f.recommendations)
        explained = {l.effect.id for l in group_links if l.relation.kind in ("side_effect", "cause")}
        root_causes = [f for f in group if f.id not in explained] or group
        root = min(root_causes, key=lambda f: (0 if f.assessment == ATTACK else 1, SEV_RANK.get(f.severity, 9)))
        summary_parts = [narrative] if narrative else []
        summary_parts.append(root.summary)
        if len(group) > 1:
            others = [f for f in group if f is not root]
            summary_parts.append("Related observations: " + "; ".join(f.title for f in others[:5]) + ".")
        incidents.append({
            "title": title,
            "verdict": verdict,
            "verdict_label": VERDICT_LABELS[verdict],
            "verdict_notes": verdict_notes,
            "severity": severity,
            "confidence": confidence,
            "confidence_reason": confidence_reason,
            "summary": " ".join(summary_parts),
            "likely_root_cause": root.likely_cause,
            "root_finding": root.id,
            "impact": root.impact,
            "alternatives": _dedupe([a for f in group for a in f.alternatives], 6),
            "uncertainty": uncertainty,
            "recommendations": _dedupe(recs, 10),
            "observed_facts": _dedupe([fact for f in group for fact in f.facts], 12),
            "reasoning": reasoning,
            "links": [l.to_dict() for l in group_links],
            "findings": [f.id for f in group],
            "kinds": sorted({f.kind for f in group}),
            "affected_hosts": _hosts(group),
            "time_start": min((f.time_start for f in group if f.time_start is not None), default=None),
            "time_end": max((f.time_end for f in group if f.time_end is not None), default=None),
            "timeline": _timeline(group, ctx),
        })
    verdict_rank = {"attack": 0, "mixed": 0, "fault": 1, "inconclusive": 2, "benign": 3}
    incidents.sort(key=lambda i: (verdict_rank[i["verdict"]], SEV_RANK.get(i["severity"], 9), i["time_start"] or 0))
    for n, inc in enumerate(incidents, start=1):
        inc["id"] = f"INC-{n:03d}"
        if inc["time_start"] is not None:
            inc["relative_start"] = round(inc["time_start"] - ctx.start_ts, 3)
            inc["relative_end"] = round((inc["time_end"] or inc["time_start"]) - ctx.start_ts, 3)
    return incidents, _overall(incidents)


def _overall(incidents: list[dict[str, Any]]) -> dict[str, Any]:
    counts: dict[str, int] = defaultdict(int)
    for inc in incidents:
        counts[inc["verdict"]] += 1
    attacks = counts["attack"] + counts["mixed"]
    faults = counts["fault"]
    if attacks:
        status, label = "attack", "Possible attack detected"
    elif faults:
        status, label = "fault", "Network faults detected"
    elif counts["inconclusive"]:
        status, label = "inconclusive", "Needs investigation"
    else:
        status, label = "clean", "No problems detected"
    parts = []
    if attacks:
        names = [i["title"] for i in incidents if i["verdict"] in ("attack", "mixed")][:3]
        parts.append(f"{attacks} incident{'s match' if attacks > 1 else ' matches'} attack indicators "
                     f"({'; '.join(names)})")
    if faults:
        names = [i["title"] for i in incidents if i["verdict"] == "fault"][:3]
        parts.append(f"{faults} look{'s' if faults == 1 else ''} like ordinary network fault{'s' if faults > 1 else ''} "
                     f"({'; '.join(names)})")
    if counts["inconclusive"]:
        parts.append(f"{counts['inconclusive']} need{'s' if counts['inconclusive'] == 1 else ''} more evidence")
    if counts["benign"]:
        parts.append(f"{counts['benign']} {'is' if counts['benign'] == 1 else 'are'} expected behaviour")
    headline = (". ".join(p[0].upper() + p[1:] for p in parts) + ".") if parts else ""
    return {"status": status, "label": label, "headline": headline,
            "counts": {k: v for k, v in counts.items() if v}}
