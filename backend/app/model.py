"""Core data structures shared by the parser, detectors and correlation engine."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Assessment of what a finding most likely represents. Detectors choose one based on
# documented indicators; the correlation engine re-evaluates it at incident level.
FAULT = "fault"
ATTACK = "attack"
BENIGN = "benign"
INCONCLUSIVE = "inconclusive"

SEVERITIES = ("critical", "high", "medium", "low", "info")
STRENGTHS = ("strong", "moderate", "weak")


@dataclass(slots=True)
class PacketRecord:
    """Metadata extracted from one captured frame. Payload bytes are never stored."""

    n: int                      # 1-based packet number, identical to Wireshark's frame number
    ts: float                   # capture timestamp (seconds since epoch)
    caplen: int
    wirelen: int
    eth_src: str | None = None
    eth_dst: str | None = None
    vlan: int | None = None
    l3: str | None = None       # "IPv4", "IPv6", "ARP" or None
    ip_src: str | None = None
    ip_dst: str | None = None
    ttl: int | None = None
    ip_id: int | None = None
    ip_len: int | None = None
    df: bool = False
    fragment: bool = False
    ip_proto: int | None = None
    l4: str | None = None       # "TCP", "UDP", "ICMP", "ICMPv6" or None
    sport: int | None = None
    dport: int | None = None
    tcp_flags: int | None = None
    seq: int | None = None
    ack: int | None = None
    win: int | None = None
    payload_len: int = 0
    tcp_hlen: int = 0
    mss: int | None = None
    icmp_type: int | None = None
    icmp_code: int | None = None
    icmp_mtu: int | None = None
    icmp_inner: dict[str, Any] | None = None
    arp_op: int | None = None
    arp_psrc: str | None = None
    arp_pdst: str | None = None
    arp_hwsrc: str | None = None
    arp_hwdst: str | None = None
    dns: dict[str, Any] | None = None
    dhcp: dict[str, Any] | None = None
    app: str | None = None      # "DNS", "DHCP" when decoded
    malformed: str | None = None  # reason when part of the frame could not be decoded

    @property
    def protocol(self) -> str:
        if self.app:
            return self.app
        if self.l4:
            return self.l4
        if self.l3 == "ARP":
            return "ARP"
        if self.l3:
            return self.l3
        return "Other"


# TCP flag bits
FIN, SYN, RST, PSH, ACK, URG, ECE, CWR = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80


def flag_names(flags: int | None) -> str:
    if flags is None:
        return ""
    names = [(SYN, "SYN"), (ACK, "ACK"), (FIN, "FIN"), (RST, "RST"), (PSH, "PSH"), (URG, "URG"),
             (ECE, "ECE"), (CWR, "CWR")]
    out = [name for bit, name in names if flags & bit]
    return ",".join(out) if out else "NONE"


@dataclass
class Evidence:
    packet: int
    role: str


@dataclass
class Indicator:
    """One documented reason that pushes the assessment toward fault, attack or benign."""

    text: str
    points_to: str          # FAULT, ATTACK or BENIGN
    strength: str           # "strong", "moderate" or "weak"

    def to_dict(self) -> dict[str, str]:
        return {"text": self.text, "points_to": self.points_to, "strength": self.strength}


@dataclass
class Finding:
    """A single detector observation with its evidence and plain-language explanation."""

    detector: str               # module that produced it, e.g. "tcp_retransmissions"
    kind: str                   # machine-readable type, e.g. "TCP_RETRANSMISSIONS"
    title: str
    category: str               # "fault" or "attack": which official challenge list it belongs to
    assessment: str             # FAULT / ATTACK / BENIGN / INCONCLUSIVE after weighing indicators
    severity: str
    evidence_strength: str
    summary: str                # plain-language: what happened
    impact: str                 # what the user would notice
    likely_cause: str
    recommendations: list[str]
    facts: list[str] = field(default_factory=list)          # directly observed, with numbers
    alternatives: list[str] = field(default_factory=list)   # other explanations that fit
    limitations: list[str] = field(default_factory=list)    # what the capture cannot prove
    indicators: list[Indicator] = field(default_factory=list)
    hosts: dict[str, list[str]] = field(default_factory=dict)  # role -> IPs / MACs
    time_start: float | None = None
    time_end: float | None = None
    evidence: list[Evidence] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)
    rule: str = ""              # human-readable rule that fired
    id: str = ""

    def entities(self) -> set[str]:
        out: set[str] = set()
        for values in self.hosts.values():
            out.update(v for v in values if v)
        return out

    def packet_numbers(self) -> list[int]:
        return sorted({e.packet for e in self.evidence})

    def to_dict(self, max_evidence: int) -> dict[str, Any]:
        ordered = sorted(self.evidence, key=lambda e: e.packet)
        seen: set[int] = set()
        unique: list[Evidence] = []
        for item in ordered:
            if item.packet not in seen:
                seen.add(item.packet)
                unique.append(item)
        return {
            "id": self.id,
            "detector": self.detector,
            "kind": self.kind,
            "title": self.title,
            "category": self.category,
            "assessment": self.assessment,
            "severity": self.severity,
            "evidence_strength": self.evidence_strength,
            "summary": self.summary,
            "impact": self.impact,
            "likely_cause": self.likely_cause,
            "recommendations": self.recommendations,
            "facts": self.facts,
            "alternatives": self.alternatives,
            "limitations": self.limitations,
            "indicators": [i.to_dict() for i in self.indicators],
            "hosts": self.hosts,
            "time_start": self.time_start,
            "time_end": self.time_end,
            "rule": self.rule,
            "metrics": self.metrics,
            "evidence": [{"packet": e.packet, "role": e.role} for e in unique[:max_evidence]],
            "evidence_total": len(unique),
            "evidence_truncated": len(unique) > max_evidence,
        }


def span(records: list[PacketRecord]) -> tuple[float | None, float | None]:
    if not records:
        return None, None
    times = [r.ts for r in records]
    return min(times), max(times)


def assess(indicators: list[Indicator], default: str = INCONCLUSIVE) -> str:
    """Transparent rule for turning indicators into an assessment.

    - Any strong indicator, or two or more moderate ones, decides the direction.
    - If attack and fault are both supported at that level, the attack wins only when its
      support is strictly stronger; otherwise the result is INCONCLUSIVE.
    - Weak indicators alone never produce an ATTACK verdict.
    """
    def support(direction: str) -> tuple[int, int, int]:
        rel = [i for i in indicators if i.points_to == direction]
        return (sum(i.strength == "strong" for i in rel), sum(i.strength == "moderate" for i in rel),
                sum(i.strength == "weak" for i in rel))

    def decisive(s: tuple[int, int, int]) -> bool:
        return s[0] >= 1 or s[1] >= 2

    attack, fault, benign = support(ATTACK), support(FAULT), support(BENIGN)
    if decisive(attack) and not decisive(fault) and not decisive(benign):
        return ATTACK
    if decisive(attack) and (decisive(fault) or decisive(benign)):
        other = max(fault, benign)
        return ATTACK if attack > other else INCONCLUSIVE
    if decisive(fault):
        return FAULT
    if decisive(benign):
        return BENIGN
    if attack[1] == 1 and not any(fault) and not any(benign):
        return INCONCLUSIVE
    if any(fault):
        return FAULT if default == INCONCLUSIVE else default
    return default
