"""NetSentinel's custom, offline PCAP analysis and rule-based detection engine."""
from __future__ import annotations
from collections import defaultdict, Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from scapy.all import PcapReader, IP, IPv6, TCP, UDP, DNS, DNSQR, ARP, BOOTP, DHCP

MAX_PACKETS = 500_000


def _ts(value: float) -> str:
    return datetime.fromtimestamp(float(value), tz=timezone.utc).isoformat()


def analyze_pcap(path: str | Path) -> dict[str, Any]:
    """Analyze an offline capture. Never transmits packets or touches a live interface."""
    packets: list[dict[str, Any]] = []
    stats = Counter()
    conversations: dict[tuple, dict[str, Any]] = {}
    syn_ports: dict[tuple[str, str], list[tuple[float, int]]] = defaultdict(list)
    arp_claims: dict[str, dict[str, list[int]]] = defaultdict(lambda: defaultdict(list))
    dns_nxdomain: dict[str, list[int]] = defaultdict(list)
    dhcp_servers: dict[str, list[int]] = defaultdict(list)
    tcp_seen: dict[tuple, dict[int, list[int]]] = defaultdict(lambda: defaultdict(list))
    first_ts = last_ts = None

    with PcapReader(str(path)) as reader:
        for index, pkt in enumerate(reader, start=1):
            if index > MAX_PACKETS:
                raise ValueError(f"Capture exceeds the {MAX_PACKETS:,}-packet analysis limit")
            timestamp = float(pkt.time)
            first_ts = timestamp if first_ts is None else first_ts
            last_ts = timestamp
            src = dst = None
            if IP in pkt:
                src, dst = pkt[IP].src, pkt[IP].dst
            elif IPv6 in pkt:
                src, dst = pkt[IPv6].src, pkt[IPv6].dst
            proto = "OTHER"
            if TCP in pkt:
                proto = "TCP"; stats["tcp"] += 1
                tcp = pkt[TCP]
                flow = (src, int(tcp.sport), dst, int(tcp.dport))
                conversations.setdefault(str(flow), {"src": src, "dst": dst, "protocol": "TCP", "packets": 0})["packets"] += 1
                flags = int(tcp.flags)
                # SYN without ACK is a connection initiation; count distinct target ports per source/target.
                if (flags & 0x02) and not (flags & 0x10) and src and dst:
                    syn_ports[(src, dst)].append((timestamp, int(tcp.dport)))
                if flags & 0x04:
                    stats["tcp_rst"] += 1
                # Repeated sequence starts in the same direction are evidence candidates, not definitive proof.
                tcp_seen[flow][int(tcp.seq)].append(index)
            elif UDP in pkt:
                proto = "UDP"; stats["udp"] += 1
                udp = pkt[UDP]
                conversations.setdefault(str((src, int(udp.sport), dst, int(udp.dport))), {"src": src, "dst": dst, "protocol": "UDP", "packets": 0})["packets"] += 1
            elif ARP in pkt:
                proto = "ARP"; stats["arp"] += 1
                arp = pkt[ARP]
                if int(arp.op) in (1, 2) and str(arp.psrc) not in ("0.0.0.0", ""):
                    arp_claims[str(arp.psrc)][str(arp.hwsrc).lower()].append(index)
            if DNS in pkt and pkt[DNS].qr == 1 and int(pkt[DNS].rcode) == 3 and src:
                dns_nxdomain[src].append(index)
            if DHCP in pkt and BOOTP in pkt and int(pkt[BOOTP].op) == 2:
                server = str(pkt[IP].src) if IP in pkt else str(pkt[IPv6].src) if IPv6 in pkt else "unknown"
                dhcp_servers[server].append(index)
            packets.append({"number": index, "timestamp": timestamp, "time": _ts(timestamp), "src": src, "dst": dst, "protocol": proto})

    incidents: list[dict[str, Any]] = []
    def add(kind: str, severity: str, title: str, summary: str, cause: str, fix: str,
            evidence: list[int], confidence: str = "Medium") -> None:
        incidents.append({"id": f"INC-{len(incidents)+1:03d}", "type": kind, "severity": severity,
            "title": title, "summary": summary, "likely_cause": cause, "recommendation": fix,
            "evidence_packets": sorted(set(evidence))[:30], "confidence": confidence})

    # Port scan: 15+ distinct destination ports from one source to one target within 10 seconds.
    for (source, target), events in syn_ports.items():
        events.sort()
        left = 0
        for right, (when, _) in enumerate(events):
            while when - events[left][0] > 10:
                left += 1
            window = events[left:right+1]
            ports = {port for _, port in window}
            if len(ports) >= 15:
                evidence = [p["number"] for p in packets if p["src"] == source and p["dst"] == target and p["timestamp"] >= window[0][0] and p["timestamp"] <= when and p["protocol"] == "TCP"]
                add("PORT_SCAN", "High", "Possible TCP port scan", f"{source} sent SYN traffic to {len(ports)} distinct ports on {target} within 10 seconds.",
                    "A host may be enumerating exposed services. Authorized vulnerability scanning can produce the same pattern.",
                    "Verify whether the source is an authorized scanner. If not, isolate and investigate the source host.", evidence, "High")
                break

    for ip, macs in arp_claims.items():
        if len(macs) > 1:
            evidence = [n for nums in macs.values() for n in nums]
            add("ARP_MAPPING_CHANGE", "High", "Conflicting ARP address ownership", f"IP address {ip} was associated with multiple MAC addresses: {', '.join(macs)}.",
                "This may indicate ARP spoofing, failover, or a legitimate network reconfiguration.",
                "Check the switch/router ARP table and verify the device owning this IP before taking action.", evidence, "Medium")

    for source, nums in dns_nxdomain.items():
        if len(nums) >= 10:
            add("DNS_NXDOMAIN_SPIKE", "Medium", "High rate of failed DNS lookups", f"{source} received {len(nums)} NXDOMAIN responses.",
                "A misconfigured client, invalid domain requests, or suspicious domain-generation activity may be responsible.",
                "Review queried domain names and client configuration; compare against normal baseline traffic.", nums, "Medium")

    if len(dhcp_servers) > 1:
        evidence = [n for nums in dhcp_servers.values() for n in nums]
        add("MULTIPLE_DHCP_SERVERS", "High", "Multiple DHCP servers observed", f"DHCP offer/ack traffic came from: {', '.join(dhcp_servers)}.",
            "An unauthorized DHCP server may be present, though multiple servers can be intentional in managed networks.",
            "Verify each DHCP server against the network configuration and inspect offered gateway/DNS settings.", evidence, "Medium")

    rst_packets = [p["number"] for p in packets if p["protocol"] == "TCP"]
    if stats["tcp_rst"] >= 10:
        # Locate actual RST packets from the original packet stream by reparsing only metadata is unnecessary here;
        # packet numbers are collected in a second lightweight pass below.
        rst_numbers = []
        with PcapReader(str(path)) as reader:
            for i, pkt in enumerate(reader, start=1):
                if TCP in pkt and (int(pkt[TCP].flags) & 0x04): rst_numbers.append(i)
        add("TCP_RESETS", "Medium", "Elevated TCP reset activity", f"Observed {stats['tcp_rst']} TCP RST packets.",
            "Connections may be rejected, terminated by applications, or interrupted by network/security devices.",
            "Inspect affected endpoints and services; correlate resets with connection failures and firewall logs.", rst_numbers, "Medium")

    retransmission_candidates = []
    for flow, seqs in tcp_seen.items():
        for seq, nums in seqs.items():
            if len(nums) > 1:
                retransmission_candidates.extend(nums[1:])
    if len(retransmission_candidates) >= 5:
        add("TCP_RETRANSMISSION_CANDIDATES", "Medium", "Repeated TCP sequence numbers", f"Found {len(retransmission_candidates)} repeated TCP sequence-number observations.",
            "Packet loss or retransmission may be occurring; packet duplication or capture artifacts can also produce repeats.",
            "Check packet timing, ACK behavior, interface drops and network path health before concluding packet loss.", retransmission_candidates, "Low")

    duration = max(0.0, (last_ts or 0) - (first_ts or 0)) if packets else 0.0
    return {"file": Path(path).name, "packets_analyzed": len(packets), "duration_seconds": round(duration, 3),
        "protocols": {"TCP": stats["tcp"], "UDP": stats["udp"], "ARP": stats["arp"]},
        "conversations": list(conversations.values())[:100], "incidents": incidents,
        "timeline": packets[:500], "summary": {"incident_count": len(incidents), "high": sum(i["severity"] == "High" for i in incidents),
        "medium": sum(i["severity"] == "Medium" for i in incidents), "low": sum(i["severity"] == "Low" for i in incidents)},
        "notice": "Findings are indicators based on this capture, not proof of malicious activity. Analysis is offline."}
