"""Evidence engine: human-readable summaries of the packets that support a diagnosis.

Only header metadata is exposed. Application payload bytes are never included in the API
response, so uploaded captures cannot leak passwords or message contents through the UI.
"""
from __future__ import annotations

from typing import Any

from .model import PacketRecord, flag_names

ICMP_NAMES = {(0, None): "Echo reply", (8, None): "Echo request", (3, 0): "Network unreachable",
              (3, 1): "Host unreachable", (3, 3): "Port unreachable", (3, 4): "Fragmentation needed",
              (3, 13): "Administratively prohibited", (11, 0): "TTL exceeded", (5, None): "Redirect"}
ICMP6_NAMES = {1: "Destination unreachable", 2: "Packet too big", 3: "Time exceeded",
               128: "Echo request", 129: "Echo reply", 133: "Router solicitation",
               134: "Router advertisement", 135: "Neighbor solicitation", 136: "Neighbor advertisement"}
DNS_RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}


def describe(rec: PacketRecord) -> str:
    if rec.malformed and rec.l3 is None:
        return f"Malformed frame ({rec.malformed})"
    if rec.arp_op is not None:
        if rec.arp_op == 1:
            if rec.arp_psrc == "0.0.0.0":
                return f"ARP probe: is {rec.arp_pdst} in use? (from {rec.arp_hwsrc})"
            return f"ARP request: who has {rec.arp_pdst}? tell {rec.arp_psrc}"
        if rec.arp_op == 2:
            return f"ARP reply: {rec.arp_psrc} is at {rec.arp_hwsrc}"
        return f"ARP opcode {rec.arp_op}"
    if rec.dns is not None:
        d = rec.dns
        if d["qr"] == 0:
            return f"DNS query {d['qtype'] or ''} {d['qname'] or '?'} (id {d['id']})"
        rcode = DNS_RCODES.get(d["rcode"], str(d["rcode"]))
        answers = ", ".join(a["value"] for a in d["answers"][:4])
        return (f"DNS response {rcode} {d['qname'] or '?'}" + (f" -> {answers}" if answers else "")
                + f" (id {d['id']})")
    if rec.dhcp is not None:
        d = rec.dhcp
        extra = []
        if d.get("yiaddr") and d["yiaddr"] != "0.0.0.0":
            extra.append(f"offers {d['yiaddr']}")
        if d.get("router"):
            extra.append(f"gateway {', '.join(d['router'])}")
        if d.get("dns"):
            extra.append(f"DNS {', '.join(d['dns'])}")
        if d.get("server_id"):
            extra.append(f"server {d['server_id']}")
        return f"DHCP {d.get('msg_type') or '?'} " + "; ".join(extra) + f" (client {d.get('chaddr')})"
    if rec.l4 == "TCP":
        text = (f"TCP {rec.sport} -> {rec.dport} [{flag_names(rec.tcp_flags)}] seq={rec.seq} "
                f"ack={rec.ack} len={rec.payload_len}")
        if rec.mss:
            text += f" MSS={rec.mss}"
        return text
    if rec.l4 == "UDP":
        return f"UDP {rec.sport} -> {rec.dport} len={rec.payload_len}"
    if rec.l4 == "ICMP":
        name = ICMP_NAMES.get((rec.icmp_type, rec.icmp_code)) or ICMP_NAMES.get((rec.icmp_type, None)) \
            or f"type {rec.icmp_type} code {rec.icmp_code}"
        text = f"ICMP {name}"
        if rec.icmp_mtu:
            text += f" (next-hop MTU {rec.icmp_mtu})"
        if rec.icmp_inner:
            i = rec.icmp_inner
            text += f" about {i.get('src')} -> {i.get('dst')}"
            if i.get("dport") is not None:
                text += f":{i['dport']}"
        return text
    if rec.l4 == "ICMPv6":
        text = f"ICMPv6 {ICMP6_NAMES.get(rec.icmp_type, f'type {rec.icmp_type}')}"
        if rec.icmp_mtu:
            text += f" (MTU {rec.icmp_mtu})"
        return text
    if rec.fragment:
        return f"{rec.l3} fragment (protocol {rec.ip_proto})"
    if rec.l3:
        return f"{rec.l3} protocol {rec.ip_proto}"
    return "Non-IP frame"


def summarize(rec: PacketRecord, start_ts: float) -> dict[str, Any]:
    out: dict[str, Any] = {
        "number": rec.n,
        "time": round(rec.ts, 6),
        "relative": round(rec.ts - start_ts, 6),
        "src": rec.ip_src or rec.arp_psrc or rec.eth_src,
        "dst": rec.ip_dst or rec.arp_pdst or rec.eth_dst,
        "src_mac": rec.eth_src,
        "dst_mac": rec.eth_dst,
        "protocol": rec.protocol,
        "length": rec.wirelen,
        "info": describe(rec),
    }
    if rec.ttl is not None:
        out["ttl"] = rec.ttl
    if rec.sport is not None:
        out["sport"], out["dport"] = rec.sport, rec.dport
    if rec.malformed:
        out["malformed"] = rec.malformed
    return out
