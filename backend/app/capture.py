"""Safe capture reading and NetSentinel's own bounded protocol decoder.

Scapy is used only for decoding DHCP payloads; container framing is done by the bounded
reader in ``pcapio`` and DNS messages are decoded by ``decode_dns`` below. Ethernet, VLAN, ARP, IPv4, IPv6, TCP, UDP, ICMP and ICMPv6 headers are decoded
here with explicit bounds checks, which is roughly 100x faster than full Scapy dissection
and lets every malformed frame be recorded instead of crashing the analysis.
"""
from __future__ import annotations

import ipaddress
import struct
import time
from dataclasses import dataclass, field
from typing import IO, Any

from scapy.layers.dhcp import BOOTP, DHCP

from .config import Limits
from .model import PacketRecord
from .pcapio import ContainerError, ContainerStatus, iter_frames

PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",  # microsecond pcap (LE / BE)
    b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d",  # nanosecond pcap
}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"

# Link types we can decode (others are counted but not analysed).
LINKTYPE_NULL, LINKTYPE_ETHERNET, LINKTYPE_RAW, LINKTYPE_RAW_ALT = 0, 1, 101, 12
LINKTYPE_IPV4, LINKTYPE_IPV6, LINKTYPE_SLL, LINKTYPE_SLL2 = 228, 229, 113, 276
SUPPORTED_LINKTYPES = {LINKTYPE_NULL, LINKTYPE_ETHERNET, LINKTYPE_RAW, LINKTYPE_RAW_ALT,
                       LINKTYPE_IPV4, LINKTYPE_IPV6, LINKTYPE_SLL, LINKTYPE_SLL2}


class CaptureError(ValueError):
    """Raised for input that is not a usable capture. Messages are safe to show to users."""


@dataclass
class ParseReport:
    file_format: str = "unknown"
    packets_read: int = 0
    malformed_packets: int = 0
    unsupported_link_packets: int = 0
    truncated_file: bool = False
    stopped_early: str | None = None    # reason when a resource limit stopped parsing
    warnings: list[str] = field(default_factory=list)
    parse_seconds: float = 0.0


def sniff_format(header: bytes) -> str:
    """Identify the container from its magic number, never from the file name."""
    if header[:4] in PCAP_MAGICS:
        return "pcap"
    if header[:4] == PCAPNG_MAGIC:
        return "pcapng"
    raise CaptureError("The file is not a pcap or pcapng capture (unrecognised file signature).")


# --- small cached string helpers (interning keeps memory low for large captures) -----------

_mac_cache: dict[bytes, str] = {}
_ip4_cache: dict[bytes, str] = {}
_ip6_cache: dict[bytes, str] = {}


def _mac(raw: bytes) -> str:
    s = _mac_cache.get(raw)
    if s is None:
        s = ":".join(f"{b:02x}" for b in raw)
        if len(_mac_cache) < 200_000:
            _mac_cache[raw] = s
    return s


def _ip4(raw: bytes) -> str:
    s = _ip4_cache.get(raw)
    if s is None:
        s = ".".join(str(b) for b in raw)
        if len(_ip4_cache) < 200_000:
            _ip4_cache[raw] = s
    return s


def _ip6(raw: bytes) -> str:
    s = _ip6_cache.get(raw)
    if s is None:
        s = str(ipaddress.IPv6Address(raw))
        if len(_ip6_cache) < 200_000:
            _ip6_cache[raw] = s
    return s


def _text(value: Any, limit: int = 255) -> str:
    if isinstance(value, bytes):
        value = value.decode("ascii", errors="replace")
    text = str(value)
    # Strip control characters so hostile names cannot inject into logs or the UI.
    text = "".join(ch if 32 <= ord(ch) < 127 else "?" for ch in text)
    return text[:limit]


# --- application decoders ----------------------------------------------------------------

DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA",
             33: "SRV", 65: "HTTPS"}
_MAX_DNS_ANSWERS = 32


class _DnsError(ValueError):
    pass


def _dns_name(buf: bytes, off: int) -> tuple[str, int]:
    """Decode a (possibly compressed) DNS name. Returns (name, offset after the name).

    Compression pointers must point strictly backwards, so a hostile message cannot create a
    loop; total length is capped at 255 bytes as in RFC 1035.
    """
    labels: list[str] = []
    end: int | None = None
    total = 0
    limit = len(buf)
    while True:
        if off >= limit:
            raise _DnsError("name runs past end")
        length = buf[off]
        if length == 0:
            off += 1
            break
        if length & 0xC0 == 0xC0:
            if off + 1 >= limit:
                raise _DnsError("truncated pointer")
            ptr = ((length & 0x3F) << 8) | buf[off + 1]
            if ptr >= off:
                raise _DnsError("forward or self pointer")
            if end is None:
                end = off + 2
            off = ptr
            continue
        if length & 0xC0:
            raise _DnsError("bad label type")
        label = buf[off + 1:off + 1 + length]
        if len(label) < length:
            raise _DnsError("truncated label")
        total += length + 1
        if total > 255:
            raise _DnsError("name too long")
        labels.append(_text(label, 63))
        off += 1 + length
    return ".".join(labels).lower(), (end if end is not None else off)


def decode_dns(payload: bytes) -> dict[str, Any] | None:
    """NetSentinel's own bounded DNS message decoder (header, question, answer records)."""
    if len(payload) < 12:
        return None
    try:
        txid, flags, qd, an, _ns, _ar = struct.unpack_from("!HHHHHH", payload, 0)
        off = 12
        qname = qtype = None
        if qd:
            qname, off = _dns_name(payload, off)
            if off + 4 > len(payload):
                raise _DnsError("truncated question")
            qt = struct.unpack_from("!H", payload, off)[0]
            qtype = DNS_TYPES.get(qt, str(qt))
            off += 4
            for _ in range(min(qd, 4) - 1):          # skip any extra questions
                _, off = _dns_name(payload, off)
                off += 4
        answers = []
        for _ in range(min(an, _MAX_DNS_ANSWERS)):
            name, off = _dns_name(payload, off)
            if off + 10 > len(payload):
                break
            rtype, _rclass, ttl, rdlen = struct.unpack_from("!HHIH", payload, off)
            off += 10
            rdata = payload[off:off + rdlen]
            if len(rdata) < rdlen:
                break
            value = None
            if rtype == 1 and rdlen == 4:
                value = ".".join(str(b) for b in rdata)
            elif rtype == 28 and rdlen == 16:
                value = str(ipaddress.IPv6Address(rdata))
            elif rtype in (2, 5, 12):
                value = _dns_name(payload, off)[0]
            if value is not None:
                answers.append({"name": name, "type": DNS_TYPES.get(rtype, str(rtype)),
                                "value": value, "ttl": int(ttl)})
            off += rdlen
        return {"id": txid, "qr": flags >> 15, "rcode": flags & 0x0F, "qname": qname,
                "qtype": qtype, "answers": answers, "ancount": an}
    except (_DnsError, struct.error, ValueError):
        return None


DHCP_MSG = {1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE", 5: "ACK", 6: "NAK",
            7: "RELEASE", 8: "INFORM"}


def decode_dhcp(payload: bytes) -> dict[str, Any] | None:
    if len(payload) < 240:
        return None
    try:
        bootp = BOOTP(payload)
    except Exception:
        return None
    try:
        info: dict[str, Any] = {"op": int(bootp.op), "xid": int(bootp.xid),
                                "chaddr": _mac(bytes(bootp.chaddr)[:6]),
                                "yiaddr": str(bootp.yiaddr), "ciaddr": str(bootp.ciaddr),
                                "giaddr": str(bootp.giaddr), "msg_type": None, "server_id": None,
                                "router": [], "dns": [], "requested_ip": None, "lease": None}
        if DHCP in bootp:
            for opt in bootp[DHCP].options:
                if not isinstance(opt, tuple) or len(opt) < 2:
                    continue
                name, values = opt[0], opt[1:]
                if name == "message-type":
                    info["msg_type"] = DHCP_MSG.get(int(values[0]), str(values[0]))
                elif name == "server_id":
                    info["server_id"] = _text(values[0], 45)
                elif name == "router":
                    info["router"] = [_text(v, 45) for v in values[:8]]
                elif name == "name_server":
                    info["dns"] = [_text(v, 45) for v in values[:8]]
                elif name == "requested_addr":
                    info["requested_ip"] = _text(values[0], 45)
                elif name == "lease_time":
                    info["lease"] = int(values[0])
        return info
    except Exception:
        return None


# --- link / network / transport decoding ---------------------------------------------------

def _decode_l4(rec: PacketRecord, proto: int, seg: bytes) -> None:
    rec.ip_proto = proto
    if proto == 6:
        if len(seg) < 20:
            rec.malformed = "truncated TCP header"
            return
        sport, dport, seq, ack, off_flags, win = struct.unpack_from("!HHIIHH", seg, 0)
        hlen = (off_flags >> 12) * 4
        if hlen < 20 or hlen > len(seg):
            rec.malformed = "invalid TCP header length"
            return
        rec.l4, rec.sport, rec.dport = "TCP", sport, dport
        rec.seq, rec.ack, rec.win = seq, ack, win
        rec.tcp_flags = off_flags & 0xFF
        rec.tcp_hlen = hlen
        rec.payload_len = len(seg) - hlen
        # MSS option (kind 2) is only meaningful on SYN segments.
        i = 20
        while i < hlen:
            kind = seg[i]
            if kind == 0:
                break
            if kind == 1:
                i += 1
                continue
            if i + 1 >= hlen:
                break
            length = seg[i + 1]
            if length < 2 or i + length > hlen:
                break
            if kind == 2 and length == 4:
                rec.mss = struct.unpack_from("!H", seg, i + 2)[0]
            i += length
    elif proto == 17:
        if len(seg) < 8:
            rec.malformed = "truncated UDP header"
            return
        sport, dport, ulen = struct.unpack_from("!HHH", seg, 0)
        rec.l4, rec.sport, rec.dport = "UDP", sport, dport
        body = seg[8:ulen] if 8 <= ulen <= len(seg) else seg[8:]
        rec.payload_len = len(body)
        if 53 in (sport, dport) or 5353 in (sport, dport):
            dns = decode_dns(body)
            if dns is not None:
                rec.dns, rec.app = dns, "DNS"
        elif {sport, dport} & {67, 68}:
            dhcp = decode_dhcp(body)
            if dhcp is not None:
                rec.dhcp, rec.app = dhcp, "DHCP"
    elif proto in (1, 58):
        if len(seg) < 8:
            rec.malformed = "truncated ICMP header"
            return
        rec.l4 = "ICMP" if proto == 1 else "ICMPv6"
        rec.icmp_type, rec.icmp_code = seg[0], seg[1]
        rec.payload_len = len(seg) - 8
        if proto == 1 and rec.icmp_type == 3 and rec.icmp_code == 4:
            rec.icmp_mtu = struct.unpack_from("!H", seg, 6)[0]
        if proto == 58 and rec.icmp_type == 2:
            rec.icmp_mtu = struct.unpack_from("!I", seg, 4)[0]
        # ICMP errors quote the offending packet's header; keep the flow identity only.
        if (proto == 1 and rec.icmp_type in (3, 11)) or (proto == 58 and rec.icmp_type in (1, 2, 3)):
            rec.icmp_inner = _decode_quoted(seg[8:], ipv6=(proto == 58))


def _decode_quoted(inner: bytes, ipv6: bool) -> dict[str, Any] | None:
    try:
        if not ipv6:
            if len(inner) < 20 or inner[0] >> 4 != 4:
                return None
            ihl = (inner[0] & 0x0F) * 4
            proto = inner[9]
            out: dict[str, Any] = {"src": _ip4(inner[12:16]), "dst": _ip4(inner[16:20]),
                                   "proto": proto,
                                   "len": struct.unpack_from("!H", inner, 2)[0]}
            l4 = inner[ihl:]
        else:
            if len(inner) < 40 or inner[0] >> 4 != 6:
                return None
            proto = inner[6]
            out = {"src": _ip6(inner[8:24]), "dst": _ip6(inner[24:40]), "proto": proto,
                   "len": struct.unpack_from("!H", inner, 4)[0] + 40}
            l4 = inner[40:]
        if proto in (6, 17) and len(l4) >= 4:
            out["sport"], out["dport"] = struct.unpack_from("!HH", l4, 0)
        if proto == 6 and len(l4) >= 8:
            out["seq"] = struct.unpack_from("!I", l4, 4)[0]
        return out
    except Exception:
        return None


def _decode_ipv4(rec: PacketRecord, data: bytes) -> None:
    if len(data) < 20:
        rec.malformed = "truncated IPv4 header"
        return
    ver_ihl = data[0]
    ihl = (ver_ihl & 0x0F) * 4
    if ver_ihl >> 4 != 4 or ihl < 20 or ihl > len(data):
        rec.malformed = "invalid IPv4 header"
        return
    total_len, ip_id, frag = struct.unpack_from("!HHH", data, 2)
    rec.l3, rec.ttl, rec.ip_id = "IPv4", data[8], ip_id
    rec.ip_src, rec.ip_dst = _ip4(data[12:16]), _ip4(data[16:20])
    rec.df = bool(frag & 0x4000)
    rec.fragment = bool(frag & 0x2000) or (frag & 0x1FFF) != 0
    if total_len < ihl:
        total_len = len(data)          # TSO / zero length: trust the captured bytes
    rec.ip_len = total_len
    body = data[ihl:min(total_len, len(data))]
    if rec.fragment and (frag & 0x1FFF) != 0:
        rec.ip_proto = data[9]
        return                          # non-first fragment: no L4 header
    _decode_l4_with_len(rec, data[9], body, total_len - ihl)


def _decode_l4_with_len(rec: PacketRecord, proto: int, body: bytes, declared: int) -> None:
    _decode_l4(rec, proto, body)
    if rec.l4 == "TCP":
        # Payload length comes from the IP length field so it stays correct even when the
        # capture was truncated by a small snaplen.
        rec.payload_len = max(0, declared - rec.tcp_hlen)


def _decode_ipv6(rec: PacketRecord, data: bytes) -> None:
    if len(data) < 40 or data[0] >> 4 != 6:
        rec.malformed = "invalid IPv6 header"
        return
    plen = struct.unpack_from("!H", data, 4)[0]
    nxt = data[6]
    rec.l3, rec.ttl = "IPv6", data[7]
    rec.ip_src, rec.ip_dst = _ip6(data[8:24]), _ip6(data[24:40])
    rec.ip_len = plen + 40
    off = 40
    # Walk a bounded number of extension headers.
    for _ in range(8):
        if nxt in (0, 43, 60) and off + 8 <= len(data):
            nxt, hlen = data[off], (data[off + 1] + 1) * 8
            off += hlen
        elif nxt == 44 and off + 8 <= len(data):
            frag_off = struct.unpack_from("!H", data, off + 2)[0] >> 3
            rec.fragment = True
            nxt = data[off]
            off += 8
            if frag_off:
                rec.ip_proto = nxt
                return
        else:
            break
    if off > len(data):
        rec.malformed = "truncated IPv6 extension header"
        return
    _decode_l4_with_len(rec, nxt, data[off:40 + plen], 40 + plen - off)


def _decode_arp(rec: PacketRecord, data: bytes) -> None:
    if len(data) < 28:
        rec.malformed = "truncated ARP"
        return
    htype, ptype, hlen, plen, op = struct.unpack_from("!HHBBH", data, 0)
    if htype != 1 or ptype != 0x0800 or hlen != 6 or plen != 4:
        rec.l3 = "ARP"
        rec.malformed = "unsupported ARP hardware/protocol type"
        return
    rec.l3, rec.arp_op = "ARP", op
    rec.arp_hwsrc, rec.arp_psrc = _mac(data[8:14]), _ip4(data[14:18])
    rec.arp_hwdst, rec.arp_pdst = _mac(data[18:24]), _ip4(data[24:28])


def _decode_ethertype(rec: PacketRecord, etype: int, data: bytes) -> None:
    if etype == 0x0800:
        _decode_ipv4(rec, data)
    elif etype == 0x86DD:
        _decode_ipv6(rec, data)
    elif etype == 0x0806:
        _decode_arp(rec, data)


def decode_frame(n: int, ts: float, data: bytes, wirelen: int, linktype: int) -> PacketRecord:
    rec = PacketRecord(n=n, ts=ts, caplen=len(data), wirelen=wirelen)
    try:
        if linktype == LINKTYPE_ETHERNET:
            if len(data) < 14:
                rec.malformed = "truncated Ethernet header"
                return rec
            rec.eth_dst, rec.eth_src = _mac(data[0:6]), _mac(data[6:12])
            etype, off = struct.unpack_from("!H", data, 12)[0], 14
            for _ in range(2):  # 802.1Q / QinQ
                if etype in (0x8100, 0x88A8) and off + 4 <= len(data):
                    rec.vlan = struct.unpack_from("!H", data, off)[0] & 0x0FFF
                    etype = struct.unpack_from("!H", data, off + 2)[0]
                    off += 4
            _decode_ethertype(rec, etype, data[off:])
        elif linktype in (LINKTYPE_RAW, LINKTYPE_RAW_ALT, LINKTYPE_IPV4, LINKTYPE_IPV6):
            if data and data[0] >> 4 == 4:
                _decode_ipv4(rec, data)
            elif data and data[0] >> 4 == 6:
                _decode_ipv6(rec, data)
        elif linktype == LINKTYPE_NULL:
            if len(data) >= 4:
                family = struct.unpack_from("<I", data, 0)[0]
                if family > 0xFFFF:
                    family = struct.unpack_from(">I", data, 0)[0]
                if family == 2:
                    _decode_ipv4(rec, data[4:])
                elif family in (24, 28, 30):
                    _decode_ipv6(rec, data[4:])
        elif linktype == LINKTYPE_SLL:
            if len(data) >= 16:
                if struct.unpack_from("!H", data, 4)[0] == 1 and struct.unpack_from("!H", data, 10)[0] == 6:
                    rec.eth_src = _mac(data[6:12])
                _decode_ethertype(rec, struct.unpack_from("!H", data, 14)[0], data[16:])
        elif linktype == LINKTYPE_SLL2:
            if len(data) >= 20:
                if data[11] == 6:
                    rec.eth_src = _mac(data[12:18])
                _decode_ethertype(rec, struct.unpack_from("!H", data, 0)[0], data[20:])
    except Exception as exc:  # defensive: decoding must never abort the analysis
        rec.malformed = f"decoder error ({type(exc).__name__})"
    return rec


# --- container iteration ------------------------------------------------------------------

def read_capture(fileobj: IO[bytes], limits: Limits,
                 deadline: float | None = None) -> tuple[list[PacketRecord], ParseReport]:
    """Read and decode every frame of a capture, enforcing resource limits.

    The caller owns ``fileobj`` and is responsible for closing it; this function never opens
    files by name, so it cannot leave handles open on Windows. Container framing is handled
    by :mod:`pcapio`, which validates every length field before reading.
    """
    report = ParseReport()
    started = time.monotonic()
    fileobj.seek(0, 2)
    size = fileobj.tell()
    fileobj.seek(0)
    if size == 0:
        raise CaptureError("The uploaded file is empty.")
    report.file_format = sniff_format(fileobj.read(4))
    fileobj.seek(0)
    status = ContainerStatus()
    try:
        frames = iter_frames(fileobj, size, limits.max_record_bytes, status)
        first = next(frames, None)
    except ContainerError as exc:
        raise CaptureError(str(exc)) from None

    records: list[PacketRecord] = []
    n = 0
    frame = first
    while frame is not None:
        n += 1
        if n > limits.max_packets:
            report.stopped_early = (f"Packet limit reached: only the first {limits.max_packets:,} "
                                    "packets were analysed.")
            break
        if deadline is not None and n % 2000 == 0 and time.monotonic() > deadline:
            report.stopped_early = (f"Time limit reached while parsing: {n - 1:,} packets were "
                                    "analysed.")
            break
        if frame.linktype not in SUPPORTED_LINKTYPES:
            report.unsupported_link_packets += 1
        rec = decode_frame(n, frame.ts, frame.data, frame.wirelen or len(frame.data), frame.linktype)
        if rec.malformed:
            report.malformed_packets += 1
        records.append(rec)
        frame = next(frames, None)

    if status.corrupt and not report.stopped_early:
        report.truncated_file = True
        report.warnings.append(f"{status.corrupt} Analysis covers the {len(records):,} complete "
                               "packets before that point.")
    if status.oversized_records:
        report.warnings.append(f"{status.oversized_records} packet records were larger than "
                               f"{limits.max_record_bytes:,} bytes and were skipped as corrupt.")
    if not records and not report.truncated_file:
        report.warnings.append("The capture contains no packets.")

    report.packets_read = len(records)
    if report.unsupported_link_packets:
        report.warnings.append(f"{report.unsupported_link_packets} packets use a link type that "
                               "NetSentinel does not decode; they are counted but not analysed.")
    if report.malformed_packets:
        report.warnings.append(f"{report.malformed_packets} packets were malformed or truncated "
                               "and were only partially analysed.")
    report.parse_seconds = round(time.monotonic() - started, 3)
    return records, report
