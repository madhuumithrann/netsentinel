"""Bounded pcap / pcapng container reader.

Why not Scapy's reader: it trusts the length fields in record headers. A ~140-byte file
whose record claims a 4 GB length makes it allocate 4 GB (verified during the audit). This
reader checks every length against both the remaining file size and a per-record limit
*before* reading, and skips (seeks over) non-packet blocks instead of loading them.

Yields ``RawFrame`` objects; never raises on corrupt input after the file header - it stops
and reports why through ``ContainerStatus``.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import IO, Iterator


class ContainerError(ValueError):
    """The file header itself is invalid. Message is safe to show to users."""


@dataclass
class RawFrame:
    data: bytes
    ts: float
    wirelen: int
    caplen_declared: int
    linktype: int


@dataclass
class ContainerStatus:
    file_format: str = "unknown"
    corrupt: str | None = None          # why reading stopped early, if it did
    oversized_records: int = 0
    skipped_blocks: int = 0
    notes: list[str] = field(default_factory=list)


PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 1e6), b"\xa1\xb2\xc3\xd4": (">", 1e6),
    b"\x4d\x3c\xb2\xa1": ("<", 1e9), b"\xa1\xb2\x3c\x4d": (">", 1e9),
}
PCAPNG_SHB = 0x0A0D0D0A
BYTE_ORDER_MAGIC = 0x1A2B3C4D


def _read_exact(f: IO[bytes], n: int) -> bytes | None:
    data = f.read(n)
    return data if len(data) == n else None


def iter_pcap(f: IO[bytes], size: int, max_record: int, status: ContainerStatus) -> Iterator[RawFrame]:
    header = _read_exact(f, 24)
    if header is None or header[:4] not in PCAP_MAGIC:
        raise ContainerError("The pcap file header is invalid or incomplete.")
    endian, resolution = PCAP_MAGIC[header[:4]]
    status.file_format = "pcap"
    _vmaj, _vmin, _zone, _sig, snaplen, network = struct.unpack(endian + "HHiIII", header[4:24])
    linktype = network & 0x0FFFFFFF
    pos = 24
    while True:
        rec = f.read(16)
        if not rec:
            return
        if len(rec) < 16:
            status.corrupt = "The capture ends with an incomplete packet record (the file was probably cut off)."
            return
        sec, frac, incl, orig = struct.unpack(endian + "IIII", rec)
        pos += 16
        remaining = size - pos
        if incl > remaining:
            status.corrupt = ("A packet record claims more data than the file contains "
                              "(the file is truncated or corrupt).")
            return
        if incl > max_record:
            # Skip without reading it into memory.
            f.seek(incl, 1)
            pos += incl
            status.oversized_records += 1
            continue
        data = f.read(incl)
        pos += incl
        yield RawFrame(data, sec + frac / resolution, orig, incl, linktype)


def _tsresol(options: bytes, endian: str) -> float:
    i = 0
    while i + 4 <= len(options):
        code, length = struct.unpack_from(endian + "HH", options, i)
        if code == 0:
            break
        value = options[i + 4:i + 4 + length]
        if code == 9 and length >= 1:
            v = value[0]
            return float(2 ** (v & 0x7F)) if v & 0x80 else float(10 ** min(v, 18))
        i += 4 + length + ((4 - length % 4) % 4)
    return 1e6


def iter_pcapng(f: IO[bytes], size: int, max_record: int, status: ContainerStatus) -> Iterator[RawFrame]:
    status.file_format = "pcapng"
    endian = "<"
    interfaces: list[tuple[int, float]] = []   # (linktype, ticks per second)
    pos = 0
    first = True
    max_block = max_record + 64 * 1024
    while True:
        head = f.read(8)
        if not head:
            return
        if len(head) < 8:
            status.corrupt = "The capture ends with an incomplete block (the file was probably cut off)."
            return
        btype_le = struct.unpack("<I", head[:4])[0]
        if btype_le == PCAPNG_SHB:
            bom = _read_exact(f, 4)
            if bom is None:
                status.corrupt = "Incomplete section header block."
                return
            if struct.unpack("<I", bom)[0] == BYTE_ORDER_MAGIC:
                endian = "<"
            elif struct.unpack(">I", bom)[0] == BYTE_ORDER_MAGIC:
                endian = ">"
            else:
                if first:
                    raise ContainerError("The pcapng section header is invalid.")
                status.corrupt = "Invalid section header inside the capture."
                return
            f.seek(-4, 1)
            interfaces = []   # interface ids are per section
        elif first:
            raise ContainerError("The pcapng file does not start with a section header block.")
        first = False
        btype, blen = struct.unpack(endian + "II", head)
        remaining = size - pos
        if blen < 12 or blen % 4 or blen > remaining:
            status.corrupt = "A pcapng block has an invalid length (the file is truncated or corrupt)."
            return
        body_len = blen - 12
        if btype in (6, 3, 2, 1, PCAPNG_SHB) and blen <= max_block:
            body = _read_exact(f, body_len)
            trailer = _read_exact(f, 4)
            if body is None or trailer is None:
                status.corrupt = "A pcapng block is incomplete."
                return
            pos += blen
        else:
            # Unknown, statistics, name-resolution or oversized blocks: skip without reading.
            f.seek(body_len + 4, 1)
            pos += blen
            if btype in (6, 3, 2):
                status.oversized_records += 1
            else:
                status.skipped_blocks += 1
            continue
        if btype == 1:                                    # Interface Description Block
            if len(body) < 8:
                status.corrupt = "Invalid interface description block."
                return
            linktype = struct.unpack_from(endian + "H", body, 0)[0]
            interfaces.append((linktype, _tsresol(body[8:], endian)))
        elif btype == 6:                                  # Enhanced Packet Block
            if len(body) < 20:
                status.corrupt = "Invalid packet block."
                return
            iface, high, low, caplen, orig = struct.unpack_from(endian + "IIIII", body, 0)
            if iface >= len(interfaces) or caplen > len(body) - 20:
                status.corrupt = "A packet block references an unknown interface or invalid length."
                return
            linktype, resol = interfaces[iface]
            if caplen > max_record:
                status.oversized_records += 1
                continue
            yield RawFrame(body[20:20 + caplen], ((high << 32) | low) / resol, orig, caplen, linktype)
        elif btype == 3:                                  # Simple Packet Block
            if not interfaces or len(body) < 4:
                status.corrupt = "Invalid simple packet block."
                return
            orig = struct.unpack_from(endian + "I", body, 0)[0]
            caplen = min(orig, len(body) - 4)
            linktype, _ = interfaces[0]
            yield RawFrame(body[4:4 + caplen], 0.0, orig, caplen, linktype)
        elif btype == 2:                                  # obsolete Packet Block
            if len(body) < 20:
                status.corrupt = "Invalid packet block."
                return
            iface, _drops, high, low, caplen, orig = struct.unpack_from(endian + "HHIIII", body, 0)
            if iface >= len(interfaces) or caplen > len(body) - 20:
                status.corrupt = "A packet block references an unknown interface or invalid length."
                return
            linktype, resol = interfaces[iface]
            yield RawFrame(body[20:20 + caplen], ((high << 32) | low) / resol, orig, caplen, linktype)


def iter_frames(f: IO[bytes], size: int, max_record: int, status: ContainerStatus) -> Iterator[RawFrame]:
    magic = f.read(4)
    f.seek(0)
    if magic in PCAP_MAGIC:
        return iter_pcap(f, size, max_record, status)
    if len(magic) == 4 and struct.unpack("<I", magic)[0] == PCAPNG_SHB:
        return iter_pcapng(f, size, max_record, status)
    raise ContainerError("The file is not a pcap or pcapng capture (unrecognised file signature).")
