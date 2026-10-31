"""Input-handling and API security tests.

These reproduce the problems found in the audit of the original prototype (4 GB allocation
from a 140-byte file, temp-file leaks on Windows, 500 errors on malformed input, unbounded
uploads, permissive CORS for other sites) and lock in the fixes.
"""
from __future__ import annotations

import glob
import io
import os
import random
import struct
import tempfile
import tracemalloc

import pytest
from fastapi.testclient import TestClient
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Dot1Q, Ether
from scapy.utils import PcapNgWriter, wrpcap

from app.analyzer import analyze_file
from app.capture import CaptureError, read_capture
from app.config import Limits
from app.main import app
from lab.packets import Timeline, office_background

client = TestClient(app)
PCAP_HEADER = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
MAC = dict(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")


def _valid_pcap_bytes(tmp_path) -> bytes:
    tl = Timeline()
    office_background(tl, duration=8)
    path = tmp_path / "valid.pcap"
    tl.write(str(path))
    return path.read_bytes()


def _analyze_bytes(data: bytes) -> dict:
    return analyze_file(io.BytesIO(data), "x.pcap")


# --- hostile length fields -----------------------------------------------------------------

@pytest.mark.parametrize("claimed", [0xFFFFFFF0, 0x7FFFFFFF, 10_000_000])
def test_huge_record_length_does_not_allocate(claimed):
    data = PCAP_HEADER + struct.pack("<IIII", 0, 0, claimed, claimed) + b"\x00" * 100
    tracemalloc.start()
    result = _analyze_bytes(data)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert peak < 50 * 1024 * 1024, f"peak memory {peak / 1e6:.0f} MB"
    assert result["parse"]["truncated_file"] is True
    assert result["packets_analyzed"] == 0


def test_pcapng_huge_block_length_does_not_allocate():
    shb = struct.pack("<IIIHHq", 0x0A0D0D0A, 28, 0x1A2B3C4D, 1, 0, -1) + struct.pack("<I", 28)
    evil = struct.pack("<II", 6, 0xFFFFFFF0) + b"\x00" * 64
    tracemalloc.start()
    result = _analyze_bytes(shb + evil)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert peak < 50 * 1024 * 1024
    assert result["parse"]["truncated_file"] is True


def test_oversized_record_is_skipped_not_loaded():
    limits = Limits(max_record_bytes=1000)
    frame = bytes(Ether(**MAC) / IP() / UDP() / (b"x" * 2000))
    small = bytes(Ether(**MAC) / IP() / UDP(sport=1, dport=2))
    data = PCAP_HEADER
    for f in (small, frame, small):
        data += struct.pack("<IIII", 1, 0, len(f), len(f)) + f
    records, report = read_capture(io.BytesIO(data), limits)
    assert len(records) == 2
    assert any("larger than" in w for w in report.warnings)


# --- malformed, truncated and unusual captures -----------------------------------------

def test_truncated_capture_reports_warning(tmp_path):
    data = _valid_pcap_bytes(tmp_path)
    cut = data[: len(data) // 2 + 7]
    result = _analyze_bytes(cut)
    assert result["parse"]["truncated_file"] is True
    assert result["packets_analyzed"] > 0
    assert any("cut off" in w or "truncated" in w for w in result["warnings"])


def test_header_only_capture():
    result = _analyze_bytes(PCAP_HEADER)
    assert result["packets_analyzed"] == 0
    assert "The capture contains no packets." in result["warnings"]
    assert result["verdict"]["status"] == "clean"


@pytest.mark.parametrize("payload", [b"hello, not a capture", b"\x89PNG\r\n\x1a\n" + b"\x00" * 40,
                                     b"PK\x03\x04" + b"\x00" * 40, b"\xd4\xc3"])
def test_non_capture_rejected(payload):
    with pytest.raises(CaptureError):
        _analyze_bytes(payload)


def test_fuzzed_captures_never_crash(tmp_path):
    """Random byte mutations of a valid capture must never raise anything but CaptureError."""
    original = _valid_pcap_bytes(tmp_path)
    rng = random.Random(1337)
    for _ in range(150):
        data = bytearray(original)
        for _ in range(rng.randint(1, 40)):
            data[rng.randrange(len(data))] = rng.randrange(256)
        if rng.random() < 0.3:
            data = data[: rng.randrange(24, len(data))]
        try:
            result = _analyze_bytes(bytes(data))
            assert isinstance(result["findings"], list)
        except CaptureError:
            pass


def test_pcapng_matches_pcap(tmp_path):
    tl = Timeline()
    office_background(tl, duration=10)
    pkts = tl.packets()
    wrpcap(str(tmp_path / "a.pcap"), pkts)
    writer = PcapNgWriter(str(tmp_path / "a.pcapng"))
    for p in pkts:
        writer.write(p)
    writer.close()
    with open(tmp_path / "a.pcap", "rb") as f1, open(tmp_path / "a.pcapng", "rb") as f2:
        a, _ = read_capture(f1, Limits())
        b, rb = read_capture(f2, Limits())
    assert rb.file_format == "pcapng"
    assert len(a) == len(b) == len(pkts)
    for x, y in zip(a, b):
        assert (x.ip_src, x.ip_dst, x.sport, x.dport, x.tcp_flags, x.seq) == \
               (y.ip_src, y.ip_dst, y.sport, y.dport, y.tcp_flags, y.seq)
        assert abs(x.ts - y.ts) < 1e-5


def test_vlan_ipv6_and_nanosecond(tmp_path):
    pkts = [Ether(**MAC) / Dot1Q(vlan=42) / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1, dport=80, flags="S"),
            Ether(**MAC) / IPv6(src="fe80::1", dst="fe80::2") / TCP(sport=2, dport=443, flags="S")]
    for p in pkts:
        p.time = 1_793_000_000.123456789
    wrpcap(str(tmp_path / "n.pcap"), pkts, nano=True)
    with open(tmp_path / "n.pcap", "rb") as f:
        recs, _ = read_capture(f, Limits())
    assert recs[0].vlan == 42 and recs[0].dport == 80 and recs[0].ip_src == "10.0.0.1"
    assert recs[1].l3 == "IPv6" and recs[1].ip_src == "fe80::1" and recs[1].dport == 443
    assert abs(recs[0].ts - 1_793_000_000.123456789) < 1e-6


def test_unsupported_linktype_is_counted_not_crashing():
    header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 147)
    frame = b"\x01" * 60
    data = header + struct.pack("<IIII", 0, 0, len(frame), len(frame)) + frame
    result = _analyze_bytes(data)
    assert result["packets_analyzed"] == 1
    assert any("link type" in w for w in result["warnings"])


def test_packet_limit_stops_early(tmp_path):
    data = _valid_pcap_bytes(tmp_path)
    records, report = read_capture(io.BytesIO(data), Limits(max_packets=20))
    assert len(records) == 20 and report.stopped_early


def test_no_payload_bytes_in_response(tmp_path):
    secret = b"password=hunter2-SECRET"
    pkt = Ether(**MAC) / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80, flags="PA") / secret
    wrpcap(str(tmp_path / "s.pcap"), [pkt] * 3)
    r = client.post("/api/analyze", files={"file": ("s.pcap", (tmp_path / "s.pcap").read_bytes())})
    assert r.status_code == 200
    assert b"hunter2" not in r.content


# --- API ------------------------------------------------------------------------------------

def _temp_snapshot():
    return set(glob.glob(os.path.join(tempfile.gettempdir(), "*")))


def test_api_rejects_bad_input_without_leaking_files():
    before = _temp_snapshot()
    cases = [("x.pcap", b"not a capture at all", 422), ("x.pcap", b"", 400), ("x.exe", b"abc", 400),
             ("x.pcap.exe", PCAP_HEADER, 400)]
    for name, data, status in cases:
        r = client.post("/api/analyze", files={"file": (name, data)})
        assert r.status_code == status, (name, r.status_code, r.text)
        detail = r.json()["detail"]
        assert "Traceback" not in detail and "\\" not in detail and "Scapy" not in detail
    leaked = [p for p in _temp_snapshot() - before if "netsentinel" in os.path.basename(p).lower()]
    assert not leaked


def test_api_upload_size_limit_rejects_before_reading():
    r = client.post("/api/analyze", content=b"x" * 10,
                    headers={"content-type": "multipart/form-data; boundary=x",
                             "content-length": str(500 * 1024 * 1024)})
    assert r.status_code == 413


def test_api_filename_is_sanitised(tmp_path):
    data = _valid_pcap_bytes(tmp_path)
    r = client.post("/api/analyze", files={"file": ("../../etc/<script>x" + "a" * 300 + ".pcap", data)})
    assert r.status_code == 200
    name = r.json()["file"]
    assert "/" not in name and "<" not in name and len(name) <= 120


def test_api_cors_only_local_origins(tmp_path):
    ok = client.get("/api/health", headers={"Origin": "http://127.0.0.1:5174"})
    assert ok.headers.get("access-control-allow-origin") == "http://127.0.0.1:5174"
    bad = client.get("/api/health", headers={"Origin": "http://evil.example"})
    assert "access-control-allow-origin" not in bad.headers
    assert ok.headers["x-content-type-options"] == "nosniff"


def test_api_sample_endpoint_rejects_unknown_and_traversal():
    assert client.post("/api/samples/..%2F..%2Fetc%2Fpasswd/analyze").status_code == 404
    assert client.post("/api/samples/not-a-sample/analyze").status_code == 404
