"""Tests for NetSentinel's own protocol decoders (capture.py)."""
from __future__ import annotations

import random
import struct

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP, IPerror, UDPerror
from scapy.layers.l2 import ARP, Ether

from app.capture import decode_dns, decode_frame

MAC = dict(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")


def test_dns_decoder_matches_scapy_built_messages():
    msg = DNS(id=4242, qr=1, rd=1, ra=1, rcode=0, qd=DNSQR(qname="www.example.com", qtype="A"),
              an=[DNSRR(rrname="www.example.com", type="CNAME", rdata="edge.cdn.example.net", ttl=60),
                  DNSRR(rrname="edge.cdn.example.net", type="A", rdata="93.184.216.34", ttl=30),
                  DNSRR(rrname="edge.cdn.example.net", type="AAAA", rdata="2606:2800:220:1::1", ttl=30)])
    d = decode_dns(bytes(msg))
    assert d["id"] == 4242 and d["qr"] == 1 and d["rcode"] == 0
    assert d["qname"] == "www.example.com" and d["qtype"] == "A"
    assert [(a["type"], a["value"]) for a in d["answers"]] == [
        ("CNAME", "edge.cdn.example.net"), ("A", "93.184.216.34"), ("AAAA", "2606:2800:220:1::1")]
    assert d["answers"][1]["ttl"] == 30


def test_dns_query_and_nxdomain():
    q = decode_dns(bytes(DNS(id=7, rd=1, qd=DNSQR(qname="Missing.Example.org", qtype="AAAA"))))
    assert q["qr"] == 0 and q["qname"] == "missing.example.org" and q["qtype"] == "AAAA" and q["answers"] == []
    nx = decode_dns(bytes(DNS(id=7, qr=1, rcode=3, qd=DNSQR(qname="missing.example.org"))))
    assert nx["rcode"] == 3


def _header(qd=1, an=0):
    return struct.pack("!HHHHHH", 1, 0x8180, qd, an, 0, 0)


def test_dns_pointer_loop_is_rejected_quickly():
    # The question name is a pointer to itself: a naive decoder loops forever.
    assert decode_dns(_header() + b"\xc0\x0c" + b"\x00\x01\x00\x01") is None
    # Two pointers referencing each other.
    looped = _header() + b"\x01a\xc0\x0e" + b"\x00\x01\x00\x01"
    assert decode_dns(looped) is None


def test_dns_overlong_and_truncated_names_rejected():
    long_name = b"".join(bytes([63]) + b"a" * 63 for _ in range(5)) + b"\x00"
    assert decode_dns(_header() + long_name + b"\x00\x01\x00\x01") is None
    assert decode_dns(_header() + b"\x05abc") is None
    assert decode_dns(b"\x00" * 5) is None


def test_dns_decoder_random_garbage_never_raises():
    rng = random.Random(7)
    base = bytes(DNS(id=1, qr=1, qd=DNSQR(qname="a.example.com"),
                     an=[DNSRR(rrname="a.example.com", rdata="1.2.3.4")]))
    for _ in range(2000):
        data = bytearray(base)
        for _ in range(rng.randint(1, 8)):
            data[rng.randrange(len(data))] = rng.randrange(256)
        result = decode_dns(bytes(data))
        assert result is None or isinstance(result["answers"], list)


def test_names_are_sanitised():
    msg = _header() + b"\x08ev\x01l\x1b[0m" + b"\x00" + b"\x00\x01\x00\x01"
    d = decode_dns(msg)
    assert d is not None and "\x1b" not in d["qname"] and "\x01" not in d["qname"]


def test_tcp_payload_length_uses_ip_length_even_when_snapped():
    pkt = bytes(Ether(**MAC) / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1, dport=2, flags="PA") / (b"x" * 1000))
    rec = decode_frame(1, 0.0, pkt[:96], len(pkt), 1)     # snaplen 96
    assert rec.l4 == "TCP" and rec.payload_len == 1000


def test_icmp_error_quotes_are_not_treated_as_traffic():
    pkt = bytes(Ether(**MAC) / IP(src="10.0.0.254", dst="10.0.0.2") / ICMP(type=3, code=3) /
                IPerror(src="10.0.0.2", dst="10.0.0.9", proto=17) / UDPerror(sport=5353, dport=53))
    rec = decode_frame(1, 0.0, pkt, len(pkt), 1)
    assert rec.l4 == "ICMP" and rec.dns is None and rec.sport is None
    assert rec.icmp_inner["dst"] == "10.0.0.9" and rec.icmp_inner["dport"] == 53


def test_arp_and_mss_and_df():
    arp = bytes(Ether(src="02:00:00:00:00:66", dst="ff:ff:ff:ff:ff:ff") /
                ARP(op=2, hwsrc="02:00:00:00:00:66", psrc="192.168.1.1", hwdst="ff:ff:ff:ff:ff:ff", pdst="192.168.1.1"))
    rec = decode_frame(1, 0.0, arp, len(arp), 1)
    assert rec.arp_op == 2 and rec.arp_psrc == "192.168.1.1" and rec.arp_hwsrc == "02:00:00:00:00:66"
    syn = bytes(Ether(**MAC) / IP(flags="DF") / TCP(flags="S", options=[("MSS", 1360)]))
    rec = decode_frame(2, 0.0, syn, len(syn), 1)
    assert rec.mss == 1360 and rec.df is True


def test_truncated_headers_marked_malformed():
    pkt = bytes(Ether(**MAC) / IP() / TCP())
    for cut in (10, 20, 30, 40):
        rec = decode_frame(1, 0.0, pkt[:cut], len(pkt), 1)
        assert rec.malformed or rec.l4 is None


def test_dns_decoding_through_udp():
    pkt = bytes(Ether(**MAC) / IP(src="192.168.1.1", dst="192.168.1.10") / UDP(sport=53, dport=5000) /
                DNS(id=9, qr=1, qd=DNSQR(qname="intranet.local"), an=[DNSRR(rrname="intranet.local", rdata="192.168.1.20")]))
    rec = decode_frame(1, 0.0, pkt, len(pkt), 1)
    assert rec.app == "DNS" and rec.dns["answers"][0]["value"] == "192.168.1.20"
