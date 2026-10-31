"""End-to-end regression: a plain 20-port SYN scan must be reported as PORT_SCAN."""
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

from app.analyzer import analyze_pcap

SCANNER_MAC, TARGET_MAC = "02:00:00:00:0a:05", "02:00:00:00:0a:0a"


def test_detects_port_scan(tmp_path):
    packets = []
    for i, port in enumerate(range(20, 40)):
        syn = (Ether(src=SCANNER_MAC, dst=TARGET_MAC) / IP(src="10.0.0.5", dst="10.0.0.10") /
               TCP(sport=40000 + i, dport=port, flags="S"))
        syn.time = 1_700_000_000 + i * 0.01
        packets.append(syn)
    path = tmp_path / "scan.pcap"
    wrpcap(str(path), packets)
    result = analyze_pcap(path)
    scans = [f for f in result["findings"] if f["kind"] == "PORT_SCAN"]
    assert len(scans) == 1
    assert scans[0]["hosts"]["scanner"] == ["10.0.0.5"]
    assert scans[0]["metrics"]["distinct_ports"] == 20
    assert scans[0]["assessment"] == "attack"
