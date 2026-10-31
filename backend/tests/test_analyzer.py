from scapy.all import Ether, IP, TCP, wrpcap
from app.analyzer import analyze_pcap


def test_detects_port_scan(tmp_path):
    packets = [Ether()/IP(src="10.0.0.5", dst="10.0.0.10")/TCP(sport=40000+i, dport=port, flags="S") for i, port in enumerate(range(20, 40))]
    path = tmp_path / "scan.pcap"
    wrpcap(str(path), packets)
    result = analyze_pcap(path)
    assert any(item["type"] == "PORT_SCAN" for item in result["incidents"])
