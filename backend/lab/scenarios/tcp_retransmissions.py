"""Ground-truth scenarios for TCP retransmissions and SYN retries."""
from __future__ import annotations

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from ..packets import (CLIENT, CLIENT2, CLIENT3, GATEWAY, SERVER, WEB, Host, Timeline,
                       office_background, tcp_session)
from . import Scenario

MSS = 1460


def seg(tl: Timeline, t: float, src: Host, dst: Host, sport: int, dport: int, seq: int, ack: int,
        flags: str, payload: int = 0, smac: str | None = None, dmac: str | None = None,
        ip_id: int = 1, df: bool = True) -> None:
    pkt = (Ether(src=smac or src.mac, dst=dmac or dst.mac) /
           IP(src=src.ip, dst=dst.ip, id=ip_id, flags="DF" if df else 0) /
           TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags, window=64240))
    if payload:
        pkt = pkt / Raw(b"d" * payload)
    tl.add(t, pkt)


def lossy_download(tl: Timeline, t: float, client: Host, server: Host, sport: int, dport: int,
                   segments: int, lost: set[int], mode: str = "fast", isn_c: int = 1000,
                   isn_s: int = 500_000, server_mac: str | None = None) -> float:
    """Server sends ``segments`` full-size segments; the ones in ``lost`` are dropped after the
    capture point and resent. ``mode`` "fast" = receiver sends 3+ duplicate ACKs and the server
    fast-retransmits; "timeout" = the server resends after an RTO of 0.3 s."""
    sm = server_mac or server.mac
    c_seq, s_seq = isn_c, isn_s
    seg(tl, t, client, server, sport, dport, c_seq, 0, "S", dmac=sm)
    seg(tl, t + 0.02, server, client, dport, sport, s_seq, c_seq + 1, "SA", smac=sm)
    c_seq += 1
    s_seq += 1
    seg(tl, t + 0.03, client, server, sport, dport, c_seq, s_seq, "A", dmac=sm)
    seg(tl, t + 0.031, client, server, sport, dport, c_seq, s_seq, "PA", 300, dmac=sm)
    c_seq += 300
    now = t + 0.06
    ip_id = 100
    highest_acked = s_seq
    pending_loss = None
    dupacks = 0
    for i in range(segments):
        start = s_seq + i * MSS
        ip_id += 1
        seg(tl, now, server, client, dport, sport, start, c_seq, "A", MSS, smac=sm, ip_id=ip_id)
        if i in lost:
            pending_loss = start
            if mode == "timeout":
                # Tail-style loss: the receiver has nothing else to acknowledge; RTO fires.
                ip_id += 1
                seg(tl, now + 0.3, server, client, dport, sport, start, c_seq, "A", MSS, smac=sm, ip_id=ip_id)
                highest_acked = start + MSS
                seg(tl, now + 0.32, client, server, sport, dport, c_seq, highest_acked, "A", dmac=sm)
                pending_loss = None
                now += 0.33
                continue
            dupacks = 0
        elif pending_loss is not None:
            # Every segment after the hole produces a duplicate ACK for the missing data; the
            # third one triggers a fast retransmit, after which everything is acknowledged.
            seg(tl, now + 0.01, client, server, sport, dport, c_seq, pending_loss, "A", dmac=sm)
            dupacks += 1
            if dupacks == 3:
                ip_id += 1
                seg(tl, now + 0.012, server, client, dport, sport, pending_loss, c_seq, "A", MSS,
                    smac=sm, ip_id=ip_id)
                highest_acked = start + MSS
                seg(tl, now + 0.022, client, server, sport, dport, c_seq, highest_acked, "A", dmac=sm)
                pending_loss = None
        else:
            if i % 2 == 1:
                highest_acked = start + MSS
                seg(tl, now + 0.01, client, server, sport, dport, c_seq, highest_acked, "A", dmac=sm)
        now += 0.002
    end_seq = s_seq + segments * MSS
    seg(tl, now + 0.02, client, server, sport, dport, c_seq, end_seq, "A", dmac=sm)
    seg(tl, now + 0.05, client, server, sport, dport, c_seq, end_seq, "FA", dmac=sm)
    seg(tl, now + 0.06, server, client, dport, sport, end_seq, c_seq + 1, "FA", smac=sm)
    seg(tl, now + 0.07, client, server, sport, dport, c_seq + 1, end_seq + 1, "A", dmac=sm)
    return now + 0.07


def _lossy_internet_path() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=45)
    # Three downloads from the same internet server lose ~5% of segments (fast retransmits).
    for k, c in enumerate((CLIENT, CLIENT2, CLIENT3)):
        lossy_download(tl, 5 + k * 8, c, WEB, 45000 + k, 443, segments=100,
                       lost={10, 31, 52, 70, 88}, isn_c=11_000 * (k + 1), isn_s=2_000_000 * (k + 1),
                       server_mac=GATEWAY.mac)
    return tl


def _timeout_losses() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=30)
    lossy_download(tl, 4, CLIENT2, SERVER, 46000, 445, segments=60, lost={9, 19, 29, 39, 49},
                   mode="timeout", isn_s=7_000_000)
    return tl


def _single_loss() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=30)
    lossy_download(tl, 4, CLIENT, WEB, 47000, 443, segments=400, lost={150},
                   isn_s=9_000_000, server_mac=GATEWAY.mac)
    return tl


def _bulk_delayed_acks() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=30)
    # 2 MB download with delayed ACKs: hundreds of pure ACKs repeat the client's sequence number.
    tcp_session(tl, 3, CLIENT, SERVER, 48000, 445, exchanges=[(500, 2_000_000)], rtt=0.002,
                isn_c=123, isn_s=456_000)
    return tl


def _keepalives() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=90)
    # An idle SSH session kept alive every 10 s (1-byte keepalive at seq-1, answered by an ACK).
    c_seq, s_seq = 5_001, 80_001
    seg(tl, 1, CLIENT3, SERVER, 49000, 22, c_seq - 1, 0, "S")
    seg(tl, 1.001, SERVER, CLIENT3, 22, 49000, s_seq - 1, c_seq, "SA")
    seg(tl, 1.002, CLIENT3, SERVER, 49000, 22, c_seq, s_seq, "A")
    seg(tl, 1.01, CLIENT3, SERVER, 49000, 22, c_seq, s_seq, "PA", 40)
    seg(tl, 1.02, SERVER, CLIENT3, 22, 49000, s_seq, c_seq + 40, "PA", 60)
    c_seq, s_seq = c_seq + 40, s_seq + 60
    seg(tl, 1.03, CLIENT3, SERVER, 49000, 22, c_seq, s_seq, "A")
    for k in range(8):
        t = 11 + 10 * k
        seg(tl, t, CLIENT3, SERVER, 49000, 22, c_seq - 1, s_seq, "A", 1)
        seg(tl, t + 0.001, SERVER, CLIENT3, 22, 49000, s_seq, c_seq, "A")
    return tl


def _capture_duplicates() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=20)
    # Captured on a SPAN port that mirrors both directions twice: every frame appears twice
    # 40 microseconds apart with the same IP ID. This is a capture artefact, not loss.
    inner = Timeline()
    lossy_download(inner, 3, CLIENT, SERVER, 50500, 8080, segments=80, lost=set(), isn_s=3_300_000)
    for i, (t, _, pkt) in enumerate(sorted(inner.items, key=lambda x: (x[0], x[1]))):
        pkt[IP].id = 2000 + i
        tl.add(t, pkt)
        tl.add(t + 0.00004, pkt.copy())
    return tl


def _syn_retries() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=40)
    # The backup server's port 873 silently drops SYNs (firewall DROP rule): clients retry with
    # the same initial sequence number at 1 s, 3 s and 7 s and never get an answer.
    for k, c in enumerate((CLIENT, CLIENT2, CLIENT3, CLIENT)):
        isn = 70_000 + k * 1000
        base = 4 + k * 6
        for delay in (0, 1, 3, 7):
            seg(tl, base + delay, c, SERVER, 51500 + k, 873, isn, 0, "S")
    return tl


def _syn_retry_then_ok() -> Timeline:
    tl = Timeline()
    office_background(tl, duration=30)
    # One lost SYN, retried once and answered: normal, below the reporting threshold.
    seg(tl, 5, CLIENT, SERVER, 52000, 443, 9_999, 0, "S")
    tcp_session(tl, 6, CLIENT, SERVER, 52000, 443, isn_c=9_999, isn_s=31_000)
    return tl


RETX_KINDS = {"TCP_RETRANSMISSIONS"}

SCENARIOS = [
    Scenario("retx_lossy_internet_path", "Downloads from one internet server lose about 5% of packets",
             _lossy_internet_path, expect=RETX_KINDS, forbid={"MTU_BLACKHOLE_SUSPECTED"},
             expect_assessment={"TCP_RETRANSMISSIONS": "fault"}, forbid_attacks=True,
             sample="fault_packet_loss.pcap"),
    Scenario("retx_timeout_losses", "File-server download recovering from losses by timeout",
             _timeout_losses, expect=RETX_KINDS, forbid_attacks=True),
    Scenario("retx_neg_single_loss", "One lost segment in a long download (normal, below threshold)",
             _single_loss, forbid=RETX_KINDS, forbid_attacks=True),
    Scenario("retx_neg_delayed_acks", "Bulk download with delayed ACKs (fooled the original prototype)",
             _bulk_delayed_acks, forbid=RETX_KINDS, forbid_attacks=True),
    Scenario("retx_neg_keepalives", "Idle SSH session with TCP keep-alives",
             _keepalives, forbid=RETX_KINDS, forbid_attacks=True),
    Scenario("retx_neg_capture_duplicates", "Every frame captured twice by a SPAN port (artefact, not loss)",
             _capture_duplicates, forbid=RETX_KINDS, forbid_attacks=True),
    Scenario("retx_syn_retries", "A firewall silently drops connections to the backup service",
             _syn_retries, expect={"TCP_SYN_RETRIES"}, forbid={"PORT_SCAN"},
             expect_assessment={"TCP_SYN_RETRIES": "fault"}, forbid_attacks=True),
    Scenario("retx_neg_syn_retry_once", "One SYN retried once and then answered (normal)",
             _syn_retry_then_ok, forbid={"TCP_SYN_RETRIES"}, forbid_attacks=True),
]
