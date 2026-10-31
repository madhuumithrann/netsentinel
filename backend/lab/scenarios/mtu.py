"""Ground-truth scenarios for MTU problems (ICMP-reported and silent black holes)."""
from __future__ import annotations

from ..packets import CLIENT, CLIENT2, GATEWAY, WEB, Timeline, icmp_frag_needed, office_background
from .tcp_retransmissions import lossy_download, seg
from . import Scenario

MTU_KINDS = {"MTU_ICMP_FRAG_NEEDED", "MTU_BLACKHOLE_SUSPECTED"}


def _upload_handshake(tl, t, client, sport, isn_c, isn_s, mss=1460):
    gm = GATEWAY.mac
    seg(tl, t, client, WEB, sport, 443, isn_c, 0, "S", dmac=gm)
    seg(tl, t + 0.03, WEB, client, 443, sport, isn_s, isn_c + 1, "SA", smac=gm)
    seg(tl, t + 0.06, client, WEB, sport, 443, isn_c + 1, isn_s + 1, "A", dmac=gm)
    # A small request that is acknowledged normally: the path works for small packets.
    seg(tl, t + 0.07, client, WEB, sport, 443, isn_c + 1, isn_s + 1, "PA", 200, dmac=gm)
    seg(tl, t + 0.10, WEB, client, 443, sport, isn_s + 1, isn_c + 201, "PA", 300, smac=gm)
    seg(tl, t + 0.11, client, WEB, sport, 443, isn_c + 201, isn_s + 301, "A", dmac=gm)
    return isn_c + 201, isn_s + 301


def _icmp_frag_needed() -> Timeline:
    """A VPN link with MTU 1400: the router reports it and the client adapts (PMTUD works)."""
    tl = Timeline()
    office_background(tl, duration=30)
    gm = GATEWAY.mac
    for k, c in enumerate((CLIENT, CLIENT2)):
        t = 5 + k * 6
        sport = 41000 + k
        c_seq, s_seq = _upload_handshake(tl, t, c, sport, 100_000 * (k + 1), 900_000 * (k + 1))
        # 1460-byte segment (1500-byte packet) with DF: dropped by the router, which says why.
        seg(tl, t + 0.2, c, WEB, sport, 443, c_seq, s_seq, "PA", 1460, dmac=gm, ip_id=500 + k)
        icmp_frag_needed(tl, t + 0.21, GATEWAY, c, c.ip, WEB.ip, sport, 443, mtu=1400, seq=c_seq)
        # PMTUD: the client resends in 1360-byte segments, which are acknowledged.
        seg(tl, t + 0.22, c, WEB, sport, 443, c_seq, s_seq, "A", 1360, dmac=gm, ip_id=501 + k)
        seg(tl, t + 0.221, c, WEB, sport, 443, c_seq + 1360, s_seq, "PA", 100, dmac=gm, ip_id=502 + k)
        seg(tl, t + 0.26, WEB, c, 443, sport, s_seq, c_seq + 1460, "A", smac=gm)
    return tl


def _blackhole() -> Timeline:
    """PPPoE/VPN path that drops large packets while ICMP is filtered: uploads stall."""
    tl = Timeline()
    office_background(tl, duration=40)
    gm = GATEWAY.mac
    c = CLIENT
    sport = 42000
    c_seq, s_seq = _upload_handshake(tl, 5, c, sport, 300_000, 800_000)
    # The full-size segment vanishes; the server still answers (duplicate ACKs prove it is alive).
    t = 5.3
    for i, backoff in enumerate((0, 0.3, 0.9, 2.1, 4.5)):
        seg(tl, t + backoff, c, WEB, sport, 443, c_seq, s_seq, "PA", 1460, dmac=gm, ip_id=700 + i)
        seg(tl, t + backoff + 0.03, WEB, c, 443, sport, s_seq, c_seq, "A", smac=gm)
    # The client's black-hole detection finally resends the same data in smaller pieces: it works.
    t2 = t + 9.5
    seg(tl, t2, c, WEB, sport, 443, c_seq, s_seq, "A", 700, dmac=gm, ip_id=720)
    seg(tl, t2 + 0.001, c, WEB, sport, 443, c_seq + 700, s_seq, "PA", 760, dmac=gm, ip_id=721)
    seg(tl, t2 + 0.03, WEB, c, 443, sport, s_seq, c_seq + 1460, "A", smac=gm)
    return tl


def _ordinary_loss_is_not_mtu() -> Timeline:
    """Random loss of full-size segments that are later delivered at full size: not an MTU issue."""
    tl = Timeline()
    office_background(tl, duration=30)
    lossy_download(tl, 4, CLIENT2, WEB, 43000, 443, segments=80, lost={7, 33, 61},
                   isn_s=5_500_000, server_mac=GATEWAY.mac)
    return tl


SCENARIOS = [
    Scenario("mtu_icmp_frag_needed", "Router reports a 1400-byte path MTU (VPN link); clients adapt",
             _icmp_frag_needed, expect={"MTU_ICMP_FRAG_NEEDED"}, forbid={"MTU_BLACKHOLE_SUSPECTED"},
             expect_assessment={"MTU_ICMP_FRAG_NEEDED": "fault"}, forbid_attacks=True),
    Scenario("mtu_blackhole", "Large packets silently dropped (ICMP filtered): uploads stall",
             _blackhole, expect={"MTU_BLACKHOLE_SUSPECTED"}, forbid={"MTU_ICMP_FRAG_NEEDED"},
             expect_assessment={"MTU_BLACKHOLE_SUSPECTED": "fault"}, forbid_attacks=True,
             sample="fault_mtu_blackhole.pcap"),
    Scenario("mtu_neg_ordinary_loss", "Ordinary packet loss of full-size segments (not an MTU problem)",
             _ordinary_loss_is_not_mtu, forbid=MTU_KINDS, forbid_attacks=True),
]
