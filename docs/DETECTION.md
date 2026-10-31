# Detection methodology

Every detector is our own code in `backend/app/detectors/`. The module docstring at the top of
each file holds the full algorithm, its thresholds and its limitations. This page summarises
them. Thresholds are listed in `backend/app/config.py` or as documented constants in each
module.

## How a finding is judged

Detectors do not report a bare "score". Each finding carries **indicators**. An indicator is a
sentence describing one piece of evidence, the direction it points (fault, attack or benign)
and its strength (strong, moderate or weak). `model.assess()` turns the indicators into an
assessment with one published rule:

- One **strong** indicator, or **two moderate** ones, decides a direction.
- If attack and fault are both decisive, "attack" wins only when its support is strictly
  stronger. Otherwise the result is **inconclusive**.
- Weak indicators alone can never produce an attack verdict.

Every finding also lists the **facts** observed (with numbers), **alternative explanations**,
**limitations**, the **rule** that fired and the **evidence packets**, each with the reason it
counts as evidence.

## Fault detectors

| Official challenge point | Finding kinds | What the rule looks at | False-positive controls |
|---|---|---|---|
| TCP retransmissions | `TCP_RETRANSMISSIONS`, `TCP_SYN_RETRIES` | Per connection and direction, it tracks the highest sequence number sent, using 32-bit serial arithmetic. Only segments that occupy sequence space can be retransmitted. Each resend is classified as fast retransmit (3+ duplicate ACKs first), timeout (RTO), spurious (data already ACKed) or "original not captured" (loss before the capture point). | Pure ACKs, keep-alives, zero-window probes, capture duplicates (same IP ID within 0.5 ms), short reordering, and PMTUD or black-hole resends (reported by the MTU detector). A flow must reach 3 retransmissions **and** 2% of its segments. A scanner's single probe per port is never treated as a SYN retry. |
| TCP resets | `TCP_CONNECTION_REFUSED`, `TCP_CONNECTION_RESET` | Each RST is classified within its connection: *refused* (RST answering a SYN), *aborted* (RST on an established connection before FIN) or *closing* (RST after FIN, or a client abort after a completed exchange, which browsers do deliberately). | Closing resets are never reported. Refusals need 3 or more attempts to the **same** service, so a port scan (one probe per port) is not mistaken for an outage. A reset whose TTL differs by 5 or more from that endpoint's other packets is flagged as possibly injected. |
| DNS failures | `DNS_SERVER_UNRESPONSIVE`, `DNS_SERVER_FAILURE`, `DNS_NXDOMAIN` | Queries are matched to responses by client, port, server and transaction ID. Timeouts and SERVFAIL/REFUSED answers are attributed to the **server**, and NXDOMAIN to the **client** that asked. The original prototype blamed the resolver for clients' NXDOMAIN answers. | Queries in the last 2 s of the capture are not counted as timeouts. ICMP errors that quote DNS are never decoded as DNS. mDNS and LLMNR are excluded. NXDOMAIN is never treated as hijacking. |
| Duplicate IPs, ARP conflicts | `DUPLICATE_IP`, `ARP_CONFLICT`, `ARP_MAPPING_CHANGED` (benign) | Per (VLAN, IP) claim timelines are built from ARP. The detector checks for two MACs that both answer *solicited* requests, RFC 5227 probes answered by a defender, gratuitous ARP from both devices, and both MACs sending normal IP traffic. | A single clean hand-over (old MAC goes silent, new MAC appears, no reversion) is reported as *expected behaviour*: device replacement or failover. VRRP/HSRP virtual MACs are recognised. |
| MTU mismatches | `MTU_ICMP_FRAG_NEEDED`, `MTU_BLACKHOLE_SUSPECTED` | ICMP "fragmentation needed" or ICMPv6 "packet too big" messages are grouped per router, with the next-hop MTU and the affected flows, and a check of whether PMTUD took effect. Black hole: large DF segments are resent 3 or more times and never ACKed, while small segments are ACKed and the receiver is still alive. | Large segments eventually ACKed at full size are ordinary loss, not MTU. Forged "too big" messages are flagged: MTU values below any real link, or a quoted sequence number the flow never sent. |
| Unusual delays | `SLOW_TCP_HANDSHAKE`, `SLOW_SERVER_RESPONSE`, `DNS_SLOW_RESPONSES`, `CAPTURE_GAP` | The handshake time is split into the server leg and the client leg around the capture point. The scope is decided as one server, the whole path, internet-only, or one client's link. **Network or application?** A slow first response after a fast handshake means the server application is slow, not the network. | Connections with SYN retransmissions are skipped (that is loss, not delay). Idle keep-alive connections and server pushes are not "slow responses". A single slow connection is not reported. |

## Attack detectors

| Official challenge point | Finding kinds | Indicators that make it an attack | What keeps false alarms low |
|---|---|---|---|
| Port scans | `PORT_SCAN`, `HOST_SWEEP` | Distinct ports on one host (vertical) or one port on many hosts (horizontal) inside a 60 s window, a slow scan over the whole capture, and FIN/NULL/XMAS probes (no legitimate use). UDP probes are recognised from ICMP port-unreachable replies. The finding reports the **true scope** and the **open ports discovered**. | The key control is the **failure ratio**: at least 60% of probes must never become a data-carrying session. A client that really *uses* 20 services, FTP passive data connections, and a browser opening many connections to one server are not scans. |
| ARP spoofing | `ARP_SPOOFING` | Unsolicited replies, periodic re-poisoning, flip-flopping ownership, impersonation of the gateway or DNS server, one MAC claiming several IPs, Ethernet source differing from the ARP sender, and **traffic redirection and relaying**. The detector sees the same IP packet (same ID) arrive at the attacker's MAC and leave it again with TTL−1. | Requires the documented indicator combination (`assess()`). Device replacement and failover are separated as benign, and two hosts sharing an IP as a fault. |
| DNS hijacking | `DNS_HIJACK_SUSPECTED`, `DNS_DGA_PATTERN` | Two different answers to the same query (an on-path injector racing the real server), a response whose IP TTL differs from that server's other responses, unsolicited responses, answers from a server the client did not query, and a resolver not handed out by DHCP. | A public name resolving to a private IP is only a **weak** indicator (split-horizon DNS is legitimate). CDN answers that change over time are not conflicts. |
| Rogue DHCP servers | `ROGUE_DHCP_SERVER`, `MULTIPLE_DHCP_SERVERS` (not an attack) | Server identity comes from option 54 plus the MAC. The offered router and DNS are compared between servers. Also checked: a server offering itself as the gateway, one server identifier sent from two MACs (spoofing the legitimate server), and clients that **accepted** the rogue's lease. | DHCP relays are not counted as extra servers. Redundant servers handing out identical settings are reported as *expected behaviour* with a request to verify. The legitimate server is the one whose gateway actually forwards traffic. |
| (DHCP faults) | `DHCP_NO_RESPONSE`, `DHCP_NAK` | DISCOVERs with no OFFER (server down, relay broken or pool exhausted), and NAK storms. | Thresholds per client. |

## Incident reconstruction

`backend/app/correlate.py` links findings only when **all three** conditions hold:

1. **A documented relationship.** The pair of kinds appears in `RELATIONS`, a curated table of
   attack chains (ARP poisoning followed by forged DNS), side effects (a port scan producing
   refused connections) and fault causes (an MTU black hole causing retransmissions). Each
   relationship has a written explanation that is shown to the user.
2. **A shared host.** Both findings involve the same IP or MAC. The exception is relations
   explicitly marked time-only, such as DNS timeouts and failing connections starting
   together during an uplink outage.
3. **Time proximity.** Their time ranges overlap or fall within 120 s.

Linked findings become one incident with a merged, chronological timeline built from their
evidence packets. The incident also gets affected hosts with roles, the root-cause finding
(the one not explained by another), merged recommendations, and an uncertainty list that
always states that correlation does not prove causation.

The incident verdict comes from published rules: **attack**, **mixed** (an attack plus a fault
it does not explain), **fault**, **inconclusive** or **benign**. Side effects of an attack, such
as refused connections caused by a scan, are not reported as separate faults. Confidence is
raised one level when independent detectors point the same way, and the reason is shown.

## Known limitations

- The capture point decides what is visible. A capture at a receiver never sees packets lost
  upstream, and an on-path injector is invisible if the capture is taken beyond it.
- Thresholds are engineering judgement for small networks, not universal truths. They are all
  in one place so they can be tuned.
- TCP SACK blocks and TLS/HTTP contents are not decoded. Diagnosis uses headers and timing only.
- IPv6 Neighbor Discovery spoofing and DHCPv6 / rogue router advertisements are not covered.
- Accuracy is measured on synthetic scenarios written by the same team (see
  [EVALUATION.md](EVALUATION.md)). Real-world accuracy has not been measured.
