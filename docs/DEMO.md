# Demo script (about 4 minutes)

A reproducible walkthrough for the demo video. Everything shown is real output from the
bundled synthetic samples. Start the backend and frontend as in the README, then open
http://127.0.0.1:5173.

| Time | Show | Say (key points) | Criterion |
|---|---|---|---|
| 0:00 | Title / README | Small networks have no network engineer. A packet capture holds the answer, but it is hard to read, and a fault looks just like an attack. | Problem |
| 0:20 | Sidebar **Backend online** badge, sample gallery | Everything runs offline on this laptop. The badge is a live health check, and the samples are synthetic lab captures. | Feasibility |
| 0:35 | Analyse **benign_office.pcap** | A healthy office with DHCP, ARP, DNS, a large file transfer and a browser opening 30 connections. **No alarms.** The original prototype flagged 135 "retransmissions" in traffic like this. | False alarms |
| 1:00 | Analyse **incident_mitm_chain.pcap**, then open the incident | One incident, not three alerts. Read the verdict and its confidence reason. | Novelty |
| 1:15 | *Why NetSentinel reached this verdict* | The indicators are grouped by direction, each with a strength. Unsolicited ARP replies, impersonating the gateway, relaying traffic with TTL−1 and conflicting DNS answers are all evidence, not a score. | Technical |
| 1:35 | *How the findings are linked* | Each link names the rule, the shared host (192.168.1.66) and the time gap. Being close in time is never enough on its own. | Novelty |
| 1:50 | Reconstructed timeline, click a packet number | The scan, then poisoning, then forged DNS. Clicking a packet opens the Evidence explorer at that packet, showing why it is evidence and which rule fired. These are Wireshark frame numbers. | Evidence |
| 2:15 | Recommended actions checklist, *What we cannot be sure about* | Specific steps for this incident. NetSentinel says what the capture cannot prove. | Explain / fix |
| 2:35 | Analyse **incident_outage_vs_attack.pcap** | The same capture holds an internet outage **and** an unrelated scan. The result is two incidents: one fault, one attack. That is the "outage or attack?" question from the brief. | Outage vs attack |
| 3:00 | **Faults & Threats** tab, then **fault_slow_server.pcap** | The handshake is fast but the first response takes 4 s, so the network is fine and the application is slow. | Diagnosis |
| 3:15 | **Traffic** view | Activity over time with the incident ranges shaded, plus hosts with inferred roles and conversations. | Summary view |
| 3:30 | Analyse **malformed_huge_record.pcap**, then upload a renamed `.txt` | A 162-byte file that claims 4 GB is handled with a warning. A non-capture file is rejected with a clear 422 error. | Security |
| 3:45 | Terminal: `python -m pytest -q`, `python -m lab.evaluate` | 198 tests and 102 labelled scenarios. Be explicit that these are synthetic results, not real-world accuracy. | Technical |
| 4:00 | README coverage table | Every official challenge point is covered, the code is our own, and the libraries are listed. | Wrap-up |

## Before recording

- Run `python -m pytest -q` once so the numbers you show are current.
- Close other applications that use ports 8000 and 5173.
- Use a browser window at least 1280 px wide (the incident view uses two columns).
