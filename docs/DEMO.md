# Demo script (about 4 minutes)

A reproducible walkthrough for the demo video. Everything shown is real output from the
bundled synthetic samples. Start the backend and frontend as in the README, then open
http://127.0.0.1:5173 in a browser window of at least 1366 × 768.

| Time | Show | Say (key points) | Criterion |
|---|---|---|---|
| 0:00 | Title / README | Small networks have no network engineer. A packet capture holds the answer, but it is hard to read, and a fault looks just like an attack. | Problem |
| 0:20 | Landing page: **Backend online**, the coverage panel, the sample gallery | Everything runs offline on this laptop. The coverage panel maps every official fault and threat to the detector that checks it; the samples are synthetic lab captures. | Feasibility |
| 0:35 | Click **benign_office.pcap** | A healthy office with DHCP, ARP, DNS, a large file transfer and a browser opening 30 connections. The verdict is **No problems detected**, with *What was checked*: no false alarms. | False alarms |
| 0:55 | Click **New analysis** → **incident_mitm_chain.pcap**. Read the verdict at the top of the Overview | The verdict comes first: one incident, not three alerts, with its severity and confidence. **Investigate INC-001** is the next step. | Novelty |
| 1:10 | **Investigate INC-001**: *Verdict & confidence*, *What happened* | The rule that produced the verdict is shown in words. The root cause is labelled a hypothesis, not a fact. | Explain |
| 1:25 | *Why NetSentinel believes this*, *How the findings were linked* | Indicators are grouped by direction, each with a strength: evidence, not a score. Each link names the rule, the shared host (192.168.1.66) and the time gap, and the page says plainly that correlation is not proof of causation. | Technical |
| 1:50 | *Reconstructed timeline*: click a packet number such as **#247** | The scan, then poisoning, then forged DNS. Clicking a packet opens the Evidence explorer with that frame selected. | Evidence |
| 2:05 | Packet inspector: header fields, *Why this packet is evidence*, click **#246** in the reason | The frame was cited because it answers request #246, and the inspector links straight to it. The conversation section shows the other evidence between the same two hosts. Frame numbers match Wireshark. | Evidence |
| 2:25 | Browser **Back** to the incident, then *Recommended response* and *What we cannot be sure about* | Back and Forward work. The steps are specific to this incident, and NetSentinel says what the capture cannot prove. | Explain / fix |
| 2:40 | **New analysis** → **incident_outage_vs_attack.pcap** | The verdict reads **Attack indicators and network faults**: an internet outage **and** an unrelated scan become two incidents, one fault and one attack. That is the "outage or attack?" question from the brief. | Outage vs attack |
| 3:00 | **Faults & Threats** | Each finding separates what was *observed* (facts, key measurements, evidence packets) from what is *inferred* (cause, impact, alternatives). | Diagnosis |
| 3:15 | **Traffic** | Activity over time with incident ranges marked, hosts with inferred roles, conversations with their evidence packets. | Summary view |
| 3:25 | **Report**, then **Print report** (show the print preview) | The full investigation report, ready to hand to whoever fixes the network. | Usability |
| 3:40 | **New analysis** → **malformed_huge_record.pcap**, then a renamed `.txt` | A 162-byte file that claims 4 GB is analysed safely, and the verdict says the capture is incomplete instead of showing a green "clean". A non-capture file is rejected with a clear error, and the previous report is marked as previous. | Security |
| 3:55 | Terminal: `python -m pytest -q`, `python -m lab.evaluate` | 198 tests and 102 labelled scenarios. Be explicit that these are synthetic results, not real-world accuracy. | Technical |
| 4:10 | README coverage table | Every official challenge point is covered, the code is our own, and the libraries are listed. | Wrap-up |

## Before recording

- Run `python -m pytest -q` once so the numbers you show are current.
- Close other applications that use ports 8000 and 5173, and restart both servers after switching git branches.
- Zoom the browser to 100 % at 1366 × 768 or larger.
