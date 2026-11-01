// Normalisation and derived data for an analysis result.
//
// The backend contract is documented, but detectors are developed in parallel and some
// fields are optional (e.g. relative_start only exists when an incident has a time, and
// an empty capture returns a reduced "traffic" object). normalizeResult() fills every
// field the UI reads with a safe default once, so components never crash on a missing
// array and never try to render an object as text.

import { SEVERITIES, severityRank } from './format.js';

const arr = (v) => (Array.isArray(v) ? v : []);
const obj = (v) => (v && typeof v === 'object' && !Array.isArray(v) ? v : {});
const num = (v) => (typeof v === 'number' && Number.isFinite(v) ? v : null);
const str = (v) => (typeof v === 'string' ? v : v == null ? '' : String(v));
const strList = (v) => arr(v).filter((x) => x != null && x !== '').map(str);

function normalizeHosts(hosts) {
  const out = {};
  for (const [role, values] of Object.entries(obj(hosts))) out[role] = strList(values);
  return out;
}

function normalizeIndicator(i) {
  const o = obj(i);
  return { text: str(o.text), points_to: str(o.points_to) || 'unknown', strength: str(o.strength) || 'weak' };
}

export function normalizeFinding(f, index) {
  const o = obj(f);
  const evidence = arr(o.evidence)
    .map((e) => obj(e))
    .filter((e) => Number.isFinite(e.packet))
    .map((e) => ({ packet: e.packet, role: str(e.role) }));
  return {
    id: str(o.id) || `F-${String(index + 1).padStart(3, '0')}`,
    detector: str(o.detector),
    kind: str(o.kind),
    title: str(o.title) || 'Untitled finding',
    category: str(o.category),
    assessment: str(o.assessment) || 'inconclusive',
    severity: str(o.severity) || 'info',
    evidence_strength: str(o.evidence_strength) || 'weak',
    summary: str(o.summary),
    impact: str(o.impact),
    likely_cause: str(o.likely_cause),
    recommendations: strList(o.recommendations),
    facts: strList(o.facts),
    alternatives: strList(o.alternatives),
    limitations: strList(o.limitations),
    indicators: arr(o.indicators).map(normalizeIndicator),
    hosts: normalizeHosts(o.hosts),
    time_start: num(o.time_start),
    time_end: num(o.time_end),
    rule: str(o.rule),
    metrics: obj(o.metrics),
    evidence,
    evidence_total: num(o.evidence_total) ?? evidence.length,
    evidence_truncated: Boolean(o.evidence_truncated),
  };
}

export function normalizeIncident(inc, index) {
  const o = obj(inc);
  return {
    id: str(o.id) || `INC-${String(index + 1).padStart(3, '0')}`,
    title: str(o.title) || 'Untitled incident',
    verdict: str(o.verdict) || 'inconclusive',
    verdict_label: str(o.verdict_label),
    verdict_notes: strList(o.verdict_notes),
    severity: str(o.severity) || 'info',
    confidence: str(o.confidence) || 'weak',
    confidence_reason: str(o.confidence_reason),
    summary: str(o.summary),
    likely_root_cause: str(o.likely_root_cause),
    root_finding: str(o.root_finding),
    impact: str(o.impact),
    alternatives: strList(o.alternatives),
    uncertainty: strList(o.uncertainty),
    recommendations: strList(o.recommendations),
    observed_facts: strList(o.observed_facts),
    reasoning: arr(o.reasoning).map((r) => ({ finding: str(obj(r).finding), ...normalizeIndicator(r) })),
    links: arr(o.links).map((l) => {
      const x = obj(l);
      return { from: str(x.from), to: str(x.to), type: str(x.type), explanation: str(x.explanation), basis: str(x.basis) };
    }),
    findings: strList(o.findings),
    kinds: strList(o.kinds),
    affected_hosts: arr(o.affected_hosts)
      .map((h) => obj(h))
      .filter((h) => h.address)
      .map((h) => ({ address: str(h.address), roles: strList(h.roles) })),
    time_start: num(o.time_start),
    time_end: num(o.time_end),
    relative_start: num(o.relative_start),
    relative_end: num(o.relative_end),
    timeline: arr(o.timeline)
      .map((e) => obj(e))
      .map((e) => ({
        time: num(e.time),
        relative: num(e.relative),
        packet: num(e.packet),
        finding: str(e.finding),
        kind: str(e.kind),
        role: str(e.role),
        src: str(e.src),
        dst: str(e.dst),
        info: str(e.info),
      })),
  };
}

function normalizePacket(p) {
  const o = obj(p);
  return {
    number: num(o.number),
    time: num(o.time),
    relative: num(o.relative),
    src: str(o.src),
    dst: str(o.dst),
    src_mac: str(o.src_mac),
    dst_mac: str(o.dst_mac),
    protocol: str(o.protocol),
    length: num(o.length),
    info: str(o.info),
    ttl: num(o.ttl),
    sport: num(o.sport),
    dport: num(o.dport),
    malformed: o.malformed ? str(o.malformed) : '',
  };
}

export function normalizeResult(raw) {
  const r = obj(raw);
  const findings = arr(r.findings).map(normalizeFinding);
  const incidents = arr(r.incidents).map(normalizeIncident);
  const traffic = obj(r.traffic);
  const parse = obj(r.parse);
  const summary = obj(r.summary);
  const bySeverity = obj(summary.by_severity);
  const verdict = obj(r.verdict);

  // Fall back to counting findings if the summary block is missing.
  const countAssessment = (a) => findings.filter((f) => f.assessment === a).length;
  const severityCounts = {};
  for (const s of SEVERITIES) {
    severityCounts[s] = num(bySeverity[s]) ?? findings.filter((f) => f.severity === s).length;
  }

  const packets = {};
  for (const [key, value] of Object.entries(obj(r.packets))) packets[key] = normalizePacket(value);

  const conversations = arr(traffic.conversations).map((c) => {
    const o = obj(c);
    return {
      a: str(o.a),
      b: str(o.b),
      protocol: str(o.protocol),
      packets: num(o.packets) ?? 0,
      bytes: num(o.bytes) ?? 0,
      first: num(o.first),
      start: num(o.start),
      end: num(o.end),
    };
  });

  return {
    file: str(r.file) || 'capture',
    format: str(r.format),
    packets_analyzed: num(r.packets_analyzed) ?? 0,
    duration_seconds: num(r.duration_seconds) ?? 0,
    capture_start: num(r.capture_start),
    parse: {
      malformed_packets: num(parse.malformed_packets) ?? 0,
      truncated_file: Boolean(parse.truncated_file),
      stopped_early: parse.stopped_early ? str(parse.stopped_early) : '',
      parse_seconds: num(parse.parse_seconds),
    },
    warnings: strList(r.warnings),
    traffic: {
      protocols: Object.fromEntries(
        Object.entries(obj(traffic.protocols)).filter(([, v]) => Number.isFinite(v)),
      ),
      series: arr(traffic.series)
        .map((b) => obj(b))
        .filter((b) => Number.isFinite(b.t))
        .map((b) => ({ t: b.t, packets: num(b.packets) ?? 0, TCP: num(b.TCP) ?? 0, UDP: num(b.UDP) ?? 0, Other: num(b.Other) ?? 0 })),
      bucket_seconds: num(traffic.bucket_seconds),
      top_talkers: arr(traffic.top_talkers)
        .map((t) => obj(t))
        .filter((t) => t.ip)
        .map((t) => ({ ip: str(t.ip), packets: num(t.packets) ?? 0, bytes: num(t.bytes) ?? 0, local: Boolean(t.local) })),
      conversations,
      conversation_total: num(traffic.conversation_total) ?? conversations.length,
      tcp_connections: num(traffic.tcp_connections),
    },
    hosts: arr(r.hosts)
      .map((h) => obj(h))
      .filter((h) => h.ip)
      .map((h) => ({ ip: str(h.ip), macs: strList(h.macs), packets: num(h.packets) ?? 0, roles: strList(h.roles) })),
    findings,
    incidents,
    verdict: {
      // Without a verdict block, findings alone must never read as "clean".
      status: str(verdict.status) || (incidents.length || findings.length ? 'inconclusive' : 'clean'),
      label: str(verdict.label),
      headline: str(verdict.headline),
      counts: Object.fromEntries(
        Object.entries(obj(verdict.counts)).filter(([, v]) => Number.isFinite(v) && v > 0),
      ),
    },
    summary: {
      findings: num(summary.findings) ?? findings.length,
      incidents: num(summary.incidents) ?? incidents.length,
      faults: num(summary.faults) ?? countAssessment('fault'),
      attacks: num(summary.attacks) ?? countAssessment('attack'),
      inconclusive: num(summary.inconclusive) ?? countAssessment('inconclusive'),
      benign: num(summary.benign) ?? countAssessment('benign'),
      by_severity: severityCounts,
    },
    packets,
    detectors: arr(r.detectors)
      .map((d) => obj(d))
      .map((d) => ({ name: str(d.name), findings: num(d.findings) ?? 0, status: str(d.status) || 'unknown', seconds: num(d.seconds) })),
    analysis_seconds: num(r.analysis_seconds),
    notice: str(r.notice),
  };
}

/**
 * Lookup tables and the flat evidence list used by several views. Built once per result
 * (memoised in App) so filtering and navigation stay cheap.
 */
export function buildIndex(result) {
  const findingsById = new Map(result.findings.map((f) => [f.id, f]));
  const incidentsById = new Map(result.incidents.map((i) => [i.id, i]));
  const incidentOfFinding = new Map();
  for (const inc of result.incidents) {
    for (const fid of inc.findings) if (!incidentOfFinding.has(fid)) incidentOfFinding.set(fid, inc);
  }

  // One row per (finding, packet): the same frame can be evidence for two findings,
  // each for a different reason, and both reasons are shown.
  const evidenceRows = [];
  for (const f of result.findings) {
    const incident = incidentOfFinding.get(f.id) || null;
    f.evidence.forEach((ev, i) => {
      const pkt = result.packets[String(ev.packet)] || null;
      evidenceRows.push({
        key: `${f.id}:${ev.packet}:${i}`,
        packet: ev.packet,
        role: ev.role,
        finding: f,
        incident,
        pkt,
        search: [
          `#${ev.packet}`,
          String(ev.packet),
          ev.role,
          f.id,
          f.title,
          f.rule,
          f.detector,
          f.kind,
          incident ? `${incident.id} ${incident.title}` : '',
          pkt ? `${pkt.src} ${pkt.dst} ${pkt.src_mac} ${pkt.dst_mac} ${pkt.protocol} ${pkt.info}` : '',
        ]
          .join(' ')
          .toLowerCase(),
      });
    });
  }
  evidenceRows.sort((a, b) => a.packet - b.packet || a.finding.id.localeCompare(b.finding.id));

  const incidentCounts = { attack: 0, fault: 0, inconclusive: 0, benign: 0 };
  for (const inc of result.incidents) {
    if (inc.verdict === 'attack' || inc.verdict === 'mixed') incidentCounts.attack += 1;
    else if (inc.verdict in incidentCounts) incidentCounts[inc.verdict] += 1;
  }

  // Packet number -> every evidence row citing it (one frame can support several findings).
  const evidenceByPacket = new Map();
  for (const row of evidenceRows) {
    if (!evidenceByPacket.has(row.packet)) evidenceByPacket.set(row.packet, []);
    evidenceByPacket.get(row.packet).push(row);
  }
  const evidencePackets = [...evidenceByPacket.keys()].sort((a, b) => a - b);
  // Finding id -> its evidence packet numbers in capture order (for previous / next).
  const packetsByFinding = new Map(
    result.findings.map((f) => [f.id, [...new Set(f.evidence.map((e) => e.packet))].sort((a, b) => a - b)]),
  );

  return {
    findingsById,
    incidentsById,
    incidentOfFinding,
    evidenceRows,
    incidentCounts,
    evidenceByPacket,
    evidencePackets,
    packetsByFinding,
  };
}

/**
 * Is the capture complete enough for a "clean" result to mean anything? Built only from
 * the backend's parse report; never guessed.
 */
export function captureQuality(result) {
  const reasons = [];
  if (result.parse.truncated_file) {
    reasons.push('the file is truncated or corrupt; only the complete packets before that point were analysed');
  }
  if (result.parse.stopped_early) reasons.push(`analysis stopped early (${result.parse.stopped_early})`);
  if (result.parse.malformed_packets > 0) {
    reasons.push(`${result.parse.malformed_packets} packet${result.parse.malformed_packets === 1 ? ' was' : 's were'} malformed`);
  }
  if (result.packets_analyzed === 0) reasons.push('the capture contains no packets');
  return { incomplete: reasons.length > 0, empty: result.packets_analyzed === 0, reasons };
}

/**
 * How the capture-level verdict is presented. The backend's overall status folds any
 * attack into "attack"; verdict.counts keeps the split, so a capture with both attack
 * and fault incidents is shown as "mixed" here without changing the backend contract.
 */
export function overallAssessment(result, index) {
  const c = result.verdict.counts;
  const counts = {
    attack: (c.attack || 0) + (c.mixed || 0),
    fault: c.fault || 0,
    inconclusive: c.inconclusive || 0,
    benign: c.benign || 0,
  };
  // Older responses without counts: fall back to the incidents themselves.
  if (!Object.keys(c).length && index) Object.assign(counts, index.incidentCounts);
  const quality = captureQuality(result);
  const status = result.verdict.status;
  let kind = status;
  let label = result.verdict.label;
  if (status === 'attack' && counts.fault > 0) {
    kind = 'mixed';
    label = 'Attack indicators and network faults';
  } else if (status === 'clean' && quality.incomplete) {
    kind = 'incomplete';
    label = quality.empty ? 'Nothing to analyse' : 'No issues found in the readable part';
  }
  const fallback = { attack: 'Possible attack detected', fault: 'Network faults detected', inconclusive: 'Needs investigation', clean: 'No problems detected' };
  return {
    kind, // attack | mixed | fault | inconclusive | clean | incomplete
    tone: { attack: 'attack', mixed: 'attack', fault: 'fault', inconclusive: 'inconclusive', clean: 'clean' }[kind] || 'neutral',
    label: label || fallback[status] || 'Analysis complete',
    headline: result.verdict.headline,
    counts,
    quality,
  };
}

// Conversations are keyed by transport protocol; packet summaries name the application.
const TRANSPORT_OF = { DNS: ['UDP', 'TCP'], DHCP: ['UDP'] };

/**
 * The conversation (from traffic.conversations) a packet belongs to, matched exactly the
 * way the backend builds them: sorted address pair + transport protocol. Returns
 * { conversation, capped } where capped means the list was cut to the busiest N, so a
 * missing match is "not in the list", not "does not exist".
 */
export function findConversation(result, pkt) {
  const capped = result.traffic.conversation_total > result.traffic.conversations.length;
  if (!pkt || !pkt.src || !pkt.dst) return { conversation: null, capped };
  const [a, b] = [pkt.src, pkt.dst].sort();
  const candidates = [pkt.protocol, ...(TRANSPORT_OF[pkt.protocol] || [])];
  for (const proto of candidates) {
    const conversation = result.traffic.conversations.find((c) => c.a === a && c.b === b && c.protocol === proto);
    if (conversation) return { conversation, capped };
  }
  return { conversation: null, capped };
}

/** Evidence packets (unique, capture order) that fall inside a conversation. */
export function conversationPackets(result, index, conversation) {
  if (!conversation) return [];
  return index.evidencePackets.filter((n) => {
    const p = result.packets[String(n)];
    if (!p || !p.src || !p.dst) return false;
    const [a, b] = [p.src, p.dst].sort();
    if (a !== conversation.a || b !== conversation.b) return false;
    return p.protocol === conversation.protocol || (TRANSPORT_OF[p.protocol] || []).includes(conversation.protocol);
  });
}

/**
 * Split text such as "answering request #246" into text and packet-reference segments.
 * Only frame citations ("request #N", "packet #N", "frame #N") are references: the backend
 * also writes counters with "#" ("duplicate ACK #2", "SYN retransmission #1"), and those
 * must stay plain text rather than link to an unrelated packet.
 */
export function splitPacketRefs(text) {
  const out = [];
  const re = /\b(request|packet|frame)\s+#(\d{1,9})\b/gi;
  let last = 0;
  let m;
  while ((m = re.exec(text)) !== null) {
    const refStart = m.index + m[0].indexOf('#');
    if (refStart > last) out.push({ text: text.slice(last, refStart) });
    out.push({ packet: Number(m[2]) });
    last = m.index + m[0].length;
  }
  if (last < text.length) out.push({ text: text.slice(last) });
  return out;
}

/** The finding-assessment groups used by the Faults & Threats view, in display order. */
export const ASSESSMENT_GROUPS = ['attack', 'fault', 'inconclusive', 'benign'];

/** Group for a finding (unknown assessments are treated as needing investigation). */
export function assessmentGroup(finding) {
  return ASSESSMENT_GROUPS.includes(finding.assessment) ? finding.assessment : 'inconclusive';
}

/** Findings sorted for display: most severe first, then earliest. */
export function sortFindings(findings) {
  return [...findings].sort(
    (a, b) => severityRank(a.severity) - severityRank(b.severity) || (a.time_start ?? 0) - (b.time_start ?? 0),
  );
}

/**
 * Protocol counts for a bar chart: biggest first, with the long tail folded into one
 * "N more protocols" row so the chart stays readable.
 */
export function protocolRows(protocols, maxRows = 8) {
  const entries = Object.entries(protocols || {}).sort((a, b) => b[1] - a[1]);
  const total = entries.reduce((s, [, v]) => s + v, 0);
  const rows = entries.slice(0, maxRows).map(([name, count]) => ({ name, count }));
  const rest = entries.slice(maxRows);
  if (rest.length) {
    rows.push({ name: `${rest.length} more`, count: rest.reduce((s, [, v]) => s + v, 0), folded: rest.map(([n]) => n) });
  }
  return { rows, total };
}

/**
 * The backend's series holds bucket START times. For a step chart the last bucket must
 * also extend to the end of the capture, so a closing point is appended.
 */
export function trafficSeries(series, duration) {
  if (!series.length) return [];
  const out = series.map((b) => ({ ...b }));
  const last = out[out.length - 1];
  if (Number.isFinite(duration) && duration > last.t) out.push({ ...last, t: duration, closing: true });
  return out;
}
