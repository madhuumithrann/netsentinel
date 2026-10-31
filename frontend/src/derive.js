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
      status: str(verdict.status) || (incidents.length ? 'inconclusive' : 'clean'),
      label: str(verdict.label),
      headline: str(verdict.headline),
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

  return { findingsById, incidentsById, incidentOfFinding, evidenceRows, incidentCounts };
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
