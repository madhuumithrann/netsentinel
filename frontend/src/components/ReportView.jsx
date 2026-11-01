// Printable investigation report. Every sentence is a deterministic template filled from
// the analysis result (no generated prose), so what is printed is exactly what the
// detectors and the correlation engine reported.
import { useEffect, useMemo, useState } from 'react';
import { Check, Eye, Lightbulb, Link2, Printer, TriangleAlert } from 'lucide-react';
import { sortFindings } from '../derive.js';
import {
  assessmentLabel,
  assessmentTone,
  formatDuration,
  formatInt,
  formatMetric,
  formatOffset,
  formatOffsetRange,
  formatRunTime,
  formatUtc,
  humanize,
  incidentVerdictLabel,
  linkTypeLabel,
  plural,
  severityLabel,
  severityRank,
  strengthLabel,
} from '../format.js';
import { Badge, FindingRef, PacketRef, RefText, SeverityBadge, StrengthChip, VerdictBadge } from './ui.jsx';

const TIMELINE_LIMIT = 20;
const EVIDENCE_LIMIT = 8;
const METRIC_LIMIT = 8;
const SERVICE_LIMIT = 8;

const MIXED_NOTE = 'combine attack indicators with network faults';

/** Section ids double as DOM ids; incident ids are sanitised so any backend id is a valid id. */
const incidentAnchor = (id) => `rp-inc-${String(id).replace(/[^A-Za-z0-9_-]/g, '_')}`;

const capitalise = (s) => (s ? s.charAt(0).toUpperCase() + s.slice(1) : s);

// Protocol acronyms that humanize() lower-cases inside snake_case metric keys.
const ACRONYMS = { ip: 'IP', ips: 'IPs', ttl: 'TTL', mac: 'MAC', macs: 'MACs', dns: 'DNS', dhcp: 'DHCP', tcp: 'TCP',
  udp: 'UDP', arp: 'ARP', mtu: 'MTU', mss: 'MSS', syn: 'SYN', rst: 'RST', icmp: 'ICMP', rtt: 'RTT', txid: 'TXID' };

const withAcronyms = (text) => text.split(' ').map((w) => ACRONYMS[w.toLowerCase()] || w).join(' ');

/** "ttl_anomalies" -> "TTL anomalies". */
const metricLabel = (key) => capitalise(withAcronyms(humanize(key)));

/** "a, b and c" */
function joinList(items) {
  if (items.length <= 1) return items.join('');
  return `${items.slice(0, -1).join(', ')} and ${items[items.length - 1]}`;
}

// Frame citations ("request #246") become packet links; counters ("SYN retransmission #1") stay text.
const CitedText = RefText;

/** Offset range of an incident, from relative offsets or (if absent) from epoch times. */
function incidentRange(inc, captureStart) {
  let start = inc.relative_start;
  let end = inc.relative_end;
  if (!Number.isFinite(start) && Number.isFinite(inc.time_start) && Number.isFinite(captureStart)) {
    start = inc.time_start - captureStart;
    end = Number.isFinite(inc.time_end) ? inc.time_end - captureStart : null;
  }
  return formatOffsetRange(start, end);
}

/** Time spanned by the capture; one packet has no span, so it is not shown as "0 ms". */
function captureSpan(result) {
  if (result.packets_analyzed > 1) return formatDuration(result.duration_seconds);
  return result.packets_analyzed === 1 ? 'single packet' : 'not available';
}

/** Incident verdict counts for the summary sentence; mixed kept apart, unknown verdicts read as inconclusive. */
function verdictCounts(incidents) {
  const c = { attack: 0, mixed: 0, fault: 0, inconclusive: 0, benign: 0 };
  for (const inc of incidents) c[inc.verdict in c ? inc.verdict : 'inconclusive'] += 1;
  return c;
}

function verdictPhrases(c) {
  const n = (k, one, many) => `${formatInt(c[k])} ${c[k] === 1 ? one : many}`;
  return [
    c.attack && n('attack', 'matches attack indicators', 'match attack indicators'),
    c.mixed && n('mixed', 'combines attack indicators with network faults', MIXED_NOTE),
    c.fault && n('fault', 'looks like an ordinary network fault', 'look like ordinary network faults'),
    c.inconclusive && n('inconclusive', 'needs further investigation', 'need further investigation'),
    c.benign && n('benign', 'is consistent with expected behaviour', 'are consistent with expected behaviour'),
  ].filter(Boolean);
}

/** "192.168.1.66:54321 → 192.168.1.20:22" (falls back to MAC addresses for non-IP frames). */
function endpoints(pkt) {
  const side = (ip, mac, port) => {
    const host = ip || mac || '?';
    return Number.isFinite(port) ? `${host}:${port}` : host;
  };
  return `${side(pkt.src, pkt.src_mac, pkt.sport)} → ${side(pkt.dst, pkt.dst_mac, pkt.dport)}`;
}

/**
 * Protocol / destination-port pairs across the evidence packets of an incident's findings.
 * Only frames whose summaries are in the response count, so this is labelled as exactly that.
 */
function evidenceServices(findingIds, result, index) {
  const seen = new Set();
  const counts = new Map();
  for (const fid of findingIds) {
    for (const n of index.packetsByFinding.get(fid) || []) {
      if (seen.has(n)) continue;
      seen.add(n);
      const pkt = result.packets[String(n)];
      if (!pkt || !Number.isFinite(pkt.dport)) continue;
      const key = `${pkt.protocol || '?'}|${pkt.dport}`;
      const row = counts.get(key) || { protocol: pkt.protocol || '?', port: pkt.dport, packets: 0 };
      row.packets += 1;
      counts.set(key, row);
    }
  }
  return [...counts.values()].sort((a, b) => b.packets - a.packets || a.port - b.port);
}

/** Scalar metrics only (numbers, text, yes/no); structured breakdowns stay in the finding detail. */
function scalarMetrics(metrics) {
  const all = Object.entries(metrics || {});
  const scalar = all.filter(([, v]) => ['number', 'string', 'boolean'].includes(typeof v) && v !== '');
  return { rows: scalar.slice(0, METRIC_LIMIT), hidden: all.length - Math.min(scalar.length, METRIC_LIMIT) };
}

/** A CSS string literal; the file name comes from the upload, so quotes, backslashes and markup are escaped. */
function cssString(text) {
  const clipped = text.length > 90 ? `${text.slice(0, 89)}…` : text;
  const escaped = clipped
    .replace(/[\\"]/g, (c) => `\\${c}`)
    .replace(/[\n\r<>]/g, (c) => `\\${c.charCodeAt(0).toString(16)} `);
  return `"${escaped}"`;
}

/**
 * Printed page furniture (running header with the file name, page numbers). Rendered only
 * while the report is mounted, so printing any other view is unaffected. Margin boxes do
 * not see the :root tokens, hence the literal font and colour.
 */
function PrintPageStyle({ file, generated }) {
  const box = 'font: 8.5px "Segoe UI", system-ui, Arial, sans-serif; color: #56616e;';
  const css = `@media print { @page {
    @top-left { content: "NetSentinel investigation report"; ${box} }
    @top-right { content: ${cssString(file)}; ${box} }
    @bottom-left { content: ${cssString(`Generated ${generated}`)}; ${box} }
    @bottom-right { content: "Page " counter(page) " of " counter(pages); ${box} }
  } }`;
  return <style>{css}</style>;
}

/** Scroll a report section into view (below the sticky report bar) and move focus to its heading. */
function goToSection(id) {
  const el = document.getElementById(id);
  if (!el) return;
  const reduced = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;
  el.scrollIntoView({ behavior: reduced ? 'auto' : 'smooth', block: 'start' });
  el.querySelector('h2, h3')?.focus({ preventScroll: true });
}

/**
 * Which section is being read, for the side contents rail: the last section (in document
 * order) whose top has scrolled past a line just below the sticky bar. Nested entries come
 * after their parent, so an incident wins over the "Incident analysis" section holding it.
 */
function useActiveSection(ids) {
  const [active, setActive] = useState(ids[0] || '');
  const key = ids.join('|');
  useEffect(() => {
    let frame = 0;
    const update = () => {
      frame = 0;
      const line = window.innerHeight * 0.3;
      let current = ids[0] || '';
      for (const id of ids) {
        const el = document.getElementById(id);
        if (el && el.getBoundingClientRect().top <= line) current = id;
      }
      setActive(current);
    };
    const onScroll = () => {
      if (!frame) frame = requestAnimationFrame(update);
    };
    update();
    window.addEventListener('scroll', onScroll, { passive: true });
    window.addEventListener('resize', onScroll);
    return () => {
      cancelAnimationFrame(frame);
      window.removeEventListener('scroll', onScroll);
      window.removeEventListener('resize', onScroll);
    };
  }, [key]); // key is the stable form of ids
  return active;
}

/**
 * Contents list. Buttons, not href="#…" links: the URL hash is the app's router. Incidents
 * are nested under their section so a column break never separates them from it.
 */
function Toc({ entries, active, variant }) {
  const link = (e) => (
    <button type="button" className="rp-toc-link" onClick={() => goToSection(e.id)} title={e.label}
            aria-current={variant === 'rail' && active === e.id ? 'location' : undefined}>
      <span className="rp-toc-num">{e.num}</span>
      <span className="rp-toc-text">{e.label}</span>
    </button>
  );
  return (
    <nav className={`rp-toc rp-toc-${variant} no-print`} aria-label={variant === 'rail' ? 'Report contents (side)' : 'Report contents'}>
      <div className="eyebrow">Contents</div>
      <ol className="rp-toc-list">
        {entries.map((e) => (
          <li key={e.id}>
            {link(e)}
            {e.children?.length > 0 && (
              <ol className="rp-toc-sub">
                {e.children.map((c) => (
                  <li key={c.id}>{link(c)}</li>
                ))}
              </ol>
            )}
          </li>
        ))}
      </ol>
    </nav>
  );
}

function SectionHead({ num, children, sub = false, id }) {
  const H = sub ? 'h3' : 'h2';
  return (
    <H className={sub ? 'rp-h3' : 'rp-h2'} id={id} tabIndex={-1}>
      <span className="rp-num">{num}</span>
      <span>{children}</span>
    </H>
  );
}

/**
 * A labelled block inside an incident. The kicker states what kind of statement the content
 * is (observed in the capture / correlated by rules / inferred), so facts and hypotheses
 * are never mixed up; `tone` only styles that label.
 */
function Block({ title, kicker, tone = 'observed', icon: Icon, children, note }) {
  return (
    <div className="rp-block">
      <div className="rp-block-head">
        {kicker && (
          <span className={`rp-kicker rp-kicker-${tone}`}>
            {Icon && <Icon size={12} aria-hidden="true" />}
            {kicker}
          </span>
        )}
        <h4 className="rp-h4">{title}</h4>
      </div>
      {children}
      {note && <p className="rp-note">{note}</p>}
    </div>
  );
}

function Meta({ items, className = '' }) {
  return (
    <dl className={`rp-meta ${className}`}>
      {items.map(([label, value]) => (
        <div key={label} className="rp-meta-item">
          <dt>{label}</dt>
          <dd>{value}</dd>
        </div>
      ))}
    </dl>
  );
}

function ReportHeader({ result, assessment, generated }) {
  const done = result.detectors.filter((d) => d.status === 'ok').length;
  const total = result.detectors.length;
  const start = result.capture_start;
  const hasTime = Number.isFinite(start) && result.packets_analyzed > 0;
  return (
    <header className="rp-header">
      <div className="rp-header-top">
        <div className="rp-title-block">
          <div className="eyebrow">Investigation report</div>
          <h1 id="view-title" tabIndex={-1}>NetSentinel investigation report</h1>
          <div className="rp-file mono break">{result.file}</div>
        </div>
        <div className="rp-header-side">
          <Badge tone={assessment.tone}>
            <span className={`dot dot-${assessment.tone}`} aria-hidden="true" />
            {assessment.label}
          </Badge>
          <button type="button" className="button button-sm no-print" onClick={() => window.print()}>
            <Printer size={14} aria-hidden="true" /> Print report
          </button>
        </div>
      </div>
      <Meta
        items={[
          ['Format', result.format ? result.format.toUpperCase() : 'not reported'],
          ['Packets analysed', formatInt(result.packets_analyzed)],
          ['Capture start', hasTime ? formatUtc(start) : 'not available'],
          ['Capture end', hasTime ? formatUtc(start + result.duration_seconds) : 'not available'],
          ['Duration', captureSpan(result)],
          ['Analysis time', Number.isFinite(result.analysis_seconds) ? formatRunTime(result.analysis_seconds) : 'not reported'],
          ['Detectors completed', total ? `${done} of ${total}` : 'none reported'],
          ['Report generated', generated],
        ]}
      />
    </header>
  );
}

function ExecutiveSummary({ result, index, nav, assessment, num }) {
  const { incidents, findings } = result;
  const c = verdictCounts(incidents);
  const failed = result.detectors.filter((d) => d.status !== 'ok');
  const ran = result.detectors.length - failed.length;
  const ungrouped = findings.filter((f) => !index.incidentOfFinding.has(f.id)).length;
  const worst = [...incidents].sort((a, b) => severityRank(a.severity) - severityRank(b.severity))[0];
  const { quality } = assessment;

  const opening = result.packets_analyzed > 1 && result.duration_seconds > 0
    ? `NetSentinel analysed ${plural(result.packets_analyzed, 'packet')} captured over ${formatDuration(result.duration_seconds)}.`
    : `NetSentinel analysed ${plural(result.packets_analyzed, 'packet')}.`;
  let body;
  if (incidents.length) {
    body = `It reconstructed ${plural(incidents.length, 'incident')} from ${plural(findings.length, 'finding')}: ${joinList(verdictPhrases(c))}.`;
  } else if (findings.length) {
    body = `It raised ${plural(findings.length, 'finding')} but did not group them into incidents.`;
  } else if (result.packets_analyzed === 0) {
    body = 'There was nothing to examine, so no detector could raise a finding.';
  } else {
    body = `None of the ${plural(ran, 'detector')} that ran raised a finding, so there were no incidents to reconstruct.`;
  }
  const extra = [
    ungrouped > 0 && incidents.length > 0 && `${plural(ungrouped, 'finding')} ${ungrouped === 1 ? 'was' : 'were'} not assigned to any incident.`,
    failed.length > 0 && `${plural(failed.length, 'detector')} did not complete (see section ${num.method}), so ${failed.length === 1 ? 'its category was' : 'their categories were'} not checked.`,
  ].filter(Boolean);

  const severe = (result.summary.by_severity.critical || 0) + (result.summary.by_severity.high || 0);
  const figures = [
    ['Packets analysed', formatInt(result.packets_analyzed)],
    ['Capture duration', captureSpan(result)],
    ['Incidents', formatInt(incidents.length)],
    ['Findings', formatInt(findings.length)],
    ['Critical / high findings', formatInt(severe)],
    ['Evidence packets cited', formatInt(index.evidencePackets.length)],
  ];

  return (
    <section className="rp-section" id="rp-summary" aria-labelledby="rp-summary-h">
      <SectionHead num={num.summary} id="rp-summary-h">Executive summary</SectionHead>
      <div className={`rp-verdict rail rail-${assessment.tone}`}>
        <div className="eyebrow">Overall assessment</div>
        <p className="rp-verdict-label">{assessment.label}</p>
      </div>
      <p className="rp-lead">
        {opening} {body} {extra.join(' ')}
      </p>
      {worst && (
        <p className="rp-text">
          Highest-severity incident:{' '}
          <FindingRef id={worst.id} title={worst.title} onClick={() => nav.openIncident(worst.id)} />{' '}
          <span className="strong">{worst.title}</span> ({severityLabel(worst.severity)} severity,{' '}
          {strengthLabel(worst.confidence).toLowerCase()} confidence).
        </p>
      )}
      {assessment.headline && (
        <figure className="rp-quote">
          <blockquote>{assessment.headline}</blockquote>
          <figcaption>Analysis engine headline</figcaption>
        </figure>
      )}
      <dl className="rp-figures">
        {figures.map(([label, value]) => (
          <div key={label}>
            <dt>{label}</dt>
            <dd>{value}</dd>
          </div>
        ))}
      </dl>
      {quality.reasons.length > 0 && (
        <div className="rp-caveat" role="note">
          <TriangleAlert size={16} aria-hidden="true" />
          <div>
            <div className="strong">Capture-quality caveats</div>
            <ul className="text-list">
              {quality.reasons.map((r) => (
                <li key={r}>{capitalise(r)}.</li>
              ))}
            </ul>
            <p className="rp-note">Only the readable part of the capture was analysed; the absence of a finding is weaker evidence here.</p>
          </div>
        </div>
      )}
    </section>
  );
}

const METHOD_NOTES = [
  'Each detector reports indicators that point to an attack, a fault or expected behaviour, each with a strength. One strong indicator, or two moderate ones, decide a direction. When attack and a competing direction (fault or expected behaviour) are both decisive, attack wins only with strictly stronger support; otherwise the finding is inconclusive.',
  'Weak indicators on their own never produce an attack verdict.',
  'An incident is an attack when it contains an attack finding and every fault in it is explained as a side effect of that attack; it is mixed when an unexplained fault remains, and a fault when it contains faults but no attack finding.',
  'Confidence is the evidence strength of the strongest finding supporting the verdict, raised one level when two or more independent detectors point the same way.',
  'Findings are linked by documented rules (shared hosts, timing, known cause-and-effect relationships). Temporal correlation does not prove causation.',
];

const VERDICT_ORDER = ['attack', 'mixed', 'fault', 'inconclusive', 'benign'];

function AssessmentSection({ result, nav, num, assessment }) {
  const { incidents } = result;
  const c = verdictCounts(incidents);
  return (
    <section className="rp-section" id="rp-assessment" aria-labelledby="rp-assessment-h">
      <SectionHead num={num.assessment} id="rp-assessment-h">Overall assessment &amp; confidence</SectionHead>
      <div className="rp-assess-line">
        <span className="rp-assess-label">
          <span className={`dot dot-${assessment.tone}`} aria-hidden="true" />
          {assessment.label}
        </span>
        {incidents.length > 0 && (
          <ul className="plain-list rp-verdict-split" aria-label="Incidents by verdict">
            {VERDICT_ORDER.filter((v) => c[v]).map((v) => (
              <li key={v}>
                <VerdictBadge verdict={v} />
                <span className="num strong">{formatInt(c[v])}</span>
              </li>
            ))}
          </ul>
        )}
      </div>
      {incidents.length ? (
        <div className="table-wrap rp-table-wrap">
          <table className="table table-dense rp-table">
            <thead>
              <tr>
                <th scope="col">Incident</th>
                <th scope="col">Title</th>
                <th scope="col">Verdict</th>
                <th scope="col">Severity</th>
                <th scope="col">Confidence</th>
                <th scope="col" className="num">Findings</th>
                <th scope="col">Time range</th>
              </tr>
            </thead>
            <tbody>
              {incidents.map((inc) => (
                <tr key={inc.id}>
                  <td><FindingRef id={inc.id} title={inc.title} onClick={() => nav.openIncident(inc.id)} /></td>
                  <td className="rp-cell-title">{inc.title}</td>
                  <td><VerdictBadge verdict={inc.verdict} label={inc.verdict_label} /></td>
                  <td><SeverityBadge severity={inc.severity} /></td>
                  <td><StrengthChip strength={inc.confidence} /></td>
                  <td className="num">{formatInt(inc.findings.length)}</td>
                  <td className="mono nowrap small">{incidentRange(inc, result.capture_start)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="rp-text">No incidents were reconstructed, so there is no per-incident verdict to grade.</p>
      )}
      <div className="rp-method">
        <div className="rp-h4">How verdicts and confidence are decided</div>
        <ul className="text-list">
          {METHOD_NOTES.map((t) => (
            <li key={t}>{t}</li>
          ))}
        </ul>
      </div>
    </section>
  );
}

function IncidentSection({ inc, num, result, index, nav, checks }) {
  const members = inc.findings.map((id) => index.findingsById.get(id)).filter(Boolean);
  const ctx = { captureStart: result.capture_start, duration: result.duration_seconds };
  const openPacket = (finding) => (n) => nav.openPacket(n, { finding, incident: inc.id });
  const services = evidenceServices(inc.findings, result, index);
  const evidenceCount = new Set(inc.findings.flatMap((fid) => index.packetsByFinding.get(fid) || [])).size;
  const limitations = [...new Set([...inc.uncertainty, ...members.flatMap((f) => f.limitations)])];
  const doneCount = inc.recommendations.filter((_, i) => checks?.[`${inc.id}:${i}`]).length;
  const rootFinding = inc.root_finding && index.findingsById.get(inc.root_finding);

  return (
    <article className="rp-incident" id={incidentAnchor(inc.id)}>
      <div className="rp-print-line print-only">
        {result.file} · {inc.id} · {incidentVerdictLabel(inc.verdict, inc.verdict_label)}
      </div>
      <SectionHead num={num} sub>
        <span className="rp-inc-id mono">{inc.id}</span> {inc.title}
      </SectionHead>
      <div className="cluster rp-inc-badges">
        <VerdictBadge verdict={inc.verdict} label={inc.verdict_label} />
        <SeverityBadge severity={inc.severity} />
        <StrengthChip strength={inc.confidence} prefix="Confidence" />
        <span className="xs muted">
          {incidentRange(inc, result.capture_start)} · {plural(inc.findings.length, 'finding')} ·{' '}
          {plural(evidenceCount, 'evidence packet')}
        </span>
      </div>

      {inc.summary && (
        <p className="rp-text rp-summary-text">
          <CitedText text={inc.summary} onOpenPacket={(n) => nav.openPacket(n, { incident: inc.id })} />
        </p>
      )}
      {inc.verdict_notes.length > 0 && (
        <ul className="text-list rp-notes">
          {inc.verdict_notes.map((t) => (
            <li key={t}>{t}</li>
          ))}
        </ul>
      )}

      <Block kicker="Observed" icon={Eye} title="Facts measured in the capture">
        {inc.observed_facts.length ? (
          <ul className="text-list">
            {inc.observed_facts.map((t, i) => (
              <li key={i}><CitedText text={t} onOpenPacket={(n) => nav.openPacket(n, { incident: inc.id })} /></li>
            ))}
          </ul>
        ) : (
          <p className="rp-text muted">The detectors reported no separate observed facts for this incident.</p>
        )}
      </Block>

      <Block kicker="Correlated" tone="correlated" icon={Link2} title="How the findings were linked"
             note={inc.links.length ? 'Links record that the findings share hosts and time; they are not proof that one caused the other.' : null}>
        {inc.links.length ? (
          <ul className="plain-list rp-links">
            {inc.links.map((l, i) => (
              <li key={i}>
                <div className="rp-link-head">
                  <FindingRef id={l.from} title={index.findingsById.get(l.from)?.title} onClick={() => nav.openFinding(l.from)} />
                  <span aria-hidden="true" className="muted">→</span>
                  <span className="sr-only">linked to</span>
                  <FindingRef id={l.to} title={index.findingsById.get(l.to)?.title} onClick={() => nav.openFinding(l.to)} />
                  <Badge tone="neutral">{linkTypeLabel(l.type)}</Badge>
                </div>
                {l.explanation && <p className="rp-text">{l.explanation}</p>}
                {l.basis && <p className="rp-note">Basis: {l.basis}</p>}
              </li>
            ))}
          </ul>
        ) : (
          <p className="rp-text muted">
            {members.length > 1
              ? 'The findings were grouped into this incident, but no explicit link records were reported.'
              : 'This incident consists of a single finding; no correlation was needed.'}
          </p>
        )}
      </Block>

      <Block kicker="Hypotheses · inferred" tone="inferred" icon={Lightbulb} title="Likely root cause and alternatives">
        <dl className="rp-dl">
          {inc.likely_root_cause && (
            <>
              <dt>Likely root cause</dt>
              <dd>
                {inc.likely_root_cause}
                {rootFinding && (
                  <span className="rp-note-inline">
                    {' '}(root finding{' '}
                    <FindingRef id={rootFinding.id} title={rootFinding.title} onClick={() => nav.openFinding(rootFinding.id)} />)
                  </span>
                )}
              </dd>
            </>
          )}
          <dt>Confidence</dt>
          <dd>
            {strengthLabel(inc.confidence)}
            {inc.confidence_reason && <span className="muted"> — {inc.confidence_reason}</span>}
          </dd>
          {inc.impact && (
            <>
              <dt>Likely impact</dt>
              <dd>{inc.impact}</dd>
            </>
          )}
          {inc.alternatives.length > 0 && (
            <>
              <dt>Alternative explanations</dt>
              <dd>
                <ul className="text-list">
                  {inc.alternatives.map((t) => (
                    <li key={t}>{t}</li>
                  ))}
                </ul>
              </dd>
            </>
          )}
        </dl>
        {inc.reasoning.length > 0 && (
          <div className="table-wrap rp-table-wrap">
            <table className="table table-dense rp-table">
              <caption className="rp-caption">Indicators weighed by the detection rules</caption>
              <thead>
                <tr>
                  <th scope="col">Finding</th>
                  <th scope="col">Indicator</th>
                  <th scope="col">Points to</th>
                  <th scope="col">Strength</th>
                </tr>
              </thead>
              <tbody>
                {inc.reasoning.map((r, i) => (
                  <tr key={i}>
                    <td><FindingRef id={r.finding} onClick={r.finding ? () => nav.openFinding(r.finding) : undefined} /></td>
                    <td className="rp-cell-wrap">{r.text}</td>
                    <td><Badge tone={assessmentTone(r.points_to)}>{assessmentLabel(r.points_to)}</Badge></td>
                    <td><StrengthChip strength={r.strength} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Block>

      <div className="rp-two">
        <Block kicker="Observed" icon={Eye} title="Affected hosts">
          {inc.affected_hosts.length ? (
            <table className="table table-dense rp-table rp-table-plain">
              <thead>
                <tr>
                  <th scope="col">Address</th>
                  <th scope="col">Roles in this incident</th>
                </tr>
              </thead>
              <tbody>
                {inc.affected_hosts.map((h) => (
                  <tr key={h.address}>
                    <td className="mono small nowrap">{h.address}</td>
                    <td className="small text-2">{h.roles.map((r) => withAcronyms(humanize(r))).join(', ') || '–'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <p className="rp-text muted">No hosts were attributed to this incident.</p>
          )}
        </Block>
        <Block kicker="Observed" icon={Eye} title="Destination services seen in evidence packets"
               note={services.length > SERVICE_LIMIT ? `Showing the ${SERVICE_LIMIT} busiest of ${services.length} protocol / port pairs.` : null}>
          {services.length ? (
            <table className="table table-dense rp-table rp-table-plain">
              <thead>
                <tr>
                  <th scope="col">Protocol</th>
                  <th scope="col" className="num">Destination port</th>
                  <th scope="col" className="num">Evidence packets</th>
                </tr>
              </thead>
              <tbody>
                {services.slice(0, SERVICE_LIMIT).map((s) => (
                  <tr key={`${s.protocol}|${s.port}`}>
                    <td className="mono small">{s.protocol}</td>
                    <td className="num mono small">{s.port}</td>
                    <td className="num small">{formatInt(s.packets)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <p className="rp-text muted">The evidence packets carry no transport ports (for example ARP frames).</p>
          )}
        </Block>
      </div>

      <Block kicker="Observed" icon={Eye} title="Key technical measurements">
        <MetricsTable members={members} ctx={ctx} nav={nav} />
      </Block>

      <Block kicker="Observed" icon={Eye} title="Investigation timeline">
        <TimelineTable inc={inc} nav={nav} openPacket={openPacket} />
      </Block>

      <Block kicker="Observed" icon={Eye} title="Supporting packet evidence">
        {members.length ? (
          members.map((f) => <EvidenceTable key={f.id} finding={f} result={result} index={index} nav={nav} onOpen={openPacket(f.id)} />)
        ) : (
          <p className="rp-text muted">The findings of this incident are not in the result.</p>
        )}
      </Block>

      <Block kicker="Recommended · inferred" tone="inferred" icon={Lightbulb} title="Recommended remediation"
             note={doneCount ? `${doneCount} of ${inc.recommendations.length} marked done in this session (not saved).` : null}>
        {inc.recommendations.length ? (
          <ol className="rp-recs">
            {inc.recommendations.map((t, i) => {
              const done = Boolean(checks?.[`${inc.id}:${i}`]);
              return (
                <li key={i} className={done ? 'is-done' : ''}>
                  <span className="rp-rec-text">{t}</span>
                  {done && (
                    <span className="rp-done">
                      <Check size={12} aria-hidden="true" /> marked done in this session
                    </span>
                  )}
                </li>
              );
            })}
          </ol>
        ) : (
          <p className="rp-text muted">No remediation steps were reported for this incident.</p>
        )}
      </Block>

      <Block kicker="Caveats" tone="caveat" icon={TriangleAlert} title="Limitations and uncertainty">
        {limitations.length ? (
          <ul className="text-list">
            {limitations.map((t) => (
              <li key={t}>{t}</li>
            ))}
          </ul>
        ) : (
          <p className="rp-text muted">No limitations were reported.</p>
        )}
      </Block>
    </article>
  );
}

/**
 * The incident's timeline, capped at TIMELINE_LIMIT rows. A long timeline keeps its first
 * and last events (like the engine itself does), so the start and the end of the story
 * both stay visible, with one row stating exactly what was left out.
 */
function TimelineTable({ inc, nav, openPacket }) {
  const events = inc.timeline;
  if (!events.length) return <p className="rp-text muted">No timeline events were reported for this incident.</p>;
  const half = Math.floor(TIMELINE_LIMIT / 2);
  const cut = events.length > TIMELINE_LIMIT;
  const head = cut ? events.slice(0, half) : events;
  const tail = cut ? events.slice(-half) : [];
  const omitted = events.length - head.length - tail.length;
  const row = (e, i) => (
    <tr key={i}>
      <td className="num mono small nowrap">{formatOffset(e.relative)}</td>
      <td>{Number.isFinite(e.packet) ? <PacketRef packet={e.packet} onOpen={openPacket(e.finding)} /> : '–'}</td>
      <td><FindingRef id={e.finding} onClick={e.finding ? () => nav.openFinding(e.finding) : undefined} /></td>
      <td className="rp-cell-wrap small">
        {e.role ? <CitedText text={e.role} onOpenPacket={openPacket(e.finding)} /> : e.info || '–'}
      </td>
    </tr>
  );
  return (
    <>
      <div className="table-wrap rp-table-wrap">
        <table className="table table-dense rp-table">
          <thead>
            <tr>
              <th scope="col" className="num">Offset</th>
              <th scope="col">Packet</th>
              <th scope="col">Finding</th>
              <th scope="col">Evidence role</th>
            </tr>
          </thead>
          <tbody>
            {head.map(row)}
            {omitted > 0 && (
              <tr className="rp-gap-row">
                <td colSpan={4}>
                  {plural(omitted, 'event')} between {formatOffset(head[head.length - 1].relative)} and{' '}
                  {formatOffset(tail[0].relative)} not shown here
                </td>
              </tr>
            )}
            {tail.map((e, i) => row(e, head.length + omitted + i))}
          </tbody>
        </table>
      </div>
      {cut && (
        <p className="rp-note">
          Showing the first and last {half} of the {formatInt(events.length)} timeline events the correlation engine
          reported; the Incidents view lists all of them.
        </p>
      )}
    </>
  );
}

/** Scalar measurements per member finding, as compact label / value pairs (two columns). */
function MetricsTable({ members, ctx, nav }) {
  const groups = members.map((f) => ({ f, ...scalarMetrics(f.metrics) })).filter((g) => g.rows.length);
  if (!groups.length) return <p className="rp-text muted">The findings report no scalar measurements.</p>;
  const hidden = groups.reduce((s, g) => s + g.hidden, 0);
  return (
    <div className="rp-metrics">
      {groups.map(({ f, rows }) => (
        <div key={f.id} className="rp-metric-group">
          <div className="rp-metric-head">
            <FindingRef id={f.id} title={f.title} onClick={() => nav.openFinding(f.id)} />
            <span className="rp-metric-title">{f.title}</span>
          </div>
          <dl className="rp-metric-list">
            {rows.map(([k, v]) => (
              <div key={k} className="rp-metric">
                <dt>{metricLabel(k)}</dt>
                <dd className="mono">{formatMetric(v, ctx)}</dd>
              </div>
            ))}
          </dl>
        </div>
      ))}
      {hidden > 0 && (
        <p className="rp-note">
          {plural(hidden, 'further measurement')} (structured breakdowns or beyond the first {METRIC_LIMIT} per finding){' '}
          {hidden === 1 ? 'is' : 'are'} in the finding detail.
        </p>
      )}
    </div>
  );
}

function EvidenceTable({ finding, result, index, nav, onOpen }) {
  const packets = index.packetsByFinding.get(finding.id) || [];
  const roleOf = new Map();
  for (const e of finding.evidence) if (!roleOf.has(e.packet)) roleOf.set(e.packet, e.role);
  const shown = packets.slice(0, EVIDENCE_LIMIT);
  const total = Math.max(finding.evidence_total, packets.length);
  return (
    <div className="rp-evidence">
      <div className="rp-evidence-head">
        <FindingRef id={finding.id} title={finding.title} onClick={() => nav.openFinding(finding.id)} />
        <span className="rp-evidence-title">{finding.title}</span>
        <span className="xs muted nowrap">
          {shown.length < total ? `first ${shown.length} of ${formatInt(total)} packets` : plural(total, 'packet')}
        </span>
        {packets.length > EVIDENCE_LIMIT && (
          <button type="button" className="button button-xs no-print"
                  onClick={() => nav.viewEvidence({ finding: finding.id, incident: index.incidentOfFinding.get(finding.id)?.id || '' })}>
            All evidence
          </button>
        )}
      </div>
      {shown.length ? (
        <div className="table-wrap rp-table-wrap">
          <table className="table table-dense rp-table rp-evidence-table">
            <thead>
              <tr>
                <th scope="col">#</th>
                <th scope="col" className="num">Offset</th>
                <th scope="col">Source → destination</th>
                <th scope="col">Protocol</th>
                <th scope="col">Info</th>
                <th scope="col">Why it is evidence</th>
              </tr>
            </thead>
            <tbody>
              {shown.map((n) => {
                const pkt = result.packets[String(n)];
                return (
                  <tr key={n}>
                    <td><PacketRef packet={n} onOpen={onOpen} /></td>
                    {pkt ? (
                      <>
                        <td className="num mono small nowrap">{formatOffset(pkt.relative)}</td>
                        <td className="mono small rp-cell-endpoints">{endpoints(pkt)}</td>
                        <td className="mono small">{pkt.protocol || '–'}</td>
                        <td className="small rp-cell-wrap">{pkt.info || '–'}</td>
                      </>
                    ) : (
                      <td colSpan={4} className="small muted">Packet summary not included in the result.</td>
                    )}
                    <td className="small text-2 rp-cell-wrap">{roleOf.get(n) ? <CitedText text={roleOf.get(n)} onOpenPacket={onOpen} /> : '–'}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="rp-text muted">No evidence packets were listed for this finding.</p>
      )}
      {finding.evidence_truncated && (
        <p className="rp-note">The detector listed the first {formatInt(finding.evidence.length)} of {formatInt(finding.evidence_total)} evidence packets.</p>
      )}
    </div>
  );
}

function FindingsRegister({ result, index, nav, num }) {
  const findings = result.findings;
  return (
    <section className="rp-section" id="rp-findings" aria-labelledby="rp-findings-h">
      <SectionHead num={num} id="rp-findings-h">Findings register</SectionHead>
      <p className="rp-text muted">Every finding raised by the detectors, ordered by severity, then by time.</p>
      <div className="table-wrap rp-table-wrap">
        <table className="table table-dense rp-table">
          <thead>
            <tr>
              <th scope="col">Finding</th>
              <th scope="col">Title</th>
              <th scope="col">Detector</th>
              <th scope="col">Assessment</th>
              <th scope="col">Severity</th>
              <th scope="col">Strength</th>
              <th scope="col" className="num">Evidence</th>
              <th scope="col">Incident</th>
            </tr>
          </thead>
          <tbody>
            {sortFindings(findings).map((f) => {
              const inc = index.incidentOfFinding.get(f.id);
              return (
                <tr key={f.id}>
                  <td><FindingRef id={f.id} title={f.title} onClick={() => nav.openFinding(f.id)} /></td>
                  <td className="rp-cell-title">{f.title}</td>
                  <td className="mono small nowrap">{f.detector || '–'}</td>
                  <td><Badge tone={assessmentTone(f.assessment)}>{assessmentLabel(f.assessment)}</Badge></td>
                  <td><SeverityBadge severity={f.severity} /></td>
                  <td><StrengthChip strength={f.evidence_strength} /></td>
                  <td className="num small nowrap">{plural(f.evidence_total, 'pkt', 'pkts')}</td>
                  <td>{inc ? <FindingRef id={inc.id} title={inc.title} onClick={() => nav.openIncident(inc.id)} /> : <span className="xs muted">none</span>}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function MethodSection({ result, num }) {
  const { parse } = result;
  // stopped_early is usually repeated as the first warning; print it once.
  const warnings = [...result.warnings];
  if (parse.stopped_early && !warnings.includes(parse.stopped_early)) warnings.unshift(parse.stopped_early);
  return (
    <section className="rp-section" id="rp-method" aria-labelledby="rp-method-h">
      <SectionHead num={num} id="rp-method-h">Capture &amp; method</SectionHead>
      <div className="rp-two">
        <Block title="Parsing">
          <Meta
            className="rp-meta-compact"
            items={[
              ['Malformed packets', formatInt(parse.malformed_packets)],
              ['File truncated', parse.truncated_file ? 'yes' : 'no'],
              ['Resource limit reached', parse.stopped_early ? 'yes' : 'no'],
              ['Parse time', Number.isFinite(parse.parse_seconds) ? formatRunTime(parse.parse_seconds) : 'not reported'],
            ]}
          />
          {warnings.length > 0 ? (
            <ul className="text-list rp-warnings">
              {warnings.map((w) => (
                <li key={w}>{w}</li>
              ))}
            </ul>
          ) : (
            <p className="rp-note">The parser reported no warnings.</p>
          )}
        </Block>
        <Block title="Detectors">
          {result.detectors.length ? (
            <table className="table table-dense rp-table rp-table-plain">
              <thead>
                <tr>
                  <th scope="col">Detector</th>
                  <th scope="col">Status</th>
                  <th scope="col" className="num">Findings</th>
                  <th scope="col" className="num">Run time</th>
                </tr>
              </thead>
              <tbody>
                {result.detectors.map((d) => (
                  <tr key={d.name}>
                    <td className="mono small">{d.name || '–'}</td>
                    <td>
                      {d.status === 'ok'
                        ? <span className="rp-status-ok"><Check size={13} aria-hidden="true" /> Completed</span>
                        : <Badge tone="fault">{humanize(d.status) || 'Not completed'}</Badge>}
                    </td>
                    <td className="num small">{formatInt(d.findings)}</td>
                    <td className="num small nowrap">{formatRunTime(d.seconds)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <p className="rp-text muted">The result lists no detectors.</p>
          )}
        </Block>
      </div>
      <Block title="Scope of this report">
        <p className="rp-text">
          This report covers offline analysis of the uploaded file <span className="mono">{result.file}</span> only. The
          packet summaries it cites contain header metadata (addresses, ports, protocol fields, lengths and timing);
          packet payloads are never stored and are not part of this report. Problems outside the capture point, or below
          the detectors&apos; documented thresholds, are not visible to this analysis.
        </p>
        {result.notice && <p className="rp-text muted">{result.notice}</p>}
      </Block>
    </section>
  );
}

export default function ReportView({ result, index, nav, assessment, checks }) {
  // Real wall-clock time, fixed once per analysis result so re-renders do not change it.
  const generated = useMemo(
    () =>
      new Date().toLocaleString(undefined, {
        year: 'numeric', month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', timeZoneName: 'short',
      }),
    [result],
  );

  const hasIncidents = result.incidents.length > 0;
  const hasFindings = result.findings.length > 0;
  // Section numbers follow what is actually printed: a clean capture gets a short report.
  const num = { summary: 1, assessment: 2 };
  let next = 3;
  if (hasIncidents) num.incidents = next++;
  if (hasFindings) num.findings = next++;
  num.method = next;

  const entries = [
    { id: 'rp-summary', num: num.summary, label: 'Executive summary' },
    { id: 'rp-assessment', num: num.assessment, label: 'Overall assessment & confidence' },
    ...(hasIncidents
      ? [{
          id: 'rp-incidents',
          num: num.incidents,
          label: 'Incident analysis',
          children: result.incidents.map((inc, i) => ({
            id: incidentAnchor(inc.id), num: `${num.incidents}.${i + 1}`, label: `${inc.id} · ${inc.title}`,
          })),
        }]
      : []),
    ...(hasFindings ? [{ id: 'rp-findings', num: num.findings, label: 'Findings register' }] : []),
    { id: 'rp-method', num: num.method, label: 'Capture & method' },
  ];
  const active = useActiveSection(entries.flatMap((e) => [e.id, ...(e.children || []).map((c) => c.id)]));

  return (
    <div className="view rp">
      <PrintPageStyle file={result.file} generated={generated} />
      <Toc entries={entries} active={active} variant="rail" />
      <div className="rp-doc">
        <ReportHeader result={result} assessment={assessment} generated={generated} />
        <Toc entries={entries} active={active} variant="inline" />
        <ExecutiveSummary result={result} index={index} nav={nav} assessment={assessment} num={num} />
        <AssessmentSection result={result} nav={nav} num={num} assessment={assessment} />
        {hasIncidents && (
          <section className="rp-section" id="rp-incidents" aria-labelledby="rp-incidents-h">
            <SectionHead num={num.incidents} id="rp-incidents-h">Incident analysis</SectionHead>
            <p className="rp-text muted">
              Each incident separates what was measured (observed), how findings were grouped (correlated) and what
              that most likely means (inferred).
            </p>
            {result.incidents.map((inc, i) => (
              <IncidentSection key={inc.id} inc={inc} num={`${num.incidents}.${i + 1}`} result={result} index={index}
                               nav={nav} checks={checks} />
            ))}
          </section>
        )}
        {hasFindings && <FindingsRegister result={result} index={index} nav={nav} num={num.findings} />}
        <MethodSection result={result} num={num.method} />
        <p className="rp-end">End of report · {result.file}</p>
      </div>
    </div>
  );
}
