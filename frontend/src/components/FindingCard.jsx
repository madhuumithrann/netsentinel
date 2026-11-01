import { useId } from 'react';
import { ArrowRight, ChevronRight, CircleCheck, Clock, Eye, GitMerge, Info, Lightbulb, ListChecks, Users } from 'lucide-react';
import {
  assessmentLabel,
  assessmentTone,
  categoryNote,
  formatDuration,
  formatInt,
  formatMetric,
  formatOffset,
  formatOffsetRange,
  formatUtc,
  humanize,
  percent,
  plural,
} from '../format.js';
import { AssessmentBadge, PacketRef, RefText, SeverityBadge, StrengthChip } from './ui.jsx';

const PREVIEW_PACKETS = 10;
const MAX_ADDRESSES = 12;
const EPOCH_SUFFIX = ' into the capture';

// Metric keys are snake_case from the detectors; these words read better upper-cased.
const ACRONYMS = new Set(['id', 'ip', 'mac', 'dns', 'ttl', 'tcp', 'udp', 'arp', 'dhcp', 'mtu', 'mss', 'icmp', 'syn', 'rst', 'ack', 'txid']);

/** "rogue_mac" -> "Rogue MAC", "impersonated_ips" -> "Impersonated IPs", "open|filtered" -> "Open | filtered". */
function metricLabel(key) {
  const words = humanize(key).split(/\s+/).map((w) => {
    const lower = w.toLowerCase();
    if (ACRONYMS.has(lower)) return lower.toUpperCase();
    if (lower.endsWith('s') && ACRONYMS.has(lower.slice(0, -1))) return `${lower.slice(0, -1).toUpperCase()}s`;
    return w;
  });
  const text = words.join(' ').replace(/\s*\|\s*/g, ' | ');
  return text.charAt(0).toUpperCase() + text.slice(1);
}

const isScalar = (v) => v == null || ['number', 'string', 'boolean'].includes(typeof v);
const isPlainObject = (v) => v != null && typeof v === 'object' && !Array.isArray(v);

/**
 * A scalar metric as text. A unit is only ever taken from the key name the detector chose
 * ("_seconds", "ratio"); everything else goes through formatMetric, which also turns
 * capture epoch timestamps into offsets.
 */
function scalarText(key, value, ctx) {
  if (value == null) return 'not available';
  if (typeof value === 'number' && value < 1e8) {
    if (/_seconds$/.test(key)) return formatDuration(value);
    if (/(^|_)ratio$/.test(key) && value >= 0 && value <= 1) return percent(value, 1);
  }
  return formatMetric(value, ctx);
}

/** Table cells are labelled already, so "5.000 s into the capture" shortens to "5.000 s". */
function cellText(key, value, ctx) {
  const text = isScalar(value) ? scalarText(key, value, ctx) : formatMetric(value, ctx);
  return text.endsWith(EPOCH_SUFFIX) ? text.slice(0, -EPOCH_SUFFIX.length) : text;
}

/** Splits metrics into a compact scalar grid and readable structured rows. */
function Measurements({ metrics, ctx, Heading }) {
  const entries = Object.entries(metrics);
  if (!entries.length) return null;
  const scalars = entries.filter(([, v]) => isScalar(v));
  const complex = entries.filter(([, v]) => !isScalar(v));
  return (
    <div className="fd-block">
      <Heading className="fd-block-title">Key measurements</Heading>
      {scalars.length > 0 && (
        <dl className="fd-metrics">
          {scalars.map(([k, v]) => (
            <div key={k} className="fd-metric">
              <dt>{metricLabel(k.replace(/_seconds$/, ''))}</dt>
              <dd className={`${typeof v === 'string' ? 'mono' : 'tabular'} ${v == null ? 'faint' : ''}`}>
                {scalarText(k, v, ctx)}
              </dd>
            </div>
          ))}
        </dl>
      )}
      {complex.length > 0 && (
        <dl className="fd-structured">
          {complex.map(([k, v]) => (
            <div key={k} className="fd-structured-row">
              <dt>{metricLabel(k)}</dt>
              <dd><StructuredValue value={v} ctx={ctx} /></dd>
            </div>
          ))}
        </dl>
      )}
    </div>
  );
}

/** Arrays and objects as chips, labelled counts or a mini table; never raw JSON. */
function StructuredValue({ value, ctx }) {
  const none = <span className="faint">none</span>;
  if (Array.isArray(value)) {
    if (!value.length) return none;
    if (value.every(isScalar)) return <Chips items={value.map((v) => formatMetric(v, ctx))} />;
    if (value.every(isPlainObject)) return <MiniTable rows={value} ctx={ctx} />;
    return <span className="text-2">{formatMetric(value, ctx)}</span>;
  }
  const entries = Object.entries(value);
  if (!entries.length) return none;
  // e.g. port-scan outcomes {open: 2, closed: 96, ...}: labelled counts, zeros dimmed.
  if (entries.every(([, v]) => typeof v === 'number')) {
    return (
      <span className="fd-counts">
        {entries.map(([k, v]) => (
          <span key={k} className={`fd-count ${v === 0 ? 'is-zero' : ''}`}>
            <span className="fd-count-value tabular">{formatMetric(v, ctx)}</span>
            <span className="fd-count-label">{metricLabel(k)}</span>
          </span>
        ))}
      </span>
    );
  }
  // e.g. open ports per host {"192.168.1.20": ["22/tcp"]}: one line per key.
  if (entries.every(([, v]) => Array.isArray(v) && v.every(isScalar))) {
    return (
      <span className="fd-keyed">
        {entries.map(([k, list]) => (
          <span key={k} className="fd-keyed-row">
            <code className="fd-keyed-key">{k}</code>
            {list.length ? <Chips items={list.map((v) => formatMetric(v, ctx))} /> : none}
          </span>
        ))}
      </span>
    );
  }
  return <span className="text-2">{formatMetric(value, ctx)}</span>;
}

/** Token-like values (addresses, ports) are set in mono; phrases ("TCP SYN half-open") are not. */
function Chips({ items }) {
  return (
    <span className="chips">
      {items.map((text, i) => (
        <span key={i} className={`chip ${/\s/.test(text) ? '' : 'mono'}`}>{text}</span>
      ))}
    </span>
  );
}

function MiniTable({ rows, ctx }) {
  const columns = [...new Set(rows.flatMap((r) => Object.keys(r)))];
  return (
    <div className="table-wrap fd-mini-table">
      <table className="table table-dense">
        <thead>
          <tr>
            {columns.map((c) => (
              <th key={c} scope="col">{metricLabel(c)}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={i}>
              {columns.map((c) => (
                <td key={c} className="tabular">{cellText(c, r[c], ctx)}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function TextBlock({ title, items, Heading }) {
  if (!items.length) return null;
  return (
    <div className="fd-block">
      <Heading className="fd-block-title">{title}</Heading>
      <ul className="text-list fd-list">
        {items.map((item, i) => (
          <li key={i}>{item}</li>
        ))}
      </ul>
    </div>
  );
}

/**
 * One detector finding. The header (always visible) identifies and classifies it; the
 * body separates what was OBSERVED in the capture from what NetSentinel INFERS from it.
 * Open state is owned by the parent (`open` + `onToggle`).
 */
export default function FindingCard({ finding: f, result, index, nav, open = true, onToggle, highlight = false, headingLevel = 2 }) {
  const uid = useId();
  const h = (n) => `h${Math.min(6, Math.max(1, n))}`;
  const Title = h(headingLevel);
  const Part = h(headingLevel + 1);
  const Sub = h(headingLevel + 2);

  const incident = index?.incidentOfFinding.get(f.id) || null;
  const start = result?.capture_start;
  const ctx = { captureStart: start, duration: result?.duration_seconds };
  const hasTime = Number.isFinite(start) && Number.isFinite(f.time_start);
  const hasEnd = hasTime && Number.isFinite(f.time_end);
  const timeRange = hasTime ? formatOffsetRange(f.time_start - start, hasEnd ? f.time_end - start : null) : '';
  const timeTitle = hasTime
    ? `From the start of the capture. ${formatUtc(f.time_start)}${hasEnd && f.time_end > f.time_start ? ` to ${formatUtc(f.time_end)}` : ''}`
    : undefined;
  const openPacket = (n) => nav.openPacket(n, { finding: f.id, incident: incident?.id || '' });
  const note = categoryNote(f.category, f.assessment);
  const hostEntries = Object.entries(f.hosts).filter(([, v]) => v.length);
  const preview = f.evidence.slice(0, PREVIEW_PACKETS);
  const listed = f.evidence.length;

  return (
    <article id={`finding-${f.id}`} aria-labelledby={`${uid}-title`}
             className={`fd-card rail rail-${assessmentTone(f.assessment)} ${open ? 'is-open' : ''} ${highlight ? 'is-highlight' : ''}`}>
      <header className="fd-head">
        <div className="fd-tags">
          <span className="fd-id">{f.id}</span>
          <SeverityBadge severity={f.severity} />
          <AssessmentBadge assessment={f.assessment} />
          <StrengthChip strength={f.evidence_strength} prefix="Evidence" />
          {f.detector && <span className="chip mono" title="Detector that produced this finding">{f.detector}</span>}
        </div>
        <Title className="fd-title" id={`${uid}-title`} tabIndex={-1}>
          <button type="button" className="fd-toggle" aria-expanded={open} aria-controls={`${uid}-body`} onClick={onToggle}>
            <ChevronRight className="fd-chevron" size={16} aria-hidden="true" />
            <span>{f.title}</span>
          </button>
        </Title>
        <div className="fd-meta">
          {timeRange && (
            <span className="fd-meta-item tabular" title={timeTitle}>
              <Clock size={13} aria-hidden="true" />
              {timeRange}
            </span>
          )}
          <span className="fd-meta-item tabular">{plural(f.evidence_total, 'evidence packet')}</span>
          {incident && (
            <span className="fd-meta-item">
              <GitMerge size={13} aria-hidden="true" />
              Part of
              <button type="button" className="ref ref-button" onClick={() => nav.openIncident(incident.id)}
                      title={`Open incident ${incident.id}: ${incident.title}`}>
                {incident.id}
              </button>
            </span>
          )}
        </div>
        {!open && f.summary && <p className="fd-preview clamp-2">{f.summary}</p>}
      </header>

      <div className="fd-body" id={`${uid}-body`} hidden={!open}>
        <div className="fd-columns">
          <section className="fd-part fd-observed" aria-labelledby={`${uid}-obs`}>
            <Part className="fd-part-title" id={`${uid}-obs`}>
              <Eye size={14} aria-hidden="true" />
              Observed
              <span className="fd-part-note">measured in this capture</span>
            </Part>
            {f.summary && <p className="fd-lead">{f.summary}</p>}
            {f.facts.length > 0 && (
              <div className="fd-block">
                <Sub className="fd-block-title">Facts</Sub>
                <ul className="text-list fd-list">
                  {f.facts.map((fact, i) => (
                    <li key={i}><RefText text={fact} onOpenPacket={(n) => nav.openPacket(n)} /></li>
                  ))}
                </ul>
              </div>
            )}
            <Measurements metrics={f.metrics} ctx={ctx} Heading={Sub} />
            {preview.length > 0 && (
              <div className="fd-block">
                <div className="fd-block-head">
                  <Sub className="fd-block-title">Evidence packets</Sub>
                  <button type="button" className="button button-xs button-secondary no-print"
                          onClick={() => nav.viewEvidence({ finding: f.id })}>
                    All {formatInt(listed)} evidence packets
                    <ArrowRight size={13} aria-hidden="true" />
                  </button>
                </div>
                <div className="table-wrap fd-packets">
                  <table className="table table-dense">
                    <thead>
                      <tr>
                        <th scope="col">Packet</th>
                        <th scope="col" className="num">Time</th>
                        <th scope="col">Why it is evidence</th>
                      </tr>
                    </thead>
                    <tbody>
                      {preview.map((ev, i) => {
                        const rel = result?.packets[String(ev.packet)]?.relative;
                        return (
                          <tr key={`${ev.packet}:${i}`}>
                            <td><PacketRef packet={ev.packet} onOpen={openPacket} /></td>
                            <td className="num nowrap">{Number.isFinite(rel) ? formatOffset(rel) : '–'}</td>
                            <td className="fd-packet-role">{ev.role || <span className="faint">cited by the detector</span>}</td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
                {(listed > preview.length || f.evidence_truncated) && (
                  <p className="fd-note">
                    {listed > preview.length && `First ${preview.length} of ${formatInt(listed)} listed. `}
                    {f.evidence_truncated && f.evidence_total > listed &&
                      `The detector cited ${formatInt(f.evidence_total)} packets; the report keeps the first ${formatInt(listed)}.`}
                  </p>
                )}
              </div>
            )}
          </section>

          <section className="fd-part fd-inferred" aria-labelledby={`${uid}-inf`}>
            <Part className="fd-part-title" id={`${uid}-inf`}>
              <Lightbulb size={14} aria-hidden="true" />
              Inferred
              <span className="fd-part-note">assessment, not proof</span>
            </Part>
            <p className={`fd-category ${note.agrees ? 'agrees' : 'differs'}`}>
              {note.agrees ? <CircleCheck size={14} aria-hidden="true" /> : <Info size={14} aria-hidden="true" />}
              <span>{note.text}</span>
            </p>
            {f.likely_cause && (
              <div className="fd-block">
                <Sub className="fd-block-title">Likely cause</Sub>
                <p className="fd-text">{f.likely_cause}</p>
              </div>
            )}
            {f.impact && (
              <div className="fd-block">
                <Sub className="fd-block-title">Impact</Sub>
                <p className="fd-text">{f.impact}</p>
              </div>
            )}
            {f.indicators.length > 0 && (
              <div className="fd-block">
                <Sub className="fd-block-title">Indicators weighed</Sub>
                <ul className="plain-list fd-indicators">
                  {f.indicators.map((ind, i) => (
                    <li key={i} className="fd-indicator">
                      <div className="fd-indicator-tags">
                        <span className={`badge tone-${assessmentTone(ind.points_to)}`}>
                          Points to {assessmentLabel(ind.points_to).toLowerCase()}
                        </span>
                        <StrengthChip strength={ind.strength} />
                      </div>
                      <p className="fd-indicator-text">{ind.text}</p>
                    </li>
                  ))}
                </ul>
              </div>
            )}
            <TextBlock title="Other possible explanations" items={f.alternatives} Heading={Sub} />
            <TextBlock title="What this capture cannot show" items={f.limitations} Heading={Sub} />
          </section>
        </div>

        {(f.recommendations.length > 0 || hostEntries.length > 0) && (
          <div className={`fd-lower ${f.recommendations.length && hostEntries.length ? '' : 'is-single'}`}>
            {f.recommendations.length > 0 && (
              <section className="fd-part fd-actions" aria-labelledby={`${uid}-act`}>
                <Part className="fd-part-title" id={`${uid}-act`}>
                  <ListChecks size={14} aria-hidden="true" />
                  Recommended actions
                  <span className="fd-part-note">in order</span>
                </Part>
                <ol className="fd-steps">
                  {f.recommendations.map((r, i) => (
                    <li key={i}>{r}</li>
                  ))}
                </ol>
              </section>
            )}
            {hostEntries.length > 0 && (
              <section className="fd-part fd-hosts" aria-labelledby={`${uid}-hosts`}>
                <Part className="fd-part-title" id={`${uid}-hosts`}>
                  <Users size={14} aria-hidden="true" />
                  Hosts involved
                </Part>
                <ul className="plain-list fd-host-grid">
                  {hostEntries.map(([role, addresses]) => (
                    <li key={role} className="fd-host-row">
                      <span className="fd-host-role">{metricLabel(role)}</span>
                      <span className="chips">
                        {addresses.slice(0, MAX_ADDRESSES).map((a) => (
                          <code key={a} className="chip mono">{a}</code>
                        ))}
                        {addresses.length > MAX_ADDRESSES && (
                          <span className="faint xs fd-more">+{formatInt(addresses.length - MAX_ADDRESSES)} more</span>
                        )}
                      </span>
                    </li>
                  ))}
                </ul>
              </section>
            )}
          </div>
        )}

        <footer className="fd-foot">
          <div className="fd-rule">
            <span className="field-label">Detection rule</span>
            <code>{f.rule || 'not stated by the detector'}</code>
          </div>
          <div className="fd-foot-ids">
            <span><span className="faint">Detector</span> <code>{f.detector || 'unknown'}</code></span>
            {f.kind && <span><span className="faint">Kind</span> <code>{f.kind}</code></span>}
          </div>
        </footer>
      </div>
    </article>
  );
}
