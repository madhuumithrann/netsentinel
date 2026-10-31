import { useId, useState } from 'react';
import { ChevronDown, ChevronRight, FileSearch } from 'lucide-react';
import { assessmentTone, categoryNote, formatMetric, formatOffsetRange, humanize, plural } from '../format.js';
import { AssessmentBadge, Field, SeverityBadge, StrengthChip, TextList } from './ui.jsx';

/** "showing 200 of 950 evidence packets" when the backend capped the list. */
export function evidenceCountText(f) {
  if (f.evidence_truncated && f.evidence_total > f.evidence.length) {
    return `showing ${f.evidence.length} of ${f.evidence_total} evidence packets`;
  }
  return plural(f.evidence_total, 'evidence packet');
}

/**
 * One detector finding with its full explanation. `collapsible` renders a compact
 * header that expands on demand (used for incident member findings).
 */
export default function FindingCard({ finding: f, captureStart, incident, onViewEvidence, onOpenIncident, collapsible = false }) {
  const [open, setOpen] = useState(!collapsible);
  const bodyId = useId();
  const note = categoryNote(f.category, f.assessment);
  const rel = (t) => (Number.isFinite(t) && Number.isFinite(captureStart) ? t - captureStart : null);
  const hostEntries = Object.entries(f.hosts).filter(([, v]) => v.length);
  const metricEntries = Object.entries(f.metrics);

  const header = (
    <>
      <span className="finding-head-line">
        <code className="ref">{f.id}</code>
        <SeverityBadge severity={f.severity} />
        <AssessmentBadge assessment={f.assessment} />
        <StrengthChip strength={f.evidence_strength} prefix="Evidence" />
      </span>
      <span className="finding-title">{f.title}</span>
    </>
  );

  return (
    <article className={`finding-card assess-${f.assessment}`} aria-label={`${f.id}: ${f.title}`}>
      {collapsible ? (
        <button type="button" className="finding-toggle" aria-expanded={open} aria-controls={bodyId} onClick={() => setOpen((o) => !o)}>
          {open ? <ChevronDown size={16} aria-hidden="true" /> : <ChevronRight size={16} aria-hidden="true" />}
          <span className="finding-head">{header}</span>
        </button>
      ) : (
        <header className="finding-head">{header}</header>
      )}

      {open && (
        <div className="finding-body" id={bodyId}>
          <p className={`category-note ${note.agrees ? '' : 'is-different'}`}>{note.text}</p>
          {f.summary && <p className="lead">{f.summary}</p>}

          <div className="field-grid">
            <Field label="Likely cause">{f.likely_cause}</Field>
            <Field label="Impact">{f.impact}</Field>
            <Field label="Time in capture">
              {Number.isFinite(rel(f.time_start)) ? formatOffsetRange(rel(f.time_start), rel(f.time_end)) : null}
            </Field>
            {incident && (
              <Field label="Part of incident">
                {onOpenIncident ? (
                  <button type="button" className="link-button" onClick={() => onOpenIncident(incident.id)}>
                    {incident.id}: {incident.title}
                  </button>
                ) : (
                  `${incident.id}: ${incident.title}`
                )}
              </Field>
            )}
          </div>

          {f.recommendations.length > 0 && (
            <div className="sub-block">
              <h4>Recommended actions</h4>
              <TextList items={f.recommendations} ordered />
            </div>
          )}
          {f.facts.length > 0 && (
            <div className="sub-block">
              <h4>Observed facts</h4>
              <TextList items={f.facts} />
            </div>
          )}
          {f.indicators.length > 0 && (
            <div className="sub-block">
              <h4>Indicators weighed</h4>
              <ul className="indicator-list">
                {f.indicators.map((i, n) => (
                  <li key={n}>
                    <span className={`badge tone-${assessmentTone(i.points_to)}`}>
                      points to {humanize(i.points_to)}
                    </span>
                    <StrengthChip strength={i.strength} />
                    <span>{i.text}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
          {(f.limitations.length > 0 || f.alternatives.length > 0) && (
            <div className="sub-block uncertain">
              <h4>Limitations and other explanations</h4>
              <TextList items={[...f.limitations, ...f.alternatives.map((a) => `Alternative: ${a}`)]} />
            </div>
          )}
          {hostEntries.length > 0 && (
            <div className="sub-block">
              <h4>Hosts</h4>
              <dl className="host-roles">
                {hostEntries.map(([role, values]) => (
                  <div key={role}>
                    <dt>{humanize(role)}</dt>
                    <dd>
                      {values.slice(0, 12).map((v) => (
                        <code key={v} className="addr">
                          {v}
                        </code>
                      ))}
                      {values.length > 12 && <span className="muted small">+{values.length - 12} more</span>}
                    </dd>
                  </div>
                ))}
              </dl>
            </div>
          )}
          {metricEntries.length > 0 && (
            <details className="sub-block metrics">
              <summary>Measured values ({metricEntries.length})</summary>
              <dl className="metric-list">
                {metricEntries.map(([k, v]) => (
                  <div key={k}>
                    <dt>{humanize(k)}</dt>
                    <dd className="mono">{formatMetric(v)}</dd>
                  </div>
                ))}
              </dl>
            </details>
          )}

          <footer className="finding-foot">
            <div className="rule">
              <span className="field-label">Rule</span> <span>{f.rule || 'not stated'}</span>
              <span className="muted small">
                {' '}
                · detector <code>{f.detector || 'unknown'}</code>
                {f.kind ? (
                  <>
                    {' '}
                    · <code>{f.kind}</code>
                  </>
                ) : null}
              </span>
            </div>
            <div className="finding-evidence">
              <span className="muted small">{evidenceCountText(f)}</span>
              {onViewEvidence && f.evidence.length > 0 && (
                <button type="button" className="button button-secondary" onClick={() => onViewEvidence(f.id)}>
                  <FileSearch size={15} aria-hidden="true" /> View evidence
                </button>
              )}
            </div>
          </footer>
        </div>
      )}
    </article>
  );
}
