import { useMemo, useRef } from 'react';
import { CircleCheck } from 'lucide-react';
import { sortFindings } from '../derive.js';
import FindingCard from './FindingCard.jsx';
import { EmptyState } from './ui.jsx';

// Tabs are keyed by ASSESSMENT (what the evidence says), not by category (which
// official list the detector belongs to). The card explains any difference.
export const FINDING_TABS = [
  { id: 'attack', label: 'Threats', blurb: 'Findings whose evidence matches documented attack indicators.' },
  { id: 'fault', label: 'Faults', blurb: 'Ordinary network malfunctions: misconfiguration, outages, loss, delay.' },
  { id: 'inconclusive', label: 'Needs investigation', blurb: 'The evidence does not clearly point to a fault or an attack.' },
  { id: 'benign', label: 'Informational', blurb: 'Matched a rule, but the evidence says this is expected behaviour.' },
];

export default function FindingsView({ result, index, tab, onTabChange, onViewEvidence, onOpenIncident }) {
  const tabRefs = useRef({});
  const groups = useMemo(() => {
    const out = Object.fromEntries(FINDING_TABS.map((t) => [t.id, []]));
    for (const f of sortFindings(result.findings)) (out[f.assessment] || out.inconclusive).push(f);
    return out;
  }, [result.findings]);

  const active = FINDING_TABS.find((t) => t.id === tab) || FINDING_TABS[0];
  const list = groups[active.id];

  // Arrow keys move between tabs (WAI-ARIA tabs pattern).
  function onKeyDown(event) {
    const i = FINDING_TABS.findIndex((t) => t.id === active.id);
    let next = null;
    if (event.key === 'ArrowRight') next = FINDING_TABS[(i + 1) % FINDING_TABS.length];
    if (event.key === 'ArrowLeft') next = FINDING_TABS[(i - 1 + FINDING_TABS.length) % FINDING_TABS.length];
    if (event.key === 'Home') next = FINDING_TABS[0];
    if (event.key === 'End') next = FINDING_TABS[FINDING_TABS.length - 1];
    if (next) {
      event.preventDefault();
      onTabChange(next.id);
      tabRefs.current[next.id]?.focus();
    }
  }

  return (
    <div className="view">
      <div className="view-head">
        <h1 id="view-title" tabIndex={-1}>
          Faults &amp; Threats
        </h1>
        <p className="muted">
          Every detector finding, grouped by what its evidence indicates. {result.findings.length} finding
          {result.findings.length === 1 ? '' : 's'} in total.
        </p>
      </div>

      <div role="tablist" aria-label="Finding groups" className="tabs" onKeyDown={onKeyDown}>
        {FINDING_TABS.map((t) => (
          <button
            key={t.id}
            ref={(el) => {
              tabRefs.current[t.id] = el;
            }}
            type="button"
            role="tab"
            id={`tab-${t.id}`}
            aria-selected={t.id === active.id}
            aria-controls={`tabpanel-${t.id}`}
            tabIndex={t.id === active.id ? 0 : -1}
            className={`tab tab-${t.id}`}
            onClick={() => onTabChange(t.id)}
          >
            {t.label} <span className="tab-count">{groups[t.id].length}</span>
          </button>
        ))}
      </div>

      <div role="tabpanel" id={`tabpanel-${active.id}`} aria-labelledby={`tab-${active.id}`} className="tabpanel">
        <p className="muted">{active.blurb}</p>
        {list.length === 0 ? (
          <EmptyState icon={CircleCheck} title={`No ${active.label.toLowerCase()} findings`}>
            <p>No finding in this capture was assessed this way.</p>
          </EmptyState>
        ) : (
          <div className="finding-list">
            {list.map((f) => (
              <FindingCard
                key={f.id}
                finding={f}
                captureStart={result.capture_start}
                incident={index.incidentOfFinding.get(f.id)}
                onViewEvidence={onViewEvidence}
                onOpenIncident={onOpenIncident}
              />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
