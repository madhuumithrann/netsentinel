import { useMemo, useRef } from 'react';
import { ArrowRight, CircleCheck, CircleHelp, FileSearch, GitBranch, ListChecks, Siren } from 'lucide-react';
import {
  formatOffsetRange,
  humanize,
  incidentVerdictLabel,
  linkTypeLabel,
  plural,
  strengthLabel,
} from '../format.js';
import FindingCard from './FindingCard.jsx';
import Timeline from './Timeline.jsx';
import { EmptyState, FindingRef, SeverityBadge, StrengthChip, TextList, VerdictBadge } from './ui.jsx';

// The documented verdict rules from backend/app/correlate.py, shown to the user verbatim
// in spirit so the verdict is never a black box.
const VERDICT_RULE = {
  attack: 'At least one finding is assessed as an attack, and every fault finding in this incident is explained as a side effect of it.',
  mixed: 'At least one finding is assessed as an attack, and at least one fault is NOT explained by the attack, so both problems are present.',
  fault: 'The incident contains fault findings and no finding assessed as an attack.',
  inconclusive: 'The findings in this incident are inconclusive: the evidence supports neither a fault nor an attack strongly enough.',
  benign: 'Only informational findings: the matching traffic is consistent with expected behaviour.',
};

const DIRECTIONS = [
  { id: 'attack', label: 'Points to an attack', tone: 'attack' },
  { id: 'fault', label: 'Points to a fault', tone: 'fault' },
  { id: 'benign', label: 'Points to expected behaviour', tone: 'clean' },
];
const STRENGTH_ORDER = { strong: 0, moderate: 1, weak: 2 };

export default function IncidentsView({ result, index, selectedId, onSelect, onOpenPacket, onViewEvidence, checks, onToggleCheck }) {
  const detailHeading = useRef(null);
  const incidents = result.incidents;
  const selected = incidents.find((i) => i.id === selectedId) || incidents[0];

  if (!incidents.length) {
    return (
      <div className="view">
        <div className="view-head">
          <h1 id="view-title" tabIndex={-1}>
            Incidents
          </h1>
        </div>
        <EmptyState icon={CircleCheck} title="No incidents in this capture">
          <p>No detector rule matched, so there were no findings to correlate into incidents.</p>
        </EmptyState>
      </div>
    );
  }

  return (
    <div className="view">
      <div className="view-head">
        <h1 id="view-title" tabIndex={-1}>
          Incidents
        </h1>
        <p className="muted">
          The incident reconstruction engine groups findings that share hosts, overlap in time and match a documented
          cause-and-effect or attack-chain relationship. {plural(incidents.length, 'incident')} from{' '}
          {plural(result.findings.length, 'finding')}.
        </p>
      </div>
      <div className="incidents-layout">
        <nav aria-label="Incident list" className="incident-list">
          <ul>
            {incidents.map((inc) => (
              <li key={inc.id}>
                <button
                  type="button"
                  className={`incident-item tone-border-${inc.verdict}`}
                  aria-current={selected && inc.id === selected.id ? 'true' : undefined}
                  onClick={() => {
                    onSelect(inc.id);
                    // Move focus to the detail heading (also scrolls it into view on phones).
                    requestAnimationFrame(() => detailHeading.current?.focus());
                  }}
                >
                  <span className="incident-item-top">
                    <code className="ref">{inc.id}</code>
                    <VerdictBadge verdict={inc.verdict} label={inc.verdict_label} />
                  </span>
                  <strong>{inc.title}</strong>
                  <span className="incident-item-meta">
                    <SeverityBadge severity={inc.severity} />
                    <span className="muted small">
                      {plural(inc.findings.length, 'finding')} · {formatOffsetRange(inc.relative_start, inc.relative_end)}
                    </span>
                  </span>
                </button>
              </li>
            ))}
          </ul>
        </nav>
        {selected && (
          <IncidentDetail
            key={selected.id}
            incident={selected}
            result={result}
            index={index}
            headingRef={detailHeading}
            onOpenPacket={onOpenPacket}
            onViewEvidence={onViewEvidence}
            checks={checks}
            onToggleCheck={onToggleCheck}
          />
        )}
      </div>
    </div>
  );
}

function IncidentDetail({ incident: inc, result, index, headingRef, onOpenPacket, onViewEvidence, checks, onToggleCheck }) {
  const { findingsById } = index;
  const members = useMemo(() => inc.findings.map((id) => findingsById.get(id)).filter(Boolean), [inc.findings, findingsById]);
  const reasoning = useMemo(() => {
    const groups = Object.fromEntries(DIRECTIONS.map((d) => [d.id, []]));
    const other = [];
    for (const r of inc.reasoning) (groups[r.points_to] || other).push(r);
    for (const list of [...Object.values(groups), other]) {
      list.sort((a, b) => (STRENGTH_ORDER[a.strength] ?? 3) - (STRENGTH_ORDER[b.strength] ?? 3));
    }
    return { groups, other };
  }, [inc.reasoning]);
  const root = findingsById.get(inc.root_finding);
  const scrollToFinding = (id) => document.getElementById(`member-${id}`)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  const evidenceCount = members.reduce((n, f) => n + f.evidence_total, 0);

  return (
    <article className="incident-detail" aria-labelledby="incident-title">
      <header className={`incident-header tone-border-${inc.verdict}`}>
        <div className="incident-badges">
          <code className="ref">{inc.id}</code>
          <VerdictBadge verdict={inc.verdict} label={inc.verdict_label} />
          <SeverityBadge severity={inc.severity} />
          <StrengthChip strength={inc.confidence} prefix="Confidence" />
        </div>
        <h2 id="incident-title" ref={headingRef} tabIndex={-1}>
          {inc.title}
        </h2>
        <p className="muted small">
          {formatOffsetRange(inc.relative_start, inc.relative_end)} from capture start · {plural(members.length, 'finding')} ·{' '}
          {plural(inc.affected_hosts.length, 'host')} · {plural(evidenceCount, 'evidence packet')}
        </p>
        {inc.confidence_reason && (
          <p className="confidence-reason">
            <strong>Why {strengthLabel(inc.confidence).toLowerCase()} confidence:</strong> {inc.confidence_reason}
          </p>
        )}
      </header>

      {inc.summary && <p className="lead">{inc.summary}</p>}

      <div className="key-grid">
        <section className="key-box">
          <h3>Likely root cause</h3>
          <p>{inc.likely_root_cause || 'Not determined.'}</p>
          {inc.root_finding && (
            <p className="muted small">
              Root finding: <FindingRef id={inc.root_finding} title={root?.title} onClick={() => scrollToFinding(inc.root_finding)} />
              {root ? ` ${root.title}` : ''}
            </p>
          )}
        </section>
        <section className="key-box">
          <h3>Impact</h3>
          <p>{inc.impact || 'Not stated.'}</p>
        </section>
      </div>

      <section className="detail-section" aria-labelledby="why-title">
        <h3 id="why-title">
          <GitBranch size={17} aria-hidden="true" /> Why NetSentinel reached this verdict
        </h3>
        <p className="verdict-rule">
          <strong>{incidentVerdictLabel(inc.verdict, inc.verdict_label)}:</strong> {VERDICT_RULE[inc.verdict] || 'Verdict rule not documented for this value.'}
        </p>

        <div className="reasoning-grid">
          {DIRECTIONS.map((d) => (
            <div key={d.id} className={`reasoning-col tone-${d.tone}`}>
              <h4>
                {d.label} <span className="muted">({reasoning.groups[d.id].length})</span>
              </h4>
              {reasoning.groups[d.id].length === 0 ? (
                <p className="muted small">No indicators.</p>
              ) : (
                <ul>
                  {reasoning.groups[d.id].map((r, i) => (
                    <li key={i}>
                      <span className="reasoning-meta">
                        <StrengthChip strength={r.strength} />
                        <FindingRef id={r.finding} title={findingsById.get(r.finding)?.title} onClick={() => scrollToFinding(r.finding)} />
                      </span>
                      <span>{r.text}</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          ))}
        </div>
        {reasoning.other.length > 0 && (
          <ul className="text-list">
            {reasoning.other.map((r, i) => (
              <li key={i}>
                ({humanize(r.points_to)}, {strengthLabel(r.strength)}) {r.finding}: {r.text}
              </li>
            ))}
          </ul>
        )}
        <p className="muted small">
          Assessment rule: any strong indicator, or two or more moderate ones, decides a direction. When attack and fault
          are both supported, the attack wins only if its support is strictly stronger. Weak indicators alone never
          produce an attack verdict.
        </p>

        {inc.verdict_notes.length > 0 && (
          <div className="sub-block">
            <h4>Verdict notes</h4>
            <TextList items={inc.verdict_notes} />
          </div>
        )}

        <div className="sub-block">
          <h4>Correlation links</h4>
          {inc.links.length === 0 ? (
            <p className="muted small">
              {members.length > 1
                ? 'No explicit links were recorded between these findings.'
                : 'This incident consists of a single finding, so no correlation links were needed.'}
            </p>
          ) : (
            <ul className="link-list">
              {inc.links.map((l, i) => (
                <li key={i}>
                  <div className="link-head">
                    <FindingRef id={l.from} title={findingsById.get(l.from)?.title} onClick={() => scrollToFinding(l.from)} />
                    <ArrowRight size={14} aria-label="to" />
                    <FindingRef id={l.to} title={findingsById.get(l.to)?.title} onClick={() => scrollToFinding(l.to)} />
                    <span className={`badge link-${l.type}`}>{linkTypeLabel(l.type)}</span>
                  </div>
                  <p className="small">
                    {findingsById.get(l.from)?.title || l.from} <span className="muted">→</span>{' '}
                    {findingsById.get(l.to)?.title || l.to}
                  </p>
                  {l.explanation && <p>{l.explanation}</p>}
                  {l.basis && <p className="muted small">Basis: {l.basis}</p>}
                </li>
              ))}
            </ul>
          )}
        </div>
      </section>

      <section className="detail-section" aria-labelledby="timeline-title">
        <div className="section-title-row">
          <h3 id="timeline-title">
            <Siren size={17} aria-hidden="true" /> Reconstructed timeline
          </h3>
          <button type="button" className="button button-ghost" onClick={() => onViewEvidence({ incidentId: inc.id })}>
            <FileSearch size={15} aria-hidden="true" /> All evidence for {inc.id}
          </button>
        </div>
        <Timeline events={inc.timeline} findingsById={findingsById} onOpenPacket={(e) => onOpenPacket(e, inc.id)} />
      </section>

      <div className="grid-2">
        <section className="detail-section" aria-labelledby="hosts-title">
          <h3 id="hosts-title">Affected hosts</h3>
          {inc.affected_hosts.length === 0 ? (
            <p className="muted small">No hosts recorded.</p>
          ) : (
            <ul className="host-list">
              {inc.affected_hosts.map((h) => (
                <li key={h.address}>
                  <code className="addr">{h.address}</code>
                  <span className="chips">
                    {h.roles.map((r) => (
                      <span key={r} className={`chip role-${r}`}>
                        {humanize(r)}
                      </span>
                    ))}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </section>
        <section className="detail-section" aria-labelledby="facts-title">
          <h3 id="facts-title">Observed facts</h3>
          <p className="muted small">Directly measured in the capture.</p>
          {inc.observed_facts.length ? <TextList items={inc.observed_facts} /> : <p className="muted small">None recorded.</p>}
        </section>
      </div>

      <section className="detail-section" aria-labelledby="actions-title">
        <h3 id="actions-title">
          <ListChecks size={17} aria-hidden="true" /> Recommended actions
        </h3>
        {inc.recommendations.length === 0 ? (
          <p className="muted small">No recommendations.</p>
        ) : (
          <ol className="checklist">
            {inc.recommendations.map((rec, i) => {
              const key = `${inc.id}:${i}`;
              return (
                <li key={key}>
                  <label>
                    <input type="checkbox" checked={Boolean(checks[key])} onChange={() => onToggleCheck(key)} />
                    <span className="checklist-n" aria-hidden="true">
                      {i + 1}.
                    </span>
                    <span>{rec}</span>
                  </label>
                </li>
              );
            })}
          </ol>
        )}
        {inc.recommendations.length > 0 && (
          <p className="muted small">Ticks are a working aid for this browser session only; they are not saved or sent.</p>
        )}
      </section>

      <section className="uncertain-box" aria-labelledby="uncertain-title">
        <h3 id="uncertain-title">
          <CircleHelp size={17} aria-hidden="true" /> What we cannot be sure about
        </h3>
        {inc.uncertainty.length === 0 && inc.alternatives.length === 0 ? (
          <p className="small">No limitations were recorded, which does not mean the diagnosis is certain.</p>
        ) : (
          <>
            {inc.uncertainty.length > 0 && (
              <>
                <h4>Limits of the evidence</h4>
                <TextList items={inc.uncertainty} />
              </>
            )}
            {inc.alternatives.length > 0 && (
              <>
                <h4>Other explanations that also fit</h4>
                <TextList items={inc.alternatives} />
              </>
            )}
          </>
        )}
      </section>

      <section className="detail-section" aria-labelledby="members-title">
        <h3 id="members-title">Member findings ({members.length})</h3>
        <div className="finding-list">
          {members.map((f) => (
            <div key={f.id} id={`member-${f.id}`} className="member-anchor">
              <FindingCard finding={f} captureStart={result.capture_start} collapsible onViewEvidence={(id) => onViewEvidence({ findingId: id, incidentId: inc.id })} />
            </div>
          ))}
          {members.length < inc.findings.length && (
            <p className="muted small">
              {inc.findings.length - members.length} referenced finding(s) were not present in the response.
            </p>
          )}
        </div>
      </section>
    </article>
  );
}
