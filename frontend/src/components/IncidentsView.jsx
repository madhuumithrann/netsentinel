import { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import {
  ArrowRight,
  CircleCheck,
  CircleHelp,
  FileSearch,
  FileWarning,
  FileText,
  GitBranch,
  ListChecks,
  Microscope,
  Scale,
  Waypoints,
} from 'lucide-react';
import { captureQuality } from '../derive.js';
import {
  assessmentTone,
  formatInt,
  formatOffsetRange,
  formatUtc,
  humanize,
  incidentVerdictLabel,
  linkTypeLabel,
  plural,
  strengthLabel,
  verdictTone,
} from '../format.js';
import Timeline from './Timeline.jsx';
import {
  AssessmentBadge,
  Badge,
  EmptyState,
  FindingRef,
  PacketRef,
  Panel,
  SeverityBadge,
  StrengthChip,
  TextList,
  VerdictBadge,
} from './ui.jsx';

// The documented verdict rules from backend/app/correlate.py, shown to the user so the
// verdict is never a black box.
const VERDICT_RULE = {
  attack: 'At least one finding is assessed as an attack, and every fault finding in this incident is explained as a side effect of it.',
  mixed: 'At least one finding is assessed as an attack, and at least one fault is NOT explained by the attack, so both problems are present.',
  fault: 'The incident contains fault findings and no finding assessed as an attack.',
  inconclusive: 'The findings in this incident are inconclusive: the evidence supports neither a fault nor an attack strongly enough.',
  benign: 'Only informational findings: the matching traffic is consistent with expected behaviour.',
};

const DIRECTIONS = [
  { id: 'attack', label: 'Points to an attack', tone: 'attack', empty: 'No indicator points to an attack.' },
  { id: 'fault', label: 'Points to a fault', tone: 'fault', empty: 'No indicator points to a fault.' },
  { id: 'benign', label: 'Points to expected behaviour', tone: 'clean', empty: 'No indicator points to expected behaviour.' },
];
const STRENGTH_ORDER = { strong: 0, moderate: 1, weak: 2 };
const REASONS_PREVIEW = 3;
const MEMBER_PACKET_PREVIEW = 6;
const MAC_RE = /^[0-9a-f]{2}([:-][0-9a-f]{2}){5}$/i;

// Detail sections in display order; also drives the "On this incident" jump list.
const SECTIONS = [
  ['verdict', 'Verdict & confidence'],
  ['what', 'What happened'],
  ['why', 'Why NetSentinel believes this'],
  ['links', 'How the findings were linked'],
  ['findings', 'Supporting findings'],
  ['timeline', 'Reconstructed timeline'],
  ['hosts', 'Affected hosts'],
  ['facts', 'Observed facts'],
  ['uncertainty', 'What we cannot be sure about'],
  ['response', 'Recommended response'],
];
const sectionId = (key) => `inc-sec-${key}`;

/** Provenance tag: "Observed" = measured in the capture; the others are NetSentinel's inference. */
function Provenance({ kind }) {
  const text = { observed: 'Observed', inferred: 'Inferred', hypothesis: 'Hypothesis' }[kind];
  const title = kind === 'observed' ? 'Measured directly in this capture' : 'An assessment drawn from the evidence, not a measurement';
  return (
    <span className={`inc-prov inc-prov-${kind}`} title={title}>
      {text}
    </span>
  );
}

/**
 * Exposes the sticky report bar's height as --inc-bar so the incident list can stick just
 * below it and jumped-to sections are not hidden under it (the bar wraps on narrow screens).
 */
function useReportBarOffset(ref) {
  useLayoutEffect(() => {
    const bar = document.querySelector('.report-bar');
    const el = ref.current;
    if (!bar || !el) return undefined;
    const apply = () => el.style.setProperty('--inc-bar', `${bar.offsetHeight}px`);
    apply();
    const ro = new ResizeObserver(apply);
    ro.observe(bar);
    return () => ro.disconnect();
  }, [ref]);
}

/** Key of the detail section currently at the top of the viewport (for the jump list). */
function useActiveSection(incidentId) {
  const [active, setActive] = useState(SECTIONS[0][0]);
  useEffect(() => {
    const els = SECTIONS.map(([key]) => document.getElementById(sectionId(key))).filter(Boolean);
    if (!els.length || typeof IntersectionObserver === 'undefined') return undefined;
    const visible = new Set();
    const io = new IntersectionObserver(
      (entries) => {
        for (const e of entries) (e.isIntersecting ? visible.add(e.target.id) : visible.delete(e.target.id));
        const firstVisible = els.find((el) => visible.has(el.id));
        if (firstVisible) setActive(firstVisible.id.replace('inc-sec-', ''));
      },
      // A band just below the report bar: the first section crossing it is "current".
      { rootMargin: '-120px 0px -55% 0px' },
    );
    els.forEach((el) => io.observe(el));
    setActive(SECTIONS[0][0]);
    return () => io.disconnect();
  }, [incidentId]);
  return active;
}

export default function IncidentsView({ result, index, route, nav, checks, onToggleCheck }) {
  const rootRef = useRef(null);
  const headingRef = useRef(null);
  const focusOnChange = useRef(false);
  const incidents = result.incidents;
  const selected = index.incidentsById.get(route.incident) || incidents[0] || null;

  useReportBarOffset(rootRef);
  const activeSection = useActiveSection(selected?.id);

  // An empty or unknown id in the URL selects the first incident without a history entry.
  useEffect(() => {
    if (selected && route.incident !== selected.id) nav.set({ incident: selected.id }, { replace: true });
  }, [selected, route.incident, nav]);

  // After an explicit selection, move focus to the detail heading and bring the detail into
  // view if the page had been scrolled past its top.
  useEffect(() => {
    if (!focusOnChange.current) return;
    focusOnChange.current = false;
    const h = headingRef.current;
    if (!h) return;
    h.focus({ preventScroll: true });
    const article = h.closest('article');
    if (article && article.getBoundingClientRect().top < 0) article.scrollIntoView({ block: 'start' });
  }, [selected?.id]);

  if (!selected) return <NoIncidents result={result} nav={nav} />;

  const select = (id) => {
    if (id === selected.id) {
      headingRef.current?.focus();
      return;
    }
    focusOnChange.current = true;
    nav.openIncident(id);
  };

  const jumpTo = (key) => {
    const el = document.getElementById(sectionId(key));
    if (!el) return;
    el.scrollIntoView({ block: 'start' });
    el.setAttribute('tabindex', '-1');
    el.focus({ preventScroll: true });
  };

  return (
    <div className="view inc-view" ref={rootRef}>
      <div className="view-head">
        <div>
          <h1 id="view-title" tabIndex={-1}>
            Incidents
          </h1>
          <p className="view-sub">
            {plural(incidents.length, 'incident')} reconstructed from {plural(result.findings.length, 'finding')}
            {verdictSplit(incidents)}. Findings are grouped when they share hosts, overlap in time and match a documented
            cause-and-effect or attack-chain rule.
          </p>
        </div>
      </div>

      <div className="inc-layout">
        <aside className="inc-side no-print">
          <nav aria-label="Incident list" className="inc-side-block">
            <div className="inc-side-label">
              <span className="eyebrow">Incidents</span>
              <span className="xs faint tabular">{formatInt(incidents.length)}</span>
            </div>
            <ul className="plain-list inc-list">
              {incidents.map((inc) => (
                <li key={inc.id}>
                  <IncidentItem incident={inc} current={inc.id === selected.id} onSelect={() => select(inc.id)} />
                </li>
              ))}
            </ul>
          </nav>
          <nav aria-label={`Sections of ${selected.id}`} className="inc-side-block inc-jump">
            <div className="inc-side-label">
              <span className="eyebrow">On this incident</span>
            </div>
            <ul className="plain-list">
              {SECTIONS.map(([key, label]) => (
                <li key={key}>
                  <button type="button" className="inc-jump-item" onClick={() => jumpTo(key)}
                          aria-current={activeSection === key ? 'location' : undefined}>
                    {label}
                  </button>
                </li>
              ))}
            </ul>
          </nav>
        </aside>

        <IncidentDetail key={selected.id} incident={selected} result={result} index={index} nav={nav}
                        headingRef={headingRef} checks={checks} onToggleCheck={onToggleCheck} />
      </div>
    </div>
  );
}

/** ": 1 likely attack, 1 network fault" from the incidents' own verdict labels. */
function verdictSplit(incidents) {
  const counts = new Map();
  for (const inc of incidents) {
    const label = incidentVerdictLabel(inc.verdict).toLowerCase();
    counts.set(label, (counts.get(label) || 0) + 1);
  }
  if (incidents.length < 2) return '';
  return `: ${[...counts].map(([label, n]) => `${formatInt(n)} ${label}`).join(', ')}`;
}

function IncidentItem({ incident: inc, current, onSelect }) {
  return (
    <button type="button" className={`inc-item rail rail-${verdictTone(inc.verdict)}`}
            aria-current={current ? 'true' : undefined} onClick={onSelect}>
      <span className="inc-item-top">
        <code className="inc-item-id">{inc.id}</code>
        <VerdictBadge verdict={inc.verdict} label={inc.verdict_label} />
      </span>
      <span className="inc-item-title clamp-2">{inc.title}</span>
      <span className="inc-item-meta">
        <SeverityBadge severity={inc.severity} />
        <span className="inc-item-sub tabular">
          <span>{plural(inc.findings.length, 'finding')}</span>
          <span>{formatOffsetRange(inc.relative_start, inc.relative_end)}</span>
        </span>
      </span>
    </button>
  );
}

function NoIncidents({ result, nav }) {
  const quality = captureQuality(result);
  const findings = result.findings.length;
  return (
    <div className="view inc-view">
      <div className="view-head">
        <div>
          <h1 id="view-title" tabIndex={-1}>
            Incidents
          </h1>
          <p className="view-sub">Incident reconstruction groups related findings into one investigation.</p>
        </div>
      </div>
      <EmptyState icon={findings ? CircleHelp : quality.incomplete ? FileWarning : CircleCheck}
                  title={quality.incomplete && !findings ? 'No incidents in the readable part of this capture'
                    : 'No incidents were reconstructed from this capture'}>
        <div className="stack" style={{ '--gap': 'var(--sp-3)' }}>
          {findings ? (
            <>
              <p>
                {plural(findings, 'finding')} {findings === 1 ? 'was' : 'were'} reported, but none formed an incident.
                Review {findings === 1 ? 'it' : 'them'} individually.
              </p>
              <p>
                <button type="button" className="button button-sm" onClick={() => nav.go('findings')}>
                  Open Faults &amp; Threats <ArrowRight size={14} aria-hidden="true" />
                </button>
              </p>
            </>
          ) : (
            <p>
              No detector rule matched, so there were no findings to correlate. This is not proof that the network is
              healthy: only the traffic seen at this capture point was analysed.
            </p>
          )}
          {quality.incomplete && <p className="inc-empty-quality">Capture quality: {quality.reasons.join('; ')}.</p>}
        </div>
      </EmptyState>
    </div>
  );
}

function IncidentDetail({ incident: inc, result, index, nav, headingRef, checks, onToggleCheck }) {
  const { findingsById } = index;
  const members = useMemo(() => inc.findings.map((id) => findingsById.get(id)).filter(Boolean), [inc.findings, findingsById]);

  // Unique listed evidence packets across the member findings (a frame can support two).
  const evidence = useMemo(() => {
    const set = new Set();
    for (const f of members) for (const n of index.packetsByFinding.get(f.id) || []) set.add(n);
    return { count: set.size, capped: members.some((f) => f.evidence_truncated) };
  }, [members, index.packetsByFinding]);

  const openFinding = (id) => nav.openFinding(id);
  const findingTitle = (id) => findingsById.get(id)?.title;
  const viewEvidence = () => nav.viewEvidence({ incident: inc.id });
  const tone = verdictTone(inc.verdict);

  return (
    <article className="inc-detail" aria-labelledby="inc-detail-title">
      <header className={`panel inc-header rail rail-${tone}`}>
        <div className="inc-header-top">
          <div className="inc-header-id">
            <span className="eyebrow">
              Incident <span className="inc-header-code">{inc.id}</span>
            </span>
            <h2 id="inc-detail-title" className="inc-title" ref={headingRef} tabIndex={-1}>
              {inc.title}
            </h2>
            <div className="cluster" style={{ '--gap': '6px' }}>
              <VerdictBadge verdict={inc.verdict} label={inc.verdict_label} />
              <SeverityBadge severity={inc.severity} />
              <span className="inc-chip-box">
                <StrengthChip strength={inc.confidence} prefix="Confidence" />
              </span>
            </div>
          </div>
          <div className="inc-header-actions">
            <button type="button" className="button button-sm button-primary" onClick={viewEvidence}>
              <FileSearch size={14} aria-hidden="true" /> All evidence
            </button>
            <button type="button" className="button button-sm" onClick={() => nav.openReport()}>
              <FileText size={14} aria-hidden="true" /> In report
            </button>
          </div>
        </div>

        <dl className="inc-facts">
          <div>
            <dt>Time in capture</dt>
            <dd className="tabular">
              {formatOffsetRange(inc.relative_start, inc.relative_end)}
              {Number.isFinite(inc.time_start) && <span className="inc-facts-sub">from {formatUtc(inc.time_start)}</span>}
            </dd>
          </div>
          <div>
            <dt>Findings</dt>
            <dd className="tabular">{formatInt(inc.findings.length)}</dd>
          </div>
          <div>
            <dt>Hosts</dt>
            <dd className="tabular">{formatInt(inc.affected_hosts.length)}</dd>
          </div>
          <div>
            <dt>Evidence packets</dt>
            <dd className="tabular" title={evidence.capped ? 'At least one finding lists only its first 200 evidence packets' : undefined}>
              {formatInt(evidence.count)}
              {evidence.capped && <span className="inc-facts-sub">listed (some lists capped at 200)</span>}
            </dd>
          </div>
          {inc.kinds.length > 0 && (
            <div className="inc-facts-kinds">
              <dt>Detectors involved</dt>
              <dd className="chips">
                {inc.kinds.map((k) => (
                  <span key={k} className="chip">
                    {humanize(k)}
                  </span>
                ))}
              </dd>
            </div>
          )}
        </dl>
      </header>

      <VerdictSection incident={inc} />
      <WhatHappened incident={inc} rootTitle={findingTitle(inc.root_finding)} onOpenFinding={openFinding} />
      <ReasoningSection incident={inc} findingTitle={findingTitle} onOpenFinding={openFinding} />
      <LinksSection incident={inc} memberCount={members.length} findingTitle={findingTitle} onOpenFinding={openFinding} />

      <Panel id={sectionId('findings')} level={3} title={`Supporting findings (${members.length})`}
             eyebrow="Detector output" className="inc-section" flush>
        <ul className="plain-list inc-members">
          {members.map((f) => (
            <MemberRow key={f.id} finding={f} incident={inc} packets={index.packetsByFinding.get(f.id) || []} nav={nav} />
          ))}
        </ul>
        {members.length < inc.findings.length && (
          <p className="inc-footnote inc-flush-pad">
            {plural(inc.findings.length - members.length, 'referenced finding was', 'referenced findings were')} not present
            in the response.
          </p>
        )}
      </Panel>

      <Panel id={sectionId('timeline')} level={3} title="Reconstructed timeline" eyebrow="Evidence in capture order"
             className="inc-section">
        <Timeline incidentId={inc.id} events={inc.timeline} findingsById={findingsById}
                  onOpenPacket={(n, finding) => nav.openPacket(n, { finding, incident: inc.id })}
                  onOpenRef={(n) => nav.openPacket(n)} onViewEvidence={viewEvidence} />
      </Panel>

      <HostsSection incident={inc} hosts={result.hosts} />

      <Panel id={sectionId('facts')} level={3} title="Observed facts" eyebrow="Observed: measured directly in this capture"
             actions={<Provenance kind="observed" />} className="inc-section">
        {inc.observed_facts.length ? (
          <ul className="plain-list inc-facts-list">
            {inc.observed_facts.map((fact, i) => (
              <li key={i}>{fact}</li>
            ))}
          </ul>
        ) : (
          <p className="muted small">No observed facts were recorded for this incident.</p>
        )}
      </Panel>

      <UncertaintySection incident={inc} />
      <ResponseSection incident={inc} checks={checks} onToggleCheck={onToggleCheck} />
    </article>
  );
}

function VerdictSection({ incident: inc }) {
  return (
    <Panel id={sectionId('verdict')} level={3} title="Verdict & confidence" eyebrow="Fault-versus-attack reasoning"
           actions={<Provenance kind="inferred" />} className="inc-section">
      <div className="inc-pair">
        <div className="inc-pair-cell">
          <div className="inc-pair-head">
            <Scale size={15} aria-hidden="true" />
            <span className="field-label">Verdict</span>
            <VerdictBadge verdict={inc.verdict} label={inc.verdict_label} />
          </div>
          <p className="text-2">
            <span className="inc-rule-label">Rule applied:</span>{' '}
            {VERDICT_RULE[inc.verdict] || 'The rule for this verdict value is not documented in this interface.'}
          </p>
          {inc.verdict_notes.length > 0 && <TextList items={inc.verdict_notes} className="inc-text-list" />}
        </div>
        <div className="inc-pair-cell">
          <div className="inc-pair-head">
            <Microscope size={15} aria-hidden="true" />
            <span className="field-label">Confidence</span>
            <StrengthChip strength={inc.confidence} />
          </div>
          <p className="text-2">
            {inc.confidence_reason || `No reason was given for ${strengthLabel(inc.confidence).toLowerCase()} confidence.`}
          </p>
        </div>
      </div>
    </Panel>
  );
}

function WhatHappened({ incident: inc, rootTitle, onOpenFinding }) {
  return (
    <Panel id={sectionId('what')} level={3} title="What happened" eyebrow="Plain-language diagnosis" className="inc-section">
      <div className="stack" style={{ '--gap': 'var(--sp-4)' }}>
        {inc.summary ? <p className="inc-summary">{inc.summary}</p> : <p className="muted small">No summary was provided.</p>}
        <div className="inc-pair">
          <div className="inc-pair-cell">
            <div className="inc-pair-head">
              <span className="field-label">Likely root cause</span>
              <Provenance kind="hypothesis" />
            </div>
            <p className="text-2">{inc.likely_root_cause || 'Not determined from this capture.'}</p>
            {inc.root_finding && (
              <p className="inc-root">
                <span className="xs muted">Root finding</span>
                <FindingRef id={inc.root_finding} title={rootTitle} onClick={() => onOpenFinding(inc.root_finding)} />
                {rootTitle && <span className="xs text-2 truncate">{rootTitle}</span>}
              </p>
            )}
          </div>
          <div className="inc-pair-cell">
            <div className="inc-pair-head">
              <span className="field-label">Impact</span>
              <Provenance kind="inferred" />
            </div>
            <p className="text-2">{inc.impact || 'Not stated.'}</p>
          </div>
        </div>
      </div>
    </Panel>
  );
}

function ReasoningSection({ incident: inc, findingTitle, onOpenFinding }) {
  const [expanded, setExpanded] = useState({});
  const reasoning = useMemo(() => {
    const groups = Object.fromEntries(DIRECTIONS.map((d) => [d.id, []]));
    const other = [];
    for (const r of inc.reasoning) (groups[r.points_to] || other).push(r);
    // Stable sort: equally strong indicators keep the backend's order.
    for (const list of [...Object.values(groups), other]) {
      list.sort((a, b) => (STRENGTH_ORDER[a.strength] ?? 3) - (STRENGTH_ORDER[b.strength] ?? 3));
    }
    return { groups, other };
  }, [inc.reasoning]);

  return (
    <Panel id={sectionId('why')} level={3} title="Why NetSentinel believes this" eyebrow="Indicators from each finding"
           actions={<Provenance kind="inferred" />} className="inc-section">
      <div className="inc-reasons">
        {DIRECTIONS.map((d) => {
          const items = reasoning.groups[d.id];
          const open = Boolean(expanded[d.id]);
          return (
            <section key={d.id} className={`inc-reason-col inc-dir-${d.tone} ${items.length ? '' : 'is-empty'}`}
                     aria-label={d.label}>
              <h4 className="inc-reason-head">
                <span className={`dot dot-${d.tone}`} aria-hidden="true" />
                {d.label}
                <span className="inc-reason-count tabular">{items.length}</span>
              </h4>
              {items.length === 0 ? (
                <p className="xs faint">{d.empty}</p>
              ) : (
                <ul className="plain-list inc-reason-list">
                  {items.map((r, i) => (
                    <li key={i} className={!open && i >= REASONS_PREVIEW ? 'inc-extra' : undefined}>
                      <div className="inc-reason-meta">
                        <StrengthChip strength={r.strength} />
                        {r.finding && (
                          <FindingRef id={r.finding} title={findingTitle(r.finding)} onClick={() => onOpenFinding(r.finding)} />
                        )}
                      </div>
                      <p className="inc-reason-text">{r.text}</p>
                    </li>
                  ))}
                </ul>
              )}
              {items.length > REASONS_PREVIEW && (
                <button type="button" className="link-button inc-reason-more no-print" aria-expanded={open}
                        onClick={() => setExpanded((s) => ({ ...s, [d.id]: !open }))}>
                  {open ? `Show the strongest ${REASONS_PREVIEW}` : `Show all (${items.length})`}
                </button>
              )}
            </section>
          );
        })}
      </div>
      {reasoning.other.length > 0 && (
        <div className="inc-other">
          <div className="field-label">Other indicators</div>
          <ul className="text-list inc-text-list">
            {reasoning.other.map((r, i) => (
              <li key={i}>
                {r.finding && <code className="ref">{r.finding}</code>} ({humanize(r.points_to)}, {strengthLabel(r.strength)}){' '}
                {r.text}
              </li>
            ))}
          </ul>
        </div>
      )}
      <p className="inc-footnote">
        <Scale size={13} aria-hidden="true" /> Assessment rule: any strong indicator, or two or more moderate ones, decides a
        direction. When attack and fault are both supported, the attack wins only if its support is strictly stronger.
        Weak indicators alone never produce an attack verdict.
      </p>
    </Panel>
  );
}

function LinksSection({ incident: inc, memberCount, findingTitle, onOpenFinding }) {
  const node = (id) => (
    <span className="inc-link-node">
      <FindingRef id={id} title={findingTitle(id)} onClick={() => onOpenFinding(id)} />
      <span className="inc-link-title">{findingTitle(id) || 'Finding not in this response'}</span>
    </span>
  );
  return (
    <Panel id={sectionId('links')} level={3} title="How the findings were linked" eyebrow="Incident reconstruction"
           actions={<Provenance kind="inferred" />} className="inc-section">
      {inc.links.length === 0 ? (
        <p className="muted small">
          {memberCount > 1
            ? 'No explicit links were recorded between these findings.'
            : 'This incident consists of a single finding, so no correlation links were needed.'}
        </p>
      ) : (
        <ol className="plain-list inc-links">
          {inc.links.map((l, i) => (
            <li key={i} className="inc-link">
              <div className="inc-link-head">
                {node(l.from)}
                <span className="inc-link-arrow">
                  <ArrowRight size={14} aria-hidden="true" />
                  <Badge tone="neutral" className="inc-link-type">
                    <Waypoints size={12} aria-hidden="true" /> {linkTypeLabel(l.type)}
                  </Badge>
                  <ArrowRight size={14} aria-hidden="true" />
                </span>
                {node(l.to)}
              </div>
              {l.explanation && <p className="inc-link-text">{l.explanation}</p>}
              {l.basis && (
                <p className="inc-link-basis">
                  <span className="inc-link-basis-label">Basis</span>
                  <span className="mono">{l.basis}</span>
                </p>
              )}
            </li>
          ))}
        </ol>
      )}
      <p className="inc-footnote">
        <GitBranch size={13} aria-hidden="true" /> Findings are linked when they share hosts, fall inside the correlation time
        window and match a documented relationship. That is correlation, not proof that one caused the other.
      </p>
    </Panel>
  );
}

function MemberRow({ finding: f, incident: inc, packets, nav }) {
  const shown = packets.slice(0, MEMBER_PACKET_PREVIEW);
  const more = Math.max(0, f.evidence_total - shown.length);
  return (
    <li className={`inc-member rail rail-${assessmentTone(f.assessment)}`}>
      <div className="inc-member-head">
        <FindingRef id={f.id} title={f.title} onClick={() => nav.openFinding(f.id)} />
        <span className="inc-member-title">{f.title}</span>
        {f.id === inc.root_finding && <Badge tone="accent">Root finding</Badge>}
        <button type="button" className="button button-xs inc-member-btn"
                onClick={() => nav.viewEvidence({ incident: inc.id, finding: f.id })}>
          <FileSearch size={12} aria-hidden="true" /> Evidence
        </button>
      </div>
      <div className="inc-member-meta">
        <SeverityBadge severity={f.severity} />
        <AssessmentBadge assessment={f.assessment} />
        <StrengthChip strength={f.evidence_strength} prefix="Strength" />
        <span className="inc-member-sep" aria-hidden="true" />
        <span className="xs muted tabular nowrap">
          {plural(f.evidence_total, 'evidence packet')}
          {f.evidence_truncated ? ` (first ${formatInt(f.evidence.length)} listed)` : ''}
        </span>
        <span className="inc-member-refs">
          {shown.map((n) => (
            <PacketRef key={n} packet={n} onOpen={(p) => nav.openPacket(p, { finding: f.id, incident: inc.id })} />
          ))}
          {more > 0 && <span className="xs faint tabular">+{formatInt(more)} more</span>}
        </span>
      </div>
    </li>
  );
}

function HostsSection({ incident: inc, hosts }) {
  // Address book built from the capture-wide host table: IP -> host, MAC -> IPs seen with it.
  const book = useMemo(() => {
    const byIp = new Map(hosts.map((h) => [h.ip, h]));
    const ipsOfMac = new Map();
    for (const h of hosts) {
      for (const m of h.macs) {
        const key = m.toLowerCase();
        if (!ipsOfMac.has(key)) ipsOfMac.set(key, []);
        ipsOfMac.get(key).push(h.ip);
      }
    }
    return { byIp, ipsOfMac };
  }, [hosts]);

  return (
    <Panel id={sectionId('hosts')} level={3} title={`Affected hosts (${inc.affected_hosts.length})`}
           eyebrow="Who is involved" className="inc-section" flush>
      {inc.affected_hosts.length === 0 ? (
        <p className="muted small inc-flush-pad">No hosts were recorded for this incident.</p>
      ) : (
        <div className="table-wrap">
          <table className="table table-dense inc-hosts">
            <thead>
              <tr>
                <th scope="col">Address</th>
                <th scope="col">Role in this incident</th>
                <th scope="col">Network role</th>
                <th scope="col">Seen with</th>
              </tr>
            </thead>
            <tbody>
              {inc.affected_hosts.map((h) => {
                const isMac = MAC_RE.test(h.address);
                const host = isMac ? null : book.byIp.get(h.address);
                const ips = isMac ? book.ipsOfMac.get(h.address.toLowerCase()) || [] : [];
                return (
                  <tr key={h.address}>
                    <td className="mono nowrap">
                      <span className="inc-addr-kind">{isMac ? 'MAC' : 'IP'}</span>
                      {h.address}
                    </td>
                    <td>
                      <span className="chips">
                        {h.roles.length ? h.roles.map((r) => <span key={r} className="chip">{humanize(r)}</span>) : <span className="faint">–</span>}
                      </span>
                    </td>
                    <td className="small text-2">
                      {host?.roles.length ? host.roles.join(', ') : <span className="faint">{isMac ? '–' : 'Not identified'}</span>}
                    </td>
                    <td>
                      <SeenWith isMac={isMac} host={host} ips={ips} />
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      <p className="inc-footnote inc-flush-pad">
        Network role and address pairs come from the capture-wide host table; “–” means the capture does not show it.
        Several MACs for one IP can be a spoofing sign or an ordinary change (new device, failover); see the findings.
      </p>
    </Panel>
  );
}

function SeenWith({ isMac, host, ips }) {
  const list = isMac ? ips : host?.macs || [];
  if (!list.length) return <span className="faint small">–</span>;
  const many = list.length > 1;
  return (
    <span className="chips">
      {many && (
        <Badge tone="fault" title={isMac ? 'This MAC address was used with several IP addresses' : 'Several MAC addresses used this IP address'}>
          {list.length} {isMac ? 'IPs' : 'MACs'}
        </Badge>
      )}
      {list.map((a) => (
        <span key={a} className="chip mono">
          {a}
        </span>
      ))}
    </span>
  );
}

function UncertaintySection({ incident: inc }) {
  const empty = !inc.uncertainty.length && !inc.alternatives.length;
  return (
    <Panel id={sectionId('uncertainty')} level={3} title="What we cannot be sure about"
           eyebrow="Alternative explanations and uncertainty" actions={<Provenance kind="inferred" />}
           className="inc-section">
      {empty ? (
        <p className="small text-2">No limitations were recorded, which does not mean the diagnosis is certain.</p>
      ) : (
        <div className="inc-pair">
          {inc.alternatives.length > 0 && (
            <div className="inc-pair-cell">
              <div className="inc-pair-head">
                <CircleHelp size={15} aria-hidden="true" />
                <span className="field-label">Other explanations that also fit</span>
              </div>
              <TextList items={inc.alternatives} className="inc-text-list" />
            </div>
          )}
          {inc.uncertainty.length > 0 && (
            <div className="inc-pair-cell">
              <div className="inc-pair-head">
                <Microscope size={15} aria-hidden="true" />
                <span className="field-label">Limits of the evidence</span>
              </div>
              <TextList items={inc.uncertainty} className="inc-text-list" />
            </div>
          )}
        </div>
      )}
    </Panel>
  );
}

function ResponseSection({ incident: inc, checks, onToggleCheck }) {
  const total = inc.recommendations.length;
  const done = inc.recommendations.filter((_, i) => checks[`${inc.id}:${i}`]).length;
  return (
    <Panel id={sectionId('response')} level={3} title="Recommended response" eyebrow="Suggested fixes, in order"
           actions={
             total > 0 && (
               <span className="inc-progress xs muted tabular" aria-live="polite">
                 <ListChecks size={13} aria-hidden="true" /> {done} of {total} done
               </span>
             )
           }
           className="inc-section">
      {total === 0 ? (
        <p className="muted small">No recommendations were provided for this incident.</p>
      ) : (
        <>
          <ol className="plain-list inc-checklist">
            {inc.recommendations.map((rec, i) => {
              const key = `${inc.id}:${i}`;
              const checked = Boolean(checks[key]);
              return (
                <li key={key} className={checked ? 'is-done' : ''}>
                  <label>
                    <input type="checkbox" className="checkbox" checked={checked} onChange={() => onToggleCheck(key)} />
                    <span className="inc-check-n tabular" aria-hidden="true">
                      {i + 1}
                    </span>
                    <span className="inc-check-text">{rec}</span>
                  </label>
                </li>
              );
            })}
          </ol>
          <p className="inc-footnote">
            Ticks are a working aid for this browser session only: they are not saved or sent anywhere, and a new analysis
            clears them.
          </p>
        </>
      )}
    </Panel>
  );
}
