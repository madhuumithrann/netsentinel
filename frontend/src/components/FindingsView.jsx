import { useEffect, useMemo, useRef, useState } from 'react';
import { ChevronsDownUp, ChevronsUpDown, CircleCheck, CircleHelp, FileText, Network, Search, SearchX, TriangleAlert } from 'lucide-react';
import { ASSESSMENT_GROUPS, assessmentGroup, captureQuality, sortFindings } from '../derive.js';
import { assessmentTone, formatInt, plural, severityRank } from '../format.js';
import FindingCard from './FindingCard.jsx';
import { Callout, EmptyState } from './ui.jsx';

// Tabs are keyed by ASSESSMENT (what the evidence says), not by category (which official
// challenge list the detector belongs to). Each card explains any difference.
const GROUP_INFO = {
  attack: {
    label: 'Attack indicators',
    blurb: 'The evidence matches documented attack indicators. Indicators are not proof of intent: each finding lists the innocent explanations that were weighed.',
  },
  fault: {
    label: 'Network faults',
    blurb: 'Ordinary malfunctions such as outages, packet loss, misconfiguration or delay. The evidence shows no sign of deliberate interference.',
  },
  inconclusive: {
    label: 'Needs investigation',
    blurb: 'The evidence does not clearly point to a fault or to an attack. Check the listed alternatives before acting.',
  },
  benign: {
    label: 'Expected behaviour',
    blurb: 'A detector rule matched, but the evidence indicates normal behaviour. Listed for transparency, not as a problem.',
  },
};

const STRENGTH_RANK = { strong: 0, moderate: 1, weak: 2 };
const byTime = (a, b) => (a.time_start ?? Infinity) - (b.time_start ?? Infinity);
const bySeverity = (a, b) => severityRank(a.severity) - severityRank(b.severity);
const SORTS = {
  severity: { label: 'Severity (highest first)', compare: (a, b) => bySeverity(a, b) || byTime(a, b) },
  time: { label: 'Time (earliest first)', compare: (a, b) => byTime(a, b) || bySeverity(a, b) },
  strength: {
    label: 'Evidence strength (strongest first)',
    compare: (a, b) => (STRENGTH_RANK[a.evidence_strength] ?? 3) - (STRENGTH_RANK[b.evidence_strength] ?? 3) || bySeverity(a, b),
  },
  evidence: { label: 'Evidence packets (most first)', compare: (a, b) => b.evidence_total - a.evidence_total || bySeverity(a, b) },
};

/** Everything the search box matches: id, title, summary, kind, detector and every host address. */
function searchText(f) {
  return [f.id, f.title, f.summary, f.kind, f.detector, ...Object.values(f.hosts).flat()].join(' ').toLowerCase();
}

const sentence = (text) => text.charAt(0).toUpperCase() + text.slice(1);

/** Collapse long lists so the group can be scanned; one or two findings are shown in full. */
const AUTO_OPEN_MAX = 2;
const HIGHLIGHT_MS = 1800;

export default function FindingsView({ result, index, route, nav }) {
  const groups = useMemo(() => {
    const out = Object.fromEntries(ASSESSMENT_GROUPS.map((g) => [g, []]));
    for (const f of sortFindings(result.findings)) out[assessmentGroup(f)].push(f);
    return out;
  }, [result.findings]);

  // Active tab: a valid, non-empty route.tab wins; then the group of a deep-linked finding;
  // then the first group that has findings.
  const focusFinding = index.findingsById.get(route.finding) || null;
  const firstNonEmpty = ASSESSMENT_GROUPS.find((g) => groups[g].length) || '';
  const active = ASSESSMENT_GROUPS.includes(route.tab) && groups[route.tab].length
    ? route.tab
    : focusFinding
      ? assessmentGroup(focusFinding)
      : firstNonEmpty;
  const focusId = focusFinding && assessmentGroup(focusFinding) === active ? focusFinding.id : '';

  // Keep the URL in step with what is shown (replace: this is normalisation, not navigation).
  useEffect(() => {
    if (!active) return;
    const patch = {};
    if (route.tab !== active) patch.tab = active;
    if (route.finding && route.finding !== focusId) patch.finding = '';
    if (Object.keys(patch).length) nav.set(patch, { replace: true });
  }, [active, focusId, route.tab, route.finding, nav]);

  if (!result.findings.length) return <NoFindings result={result} nav={nav} />;

  return (
    <div className="view fd-view">
      <div className="view-head">
        <div>
          <h1 id="view-title" tabIndex={-1}>Faults &amp; Threats</h1>
          <p className="view-sub">
            {plural(result.findings.length, 'finding')} from{' '}
            {plural(new Set(result.findings.map((f) => f.detector || 'unknown')).size, 'detector')}, grouped by what
            each finding&apos;s evidence indicates. Related findings are correlated on the Incidents page.
          </p>
        </div>
      </div>

      <GroupTabs groups={groups} active={active} onSelect={(tab) => nav.set({ tab, finding: '' })} />

      <GroupPanel key={active} group={active} findings={groups[active]} focusId={focusId}
                  result={result} index={index} nav={nav} />
    </div>
  );
}

/** WAI-ARIA tabs: roving tabindex, arrow keys / Home / End move and select; empty groups are skipped. */
function GroupTabs({ groups, active, onSelect }) {
  const refs = useRef({});
  const enabled = ASSESSMENT_GROUPS.filter((g) => groups[g].length);

  function onKeyDown(event) {
    const i = enabled.indexOf(active);
    const moves = {
      ArrowRight: enabled[(i + 1) % enabled.length],
      ArrowLeft: enabled[(i - 1 + enabled.length) % enabled.length],
      Home: enabled[0],
      End: enabled[enabled.length - 1],
    };
    const next = moves[event.key];
    if (!next) return;
    event.preventDefault();
    refs.current[next]?.focus();
    if (next !== active) onSelect(next);
  }

  return (
    <div role="tablist" aria-label="Finding groups" className="tabs fd-tabs" onKeyDown={onKeyDown}>
      {ASSESSMENT_GROUPS.map((g) => {
        const count = groups[g].length;
        const selected = g === active;
        return (
          <button
            key={g}
            ref={(el) => {
              refs.current[g] = el;
            }}
            type="button"
            role="tab"
            id={`fd-tab-${g}`}
            aria-selected={selected}
            aria-controls={selected ? `fd-panel-${g}` : undefined}
            tabIndex={selected ? 0 : -1}
            disabled={!count}
            title={count ? undefined : 'No finding in this capture was assessed this way'}
            className={`tab fd-tab ${count ? '' : 'is-empty'}`}
            onClick={() => !selected && onSelect(g)}
          >
            <span className={`dot dot-${assessmentTone(g)}`} aria-hidden="true" />
            {GROUP_INFO[g].label}
            <span className="nav-count">{formatInt(count)}</span>
          </button>
        );
      })}
    </div>
  );
}

/** The one rendered tabpanel: explanation, toolbar and the (filtered, sorted) cards. */
function GroupPanel({ group, findings, focusId, result, index, nav }) {
  const [query, setQuery] = useState('');
  const [detector, setDetector] = useState('');
  const [sort, setSort] = useState('severity');
  // Explicit open/closed choices; anything not listed falls back to the default rule.
  const [openState, setOpenState] = useState({});
  const [highlightId, setHighlightId] = useState('');

  const detectors = useMemo(() => {
    const counts = new Map();
    for (const f of findings) counts.set(f.detector || 'unknown', (counts.get(f.detector || 'unknown') || 0) + 1);
    return [...counts].sort((a, b) => a[0].localeCompare(b[0]));
  }, [findings]);

  const searchIndex = useMemo(() => new Map(findings.map((f) => [f.id, searchText(f)])), [findings]);
  const q = query.trim().toLowerCase();
  const visible = useMemo(() => {
    const rows = findings.filter(
      (f) => (!detector || (f.detector || 'unknown') === detector) && (!q || searchIndex.get(f.id).includes(q)),
    );
    return rows.sort(SORTS[sort].compare);
  }, [findings, detector, q, sort, searchIndex]);
  const filtered = Boolean(q || detector);

  const isOpen = (id) => openState[id] ?? (findings.length <= AUTO_OPEN_MAX || id === focusId);
  const setAll = (open) => setOpenState(Object.fromEntries(visible.map((f) => [f.id, open])));
  const openCount = visible.filter((f) => isOpen(f.id)).length;

  // A deep-linked finding (route.finding): make sure it is visible and open, then bring it
  // into view, move focus to its heading and highlight it briefly. Keyed on the id only, so
  // it runs once per target (StrictMode's mount/unmount/mount simply repeats it).
  const visibleRef = useRef(visible);
  visibleRef.current = visible;
  useEffect(() => {
    if (!focusId) return undefined;
    setOpenState((s) => ({ ...s, [focusId]: true }));
    setHighlightId(focusId);
    if (!visibleRef.current.some((f) => f.id === focusId)) {
      setQuery('');
      setDetector('');
    }
    const frame = requestAnimationFrame(() => {
      const card = document.getElementById(`finding-${focusId}`);
      if (!card) return;
      const reduce = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;
      card.querySelector('.fd-title')?.focus({ preventScroll: true });
      // The sticky report bar wraps on narrow screens, so its real height is measured.
      const bar = document.querySelector('.report-bar');
      const offset = (bar && getComputedStyle(bar).position === 'sticky' ? bar.offsetHeight : 0) + 16;
      const top = card.getBoundingClientRect().top + window.scrollY - offset;
      window.scrollTo({ top: Math.max(0, top), behavior: reduce ? 'auto' : 'smooth' });
    });
    return () => cancelAnimationFrame(frame);
  }, [focusId]);

  useEffect(() => {
    if (!highlightId) return undefined;
    const timer = setTimeout(() => setHighlightId(''), HIGHLIGHT_MS);
    return () => clearTimeout(timer);
  }, [highlightId]);

  const info = GROUP_INFO[group];
  return (
    <div role="tabpanel" id={`fd-panel-${group}`} aria-labelledby={`fd-tab-${group}`} className="fd-panel">
      <p className="fd-group-blurb">
        <span className={`dot dot-${assessmentTone(group)}`} aria-hidden="true" />
        {info.blurb}
      </p>

      {findings.length > 1 && (
        <div className="fd-toolbar">
          <div className="filters fd-filters" role="search" aria-label={`Filter ${info.label.toLowerCase()}`}>
            <label className="filter filter-grow">
              <span className="field-label">Search</span>
              <span className="fd-search">
                <Search size={14} aria-hidden="true" />
                <input type="search" className="input" value={query} onChange={(e) => setQuery(e.target.value)}
                       placeholder="ID, title, host address, kind, detector" />
              </span>
            </label>
            <label className="filter">
              <span className="field-label">Detector</span>
              <select className="select" value={detector} onChange={(e) => setDetector(e.target.value)}>
                <option value="">All detectors ({formatInt(findings.length)})</option>
                {detectors.map(([name, n]) => (
                  <option key={name} value={name}>{name} ({formatInt(n)})</option>
                ))}
              </select>
            </label>
            <label className="filter">
              <span className="field-label">Sort by</span>
              <select className="select" value={sort} onChange={(e) => setSort(e.target.value)}>
                {Object.entries(SORTS).map(([key, s]) => (
                  <option key={key} value={key}>{s.label}</option>
                ))}
              </select>
            </label>
          </div>
          <div className="fd-toolbar-foot">
            <span className="small muted" aria-live="polite">
              {filtered
                ? `Showing ${formatInt(visible.length)} of ${plural(findings.length, 'finding')}`
                : plural(findings.length, 'finding')}
            </span>
            {visible.length > 1 && (
              <span className="cluster no-print">
                <button type="button" className="button button-ghost button-xs" onClick={() => setAll(true)}
                        disabled={openCount === visible.length}>
                  <ChevronsUpDown size={13} aria-hidden="true" /> Expand all
                </button>
                <button type="button" className="button button-ghost button-xs" onClick={() => setAll(false)}
                        disabled={openCount === 0}>
                  <ChevronsDownUp size={13} aria-hidden="true" /> Collapse all
                </button>
              </span>
            )}
          </div>
        </div>
      )}

      {visible.length ? (
        <div className="fd-cards">
          {visible.map((f) => (
            <FindingCard key={f.id} finding={f} result={result} index={index} nav={nav} headingLevel={2}
                         open={isOpen(f.id)} highlight={f.id === highlightId}
                         onToggle={() => setOpenState((s) => ({ ...s, [f.id]: !isOpen(f.id) }))} />
          ))}
        </div>
      ) : (
        <EmptyState icon={SearchX} title="No finding matches these filters">
          <p>Nothing in {info.label.toLowerCase()} matches {q ? `"${query.trim()}"` : 'the filter'}{q && detector ? ' with this detector' : ''}.</p>
          <button type="button" className="button button-sm fd-empty-action"
                  onClick={() => { setQuery(''); setDetector(''); }}>
            Clear filters
          </button>
        </EmptyState>
      )}
    </div>
  );
}

/**
 * No detector rule matched. Says plainly what that does and does not mean, and why the
 * result may be incomplete when the parser reported problems.
 */
function NoFindings({ result, nav }) {
  const quality = captureQuality(result);
  const ran = result.detectors.filter((d) => d.name);
  const failed = ran.filter((d) => !['ok', 'unknown'].includes(d.status));
  return (
    <div className="view fd-view">
      <div className="view-head">
        <div>
          <h1 id="view-title" tabIndex={-1}>Faults &amp; Threats</h1>
          <p className="view-sub">Detector findings, grouped by what their evidence indicates.</p>
        </div>
      </div>

      {quality.incomplete && (
        <Callout tone="fault" icon={TriangleAlert} title="The capture could not be analysed completely">
          {sentence(quality.reasons.join('; '))}. A missing finding may simply mean the relevant packets were not readable.
        </Callout>
      )}

      <EmptyState icon={quality.incomplete ? CircleHelp : CircleCheck}
                  title={quality.empty ? 'No packets to analyse'
                    : quality.incomplete ? 'No faults or threats found in the readable part'
                      : 'No faults or threats were detected'}>
        {quality.empty ? (
          <p>The capture holds no packets, so there is nothing to diagnose.</p>
        ) : (
          <>
            <p>
              None of the {ran.length ? plural(ran.length, 'detector') : 'detectors'} found traffic matching its rules in{' '}
              {plural(result.packets_analyzed, 'packet')}. This means no known fault or attack pattern was seen from this
              capture point; it is not proof that the network is healthy.
            </p>
            {failed.length > 0 && (
              <p className="fd-empty-warn">
                {plural(failed.length, 'detector')} did not finish ({failed.map((d) => d.name).join(', ')}), so
                {failed.length === 1 ? ' its' : ' their'} checks are missing from this result.
              </p>
            )}
          </>
        )}
        {ran.length > 0 && (
          <div className="fd-detectors">
            <span className="field-label" id="fd-detectors-label">Detectors run</span>
            <ul className="chips fd-detector-chips" aria-labelledby="fd-detectors-label">
              {ran.map((d) => (
                <li key={d.name} className="chip mono">{d.name}</li>
              ))}
            </ul>
          </div>
        )}
        {!quality.empty && (
          <div className="cluster fd-empty-actions">
            <button type="button" className="button button-sm" onClick={() => nav.go('traffic')}>
              <Network size={14} aria-hidden="true" /> Review traffic
            </button>
            <button type="button" className="button button-sm button-ghost" onClick={() => nav.openReport()}>
              <FileText size={14} aria-hidden="true" /> Open report
            </button>
          </div>
        )}
      </EmptyState>
    </div>
  );
}
