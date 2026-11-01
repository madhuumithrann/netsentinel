import {
  AlertTriangle, ArrowRight, Check, CircleDashed, CircleHelp, CircleX, FileText, FileWarning, ShieldAlert, ShieldCheck,
  Wrench,
} from 'lucide-react';
import {
  SEVERITIES, formatBytes, formatDuration, formatInt, formatOffsetRange, formatRunTime, formatUtc, humanize, plural, severityLabel,
  severityRank,
} from '../format.js';
import { ProtocolBars, TrafficChart } from './Charts.jsx';
import { COVERAGE } from './Landing.jsx';
import { Callout, Panel, SeverityBadge, Stat, StrengthChip, VerdictBadge } from './ui.jsx';

const KIND_ICON = {
  attack: ShieldAlert, mixed: ShieldAlert, fault: Wrench, inconclusive: CircleHelp, clean: ShieldCheck, incomplete: FileWarning,
};
const VERDICT_RANK = { attack: 0, mixed: 0, fault: 1, inconclusive: 2, benign: 3 };
const CONFIDENCE_RANK = { strong: 0, moderate: 1, weak: 2 };
const PREVIEW_MAX = 6;

/**
 * Most important incident first: anything with attack indicators (attack or mixed), then
 * severity, then fault before "needs investigation" before benign, then confidence, then
 * the earliest. Deterministic, so the hero's CTA and the list always agree.
 */
function byImportance(a, b) {
  const attackish = (i) => (VERDICT_RANK[i.verdict] === 0 ? 0 : 1);
  return (
    attackish(a) - attackish(b) ||
    severityRank(a.severity) - severityRank(b.severity) ||
    (VERDICT_RANK[a.verdict] ?? 4) - (VERDICT_RANK[b.verdict] ?? 4) ||
    (CONFIDENCE_RANK[a.confidence] ?? 3) - (CONFIDENCE_RANK[b.confidence] ?? 3) ||
    (a.relative_start ?? Number.MAX_VALUE) - (b.relative_start ?? Number.MAX_VALUE) ||
    a.id.localeCompare(b.id)
  );
}

/** Incident-count chips for the hero; only non-zero kinds are shown. */
const COUNT_CHIPS = [
  ['attack', 'attack', (n) => plural(n, 'attack incident')],
  ['fault', 'fault', (n) => plural(n, 'fault incident')],
  ['inconclusive', 'inconclusive', (n) => `${formatInt(n)} ${n === 1 ? 'needs' : 'need'} investigation`],
  ['benign', 'clean', (n) => `${formatInt(n)} expected behaviour`],
];

/** Finding groups, keyed like the Faults & Threats tabs, with the summary field that counts them. */
const FINDING_GROUPS = [
  { tab: 'attack', field: 'attacks', tone: 'attack', label: 'Attack indicators', note: 'matches documented attack patterns' },
  { tab: 'fault', field: 'faults', tone: 'fault', label: 'Faults', note: 'ordinary network malfunction' },
  { tab: 'inconclusive', field: 'inconclusive', tone: 'inconclusive', label: 'Needs investigation', note: 'evidence points both ways' },
  { tab: 'benign', field: 'benign', tone: 'clean', label: 'Expected behaviour', note: 'explained by normal operation' },
];

const isMac = (a) => /^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/i.test(a);
const roleLabel = (r) => humanize(r).replace(/\bmac\b/gi, 'MAC').replace(/\bdns\b/gi, 'DNS').replace(/\bdhcp\b/gi, 'DHCP');

/** IP addresses before MAC addresses (backend order otherwise), so the preview names hosts people recognise. */
function previewHosts(hosts, max) {
  const ordered = [...hosts.filter((h) => !isMac(h.address)), ...hosts.filter((h) => isMac(h.address))];
  return { shown: ordered.slice(0, max), more: Math.max(0, ordered.length - max) };
}

/* ---------- verdict hero ---------- */

function VerdictHero({ result, assessment, top, nav }) {
  const { kind, counts, quality } = assessment;
  const Icon = KIND_ICON[kind] || CircleHelp;
  const chips = COUNT_CHIPS.filter(([key]) => counts[key] > 0);
  const detectorsOk = result.detectors.filter((d) => d.status === 'ok').length;
  const nothingFound = result.findings.length === 0;

  return (
    <section className={`ov-hero is-${kind}`} aria-labelledby="ov-verdict-label">
      <span className={`ov-hero-icon tone-${assessment.tone}`} aria-hidden="true">
        <Icon size={22} />
      </span>
      <div className="ov-hero-body">
        <div className="eyebrow">Capture verdict</div>
        <h2 id="ov-verdict-label" className="ov-hero-label">{assessment.label}</h2>
        {assessment.headline && <p className="ov-hero-headline">{assessment.headline}</p>}

        {chips.length > 0 && (
          <ul className="plain-list ov-hero-chips" aria-label="Incidents by verdict">
            {chips.map(([key, tone, text]) => (
              <li key={key} className="chip">
                <span className={`dot dot-${tone}`} aria-hidden="true" />
                {text(counts[key])}
              </li>
            ))}
          </ul>
        )}

        {top && (
          <div className="ov-hero-top">
            <span className="eyebrow">Most serious</span>
            <code className="ref">{top.id}</code>
            <span className="ov-hero-top-title truncate" title={top.title}>{top.title}</span>
            <SeverityBadge severity={top.severity} />
            <StrengthChip strength={top.confidence} prefix="Confidence" />
          </div>
        )}

        {nothingFound && result.detectors.length > 0 && (
          <p className="small muted">
            {detectorsOk} of {plural(result.detectors.length, 'detector')} completed without a match
            {quality.incomplete ? ' on the part of the capture that could be read' : ''}.
          </p>
        )}

        {quality.incomplete && (
          <div className="ov-hero-caveat">
            <AlertTriangle size={14} aria-hidden="true" />
            <span>
              <strong>Capture quality:</strong> {quality.reasons.join('; ')}. Results only cover what could be read, so the
              absence of a finding is weak evidence here.
            </span>
          </div>
        )}
      </div>

      <div className="ov-hero-actions">
        {top && (
          <button type="button" className="button button-primary" onClick={() => nav.openIncident(top.id)}>
            Investigate {top.id} <ArrowRight size={15} aria-hidden="true" />
          </button>
        )}
        {!top && !nothingFound && (
          <button type="button" className="button button-primary" onClick={() => nav.go('findings')}>
            Review findings <ArrowRight size={15} aria-hidden="true" />
          </button>
        )}
        <button type="button" className="button button-secondary" onClick={nav.openReport}>
          <FileText size={15} aria-hidden="true" /> Open report
        </button>
      </div>
    </section>
  );
}

/* ---------- key stats ---------- */

function KeyStats({ result, evidenceCount }) {
  const { parse, summary } = result;
  const packetsSub = [result.format && `${result.format.toUpperCase()} file`,
    parse.malformed_packets > 0 && `${formatInt(parse.malformed_packets)} malformed`].filter(Boolean).join(' · ');
  return (
    <section className="ov-stats" aria-label="Key figures">
      <Stat label="Packets analysed" value={formatInt(result.packets_analyzed)} sub={packetsSub || undefined} />
      <Stat label="Capture duration" value={formatDuration(result.duration_seconds)}
            sub={result.packets_analyzed < 2 ? 'fewer than 2 packets: no time span'
              : result.capture_start != null ? `from ${formatUtc(result.capture_start)}` : undefined} />
      <Stat label="Analysis time" value={formatRunTime(result.analysis_seconds)}
            sub={Number.isFinite(parse.parse_seconds) ? `parsing ${formatRunTime(parse.parse_seconds)}` : undefined} />
      <Stat label="Findings" value={formatInt(summary.findings)}
            sub={summary.findings ? `${plural(evidenceCount, 'packet')} cited as evidence` : 'no detector rule matched'} />
      <Stat label="Incidents" value={formatInt(result.incidents.length)}
            sub={result.incidents.length ? `correlated from ${plural(summary.findings, 'finding')}` : 'nothing to correlate'} />
    </section>
  );
}

/* ---------- incidents preview ---------- */

/** `detailed` (when only one or two incidents are listed) adds the inferred cause and the first recommended step. */
function IncidentCard({ inc, nav, detailed }) {
  const { shown, more } = previewHosts(inc.affected_hosts, 3);
  const timed = Number.isFinite(inc.relative_start);
  return (
    <li className={`ov-inc rail rail-${inc.verdict}`}>
      <div className="ov-inc-head">
        <code className="ref">{inc.id}</code>
        <VerdictBadge verdict={inc.verdict} label={inc.verdict_label} />
        <SeverityBadge severity={inc.severity} />
        <StrengthChip strength={inc.confidence} prefix="Confidence" />
        <span className="ov-inc-meta xs muted">
          {plural(inc.findings.length, 'finding')}
          {timed && (
            <span className="tabular" title="Seconds from the first packet of the capture">
              {' · '}{formatOffsetRange(inc.relative_start, inc.relative_end)}
            </span>
          )}
        </span>
      </div>
      <h3 className="ov-inc-title">{inc.title}</h3>
      {inc.summary && <p className="ov-inc-summary clamp-2">{inc.summary}</p>}
      {detailed && (inc.likely_root_cause || inc.recommendations.length > 0) && (
        <dl className="ov-inc-detail">
          {inc.likely_root_cause && (
            <div>
              <dt>Likely cause <span className="ov-inferred">inferred</span></dt>
              <dd className="clamp-2" title={inc.likely_root_cause}>{inc.likely_root_cause}</dd>
            </div>
          )}
          {inc.recommendations.length > 0 && (
            <div>
              <dt>First step{inc.recommendations.length > 1 ? ` of ${inc.recommendations.length}` : ''}</dt>
              <dd className="clamp-2" title={inc.recommendations[0]}>{inc.recommendations[0]}</dd>
            </div>
          )}
        </dl>
      )}
      <div className="ov-inc-foot">
        {shown.length > 0 && (
          <ul className="plain-list ov-inc-hosts" aria-label="Affected hosts">
            {shown.map((h) => (
              <li key={h.address} className="ov-host" title={`${h.address}${h.roles.length ? `: ${h.roles.map(roleLabel).join(', ')}` : ''}`}>
                <code>{h.address}</code>
                {h.roles.length > 0 && <span className="ov-host-role">{h.roles.slice(0, 2).map(roleLabel).join(', ')}</span>}
              </li>
            ))}
            {more > 0 && <li className="xs muted nowrap">+{more} more</li>}
          </ul>
        )}
        <button type="button" className="button button-sm ov-inc-open" onClick={() => nav.openIncident(inc.id)}
                aria-label={`Investigate ${inc.id}: ${inc.title}`}>
          Investigate <ArrowRight size={14} aria-hidden="true" />
        </button>
      </div>
    </li>
  );
}

function IncidentsPreview({ result, ranked, nav }) {
  const shown = ranked.slice(0, PREVIEW_MAX);
  return (
    <Panel title="Incidents" eyebrow="Correlated findings, most important first" id="ov-incidents" className="ov-incidents"
           actions={result.incidents.length > 0 && <span className="xs muted">{plural(result.incidents.length, 'incident')}</span>}>
      {shown.length === 0 ? (
        <p className="muted small">
          No incidents were reconstructed.{' '}
          {result.findings.length > 0 && (
            <>
              The {plural(result.findings.length, 'finding')} are listed in{' '}
              <button type="button" className="link-button" onClick={() => nav.go('findings')}>Faults &amp; Threats</button>.
            </>
          )}
        </p>
      ) : (
        <ul className="plain-list ov-inc-list">
          {shown.map((inc) => <IncidentCard key={inc.id} inc={inc} nav={nav} detailed={shown.length <= 2} />)}
        </ul>
      )}
      <div className="panel-foot row-between ov-incidents-foot">
        <span>Incidents group findings that share hosts and time. Correlation alone does not prove one caused another.</span>
        {ranked.length > shown.length && (
          <button type="button" className="link-button" onClick={() => nav.go('incidents')}>
            All {plural(ranked.length, 'incident')} <ArrowRight size={13} aria-hidden="true" />
          </button>
        )}
      </div>
    </Panel>
  );
}

/* ---------- findings breakdown ---------- */

function FindingsBreakdown({ result, evidenceCount, nav }) {
  const { summary } = result;
  const total = SEVERITIES.reduce((s, k) => s + (summary.by_severity[k] || 0), 0);
  const sevText = SEVERITIES.filter((s) => summary.by_severity[s]).map((s) => `${summary.by_severity[s]} ${severityLabel(s).toLowerCase()}`);
  const openTab = (tab) => nav.set({ view: 'findings', tab, finding: '', incident: '', packet: null, q: '' });

  return (
    <Panel title="Findings" eyebrow="What each detector concluded" id="ov-findings" className="ov-findings"
           actions={<span className="xs muted">{plural(summary.findings, 'finding')}</span>}>
      <ul className="plain-list ov-groups">
        {FINDING_GROUPS.map((g) => {
          const n = summary[g.field] || 0;
          const body = (
            <>
              <span className={`dot dot-${g.tone}`} aria-hidden="true" />
              <span className="ov-group-label">
                <span className="ov-group-name">{g.label}</span>
                <span className="xs muted">{g.note}</span>
              </span>
              <span className="ov-group-count tabular">{formatInt(n)}</span>
            </>
          );
          return (
            <li key={g.tab}>
              {n > 0 ? (
                <button type="button" className="ov-group" onClick={() => openTab(g.tab)}
                        aria-label={`${g.label}: ${plural(n, 'finding')}. Open in Faults & Threats`}>
                  {body}
                  <ArrowRight size={13} aria-hidden="true" className="ov-group-go" />
                </button>
              ) : (
                <div className="ov-group is-zero">{body}<span className="ov-group-go" aria-hidden="true" /></div>
              )}
            </li>
          );
        })}
      </ul>

      <div className="ov-sev">
        <div className="ov-sev-head">
          <h3 className="section-title">Severity</h3>
          <span className="xs muted">how bad, independent of fault or attack</span>
        </div>
        {total > 0 ? (
          <div className="ov-sev-bar" role="img" aria-label={`Findings by severity: ${sevText.join(', ')}`}>
            {SEVERITIES.filter((s) => summary.by_severity[s] > 0).map((s) => (
              <span key={s} className={`ov-sev-seg is-${s}`} style={{ flexGrow: summary.by_severity[s] }}
                    title={`${severityLabel(s)}: ${summary.by_severity[s]}`} />
            ))}
          </div>
        ) : (
          <div className="ov-sev-bar is-empty" aria-hidden="true" />
        )}
        <ul className="plain-list ov-sev-legend" aria-hidden={total > 0 ? 'true' : undefined}>
          {SEVERITIES.map((s) => (
            <li key={s} className={summary.by_severity[s] ? '' : 'is-zero'}>
              <span className="ov-sev-name">
                <span className={`ov-sev-key is-${s}`} aria-hidden="true" />
                {severityLabel(s)}
              </span>
              <strong className="tabular">{formatInt(summary.by_severity[s] || 0)}</strong>
            </li>
          ))}
        </ul>
      </div>

      {evidenceCount > 0 && (
        <div className="panel-foot row-between">
          <span>{plural(evidenceCount, 'packet')} cited as evidence</span>
          <button type="button" className="link-button" onClick={() => nav.viewEvidence()}>
            Evidence explorer <ArrowRight size={13} aria-hidden="true" />
          </button>
        </div>
      )}
    </Panel>
  );
}

/* ---------- clean / no findings: what was checked ---------- */

function CheckedPanel({ result, quality }) {
  const byName = new Map(result.detectors.map((d) => [d.name, d]));
  const state = (detector) => {
    const d = byName.get(detector);
    if (!d) return { icon: CircleDashed, cls: 'is-skipped', text: 'not run' };
    if (d.status !== 'ok') return { icon: CircleX, cls: 'is-failed', text: `did not complete (${d.status})` };
    if (d.findings > 0) return { icon: AlertTriangle, cls: 'is-found', text: plural(d.findings, 'finding') };
    return { icon: Check, cls: 'is-ok', text: 'no match' };
  };
  return (
    <Panel title="What was checked" eyebrow="Official fault and threat categories" id="ov-checked"
           className={`ov-checked ${quality.incomplete ? 'is-partial' : ''}`}>
      <p className="small text-2 ov-checked-note">
        Each category was examined by the detector shown and none of its rules matched
        {quality.incomplete ? ` in the ${plural(result.packets_analyzed, 'packet')} that could be read` : ''}. That is not
        proof the network is healthy: problems outside this capture or below the detection thresholds are not visible.
      </p>
      <div className="ov-checked-cols">
        {COVERAGE.map(({ title, icon: GroupIcon, tone, items }) => (
          <div key={title}>
            <h3 className={`ov-coverage-title is-${tone}`}>
              <GroupIcon size={14} aria-hidden="true" /> {title}
            </h3>
            <ul className="plain-list ov-checked-list">
              {items.map(([label, detector]) => {
                const s = state(detector);
                const StateIcon = s.icon;
                return (
                  <li key={label} className={s.cls}>
                    <StateIcon size={14} aria-hidden="true" className="ov-checked-icon" />
                    <span className="truncate">{label}</span>
                    <code className="ov-coverage-det">{detector}</code>
                    <span className="xs muted nowrap ov-checked-state">{s.text}</span>
                  </li>
                );
              })}
            </ul>
          </div>
        ))}
      </div>
    </Panel>
  );
}

/* ---------- traffic ---------- */

/** The hosts that sent or received the most packets (traffic.top_talkers, already sorted by the backend). */
function BusiestHosts({ talkers }) {
  if (!talkers.length) return null;
  return (
    <>
      <h3 className="section-title ov-talkers-title">Busiest hosts</h3>
      <ul className="plain-list ov-talkers" aria-label="Busiest hosts by packets">
        {talkers.slice(0, 4).map((t) => (
          <li key={t.ip}>
            <span className="ov-talker">
              <code className="truncate" title={t.ip}>{t.ip}</code>
              {t.local && <span className="xs faint" title="Private (local network) address">local</span>}
            </span>
            <span className="num small">{plural(t.packets, 'packet')}</span>
            <span className="num xs muted">{formatBytes(t.bytes)}</span>
          </li>
        ))}
      </ul>
    </>
  );
}

/* ---------- warnings + pipeline ---------- */

/** Parse problems, limits that were hit and detector failures: never hidden. */
function CaptureWarnings({ result }) {
  const { parse } = result;
  const items = [];
  if (parse.malformed_packets > 0) {
    items.push(`${plural(parse.malformed_packets, 'packet')} could not be fully decoded and were skipped safely.`);
  }
  // stopped_early is usually also the first entry of warnings[]; avoid printing it twice.
  if (parse.stopped_early && !result.warnings.includes(parse.stopped_early)) items.push(parse.stopped_early);
  items.push(...result.warnings);
  if (parse.truncated_file && !result.warnings.length) {
    items.push('The capture file is truncated or corrupt; packets after the damaged record are missing.');
  }
  const failed = result.detectors.filter((d) => d.status !== 'ok');
  if (!items.length && !failed.length) return null;
  return (
    <Callout tone="neutral" icon={AlertTriangle} title="Capture and analysis warnings" className="ov-warnings">
      <ul className="text-list">
        {items.map((w, i) => <li key={i}>{w}</li>)}
        {failed.map((d) => (
          <li key={d.name}>Detector <code>{d.name}</code> did not complete: {d.status}</li>
        ))}
      </ul>
    </Callout>
  );
}

function Pipeline({ result }) {
  const { detectors, parse } = result;
  if (!detectors.length) {
    return <p className="small muted ov-pipeline-empty">No detectors ran (the capture contained no readable packets).</p>;
  }
  const ok = detectors.filter((d) => d.status === 'ok').length;
  const allOk = ok === detectors.length;
  const timing = `analysed in ${formatRunTime(result.analysis_seconds)}${
    Number.isFinite(parse.parse_seconds) ? ` (parsing ${formatRunTime(parse.parse_seconds)})` : ''}`;
  return (
    <details className="panel ov-pipeline">
      <summary>
        {allOk ? <Check size={15} aria-hidden="true" className="ov-pipeline-ok" />
          : <AlertTriangle size={15} aria-hidden="true" className="ov-pipeline-warn" />}
        <span className="strong">{ok} of {plural(detectors.length, 'detector')} completed</span>
        <span className="small muted">· {plural(result.summary.findings, 'finding')} · {timing}</span>
        <span className="ov-pipeline-toggle small">Detector details</span>
      </summary>
      <div className="table-wrap ov-pipeline-table">
        <table className="table table-dense">
          <thead>
            <tr>
              <th scope="col">Detector</th>
              <th scope="col">Status</th>
              <th scope="col" className="num">Findings</th>
              <th scope="col" className="num">Run time</th>
            </tr>
          </thead>
          <tbody>
            {detectors.map((d) => (
              <tr key={d.name}>
                <td className="mono">{d.name}</td>
                <td>{d.status === 'ok' ? 'completed' : <span className="ov-pipeline-warn">{d.status}</span>}</td>
                <td className="num">{formatInt(d.findings)}</td>
                <td className="num">{formatRunTime(d.seconds)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </details>
  );
}

/* ---------- the view ---------- */

/** Verdict-first command centre: verdict, key figures, incidents, findings, traffic, then pipeline details. */
export default function Overview({ result, index, nav, assessment }) {
  const ranked = [...result.incidents].sort(byImportance);
  const evidenceCount = index.evidencePackets.length;
  const nothingFound = result.findings.length === 0 && result.incidents.length === 0;

  return (
    <div className="view ov-view">
      <div className="view-head">
        <div>
          <h1 id="view-title" tabIndex={-1}>Overview</h1>
          <p className="view-sub">The verdict for this capture, the incidents behind it and the traffic they came from.</p>
        </div>
      </div>

      <VerdictHero result={result} assessment={assessment} top={ranked[0] || null} nav={nav} />
      <KeyStats result={result} evidenceCount={evidenceCount} />

      {nothingFound ? (
        <CheckedPanel result={result} quality={assessment.quality} />
      ) : (
        <div className="ov-main">
          <IncidentsPreview result={result} ranked={ranked} nav={nav} />
          <FindingsBreakdown result={result} evidenceCount={evidenceCount} nav={nav} />
        </div>
      )}

      <Panel title="Traffic overview" eyebrow="What the capture contains" id="ov-traffic"
             actions={
               <button type="button" className="button button-sm button-ghost" onClick={() => nav.go('traffic')}>
                 Traffic view <ArrowRight size={14} aria-hidden="true" />
               </button>
             }>
        <div className="ov-traffic">
          <div className="ov-traffic-chart">
            <TrafficChart traffic={result.traffic} duration={result.duration_seconds} incidents={result.incidents}
                          onOpenIncident={nav.openIncident} height={170} />
          </div>
          <div className="ov-traffic-protocols">
            <h3 className="section-title">Protocols</h3>
            <ProtocolBars protocols={result.traffic.protocols} max={6} />
            <BusiestHosts talkers={result.traffic.top_talkers} />
          </div>
        </div>
      </Panel>

      <CaptureWarnings result={result} />
      <Pipeline result={result} />
    </div>
  );
}
