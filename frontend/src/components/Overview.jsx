import { AlertTriangle, ChevronRight, CircleCheck, CircleHelp, ShieldAlert, Wrench } from 'lucide-react';
import { SEVERITIES, formatDuration, formatInt, formatUtc, plural, severityLabel, verdictTone } from '../format.js';
import { ProtocolChart } from './Charts.jsx';
import { Panel, SeverityBadge, VerdictBadge, StrengthChip } from './ui.jsx';

const VERDICT_ICON = { attack: ShieldAlert, fault: Wrench, inconclusive: CircleHelp, clean: CircleCheck };

export function VerdictBanner({ verdict }) {
  const tone = verdictTone(verdict.status);
  const Icon = VERDICT_ICON[tone] || CircleHelp;
  const statusWord = { attack: 'Attack indicators', fault: 'Fault', inconclusive: 'Inconclusive', clean: 'Clean' }[tone] || 'Unknown';
  return (
    <section className={`verdict-banner tone-${tone}`} aria-labelledby="verdict-label">
      <Icon size={30} aria-hidden="true" className="verdict-icon" />
      <div>
        <div className="eyebrow">Capture verdict · {statusWord}</div>
        <h2 id="verdict-label">{verdict.label || statusWord}</h2>
        {verdict.headline && <p>{verdict.headline}</p>}
      </div>
    </section>
  );
}

/** Parse problems, limits that were hit and detector failures: never hidden. */
export function CaptureWarnings({ result }) {
  const items = [];
  const { parse } = result;
  if (parse.truncated_file) items.push('The capture file is truncated: its last record is incomplete. Packets after the cut are missing.');
  if (parse.malformed_packets > 0) {
    items.push(`${plural(parse.malformed_packets, 'packet')} could not be fully decoded (malformed). They were skipped safely; their headers may be missing from the analysis.`);
  }
  // stopped_early is also the first entry of warnings[]; avoid printing it twice.
  if (parse.stopped_early && !result.warnings.includes(parse.stopped_early)) items.push(parse.stopped_early);
  items.push(...result.warnings);
  const failed = result.detectors.filter((d) => d.status !== 'ok');
  if (!items.length && !failed.length) return null;
  return (
    <section className="warning-box" aria-labelledby="capture-warnings-title">
      <AlertTriangle size={18} aria-hidden="true" />
      <div>
        <h2 id="capture-warnings-title">Capture and analysis warnings</h2>
        <ul className="text-list">
          {items.map((w, i) => (
            <li key={i}>{w}</li>
          ))}
          {failed.map((d) => (
            <li key={d.name}>
              Detector <code>{d.name}</code>: {d.status}
            </li>
          ))}
        </ul>
        <p className="muted">Results below only cover what could be read. Absence of a finding is weaker evidence when the capture is incomplete.</p>
      </div>
    </section>
  );
}

function Tile({ label, value, sub, tone }) {
  return (
    <div className={`tile ${tone ? `tile-${tone}` : ''}`}>
      <div className="tile-label">{label}</div>
      <div className="tile-value">{value}</div>
      {sub && <div className="tile-sub">{sub}</div>}
    </div>
  );
}

export default function Overview({ result, index, onOpenIncident, onNavigate }) {
  const { summary, incidents } = result;
  const counts = index.incidentCounts;
  const top = incidents.slice(0, 5);
  return (
    <div className="view">
      <VerdictBanner verdict={result.verdict} />
      <CaptureWarnings result={result} />

      <section aria-label="Key figures" className="tiles">
        <Tile
          label="Packets analysed"
          value={formatInt(result.packets_analyzed)}
          sub={result.format ? `${result.format} file` : undefined}
        />
        <Tile label="Capture duration" value={formatDuration(result.duration_seconds)} sub={result.capture_start ? `from ${formatUtc(result.capture_start)}` : undefined} />
        <Tile label="Incidents" value={formatInt(incidents.length)} sub={`from ${plural(summary.findings, 'finding')}`} />
        <Tile label="Attack incidents" value={formatInt(counts.attack)} tone={counts.attack ? 'attack' : undefined} sub="attack or attack + fault" />
        <Tile label="Fault incidents" value={formatInt(counts.fault)} tone={counts.fault ? 'fault' : undefined} sub={counts.inconclusive ? `${counts.inconclusive} need investigation` : 'ordinary network problems'} />
        <div className="tile">
          <div className="tile-label">Findings by severity</div>
          {summary.findings === 0 ? (
            <div className="tile-value">0</div>
          ) : (
            <ul className="sev-counts">
              {SEVERITIES.map((s) => (
                <li key={s} className={summary.by_severity[s] ? '' : 'is-zero'}>
                  <span className={`sev-dot sev-${s}`} aria-hidden="true" />
                  <span>{severityLabel(s)}</span>
                  <strong>{summary.by_severity[s]}</strong>
                </li>
              ))}
            </ul>
          )}
        </div>
      </section>

      <div className="grid-2">
        <Panel
          title="Incidents"
          eyebrow="Reconstructed from correlated findings"
          id="overview-incidents"
          actions={
            incidents.length > 0 && (
              <button type="button" className="button button-ghost" onClick={() => onNavigate('incidents')}>
                All incidents <ChevronRight size={15} aria-hidden="true" />
              </button>
            )
          }
        >
          {top.length === 0 ? (
            <p className="muted">
              No incidents. None of the detectors' rules matched this capture, so there is nothing to correlate.
            </p>
          ) : (
            <ul className="incident-mini-list">
              {top.map((inc) => (
                <li key={inc.id}>
                  <button type="button" className="incident-mini" onClick={() => onOpenIncident(inc.id)}>
                    <span className="incident-mini-top">
                      <code className="ref">{inc.id}</code>
                      <VerdictBadge verdict={inc.verdict} label={inc.verdict_label} />
                      <SeverityBadge severity={inc.severity} />
                    </span>
                    <strong>{inc.title}</strong>
                    <span className="muted small">
                      {plural(inc.findings.length, 'finding')} · <StrengthChip strength={inc.confidence} prefix="Confidence" />
                    </span>
                  </button>
                </li>
              ))}
              {incidents.length > top.length && (
                <li className="muted small">and {incidents.length - top.length} more in the Incidents view.</li>
              )}
            </ul>
          )}
        </Panel>

        <Panel title="Protocol distribution" eyebrow="Packets per protocol" id="overview-protocols">
          <ProtocolChart protocols={result.traffic.protocols} />
        </Panel>
      </div>

      <Panel title="Detectors that ran" eyebrow="Analysis pipeline" id="overview-detectors">
        {result.detectors.length === 0 ? (
          <p className="muted">No detectors ran (the capture contained no packets).</p>
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th scope="col">Detector</th>
                  <th scope="col">Status</th>
                  <th scope="col" className="num">Findings</th>
                  <th scope="col" className="num">Time</th>
                </tr>
              </thead>
              <tbody>
                {result.detectors.map((d) => (
                  <tr key={d.name}>
                    <td className="mono">{d.name}</td>
                    <td>{d.status === 'ok' ? 'completed' : d.status}</td>
                    <td className="num">{formatInt(d.findings)}</td>
                    <td className="num">{formatDuration(d.seconds)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <p className="muted small">
          Analysed in {formatDuration(result.analysis_seconds)}
          {Number.isFinite(result.parse.parse_seconds) ? ` (parsing ${formatDuration(result.parse.parse_seconds)})` : ''}.
        </p>
      </Panel>

      {result.notice && <p className="notice">{result.notice}</p>}
    </div>
  );
}
