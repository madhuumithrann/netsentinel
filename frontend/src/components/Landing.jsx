import { Lock, ShieldAlert, Wrench } from 'lucide-react';
import AnalyzePanel from './AnalyzePanel.jsx';

/**
 * The official challenge list and the backend detector module that covers each item
 * (see backend/app/detectors/*.py). Detector names are only shown when the live health
 * check (or a finished analysis) lists them, so the UI never claims a detector the
 * server did not load. The Overview reuses this list for "what was checked".
 */
export const COVERAGE = [
  {
    title: 'Network faults',
    icon: Wrench,
    tone: 'fault',
    items: [
      ['TCP retransmissions', 'tcp_retransmissions'],
      ['TCP resets', 'tcp_resets'],
      ['DNS failures', 'dns'],
      ['Duplicate IP addresses', 'arp'],
      ['ARP conflicts', 'arp'],
      ['MTU mismatches', 'mtu'],
      ['Unusual delays', 'latency'],
    ],
  },
  {
    title: 'Security threats',
    icon: ShieldAlert,
    tone: 'attack',
    items: [
      ['Port scanning', 'port_scan'],
      ['ARP spoofing', 'arp'],
      ['DNS hijacking', 'dns'],
      ['Rogue DHCP servers', 'dhcp'],
    ],
  },
];

function Coverage({ detectors, version }) {
  const live = Array.isArray(detectors);
  return (
    <section className="panel ov-coverage" aria-labelledby="coverage-title">
      <div className="panel-head">
        <div>
          <div className="eyebrow">Coverage</div>
          <h2 className="panel-title" id="coverage-title">What it looks for</h2>
        </div>
        <span className="xs muted" title={live ? detectors.join(', ') : undefined}>
          {live
            ? `${detectors.length} detector${detectors.length === 1 ? '' : 's'} loaded${version ? ` · backend v${version}` : ''}`
            : 'Detector modules are listed once the backend is online'}
        </span>
      </div>
      <div className="ov-coverage-cols">
        {COVERAGE.map(({ title, icon: Icon, tone, items }) => (
          <div key={title} className="ov-coverage-col">
            <h3 className={`ov-coverage-title is-${tone}`}>
              <Icon size={14} aria-hidden="true" /> {title}
            </h3>
            <ul className="plain-list ov-coverage-list">
              {items.map(([label, detector]) => (
                <li key={label}>
                  <span className="truncate">{label}</span>
                  {live && (
                    detectors.includes(detector)
                      ? <code className="ov-coverage-det" title={`Detector module: ${detector}`}>{detector}</code>
                      : <span className="xs faint">not loaded</span>
                  )}
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>
    </section>
  );
}

/** First screen (no analysis yet): what NetSentinel does, the upload form and the samples. */
export default function Landing({ health, samples, busy, onAnalyzeFile, onAnalyzeSample }) {
  const online = health.state === 'online';
  const detectors = online && Array.isArray(health.data?.detectors) ? health.data.detectors.map(String) : null;

  const intro = (
    <header className="ov-intro">
      <div className="eyebrow">Packet capture diagnosis</div>
      <h1 id="view-title" tabIndex={-1}>
        Find faults and attacks in packet captures, with the exact packets behind every conclusion
      </h1>
      <p className="ov-intro-lead">
        Upload a capture and NetSentinel explains what happened, the likely cause and how to fix it. It separates
        ordinary network faults from attack indicators, groups related findings into incidents and links every
        claim to the frames that support it.
      </p>
      <p className="ov-privacy">
        <Lock size={13} aria-hidden="true" />
        Analysed by your own NetSentinel backend. Captures are not stored; only header metadata is used.
      </p>
    </header>
  );

  return (
    <div className="view ov-landing">
      <AnalyzePanel variant="landing" limits={health.data?.limits} online={health.state !== 'offline'} samples={samples}
                    busy={busy} onAnalyzeFile={onAnalyzeFile} onAnalyzeSample={onAnalyzeSample} intro={intro}>
        <Coverage detectors={detectors} version={online ? health.data?.version : ''} />
      </AnalyzePanel>
    </div>
  );
}
