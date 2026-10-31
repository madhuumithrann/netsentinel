import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Download, Printer } from 'lucide-react';
import { analyzeCapture, analyzeSample, getSamples } from './api.js';
import { buildIndex, normalizeResult } from './derive.js';
import { formatInt, safeFileStem } from './format.js';
import { useHealth } from './hooks.js';
import AnalyzePanel from './components/AnalyzePanel.jsx';
import EvidenceView from './components/EvidenceView.jsx';
import FindingsView from './components/FindingsView.jsx';
import IncidentsView from './components/IncidentsView.jsx';
import Overview from './components/Overview.jsx';
import Sidebar from './components/Sidebar.jsx';
import TrafficView from './components/TrafficView.jsx';

const IDLE = { status: 'idle', label: '', startedAt: null, error: '', notice: '' };
const NO_FILTER = { incidentId: '', findingId: '', packet: null, query: '' };

export default function App() {
  const health = useHealth();
  const [view, setView] = useState('overview');
  const [raw, setRaw] = useState(null);          // backend response, kept for the JSON export
  const [job, setJob] = useState(IDLE);
  const [samples, setSamples] = useState({ items: [], error: '' });
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [findingsTab, setFindingsTab] = useState('attack');
  const [evidenceFilter, setEvidenceFilter] = useState(NO_FILTER);
  const [checks, setChecks] = useState({});
  const controller = useRef(null);

  const result = useMemo(() => (raw ? normalizeResult(raw) : null), [raw]);
  const index = useMemo(() => (result ? buildIndex(result) : null), [result]);

  // Load the bundled samples once the backend is reachable.
  const online = health.state === 'online';
  useEffect(() => {
    if (!online || samples.items.length) return undefined;
    const ctl = new AbortController();
    getSamples(ctl.signal)
      .then((items) => setSamples({ items, error: '' }))
      .catch((err) => {
        if (err.kind !== 'abort') setSamples({ items: [], error: err.message });
      });
    return () => ctl.abort();
  }, [online, samples.items.length]);

  // Move keyboard focus to the new view's heading so screen-reader users hear the change.
  useEffect(() => {
    document.getElementById('view-title')?.focus({ preventScroll: true });
    window.scrollTo({ top: 0 });
  }, [view]);

  const run = useCallback(async (label, call) => {
    controller.current?.abort();
    const ctl = new AbortController();
    controller.current = ctl;
    const startedAt = Date.now();
    setJob({ ...IDLE, status: 'running', label, startedAt });
    try {
      const data = await call(ctl.signal);
      if (controller.current !== ctl) return;
      setRaw(data);
      setSelectedIncident(null);
      setEvidenceFilter(NO_FILTER);
      setChecks({});
      const seconds = ((Date.now() - startedAt) / 1000).toFixed(1);
      setJob({ ...IDLE, notice: `Analysed ${label}: ${formatInt(data?.packets_analyzed ?? 0)} packets in ${seconds} s.` });
      const attackOrFault = Array.isArray(data?.incidents) && data.incidents.length;
      setFindingsTab(data?.summary?.attacks ? 'attack' : 'fault');
      setView(attackOrFault ? 'incidents' : 'overview');
    } catch (err) {
      if (controller.current !== ctl) return;
      if (err.kind === 'abort') {
        setJob({ ...IDLE, notice: 'Analysis cancelled. The server may still finish it in the background; the result is discarded.' });
      } else {
        setJob({ ...IDLE, status: 'error', label, error: err.message });
      }
    }
  }, []);

  const onAnalyzeFile = (file) => run(file.name, (signal) => analyzeCapture(file, signal));
  const onAnalyzeSample = (sample) => {
    const id = typeof sample === 'string' ? sample : sample.id;
    const label = typeof sample === 'string' ? sample : sample.file || sample.id;
    return run(label, (signal) => analyzeSample(id, signal));
  };
  const onCancel = () => controller.current?.abort();

  const openIncident = (id) => {
    setSelectedIncident(id);
    setView('incidents');
  };
  // Finding cards pass a finding id; incident views pass {incidentId, findingId}.
  const viewEvidence = (target) => {
    const t = typeof target === 'string' ? { findingId: target } : target || {};
    setEvidenceFilter({ ...NO_FILTER, incidentId: t.incidentId || '', findingId: t.findingId || '' });
    setView('evidence');
  };
  const openPacket = (event, incidentId) => {
    setEvidenceFilter({ ...NO_FILTER, incidentId: incidentId || '', findingId: event?.finding || '',
                        packet: Number.isFinite(event?.packet) ? event.packet : null });
    setView('evidence');
  };
  const toggleCheck = (key) => setChecks((c) => ({ ...c, [key]: !c[key] }));

  function exportJson() {
    const blob = new Blob([JSON.stringify(raw, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `netsentinel-report-${safeFileStem(result.file)}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  const counts = result
    ? { incidents: result.incidents.length, findings: result.findings.length, evidence: index.evidenceRows.length }
    : null;
  const activeView = result ? view : 'overview';

  return (
    <div className="app">
      <a className="skip-link" href="#main">Skip to content</a>
      <Sidebar view={activeView} onNavigate={setView} hasResult={Boolean(result)} counts={counts} health={health} />
      <main id="main" className="main">
        {result && (
          <header className="report-bar">
            <div>
              <div className="eyebrow">Analysis report</div>
              <div className="report-file mono" title={result.file}>{result.file}</div>
            </div>
            <div className="report-actions">
              <button type="button" className="button button-secondary" onClick={exportJson}>
                <Download size={15} aria-hidden="true" /> Download JSON
              </button>
              <button type="button" className="button button-secondary" onClick={() => window.print()}>
                <Printer size={15} aria-hidden="true" /> Print
              </button>
            </div>
          </header>
        )}

        {activeView === 'overview' && (
          <>
            {!result && (
              <div className="view-head intro">
                <h1 id="view-title" tabIndex={-1}>Diagnose a network from a packet capture</h1>
                <p className="lead">
                  NetSentinel finds faults and attacks in pcap / pcapng files, groups related findings into incidents,
                  says whether each looks like an ordinary fault or an attack, and shows the exact packets behind every
                  conclusion.
                </p>
              </div>
            )}
            <AnalyzePanel limits={health.data?.limits} job={job} onAnalyzeFile={onAnalyzeFile}
                          onAnalyzeSample={onAnalyzeSample} onCancel={onCancel}
                          samples={samples.items} compact={Boolean(result)} />
            {samples.error && <p className="inline-error">Could not load sample captures: {samples.error}</p>}
            {result && <Overview result={result} index={index} onOpenIncident={openIncident} onNavigate={setView} />}
          </>
        )}
        {activeView === 'incidents' && (
          <IncidentsView result={result} index={index} selectedId={selectedIncident} onSelect={setSelectedIncident}
                         onOpenPacket={openPacket} onViewEvidence={viewEvidence} checks={checks}
                         onToggleCheck={toggleCheck} />
        )}
        {activeView === 'findings' && (
          <FindingsView result={result} index={index} tab={findingsTab} onTabChange={setFindingsTab}
                        onViewEvidence={viewEvidence} onOpenIncident={openIncident} />
        )}
        {activeView === 'traffic' && <TrafficView result={result} onOpenIncident={openIncident} />}
        {activeView === 'evidence' && (
          <EvidenceView result={result} index={index} filter={evidenceFilter} onFilterChange={setEvidenceFilter}
                        onOpenIncident={openIncident} />
        )}

        <footer className="footer muted">
          {result?.notice || 'Findings are evidence-based indicators, not proof. Analysis runs offline on your machine.'}
        </footer>
      </main>
    </div>
  );
}
