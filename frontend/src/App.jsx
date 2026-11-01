import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import { analyzeCapture, analyzeSample, getSamples } from './api.js';
import { assessmentGroup, buildIndex, normalizeResult, overallAssessment } from './derive.js';
import { plural, safeFileStem } from './format.js';
import { useHashRoute, useHealth } from './hooks.js';
import ErrorBoundary from './components/ErrorBoundary.jsx';
import EvidenceView from './components/EvidenceView.jsx';
import FindingsView from './components/FindingsView.jsx';
import IncidentsView from './components/IncidentsView.jsx';
import JobStrip from './components/JobStrip.jsx';
import Landing from './components/Landing.jsx';
import NewAnalysisDialog from './components/NewAnalysisDialog.jsx';
import Overview from './components/Overview.jsx';
import ReportBar from './components/ReportBar.jsx';
import ReportView from './components/ReportView.jsx';
import Sidebar from './components/Sidebar.jsx';
import TrafficView from './components/TrafficView.jsx';

const IDLE = { status: 'idle', label: '', startedAt: null, error: '', notice: '' };
const NOTICE_MS = 12_000;

export default function App() {
  const health = useHealth();
  const [route, navigate] = useHashRoute();
  const [raw, setRaw] = useState(null); // untouched backend response, kept for the JSON export
  const [job, setJob] = useState(IDLE);
  const [samples, setSamples] = useState({ state: 'idle', items: [], error: '' });
  const [samplesTry, setSamplesTry] = useState(0);
  const [checks, setChecks] = useState({});
  const [dialogOpen, setDialogOpen] = useState(false);
  const controller = useRef(null);
  const routeRef = useRef(route);
  routeRef.current = route;

  const result = useMemo(() => (raw ? normalizeResult(raw) : null), [raw]);
  const index = useMemo(() => (result ? buildIndex(result) : null), [result]);
  const assessment = useMemo(() => (result ? overallAssessment(result, index) : null), [result, index]);

  // Bundled samples: load once the backend is reachable (and retry after an outage).
  const online = health.state === 'online';
  useEffect(() => {
    if (!online || samples.state === 'ready' || samples.state === 'loading') return undefined;
    const ctl = new AbortController();
    setSamples((s) => ({ ...s, state: 'loading', error: '' }));
    getSamples(ctl.signal)
      .then((items) => setSamples({ state: 'ready', items, error: '' }))
      .catch((err) => {
        if (err.kind !== 'abort') setSamples({ state: 'error', items: [], error: err.message });
      });
    return () => ctl.abort();
  }, [online, samplesTry]); // samples.state is read, not tracked: re-running on it would abort the request it starts
  const samplesView = useMemo(() => ({ ...samples, retry: () => setSamplesTry((n) => n + 1) }), [samples]);


  // A file dropped outside the upload area must not make the browser open it (and lose the report).
  useEffect(() => {
    const guard = (e) => {
      if (!e.target?.closest?.('.dropzone')) e.preventDefault();
    };
    window.addEventListener('dragover', guard);
    window.addEventListener('drop', guard);
    return () => {
      window.removeEventListener('dragover', guard);
      window.removeEventListener('drop', guard);
    };
  }, []);

  // Success notices fade after a while; errors stay until the next action.
  useEffect(() => {
    if (job.status !== 'idle' || !job.notice) return undefined;
    const t = setTimeout(() => setJob((j) => (j.status === 'idle' ? { ...j, notice: '' } : j)), NOTICE_MS);
    return () => clearTimeout(t);
  }, [job]);

  // New view: start at the top and move focus to its heading (screen readers hear the change).
  // A layout effect, so it runs before child effects that scroll to a selected packet or finding.
  // Not on the first page load: there the document start (skip link, navigation) keeps the focus.
  const activeView = result ? route.view : 'overview';
  const shownView = useRef(activeView); // compared, not counted: StrictMode runs effects twice
  useLayoutEffect(() => {
    if (shownView.current === activeView) return;
    shownView.current = activeView;
    window.scrollTo({ top: 0 });
    document.getElementById('view-title')?.focus({ preventScroll: true });
  }, [activeView]);

  const run = useCallback(
    async (label, call) => {
      controller.current?.abort();
      const ctl = new AbortController();
      controller.current = ctl;
      const startedAt = Date.now();
      setDialogOpen(false);
      setJob({ ...IDLE, status: 'running', label, startedAt });
      try {
        const data = await call(ctl.signal);
        if (controller.current !== ctl) return;
        setRaw(data);
        setChecks({});
        const seconds = ((Date.now() - startedAt) / 1000).toFixed(1);
        const packets = Number.isFinite(data?.packets_analyzed) ? data.packets_analyzed : 0;
        setJob({ ...IDLE, notice: `Analysed ${label}: ${plural(packets, 'packet')} in ${seconds} s.` });
        navigate({ view: 'overview' });
      } catch (err) {
        if (controller.current !== ctl) return;
        if (err.kind === 'abort') {
          setJob({ ...IDLE, notice: 'Analysis cancelled. The server may still finish it in the background; that result is discarded.' });
        } else {
          setJob({ ...IDLE, status: 'error', label, error: err.message });
        }
      }
    },
    [navigate],
  );

  const onAnalyzeFile = (file) => run(file.name, (signal) => analyzeCapture(file, signal));
  const onAnalyzeSample = (sample) => run(sample.file || sample.id, (signal) => analyzeSample(sample.id, signal));
  const onCancel = () => controller.current?.abort();
  const toggleCheck = (key) => setChecks((c) => ({ ...c, [key]: !c[key] }));

  // Navigation actions shared by every view. Only ids travel through the URL.
  const nav = useMemo(
    () => ({
      go: (view) => navigate({ view }),
      /** Update parameters of the current view; replace=true for typing / filtering. */
      set: (patch, opts) => navigate({ ...routeRef.current, ...patch }, opts),
      openIncident: (id) => navigate({ view: 'incidents', incident: id || '' }),
      openFinding: (id) => {
        const f = index?.findingsById.get(id);
        navigate({ view: 'findings', tab: f ? assessmentGroup(f) : '', finding: id || '' });
      },
      /** Inspect one frame. finding/incident (optional) pre-filter the explorer around it. */
      openPacket: (packet, { finding = '', incident = '' } = {}) =>
        navigate({ view: 'evidence', packet: Number.isFinite(packet) ? packet : null, finding, incident }),
      viewEvidence: ({ incident = '', finding = '', q = '' } = {}) => navigate({ view: 'evidence', incident, finding, q }),
      openReport: () => navigate({ view: 'report' }),
      newAnalysis: () => setDialogOpen(true),
    }),
    [navigate, index],
  );

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
    ? { incidents: result.incidents.length, findings: result.findings.length, evidence: index.evidencePackets.length,
        attacks: assessment.counts.attack }
    : null;
  const stale = Boolean(result) && job.status === 'error';
  const views = { result, index, route, nav };

  return (
    <div className="app">
      <a className="skip-link" href="#main">Skip to content</a>
      <Sidebar view={activeView} onNavigate={nav.go} hasResult={Boolean(result)} counts={counts} health={health} />
      <main id="main" className="main">
        {result && (
          <ReportBar result={result} assessment={assessment} view={activeView} stale={stale}
                     onNewAnalysis={nav.newAnalysis} onExport={exportJson} onPrint={() => window.print()} />
        )}
        <div className="main-inner">
          <JobStrip job={job} limits={health.data?.limits} staleFile={stale ? result.file : ''}
                    onCancel={onCancel} onDismiss={() => setJob(IDLE)} />

          {!result && (
            <Landing health={health} samples={samplesView} busy={job.status === 'running'}
                     onAnalyzeFile={onAnalyzeFile} onAnalyzeSample={onAnalyzeSample} />
          )}
          {result && (
            <ErrorBoundary resetKey={`${activeView}|${result.file}|${result.packets_analyzed}`}>
              {activeView === 'overview' && <Overview {...views} assessment={assessment} />}
              {activeView === 'incidents' && <IncidentsView {...views} checks={checks} onToggleCheck={toggleCheck} />}
              {activeView === 'findings' && <FindingsView {...views} />}
              {activeView === 'traffic' && <TrafficView {...views} />}
              {activeView === 'evidence' && <EvidenceView {...views} />}
              {activeView === 'report' && <ReportView {...views} assessment={assessment} checks={checks} />}
            </ErrorBoundary>
          )}

          <footer className="footer">
            {result?.notice ||
              'Findings are evidence-based indicators, not proof. Analysis runs on your own NetSentinel backend; captures are not stored.'}
          </footer>
        </div>
      </main>

      <NewAnalysisDialog open={dialogOpen} onClose={() => setDialogOpen(false)} health={health} samples={samplesView}
                         busy={job.status === 'running'} onAnalyzeFile={onAnalyzeFile} onAnalyzeSample={onAnalyzeSample} />
    </div>
  );
}
