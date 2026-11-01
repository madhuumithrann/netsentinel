import { Download, FilePlus2, Printer } from 'lucide-react';
import { formatDuration, formatInt, plural } from '../format.js';

const KIND_ICON_TONE = { attack: 'attack', mixed: 'attack', fault: 'fault', inconclusive: 'inconclusive', clean: 'clean', incomplete: 'neutral' };

/**
 * Sticky context bar: which capture this report is for, its overall verdict (visible on
 * every view) and the report-level actions. After a failed re-analysis the bar says the
 * report on screen is the previous one, so it is never mistaken for the failed file.
 */
export default function ReportBar({ result, assessment, view, stale, onNewAnalysis, onExport, onPrint }) {
  const { counts } = assessment;
  const split = [
    counts.attack ? plural(counts.attack, 'attack incident') : '',
    counts.fault ? plural(counts.fault, 'fault incident') : '',
    counts.inconclusive ? `${formatInt(counts.inconclusive)} to investigate` : '',
  ].filter(Boolean);
  return (
    <header className={`report-bar ${stale ? 'is-stale' : ''}`}>
      <div className="report-id">
        <span className="eyebrow">{stale ? 'Previous report (the last analysis failed)' : 'Investigation'}</span>
        <span className="report-file truncate" title={result.file}>{result.file}</span>
        <span className="report-meta">
          {[result.format && result.format.toUpperCase(), plural(result.packets_analyzed, 'packet'),
            formatDuration(result.duration_seconds)].filter(Boolean).join(' · ')}
        </span>
      </div>
      <div className="cluster" style={{ '--gap': '6px' }}>
        <span className={`badge tone-${KIND_ICON_TONE[assessment.kind] || 'neutral'}`} title={assessment.headline || assessment.label}>
          <span className={`dot dot-${KIND_ICON_TONE[assessment.kind] || 'neutral'}`} aria-hidden="true" />
          {assessment.label}
        </span>
        {split.length > 0 && <span className="xs muted">{split.join(' · ')}</span>}
      </div>
      <div className="report-actions">
        <button type="button" className="button button-sm button-primary" onClick={onNewAnalysis}>
          <FilePlus2 size={14} aria-hidden="true" /> New analysis
        </button>
        <button type="button" className="button button-sm" onClick={onExport} title="Download the raw backend response as JSON">
          <Download size={14} aria-hidden="true" /> JSON
        </button>
        <button type="button" className="button button-sm" onClick={onPrint}
                title={view === 'report' ? 'Print the full investigation report' : 'Print the current view'}>
          <Printer size={14} aria-hidden="true" /> {view === 'report' ? 'Print report' : 'Print view'}
        </button>
      </div>
    </header>
  );
}
