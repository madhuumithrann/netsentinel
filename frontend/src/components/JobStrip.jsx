import { AlertTriangle, CircleCheck, LoaderCircle, X } from 'lucide-react';
import { useElapsed } from '../hooks.js';

/**
 * Global analysis status, shown above every view: running (elapsed time and Cancel),
 * failed (the backend's message, verbatim) or just finished. There is no percentage:
 * the backend does not report progress, so none is invented.
 */
export default function JobStrip({ job, limits, staleFile, onCancel, onDismiss }) {
  const running = job.status === 'running';
  const elapsed = useElapsed(job.startedAt, running);

  if (running) {
    return (
      <div className="job-strip is-running" role="status" aria-live="polite" data-job="running">
        <LoaderCircle size={18} className="spin" aria-hidden="true" />
        <div className="job-text">
          <strong>
            Uploading and analysing <span className="mono">{job.label}</span>
          </strong>
          <span className="muted small">
            <span aria-hidden="true">{elapsed} s elapsed</span>
            {Number.isFinite(limits?.max_analysis_seconds) ? ` · the server stops after ${limits.max_analysis_seconds} s` : ''}
          </span>
          <div className="job-progress" aria-hidden="true" />
        </div>
        <button type="button" className="button button-sm button-ghost" onClick={onCancel}>
          <X size={14} aria-hidden="true" /> Cancel
        </button>
      </div>
    );
  }
  if (job.status === 'error') {
    return (
      <div className="job-strip is-error" role="alert">
        <AlertTriangle size={18} aria-hidden="true" />
        <div className="job-text">
          <strong>Analysis of {job.label} failed</strong>
          {/* The backend's own message, shown verbatim as text. */}
          <span>{job.error}</span>
          {staleFile && (
            <span className="muted small">
              The report below is still the previous analysis of <span className="mono">{staleFile}</span>.
            </span>
          )}
        </div>
        <button type="button" className="icon-button" onClick={onDismiss} aria-label="Dismiss error">
          <X size={15} aria-hidden="true" />
        </button>
      </div>
    );
  }
  if (job.notice) {
    return (
      <div className="job-strip is-done" role="status" aria-live="polite">
        <CircleCheck size={18} aria-hidden="true" />
        <div className="job-text">
          <span>{job.notice}</span>
        </div>
        <button type="button" className="icon-button" onClick={onDismiss} aria-label="Dismiss message">
          <X size={15} aria-hidden="true" />
        </button>
      </div>
    );
  }
  // Keep an empty live region mounted so the next status is announced.
  return <div className="sr-only" role="status" aria-live="polite" />;
}
