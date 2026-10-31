import { useId, useRef, useState } from 'react';
import { AlertTriangle, FileUp, LoaderCircle, Play, X } from 'lucide-react';
import { formatBytes, validateCaptureFile } from '../format.js';
import { useElapsed } from '../hooks.js';
import SampleGallery from './SampleGallery.jsx';

/**
 * Upload form (file picker + drag-and-drop), progress with elapsed time and cancel,
 * error display, and the bundled-sample gallery.
 */
export default function AnalyzePanel({ limits, job, onAnalyzeFile, onAnalyzeSample, onCancel, samples, compact }) {
  const inputId = useId();
  const hintId = useId();
  const inputRef = useRef(null);
  const [file, setFile] = useState(null);
  const [dragging, setDragging] = useState(false);

  const maxMb = limits?.max_upload_mb;
  const busy = job.status === 'running';
  const fileError = file ? validateCaptureFile(file, maxMb) : null;

  function pick(list) {
    const chosen = list && list[0];
    if (chosen) setFile(chosen);
  }

  function submit(event) {
    event.preventDefault();
    if (!file || fileError || busy) return;
    onAnalyzeFile(file);
  }

  function onDrop(event) {
    event.preventDefault();
    setDragging(false);
    if (!busy) pick(event.dataTransfer?.files);
  }

  return (
    <div className={`analyze ${compact ? 'analyze-compact' : ''}`}>
      <form className="panel analyze-form" onSubmit={submit} aria-busy={busy}>
        <div className="panel-head">
          <div>
            <div className="eyebrow">New analysis</div>
            <h2 className="panel-title">Analyse a packet capture</h2>
          </div>
        </div>

        <div
          className={`dropzone ${dragging ? 'is-dragging' : ''} ${busy ? 'is-disabled' : ''}`}
          onDragOver={(e) => {
            e.preventDefault();
            if (!busy) setDragging(true);
          }}
          onDragLeave={() => setDragging(false)}
          onDrop={onDrop}
        >
          <FileUp size={26} aria-hidden="true" />
          <div className="dropzone-text">
            <input
              ref={inputRef}
              id={inputId}
              className="file-input"
              type="file"
              accept=".pcap,.pcapng,.cap,application/vnd.tcpdump.pcap"
              aria-describedby={hintId}
              disabled={busy}
              onChange={(e) => pick(e.target.files)}
            />
            <label htmlFor={inputId} className="button button-secondary">
              Choose capture file
            </label>
            <span className="dropzone-or">or drop it here</span>
            <p id={hintId} className="hint">
              .pcap, .pcapng or .cap
              {Number.isFinite(maxMb) ? ` · up to ${maxMb} MB` : ''}
              {Number.isFinite(limits?.max_packets) ? ` · first ${limits.max_packets.toLocaleString('en-US')} packets analysed` : ''}
              . The file is analysed by your NetSentinel backend and is not stored.
            </p>
          </div>
        </div>

        {file && (
          <div className="selected-file">
            <span className="mono">{file.name}</span>
            <span className="muted">{formatBytes(file.size)}</span>
            {!busy && (
              <button
                type="button"
                className="icon-button"
                aria-label="Clear selected file"
                onClick={() => {
                  setFile(null);
                  if (inputRef.current) inputRef.current.value = '';
                }}
              >
                <X size={15} aria-hidden="true" />
              </button>
            )}
          </div>
        )}
        {fileError && (
          <p className="inline-error" role="alert">
            <AlertTriangle size={15} aria-hidden="true" /> {fileError}
          </p>
        )}

        <div className="analyze-actions">
          <button type="submit" className="button button-primary" disabled={!file || Boolean(fileError) || busy}>
            <Play size={15} aria-hidden="true" /> Analyse capture
          </button>
        </div>

        <JobStatus job={job} limits={limits} onCancel={onCancel} />
      </form>

      <SampleGallery samples={samples} busy={busy} onAnalyze={onAnalyzeSample} />
    </div>
  );
}

function JobStatus({ job, limits, onCancel }) {
  const busy = job.status === 'running';
  const elapsed = useElapsed(job.startedAt, busy);
  return (
    <div aria-live="polite">
      {busy && (
        <div className="job-running">
          <LoaderCircle size={18} className="spin" aria-hidden="true" />
          <div className="job-text">
            <strong>
              Analysing <span className="mono">{job.label}</span>
            </strong>
            <span className="muted">
              {/* Elapsed time is visual only; screen readers hear the start and the outcome. */}
              <span aria-hidden="true">{elapsed} s elapsed</span>
              {Number.isFinite(limits?.max_analysis_seconds) ? ` · the server stops after ${limits.max_analysis_seconds} s` : ''}
            </span>
          </div>
          <button type="button" className="button button-ghost" onClick={onCancel}>
            <X size={15} aria-hidden="true" /> Cancel
          </button>
        </div>
      )}
      {job.status === 'error' && (
        <div className="error-box" role="alert">
          <AlertTriangle size={18} aria-hidden="true" />
          <div>
            <strong>Analysis of {job.label} failed</strong>
            {/* The backend's own message, shown verbatim as text. */}
            <p>{job.error}</p>
          </div>
        </div>
      )}
      {job.status === 'idle' && job.notice && <p className="muted job-notice">{job.notice}</p>}
    </div>
  );
}
