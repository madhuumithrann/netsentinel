import { useId, useRef, useState } from 'react';
import { AlertTriangle, FileUp, Play, ShieldCheck, Unplug, X } from 'lucide-react';
import { formatBytes, formatInt, validateCaptureFile } from '../format.js';
import SampleGallery from './SampleGallery.jsx';

/** ".pcap, .pcapng or .cap · up to 100 MB · first 300,000 packets analysed · 90 s time limit", from the server's limits. */
function limitsHint(limits) {
  const parts = ['.pcap, .pcapng or .cap'];
  if (Number.isFinite(limits?.max_upload_mb)) parts.push(`up to ${limits.max_upload_mb} MB`);
  if (Number.isFinite(limits?.max_packets)) parts.push(`first ${formatInt(limits.max_packets)} packets analysed`);
  if (Number.isFinite(limits?.max_analysis_seconds)) parts.push(`${limits.max_analysis_seconds} s time limit`);
  return parts.join(' · ');
}

/**
 * Upload form (file picker + drag and drop) and the bundled-sample gallery. Progress,
 * errors from the server and cancel live in the global JobStrip, not here.
 *
 * variant 'landing' lays the form and the gallery out side by side; `intro` (above the
 * form) and `children` (below it) let the landing page share the form's column.
 * variant 'dialog' stacks a compact form above a compact gallery (New-analysis dialog).
 */
export default function AnalyzePanel({
  limits, busy = false, online = true, samples, onAnalyzeFile, onAnalyzeSample, variant = 'landing', intro, children,
}) {
  const inputId = useId();
  const hintId = useId();
  const inputRef = useRef(null);
  const [file, setFile] = useState(null);
  const [dragging, setDragging] = useState(false);

  const dialog = variant === 'dialog';
  const fileError = file ? validateCaptureFile(file, limits?.max_upload_mb) : null;
  const canSubmit = Boolean(file) && !fileError && !busy && online;

  function clear() {
    setFile(null);
    if (inputRef.current) inputRef.current.value = '';
  }

  function submit(event) {
    event.preventDefault();
    // Fall back to the input itself in case a file was set without a change event.
    const chosen = file || inputRef.current?.files?.[0] || null;
    if (!chosen || busy || !online || validateCaptureFile(chosen, limits?.max_upload_mb)) {
      if (chosen && !file) setFile(chosen);
      return;
    }
    onAnalyzeFile(chosen);
    clear();
  }

  function onDrop(event) {
    event.preventDefault();
    setDragging(false);
    const dropped = event.dataTransfer?.files?.[0];
    if (!busy && dropped) setFile(dropped);
  }

  const Title = dialog ? 'h3' : 'h2';
  const form = (
    <form className="panel ov-upload" onSubmit={submit} aria-busy={busy} aria-labelledby={`${inputId}-title`}>
      <div className="panel-head">
        <div>
          {!dialog && <div className="eyebrow">Your capture</div>}
          <Title className="panel-title" id={`${inputId}-title`}>Upload a packet capture</Title>
        </div>
      </div>

      <div
        className={`dropzone ov-dropzone ${dragging ? 'is-dragging' : ''} ${busy ? 'is-disabled' : ''}`}
        onDragOver={(e) => {
          e.preventDefault();
          if (!busy) setDragging(true);
        }}
        onDragLeave={(e) => {
          if (!e.currentTarget.contains(e.relatedTarget)) setDragging(false);
        }}
        onDrop={onDrop}
        // Mouse convenience: the whole drop area opens the picker. Keyboard users have the label button.
        onClick={(e) => {
          if (!busy && !e.target.closest('label, input, button')) inputRef.current?.click();
        }}
      >
        <span className="ov-dropzone-icon" aria-hidden="true"><FileUp size={20} /></span>
        <div className="ov-dropzone-text">
          <strong>{dragging ? 'Release to select this file' : 'Drop a capture file here'}</strong>
          <span className="xs muted" id={hintId}>{limitsHint(limits)}</span>
        </div>
        {/* Visually hidden but focusable; the label right after it is the visible control and shows its focus ring. */}
        <input
          ref={inputRef}
          id={inputId}
          className="sr-only ov-file-input"
          type="file"
          accept=".pcap,.pcapng,.cap,application/vnd.tcpdump.pcap"
          aria-describedby={hintId}
          disabled={busy}
          onChange={(e) => setFile(e.target.files?.[0] || null)}
        />
        <label htmlFor={inputId} className={`button button-sm ov-file-label ${busy ? 'is-disabled' : ''}`}>
          Choose file
        </label>
      </div>

      {file && (
        <div className={`ov-file ${fileError ? 'is-invalid' : ''}`}>
          <span className="mono truncate ov-file-name" title={file.name}>{file.name}</span>
          <span className="xs muted nowrap tabular">{formatBytes(file.size)}</span>
          {!busy && (
            <button type="button" className="icon-button ov-file-clear" aria-label={`Clear selected file ${file.name}`}
                    title="Clear selection" onClick={clear}>
              <X size={14} aria-hidden="true" />
            </button>
          )}
        </div>
      )}
      {fileError && (
        <p className="inline-error ov-form-msg" role="alert">
          <AlertTriangle size={14} aria-hidden="true" /> {fileError}
        </p>
      )}
      {!online && (
        <p className="ov-form-msg ov-offline" role="status">
          <Unplug size={14} aria-hidden="true" />
          The backend is offline, so nothing can be analysed right now. It is re-checked every 10 s.
        </p>
      )}

      <div className="ov-upload-foot">
        <span className="xs muted ov-upload-note">
          <ShieldCheck size={13} aria-hidden="true" /> The server re-checks format, size and limits before parsing.
        </span>
        <button type="submit" className="button button-primary" disabled={!canSubmit}>
          <Play size={14} aria-hidden="true" /> {busy ? 'Analysing…' : 'Analyse capture'}
        </button>
      </div>
    </form>
  );

  return (
    <div className={`ov-analyze ov-analyze-${variant}`}>
      <div className="ov-analyze-main">
        {intro}
        {form}
        {children}
      </div>
      <SampleGallery samples={samples} busy={busy || !online} onAnalyze={onAnalyzeSample} compact={dialog} />
    </div>
  );
}
