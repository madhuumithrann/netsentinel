import { useEffect, useRef } from 'react';
import { X } from 'lucide-react';
import AnalyzePanel from './AnalyzePanel.jsx';

/**
 * "New analysis" while a report is open: the upload form and sample gallery in a modal
 * <dialog> (native focus trap, Esc closes it). Starting an analysis closes the dialog;
 * progress then shows in the global job strip.
 */
export default function NewAnalysisDialog({ open, onClose, health, samples, busy, onAnalyzeFile, onAnalyzeSample }) {
  const ref = useRef(null);
  useEffect(() => {
    const d = ref.current;
    if (!d) return;
    if (open && !d.open) d.showModal();
    if (!open && d.open) d.close();
  }, [open]);

  return (
    <dialog ref={ref} className="dialog" aria-labelledby="new-analysis-title" onClose={onClose}
            onClick={(e) => { if (e.target === ref.current) onClose(); }}>
      {open && (
        <>
          <div className="dialog-head">
            <h2 id="new-analysis-title">New analysis</h2>
            <button type="button" className="icon-button" onClick={onClose} aria-label="Close">
              <X size={16} aria-hidden="true" />
            </button>
          </div>
          <div className="dialog-body">
            <AnalyzePanel variant="dialog" limits={health.data?.limits} online={health.state !== 'offline'}
                          samples={samples} busy={busy} onAnalyzeFile={onAnalyzeFile} onAnalyzeSample={onAnalyzeSample} />
          </div>
        </>
      )}
    </dialog>
  );
}
