import { FlaskConical, Play } from 'lucide-react';
import { sampleKindLabel } from '../format.js';
import { EmptyState, Skeleton } from './ui.jsx';

const KIND_TONE = { benign: 'clean', attack: 'attack', fault: 'fault', incident: 'incident', malformed: 'neutral' };

/** Bundled sample captures from GET /api/samples; one click analyses a sample server-side. */
export default function SampleGallery({ samples, busy, onAnalyze }) {
  return (
    <section className="panel samples" aria-labelledby="samples-title">
      <div className="panel-head">
        <div>
          <div className="eyebrow">No capture at hand?</div>
          <h2 className="panel-title" id="samples-title">
            Try a bundled sample
          </h2>
        </div>
      </div>
      {samples.state === 'loading' && (
        <div className="sample-grid">
          {[0, 1, 2].map((i) => (
            <div key={i} className="sample-card is-skeleton">
              <Skeleton lines={3} />
            </div>
          ))}
        </div>
      )}
      {samples.state === 'error' && (
        <p className="muted">Samples could not be loaded: {samples.error}</p>
      )}
      {samples.state === 'ready' && samples.items.length === 0 && (
        <EmptyState icon={FlaskConical} title="No bundled samples on this server">
          <p>The backend did not list any sample captures. Upload your own capture above.</p>
        </EmptyState>
      )}
      {samples.state === 'ready' && samples.items.length > 0 && (
        <ul className="sample-grid">
          {samples.items.map((s) => (
            <li key={s.id}>
              <button
                type="button"
                className="sample-card"
                disabled={busy}
                onClick={() => onAnalyze(s)}
                aria-label={`Analyse sample: ${String(s.title || s.id)} (${sampleKindLabel(s.kind)})`}
              >
                <span className="sample-top">
                  <span className={`badge tone-${KIND_TONE[s.kind] || 'neutral'}`}>{sampleKindLabel(s.kind)}</span>
                  <Play size={14} aria-hidden="true" className="sample-play" />
                </span>
                <strong>{String(s.title || s.id)}</strong>
                {s.description && <span className="sample-desc">{String(s.description)}</span>}
                {s.file && <span className="mono sample-file">{String(s.file)}</span>}
              </button>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
