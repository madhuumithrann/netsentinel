import { useId } from 'react';
import { FlaskConical, Play } from 'lucide-react';
import { plural, sampleKindLabel } from '../format.js';
import { Badge, EmptyState, Skeleton } from './ui.jsx';

/**
 * Display order and meaning of each sample kind. Incidents (multi-stage captures) come
 * first because they show the correlation engine; benign and malformed close the list
 * as the false-alarm and safe-parsing checks. Unknown kinds are listed last as-is.
 */
const KINDS = [
  { kind: 'incident', tone: 'accent', label: 'Multi-stage incident', note: 'Several findings that form one story' },
  { kind: 'attack', tone: 'attack', label: 'Attack', note: 'One attack technique per capture' },
  { kind: 'fault', tone: 'fault', label: 'Fault', note: 'Ordinary network malfunctions' },
  { kind: 'benign', tone: 'clean', label: 'Benign', note: 'False-alarm check' },
  { kind: 'malformed', tone: 'neutral', label: 'Malformed input', note: 'Safe-parsing check' },
];

function groupSamples(items) {
  const groups = KINDS.map((k) => ({ ...k, items: items.filter((s) => s.kind === k.kind) })).filter((g) => g.items.length);
  const other = items.filter((s) => !KINDS.some((k) => k.kind === s.kind));
  if (other.length) groups.push({ kind: 'other', tone: 'neutral', label: 'Other', note: '', items: other });
  return groups;
}

/** Title, plus the description only when it adds something (most samples repeat the title). */
function sampleText(s) {
  const title = String(s.title || s.id);
  const desc = s.description && String(s.description) !== title ? String(s.description) : '';
  return { title, desc };
}

/**
 * Bundled sample captures from GET /api/samples; one click analyses a sample server-side.
 * The landing page groups them by kind in cards; `compact` (the New-analysis dialog) shows
 * one dense row per sample with its kind as a badge.
 */
export default function SampleGallery({ samples, busy, onAnalyze, compact = false }) {
  const titleId = useId();
  const state = samples?.state || 'idle';
  const items = Array.isArray(samples?.items) ? samples.items.filter((s) => s && s.id) : [];
  const groups = state === 'ready' ? groupSamples(items) : [];
  const Title = compact ? 'h3' : 'h2';

  return (
    <section className={`panel ov-samples ${compact ? 'is-compact' : ''}`} aria-labelledby={titleId}
             aria-busy={state === 'loading'}>
      <div className="panel-head">
        <div>
          {!compact && <div className="eyebrow">No capture at hand?</div>}
          <Title className="panel-title" id={titleId}>Analyse a bundled sample</Title>
        </div>
        {items.length > 0 && (
          <span className="xs muted">{plural(items.length, 'synthetic capture')} · one click each</span>
        )}
      </div>

      {state === 'idle' && <p className="small muted">Samples are listed once the backend is online.</p>}

      {state === 'loading' && (
        <ul className="plain-list ov-sample-grid" aria-hidden="true">
          {[0, 1, 2, 3, 4, 5].slice(0, compact ? 4 : 6).map((i) => (
            <li key={i}>
              <div className="ov-sample is-skeleton">
                <Skeleton lines={compact ? 2 : 3} />
              </div>
            </li>
          ))}
        </ul>
      )}

      {state === 'error' && (
        <div className="cluster">
          <p className="inline-error">Samples could not be loaded: {String(samples.error || 'unknown error')}</p>
          {samples.retry && (
            <button type="button" className="button button-xs" onClick={samples.retry}>Retry</button>
          )}
        </div>
      )}

      {state === 'ready' && items.length === 0 && (
        <EmptyState icon={FlaskConical} title="No bundled samples on this server">
          <p>The backend did not list any sample captures. Upload your own capture instead.</p>
        </EmptyState>
      )}

      {compact && groups.length > 0 && (
        <ul className="plain-list ov-sample-rows">
          {groups.flatMap((g) =>
            g.items.map((s) => {
              const { title, desc } = sampleText(s);
              return (
                <li key={s.id}>
                  <button type="button" className="ov-sample-row" disabled={busy} onClick={() => onAnalyze(s)}
                          title={desc ? `${title}\n${desc}` : title}
                          aria-label={`Analyse sample ${s.file || s.id} (${sampleKindLabel(s.kind)}): ${title}`}>
                    <Badge tone={g.tone}>{g.kind === 'other' ? sampleKindLabel(s.kind) : g.label}</Badge>
                    <span className="ov-sample-row-text">
                      <span className="truncate ov-sample-row-title">{title}</span>
                      <span className="mono truncate ov-sample-file">{String(s.file || s.id)}</span>
                    </span>
                    <Play size={13} aria-hidden="true" className="ov-sample-play" />
                  </button>
                </li>
              );
            }),
          )}
        </ul>
      )}

      {!compact && groups.length > 0 && (
        <div className="ov-sample-groups">
          {groups.map((g) => (
            <section key={g.kind} className={`ov-sample-group ${g.items.length === 1 ? 'is-single' : ''}`}
                     aria-label={`${g.label} samples`}>
              <div className="ov-sample-group-head">
                <Badge tone={g.tone}>{g.label}</Badge>
                {g.note && <span className="xs muted truncate">{g.note}</span>}
              </div>
              <ul className="ov-sample-grid plain-list">
                {g.items.map((s) => {
                  const { title, desc } = sampleText(s);
                  return (
                    <li key={s.id}>
                      <button type="button" className="ov-sample" disabled={busy} onClick={() => onAnalyze(s)}
                              title={desc ? `${title}\n${desc}` : title}
                              aria-label={`Analyse sample ${s.file || s.id} (${sampleKindLabel(s.kind)}): ${title}`}>
                        <span className="ov-sample-top">
                          <span className="mono ov-sample-file truncate">{String(s.file || s.id)}</span>
                          <Play size={13} aria-hidden="true" className="ov-sample-play" />
                        </span>
                        <span className="ov-sample-title clamp-2">{title}</span>
                        {desc && <span className="ov-sample-desc clamp-2">{desc}</span>}
                      </button>
                    </li>
                  );
                })}
              </ul>
            </section>
          ))}
        </div>
      )}
    </section>
  );
}
