import { ArrowRight } from 'lucide-react';
import { assessmentTone, formatOffset } from '../format.js';

/**
 * Reconstructed incident timeline: one entry per representative evidence packet, in
 * capture order. Packet numbers open the Evidence explorer at that frame.
 */
export default function Timeline({ events, findingsById, onOpenPacket }) {
  if (!events.length) {
    return <p className="muted">No timeline events: the findings in this incident carry no packet evidence.</p>;
  }
  // correlate.py keeps at most 60 events (first 30 + last 30) when an incident is long.
  const condensed = events.length >= 60;
  return (
    <>
      <ol className="timeline">
        {events.map((e, i) => {
          const f = findingsById.get(e.finding);
          const tone = assessmentTone(f?.assessment);
          return (
            <li key={`${e.packet}-${e.finding}-${i}`} className={`timeline-item tone-${tone}`}>
              <span className="timeline-dot" aria-hidden="true" />
              <div className="timeline-time mono">{formatOffset(e.relative)}</div>
              <div className="timeline-body">
                <div className="timeline-line">
                  {Number.isFinite(e.packet) ? (
                    <button
                      type="button"
                      className="packet-button mono"
                      onClick={() => onOpenPacket(e)}
                      aria-label={`Open packet ${e.packet} in the Evidence explorer`}
                    >
                      #{e.packet}
                    </button>
                  ) : (
                    <span className="mono muted">#?</span>
                  )}
                  <span className={`badge tone-${tone}`} title={f ? f.title : e.kind}>
                    {e.finding}
                  </span>
                  <span className="timeline-role">{e.role}</span>
                </div>
                <div className="timeline-flow mono">
                  <span>{e.src || '?'}</span>
                  <ArrowRight size={13} aria-label="to" />
                  <span>{e.dst || '?'}</span>
                </div>
                {e.info && <div className="timeline-info mono">{e.info}</div>}
              </div>
            </li>
          );
        })}
      </ol>
      <p className="muted small">
        The timeline shows representative packets (up to two per evidence role for each finding)
        {condensed ? ' and is condensed to the first and last 30 events' : ''}. The Evidence explorer lists every
        evidence packet.
      </p>
    </>
  );
}
