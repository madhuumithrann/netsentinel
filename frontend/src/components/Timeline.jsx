import { useMemo, useState } from 'react';
import { ArrowRight, FileSearch } from 'lucide-react';
import { assessmentLabel, assessmentTone, formatInt, formatOffset, plural } from '../format.js';
import { Badge, PacketRef, RefText } from './ui.jsx';

// How many packet refs a grouped row shows before "+N more".
const GROUP_PREVIEW = 8;
// Shortest run worth collapsing: two similar events read better as two fully described rows.
const MIN_RUN = 3;

// Roles render through RefText, which links only frame citations ("request #246"), never
// counters such as "duplicate ACK #2".
const RoleText = RefText;

/** A role with its numbers normalised: "SYN probe to … port 21/tcp" and "… port 22/tcp" match. */
const patternOf = (e) => e.role.replace(/\d+/g, '#');
const sameStep = (a, b) => a.finding === b.finding && patternOf(a) === patternOf(b);

/**
 * Collapses repetition so a scan reads as one step of the reconstruction instead of a
 * dozen near-identical lines:
 * - a run of 3+ consecutive events of one finding with the same role pattern (cycle 1);
 * - a run of repeated two-step exchanges of one finding, e.g. "SYN probe" then "RST"
 *   for port after port (cycle 2, at least two repetitions).
 * Grouping is purely presentational: every packet stays listed and linkable.
 */
function groupEvents(events) {
  const groups = [];
  let i = 0;
  while (i < events.length) {
    const a = events[i];
    let j = i + 1;
    while (j < events.length && sameStep(events[j], a)) j += 1;
    if (j - i >= MIN_RUN) {
      groups.push({ finding: a.finding, cycle: 1, events: events.slice(i, j) });
      i = j;
      continue;
    }
    const b = events[i + 1];
    if (b && b.finding === a.finding) {
      let k = i + 2;
      while (k + 1 < events.length && sameStep(events[k], a) && sameStep(events[k + 1], b)) k += 2;
      if (k - i >= 4) {
        groups.push({ finding: a.finding, cycle: 2, events: events.slice(i, k) });
        i = k;
        continue;
      }
    }
    groups.push({ finding: a.finding, cycle: 1, events: [a] });
    i += 1;
  }
  return groups;
}

/** "a → b" when every event of a step shares it, otherwise "N sources / destinations". */
function flowOf(events) {
  const srcs = new Set(events.map((e) => e.src || '?'));
  const dsts = new Set(events.map((e) => e.dst || '?'));
  return {
    src: srcs.size === 1 ? events[0].src || '?' : `${srcs.size} sources`,
    dst: dsts.size === 1 ? events[0].dst || '?' : `${dsts.size} destinations`,
  };
}

/**
 * Reconstructed incident timeline: representative evidence packets in capture order, each
 * tied to the finding that cited it and the role the packet plays in that finding.
 * onOpenPacket(n, findingId) opens a frame pre-filtered to its finding; onOpenRef(n) opens a
 * frame cited inside a role text; onViewEvidence() opens every evidence packet of the incident.
 */
export default function Timeline({ incidentId, events, findingsById, onOpenPacket, onOpenRef, onViewEvidence }) {
  const groups = useMemo(() => groupEvents(events), [events]);
  if (!events.length) {
    return <p className="muted small">No timeline events: the findings in this incident carry no packet evidence.</p>;
  }
  const findingCount = new Set(events.map((e) => e.finding)).size;
  return (
    <div className="inc-tl-wrap">
      <ol className="inc-tl" aria-label={`Timeline of ${incidentId}`}>
        {groups.map((g, i) => (
          <TimelineRow key={`${g.events[0].packet}-${g.finding}-${i}`} group={g} finding={findingsById.get(g.finding)}
                       onOpenPacket={onOpenPacket} onOpenRef={onOpenRef} />
        ))}
      </ol>
      <div className="inc-tl-foot">
        <p className="inc-footnote">
          {plural(events.length, 'representative packet')} from {plural(findingCount, 'finding')}
          {groups.length < events.length ? `, shown as ${plural(groups.length, 'row')} (repeated steps grouped ×N)` : ''}.
          The timeline keeps up to 12 packets per finding and 60 per incident
          {events.length >= 60 ? ' (the first and last 30), so it is condensed here' : ''}; the Evidence explorer lists up
          to 200 evidence packets per finding.
        </p>
        <button type="button" className="button button-sm" onClick={onViewEvidence}>
          <FileSearch size={14} aria-hidden="true" /> All evidence for {incidentId}
        </button>
      </div>
    </div>
  );
}

function TimelineRow({ group, finding, onOpenPacket, onOpenRef }) {
  const [expanded, setExpanded] = useState(false);
  const { events, cycle } = group;
  const first = events[0];
  const last = events[events.length - 1];
  const tone = assessmentTone(finding?.assessment);
  const grouped = events.length > 1;
  const repeats = events.length / cycle;
  const openPacket = (n) => onOpenPacket(n, group.finding);
  // One line per step of the repeated pattern, described by its first occurrence.
  const steps = events.slice(0, cycle).map((e, s) => ({ event: e, flow: flowOf(events.filter((_, k) => k % cycle === s)) }));
  const hidden = events.length - GROUP_PREVIEW;
  const countTitle = cycle === 2
    ? `${repeats} repetitions of the same two-step exchange (${events.length} packets)`
    : `${events.length} consecutive events with the same role`;

  return (
    <li className="inc-tl-item">
      <div className="inc-tl-time tabular">
        <span>{formatOffset(first.relative)}</span>
        {grouped && Number.isFinite(last.relative) && last.relative !== first.relative && (
          <span className="inc-tl-time-end">to {formatOffset(last.relative)}</span>
        )}
      </div>
      <div className="inc-tl-rail" aria-hidden="true">
        <span className={`dot dot-${tone} inc-tl-dot`} />
      </div>
      <div className="inc-tl-body">
        <div className="inc-tl-head">
          {grouped ? (
            <span className="inc-tl-count" title={countTitle}>
              ×{formatInt(repeats)}
              {cycle === 2 && <span className="inc-tl-count-unit"> pairs</span>}
            </span>
          ) : (
            <PacketRef packet={first.packet} onOpen={openPacket} />
          )}
          <Badge tone={tone} className="inc-tl-finding" title={finding ? `${group.finding}: ${finding.title}` : first.kind}>
            {group.finding || '?'}
            {finding && <span className="inc-tl-assess">{assessmentLabel(finding.assessment)}</span>}
          </Badge>
          {cycle === 1 && (
            <span className="inc-tl-role">
              <RoleText text={first.role} onOpenPacket={onOpenRef} />
              {grouped && <span className="muted"> (first of {formatInt(events.length)})</span>}
            </span>
          )}
        </div>
        {steps.map(({ event, flow }, s) => (
          <div key={s} className={cycle === 2 ? 'inc-tl-step' : 'inc-tl-sub'}>
            {cycle === 2 && (
              <div className="inc-tl-role">
                <span className="inc-tl-step-n" aria-hidden="true">{s + 1}</span>
                <RoleText text={event.role} onOpenPacket={onOpenRef} />
              </div>
            )}
            <div className="inc-tl-meta">
              <span className="inc-tl-flow">
                {flow.src} <ArrowRight size={11} aria-label="to" /> {flow.dst}
              </span>
              {event.info && (
                <span className="inc-tl-info truncate" title={event.info}>
                  {event.info}
                </span>
              )}
            </div>
          </div>
        ))}
        {grouped && (
          <div className="inc-tl-refs">
            <span className="inc-tl-refs-label">{cycle === 2 ? 'Packets (first pair described)' : 'Packets'}</span>
            {events.map((e, i) => (
              <span key={`${e.packet}-${i}`} className={!expanded && i >= GROUP_PREVIEW ? 'inc-extra' : undefined}>
                <PacketRef packet={e.packet} onOpen={openPacket} />
              </span>
            ))}
            {hidden > 0 && (
              <button type="button" className="link-button inc-tl-more no-print" aria-expanded={expanded}
                      onClick={() => setExpanded((v) => !v)}>
                {expanded ? 'Show fewer' : `+${formatInt(hidden)} more`}
              </button>
            )}
          </div>
        )}
      </div>
    </li>
  );
}
