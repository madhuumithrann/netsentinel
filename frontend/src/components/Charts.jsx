// Traffic charts. Recharts draws the activity plot; the protocol mix is plain HTML bars.
//
// Colours: SVG presentation attributes cannot read CSS variables, so the series hex values
// below mirror the --series-* tokens in styles/base.css. Axis text and grid lines are styled
// by base.css rules on the .recharts-* classes (CSS wins over presentation attributes).
import { useMemo, useState } from 'react';
import { Area, AreaChart, CartesianGrid, ReferenceArea, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { protocolRows } from '../derive.js';
import { formatInt, formatOffset, formatOffsetRange, incidentVerdictLabel, percent, plural, verdictTone } from '../format.js';

/** Transport series in fixed stacking / legend order (a colour always means the same series). */
const SERIES = [
  { key: 'TCP', label: 'TCP', color: '#4c8dff' },
  { key: 'UDP', label: 'UDP', color: '#a78bfa' },
  { key: 'Other', label: 'Other', note: 'ARP, ICMP and anything that is not TCP or UDP', color: '#6b7f99' },
];
/** Verdict hues (mirror --attack / --fault / --info / --clean / --neutral) for in-plot range tints. */
const TONE_FILL = { attack: '#f0605a', fault: '#e3a63a', inconclusive: '#5aa2f0', clean: '#3fb950', neutral: '#8f9cad' };
const CURSOR = '#34445a'; // --chart-axis

// Plot-area geometry. The incident strip above the plot uses the same offsets so its bands
// line up exactly with the x-axis.
const MARGIN = { top: 6, right: 14, bottom: 0, left: 0 };
const Y_AXIS_WIDTH = 46;
/** Rough width of an "INC-001" label as a share of the plot, so labels in one lane never collide. */
const LABEL_SHARE = 8;
/** A range covering more than this share of the capture is shown only in the strip, not as a plot tint. */
const TINT_MAX_COVERAGE = 0.6;

/**
 * Chart points from the backend buckets. Buckets hold START times; buckets that share a
 * start (rounded times on sub-millisecond captures) are merged; each point remembers its
 * own [t0, t1) range for the tooltip, and a closing point carries the last step to the end.
 */
function buildPoints(series, duration) {
  const merged = [];
  for (const b of series) {
    const prev = merged[merged.length - 1];
    if (prev && Math.abs(prev.t - b.t) < 1e-9) {
      for (const s of SERIES) prev[s.key] += b[s.key];
      prev.packets += b.packets;
    } else {
      merged.push({ t: b.t, packets: b.packets, TCP: b.TCP, UDP: b.UDP, Other: b.Other });
    }
  }
  if (merged.length < 2) return { points: [], buckets: merged, end: 0 };
  const last = merged[merged.length - 1];
  const step = last.t - merged[merged.length - 2].t;
  const end = Number.isFinite(duration) && duration > last.t ? duration : last.t + step;
  const points = merged.map((b, i) => ({ ...b, t0: b.t, t1: i + 1 < merged.length ? merged[i + 1].t : end }));
  points.push({ ...points[points.length - 1], t: end, closing: true });
  return { points, buckets: merged, end };
}

/**
 * Count-axis ticks: whole numbers on a 1 / 2 / 2.5 / 5 x 10^k step. The top tick sits above
 * the tallest bar, so a peak never touches the frame (a 1-packet peak gets a 0-1-2 axis).
 */
function countTicks(max) {
  if (!(max > 0)) return [0, 1];
  const raw = max / 4;
  const mag = 10 ** Math.floor(Math.log10(raw));
  const steps = mag >= 10 ? [1, 2, 2.5, 5, 10] : [1, 2, 5, 10];
  const step = Math.max(1, steps.map((m) => m * mag).find((x) => x >= raw) || 10 * mag);
  const top = (Math.floor(max / step) + 1) * step;
  const ticks = [];
  for (let v = 0; v <= top; v += step) ticks.push(v);
  return ticks;
}

/** Bucket width for labels: 0.25 -> "0.25 s", 0.0042 -> "4.2 ms" (never a misleading "0 s"). */
function intervalLabel(seconds) {
  if (!(seconds > 0)) return 'interval';
  if (seconds >= 0.001) return `${Number(seconds.toFixed(3))} s`;
  return `${Number((seconds * 1000).toPrecision(2))} ms`;
}

/** ~6 round tick positions (1 / 2 / 2.5 / 5 x 10^k) from 0 to max, and the decimals they need. */
function niceTicks(max, target = 6) {
  if (!(max > 0)) return { ticks: [0], decimals: 0 };
  const raw = max / target;
  const mag = 10 ** Math.floor(Math.log10(raw));
  const step = [1, 2, 2.5, 5, 10].map((m) => m * mag).find((s) => s >= raw) || 10 * mag;
  const ticks = [];
  for (let v = 0; v <= max + step * 1e-6; v += step) ticks.push(Number(v.toFixed(10)));
  const halfStep = Math.abs(step / mag - Math.round(step / mag)) > 1e-9; // 2.5 x 10^k needs one more digit
  const decimals = Math.max(0, -Math.floor(Math.log10(step) + 1e-9) + (halfStep ? 1 : 0));
  return { ticks, decimals };
}

/**
 * Incident ranges as bands in lanes: a band goes into the first lane where it (and its
 * label) does not overlap the previous band. Positions are percentages of the time axis.
 */
function layoutBands(incidents, end) {
  const bands = incidents
    .filter((i) => Number.isFinite(i.relative_start))
    .map((i) => {
      const start = Math.min(Math.max(i.relative_start, 0), end);
      const stop = Math.min(Math.max(Number.isFinite(i.relative_end) ? i.relative_end : start, start), end);
      return {
        id: i.id,
        title: i.title,
        tone: verdictTone(i.verdict),
        verdictText: incidentVerdictLabel(i.verdict, i.verdict_label),
        start,
        stop,
        left: (start / end) * 100,
        width: ((stop - start) / end) * 100,
      };
    })
    .sort((a, b) => a.start - b.start || b.stop - a.stop);
  const laneEnds = [];
  for (const b of bands) {
    let lane = laneEnds.findIndex((x) => x <= b.left);
    if (lane === -1) {
      lane = laneEnds.length;
      laneEnds.push(0);
    }
    laneEnds[lane] = b.left + Math.max(b.width, LABEL_SHARE) + 0.5;
    b.lane = lane;
  }
  return { bands, lanes: laneEnds.length };
}

function BucketTooltip({ active, payload, series, bands }) {
  if (!active || !payload || !payload.length) return null;
  const p = payload[0].payload;
  const during = bands.filter((b) => b.start <= p.t1 && b.stop >= p.t0).map((b) => b.id);
  return (
    <div className="chart-tooltip tr-tooltip">
      <div className="chart-tooltip-title">{formatOffsetRange(p.t0, p.t1)}</div>
      {series.map((s) => (
        <div key={s.key} className={`chart-tooltip-row ${p[s.key] ? '' : 'tr-zero'}`}>
          <span className="tr-key" style={{ background: s.color }} aria-hidden="true" />
          <span className="muted">{s.label}</span>
          <strong>{formatInt(p[s.key])}</strong>
        </div>
      ))}
      {series.length > 1 && (
        <div className="chart-tooltip-row tr-tooltip-total">
          <span className="muted">Total</span>
          <strong>{plural(p.packets, 'packet')}</strong>
        </div>
      )}
      {during.length > 0 && <div className="chart-tooltip-note">Within {during.join(', ')}</div>}
    </div>
  );
}

/**
 * Packets over time, stacked by transport, with incident time ranges in a labelled strip
 * above the plot and a row of incident buttons below it. Only series that actually occur
 * in the capture are drawn. Hovering or focusing an incident button highlights its range.
 */
export function TrafficChart({ traffic, duration, incidents = [], onOpenIncident, height = 260 }) {
  const { points, buckets, end } = useMemo(() => buildPoints(traffic.series, duration), [traffic.series, duration]);
  // Only transports that occur are drawn, each with its packet total for the legend.
  const series = useMemo(
    () =>
      SERIES.map((s) => ({ ...s, total: buckets.reduce((sum, b) => sum + b[s.key], 0) })).filter((s) => s.total > 0),
    [buckets],
  );
  const yTicks = useMemo(() => countTicks(Math.max(0, ...buckets.map((b) => b.packets))), [buckets]);
  const { bands, lanes } = useMemo(
    () => (end > 0 ? layoutBands(incidents, end) : { bands: [], lanes: 0 }),
    [incidents, end],
  );
  const { ticks, decimals } = useMemo(() => niceTicks(end), [end]);
  const [hot, setHot] = useState('');

  const incidentRow = incidents.length > 0 && (
    <IncidentButtons incidents={incidents} hot={hot} onHot={setHot} onOpen={onOpenIncident} />
  );

  if (!buckets.length) {
    return <p className="muted small">No traffic timeline: the capture contained no readable packets.</p>;
  }
  if (!points.length) {
    // One bucket: every packet shares (practically) one timestamp. A plot would be a single bar.
    const b = buckets[0];
    return (
      <div className="tr-chart">
        <p className="text-2 small">
          {b.packets === 1
            ? 'The capture holds a single packet, so there is no activity over time to plot.'
            : `All ${plural(b.packets, 'packet')} share practically one timestamp${
                Number.isFinite(duration) ? ` (the capture spans ${formatOffset(duration)})` : ''
              }, so there is no activity over time to plot.`}
        </p>
        <Legend series={series} />
        {incidentRow}
      </div>
    );
  }

  const minTint = end / 200; // a near-instant incident still gets a visible sliver
  const tints = bands
    .filter((b) => b.id === hot || (b.stop - b.start) / end < TINT_MAX_COVERAGE)
    .map((b) => ({ ...b, x2: Math.min(end, Math.max(b.stop, b.start + minTint)) }));
  // The backend's width is rounded to 1 ms; a sub-millisecond capture falls back to the point spacing.
  const bucketWidth = traffic.bucket_seconds > 0 ? traffic.bucket_seconds : points[1].t - points[0].t;
  const xLabel = (v) => `${v.toFixed(decimals)}`;

  return (
    <figure className="chart tr-chart">
      <div className="tr-chart-head">
        <span className="tr-axis-unit">Packets per {intervalLabel(bucketWidth)}</span>
        <Legend series={series} />
      </div>

      {lanes > 0 && (
        <div className="tr-strip" aria-hidden="true"
             style={{ paddingLeft: MARGIN.left + Y_AXIS_WIDTH, paddingRight: MARGIN.right }}>
          <div className="tr-strip-track" style={{ height: lanes * 20 }}>
            {bands.map((b) => (
              <button key={b.id} type="button" tabIndex={-1}
                      className={`tr-band tone-${b.tone} ${hot === b.id ? 'is-hot' : ''} ${b.left > 88 ? 'is-end' : ''}`}
                      style={{ left: `${b.left}%`, width: `${b.width}%`, top: b.lane * 20 }}
                      title={`${b.id}: ${b.title} (${formatOffsetRange(b.start, b.stop)})`}
                      onMouseEnter={() => setHot(b.id)} onMouseLeave={() => setHot('')}
                      onClick={onOpenIncident ? () => onOpenIncident(b.id) : undefined}>
                <span className="tr-band-label">{b.id}</span>
              </button>
            ))}
          </div>
        </div>
      )}

      <div className="tr-plot" style={{ height }}>
        <ResponsiveContainer width="100%" height="100%" minWidth={0}>
          <AreaChart data={points} margin={MARGIN}>
            <CartesianGrid vertical={false} />
            <XAxis dataKey="t" type="number" domain={[0, end]} ticks={ticks} allowDataOverflow
                   tickFormatter={xLabel} tickLine={false} height={22} />
            <YAxis type="number" domain={[0, yTicks[yTicks.length - 1]]} ticks={yTicks} interval={0}
                   width={Y_AXIS_WIDTH} axisLine={false} tickLine={false} tickFormatter={(v) => formatInt(v)} />
            {tints.map((b) => (
              <ReferenceArea key={b.id} x1={b.start} x2={b.x2} ifOverflow="hidden"
                             fill={TONE_FILL[b.tone]} fillOpacity={b.id === hot ? 0.16 : 0.06}
                             stroke={b.id === hot ? TONE_FILL[b.tone] : 'none'} strokeOpacity={0.7} />
            ))}
            <Tooltip isAnimationActive={false} cursor={{ stroke: CURSOR, strokeWidth: 1 }}
                     content={(props) => <BucketTooltip {...props} series={series} bands={bands} />} />
            {series.map((s) => (
              <Area key={s.key} type="stepAfter" dataKey={s.key} name={s.label} stackId="transport"
                    stroke={s.color} strokeWidth={1.5} fill={s.color} fillOpacity={0.3}
                    isAnimationActive={false} activeDot={false} />
            ))}
          </AreaChart>
        </ResponsiveContainer>
      </div>
      <div className="tr-axis-title" style={{ paddingLeft: MARGIN.left + Y_AXIS_WIDTH }}>
        Seconds from the first packet
      </div>

      {incidentRow}

      <figcaption className="chart-caption">
        Packets per {intervalLabel(bucketWidth)} interval, stacked by transport layer (DNS, DHCP and other
        application protocols count under the transport that carried them).
        {bands.length
          ? ' Bands above the plot mark incident time ranges; overlapping in time does not by itself mean this traffic caused the incident.'
          : ' No incidents were reconstructed in this capture.'}
      </figcaption>
    </figure>
  );
}

/** Series legend with each transport's packet total (the colour key for plot and tooltip). */
function Legend({ series }) {
  return (
    <ul className="tr-legend plain-list" aria-label="Packets by transport">
      {series.map((s) => (
        <li key={s.key} title={s.note}>
          <span className="swatch" style={{ background: s.color }} aria-hidden="true" />
          {s.label}
          <strong className="tabular">{formatInt(s.total)}</strong>
        </li>
      ))}
    </ul>
  );
}

/** Keyboard path to the incidents drawn on the chart: id, verdict (colour + text) and time range. */
function IncidentButtons({ incidents, hot, onHot, onOpen }) {
  return (
    <ul className="tr-incidents plain-list" aria-label="Incidents on this timeline">
      {incidents.map((i) => {
        const tone = verdictTone(i.verdict);
        const content = (
          <>
            <span className={`dot dot-${tone}`} aria-hidden="true" />
            <span className="tr-inc-id">{i.id}</span>
            <span className="tr-inc-verdict">{incidentVerdictLabel(i.verdict, i.verdict_label)}</span>
            <span className="tr-inc-range">{formatOffsetRange(i.relative_start, i.relative_end)}</span>
          </>
        );
        return (
          <li key={i.id}>
            {onOpen ? (
              <button type="button" className={`tr-inc ${hot === i.id ? 'is-hot' : ''}`} title={`Open ${i.id}: ${i.title}`}
                      onClick={() => onOpen(i.id)} onMouseEnter={() => onHot(i.id)} onMouseLeave={() => onHot('')}
                      onFocus={() => onHot(i.id)} onBlur={() => onHot('')}>
                {content}
              </button>
            ) : (
              <span className="tr-inc" title={i.title}>{content}</span>
            )}
          </li>
        );
      })}
    </ul>
  );
}

/**
 * Protocol mix as plain HTML/CSS bars: no measuring, prints with the theme tokens and is
 * read naturally by screen readers. `max` rows; the long tail is folded into "N more".
 */
export function ProtocolBars({ protocols, max = 8 }) {
  const { rows, total } = useMemo(() => protocolRows(protocols, max), [protocols, max]);
  if (!rows.length) return <p className="muted small">No protocol statistics (the capture contained no packets).</p>;
  const top = rows[0].count || 1;
  return (
    <ul className="proto-bars tr-proto plain-list" aria-label="Packets per protocol">
      {rows.map((r) => {
        const pct = percent(r.count, total);
        return (
          <li key={r.name} className="proto-bar" title={r.folded ? `${r.folded.join(', ')}` : `${r.name}: ${formatInt(r.count)} packets (${pct})`}>
            <span className="proto-name">{r.name}</span>
            <span className="proto-track" aria-hidden="true">
              <span className={`proto-fill ${r.folded ? 'tr-fill-folded' : ''}`}
                    style={{ width: `${Math.max(1.5, (r.count / top) * 100)}%` }} />
            </span>
            <span className="proto-count num">{formatInt(r.count)}</span>
            <span className="proto-pct num muted">{pct}</span>
            {r.folded && <span className="sr-only"> ({r.folded.join(', ')})</span>}
          </li>
        );
      })}
    </ul>
  );
}

/** Older name, kept for callers that still import it. */
export const ProtocolChart = ProtocolBars;
