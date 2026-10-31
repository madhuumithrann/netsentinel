// Recharts (v3) charts. Colours are literal hex values because SVG presentation
// attributes are set by Recharts; they match the CSS tokens in styles.css.
import { useMemo } from 'react';
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  LabelList,
  Legend,
  ReferenceArea,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { formatAxisSeconds, formatInt, formatOffset, percent, verdictTone } from '../format.js';
import { protocolRows, trafficSeries } from '../derive.js';

// Categorical slots 1-3 (blue, orange, aqua), validated as a set on a dark surface.
export const SERIES_COLORS = { TCP: '#3987e5', UDP: '#d95926', Other: '#199e70' };
const INK = { primary: '#e6edf3', secondary: '#b3bfcc', muted: '#8d99a8', grid: '#243040', axis: '#3a4758' };
const TONE_FILL = { attack: '#f0605a', fault: '#e0a42f', inconclusive: '#5aa2f0', clean: '#3fb950', neutral: '#8d99a8' };

const tick = { fill: INK.muted, fontSize: 12 };

/** Title + one row per series, rendered inside a .chart-tooltip box. */
function TooltipRows({ payload, title }) {
  return (
    <>
      <div className="chart-tooltip-title">{title}</div>
      {payload.map((p) => (
        <div key={p.dataKey} className="chart-tooltip-row">
          <span className="swatch" style={{ background: p.color || p.fill }} aria-hidden="true" />
          <span>{p.name}</span>
          <strong>{formatInt(p.value)}</strong>
        </div>
      ))}
    </>
  );
}

/** Horizontal bars: packets per protocol (a magnitude per category, one hue). */
export function ProtocolChart({ protocols, height }) {
  const { rows, total } = useMemo(() => protocolRows(protocols), [protocols]);
  if (!rows.length) return <p className="muted">No protocol statistics (the capture contained no packets).</p>;
  const h = height || rows.length * 30 + 16;
  return (
    <figure className="chart">
      <div style={{ width: '100%', height: h }}>
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={rows} layout="vertical" margin={{ top: 4, right: 56, bottom: 4, left: 4 }} barCategoryGap={6}>
            <XAxis type="number" hide domain={[0, 'dataMax']} />
            <YAxis
              type="category"
              dataKey="name"
              width={84}
              tick={{ ...tick, fill: INK.secondary }}
              axisLine={false}
              tickLine={false}
            />
            <Tooltip
              cursor={{ fill: 'rgba(255,255,255,0.04)' }}
              content={({ active, payload }) => {
                if (!active || !payload || !payload.length) return null;
                const row = payload[0].payload;
                return (
                  <div className="chart-tooltip">
                    <div className="chart-tooltip-title">{row.name}</div>
                    <div className="chart-tooltip-row">
                      <span>Packets</span>
                      <strong>
                        {formatInt(row.count)} ({percent(row.count, total)})
                      </strong>
                    </div>
                    {row.folded && <div className="chart-tooltip-note">{row.folded.join(', ')}</div>}
                  </div>
                );
              }}
            />
            <Bar dataKey="count" name="Packets" fill={SERIES_COLORS.TCP} radius={[0, 4, 4, 0]} isAnimationActive={false}>
              <LabelList
                dataKey="count"
                position="right"
                fill={INK.secondary}
                fontSize={12}
                formatter={(v) => formatInt(v)}
              />
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
      <figcaption className="sr-only">
        Packets per protocol:{' '}
        {rows.map((r) => `${r.name} ${r.count}`).join(', ')}.
      </figcaption>
    </figure>
  );
}

/**
 * Packets over time (stacked TCP / UDP / other) with each incident's time range shaded.
 * x = seconds from the first packet; each backend bucket is drawn as a step.
 */
export function TrafficChart({ traffic, duration, incidents, onOpenIncident, height = 300 }) {
  const data = useMemo(() => trafficSeries(traffic.series, duration), [traffic.series, duration]);

  const spans = useMemo(() => {
    const maxX = Math.max(duration || 0, data.length ? data[data.length - 1].t : 0);
    // A one-packet incident has zero width; give it a minimum visible width.
    const minWidth = Math.max(traffic.bucket_seconds || 0, maxX / 150, 0.001);
    return incidents
      .filter((i) => Number.isFinite(i.relative_start))
      .map((i) => {
        const x1 = Math.max(0, i.relative_start);
        let x2 = Number.isFinite(i.relative_end) ? i.relative_end : x1;
        if (x2 - x1 < minWidth) x2 = x1 + minWidth;
        return { id: i.id, title: i.title, x1, x2, tone: verdictTone(i.verdict) };
      });
  }, [incidents, duration, data, traffic.bucket_seconds]);

  if (!data.length) return <p className="muted">No traffic timeline is available for this capture.</p>;

  const domainMax = Math.max(duration || 0, data[data.length - 1].t, ...spans.map((s) => s.x2));
  const showLabels = spans.length <= 8;
  const bucket = traffic.bucket_seconds;

  return (
    <figure className="chart">
      <div style={{ width: '100%', height }}>
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data} margin={{ top: 22, right: 16, bottom: 4, left: 0 }}>
            <CartesianGrid stroke={INK.grid} vertical={false} />
            <XAxis
              dataKey="t"
              type="number"
              domain={[0, domainMax]}
              tickFormatter={formatAxisSeconds}
              tick={tick}
              stroke={INK.axis}
              allowDataOverflow={false}
            />
            <YAxis allowDecimals={false} width={44} tick={tick} stroke={INK.axis} />
            {spans.map((s) => (
              <ReferenceArea
                key={s.id}
                x1={s.x1}
                x2={s.x2}
                fill={TONE_FILL[s.tone]}
                fillOpacity={0.16}
                stroke={TONE_FILL[s.tone]}
                strokeOpacity={0.6}
                ifOverflow="extendDomain"
                onClick={onOpenIncident ? () => onOpenIncident(s.id) : undefined}
                style={onOpenIncident ? { cursor: 'pointer' } : undefined}
                label={showLabels ? { value: s.id, position: 'insideTopLeft', fill: INK.primary, fontSize: 11 } : undefined}
              />
            ))}
            <Tooltip
              content={({ active, payload, label }) => {
                if (!active || !payload || !payload.length) return null;
                const row = payload[0].payload;
                const title = row.closing
                  ? `End of capture (${formatOffset(label)})`
                  : Number.isFinite(bucket)
                    ? `${formatOffset(label)} – ${formatOffset(label + bucket)}`
                    : formatOffset(label);
                const inside = spans.filter((s) => label >= s.x1 && label <= s.x2).map((s) => s.id);
                return (
                  <div className="chart-tooltip">
                    <TooltipRows payload={payload} title={title} />
                    {inside.length > 0 && <div className="chart-tooltip-note">During {inside.join(', ')}</div>}
                  </div>
                );
              }}
            />
            {['TCP', 'UDP', 'Other'].map((key) => (
              <Area
                key={key}
                type="stepAfter"
                dataKey={key}
                name={key === 'Other' ? 'Other (ARP, ICMP, …)' : key}
                stackId="traffic"
                stroke={SERIES_COLORS[key]}
                strokeWidth={2}
                fill={SERIES_COLORS[key]}
                fillOpacity={0.28}
                isAnimationActive={false}
                activeDot={{ r: 4 }}
              />
            ))}
            <Legend
              verticalAlign="bottom"
              height={28}
              iconType="square"
              formatter={(value) => <span style={{ color: INK.secondary, fontSize: 12 }}>{value}</span>}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
      <figcaption className="chart-caption">
        Packets per {Number.isFinite(bucket) ? `${bucket.toFixed(3)} s interval` : 'interval'}, stacked by transport.
        Shaded bands are incident time ranges{spans.length ? '' : ' (none in this capture)'}.
      </figcaption>
    </figure>
  );
}
