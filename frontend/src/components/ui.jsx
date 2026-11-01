// Small shared presentational components. Every status is shown as colour AND text,
// never colour alone.
import { useMemo, useState } from 'react';
import { ArrowDown, ArrowUp, ArrowUpDown } from 'lucide-react';
import { splitPacketRefs } from '../derive.js';
import {
  SEVERITY_LEVEL,
  assessmentLabel,
  assessmentTone,
  incidentVerdictLabel,
  severityLabel,
  strengthLabel,
  verdictTone,
} from '../format.js';

export function Badge({ tone = 'neutral', children, title, className = '' }) {
  return (
    <span className={`badge tone-${tone} ${className}`} title={title}>
      {children}
    </span>
  );
}

/** Severity as a neutral 4-bar level meter plus its name (hue is reserved for attack/fault). */
export function SeverityBadge({ severity }) {
  const level = SEVERITY_LEVEL[severity] ?? 0;
  return (
    <span className={`sev sev-${severity}`} title={`Severity: ${severityLabel(severity)}`}>
      <span className="sev-meter" aria-hidden="true">
        {[1, 2, 3, 4].map((n) => (
          <i key={n} className={n <= level ? 'on' : ''} />
        ))}
      </span>
      {severityLabel(severity)}
      <span className="sr-only"> severity</span>
    </span>
  );
}

/**
 * A capture frame number ("#123"). With onOpen it is a button that opens the packet in
 * the evidence explorer; without, plain text.
 */
export function PacketRef({ packet, onOpen, title }) {
  if (!Number.isFinite(packet)) return <span className="packet-ref">#?</span>;
  if (!onOpen) return <span className="packet-ref">#{packet}</span>;
  return (
    <button type="button" className="packet-ref" onClick={() => onOpen(packet)}
            title={title || `Inspect packet #${packet}`} aria-label={`Inspect packet ${packet}`}>
      #{packet}
    </button>
  );
}

/** Plain text in which every "#123" becomes a PacketRef. */
export function RefText({ text, onOpenPacket }) {
  if (!text) return null;
  return splitPacketRefs(text).map((seg, i) =>
    seg.packet != null ? <PacketRef key={i} packet={seg.packet} onOpen={onOpenPacket} /> : <span key={i}>{seg.text}</span>,
  );
}

/** Metric tile: label, big value, optional sub-line; tone adds a coloured left rail. */
export function Stat({ label, value, sub, tone, className = '' }) {
  return (
    <div className={`stat ${tone ? `rail rail-${tone}` : ''} ${className}`}>
      <span className="stat-label">{label}</span>
      <span className="stat-value">{value}</span>
      {sub && <span className="stat-sub">{sub}</span>}
    </div>
  );
}

/** Definition list of [label, value] pairs; pairs with an empty value are skipped. */
export function KV({ items, className = '' }) {
  const rows = items.filter(([, v]) => v != null && v !== '' && v !== false);
  if (!rows.length) return null;
  return (
    <dl className={`kv ${className}`}>
      {rows.map(([k, v]) => (
        <div key={k} style={{ display: 'contents' }}>
          <dt>{k}</dt>
          <dd>{v}</dd>
        </div>
      ))}
    </dl>
  );
}

/** Boxed message with an icon; tone colours the border and icon only. */
export function Callout({ tone = 'neutral', icon: Icon, title, children, className = '' }) {
  return (
    <div className={`callout tone-${tone} ${className}`}>
      {Icon && <Icon size={16} aria-hidden="true" />}
      <div className="stack" style={{ '--gap': '2px' }}>
        {title && <div className="callout-title">{title}</div>}
        <div className="text-2">{children}</div>
      </div>
    </div>
  );
}

/** Small section heading inside a panel (h3 by default). */
export function SectionTitle({ icon: Icon, children, count, as: Tag = 'h3', id, actions }) {
  const head = (
    <Tag className="section-title" id={id}>
      {Icon && <Icon size={15} aria-hidden="true" />}
      {children}
      {Number.isFinite(count) && <span className="count">({count})</span>}
    </Tag>
  );
  if (!actions) return head;
  return (
    <div className="row-between">
      {head}
      <div className="cluster">{actions}</div>
    </div>
  );
}

export function VerdictBadge({ verdict, label }) {
  return <Badge tone={verdictTone(verdict)}>{incidentVerdictLabel(verdict, label)}</Badge>;
}

export function AssessmentBadge({ assessment }) {
  return (
    <Badge tone={assessmentTone(assessment)} title="What the evidence says">
      Evidence: {assessmentLabel(assessment)}
    </Badge>
  );
}

/** Strong / moderate / weak, with three bars so the level is readable without colour. */
export function StrengthChip({ strength, prefix }) {
  const level = { strong: 3, moderate: 2, weak: 1 }[strength] || 0;
  return (
    <span className={`strength strength-${strength}`} title={`${prefix ? `${prefix}: ` : ''}${strengthLabel(strength)}`}>
      <span className="strength-bars" aria-hidden="true">
        {[1, 2, 3].map((n) => (
          <i key={n} className={n <= level ? 'on' : ''} />
        ))}
      </span>
      {prefix ? `${prefix}: ` : ''}
      {strengthLabel(strength)}
    </span>
  );
}

/**
 * Surface with an optional head (eyebrow, title, actions). `flush` removes the body
 * padding so a table can run edge to edge; `level` sets the title heading level.
 */
export function Panel({ title, eyebrow, actions, children, className = '', id, as: Tag = 'section', flush = false, level = 2 }) {
  const H = `h${level}`;
  return (
    <Tag className={`panel ${flush ? 'panel-flush' : ''} ${className}`} id={id}
         aria-labelledby={title && id ? `${id}-title` : undefined}>
      {(title || actions) && (
        <div className="panel-head">
          <div>
            {eyebrow && <div className="eyebrow">{eyebrow}</div>}
            {title && (
              <H className="panel-title" id={id ? `${id}-title` : undefined}>
                {title}
              </H>
            )}
          </div>
          {actions && <div className="panel-actions">{actions}</div>}
        </div>
      )}
      {children}
    </Tag>
  );
}

export function EmptyState({ icon: Icon, title, children }) {
  return (
    <div className="empty-state">
      {Icon && <Icon size={28} aria-hidden="true" />}
      <h3>{title}</h3>
      {children && <div className="empty-body">{children}</div>}
    </div>
  );
}

export function Skeleton({ lines = 3 }) {
  return (
    <div className="skeleton" aria-hidden="true">
      {Array.from({ length: lines }, (_, i) => (
        <span key={i} style={{ width: `${90 - ((i * 17) % 40)}%` }} />
      ))}
    </div>
  );
}

/** Bulleted (or numbered) list of plain strings; renders nothing for an empty list. */
export function TextList({ items, ordered = false, className = '' }) {
  if (!items || !items.length) return null;
  const Tag = ordered ? 'ol' : 'ul';
  return (
    <Tag className={`text-list ${className}`}>
      {items.map((item, i) => (
        <li key={i}>{item}</li>
      ))}
    </Tag>
  );
}

/** A labelled block (definition-style) that hides itself when there is no content. */
export function Field({ label, children }) {
  if (children == null || children === '' || (Array.isArray(children) && !children.length)) return null;
  return (
    <div className="field">
      <div className="field-label">{label}</div>
      <div className="field-value">{children}</div>
    </div>
  );
}

/** Sorting state for simple tables. */
export function useSorted(rows, initialKey, initialDir = 'desc') {
  const [sort, setSort] = useState({ key: initialKey, dir: initialDir });
  const sorted = useMemo(() => {
    const { key, dir } = sort;
    const factor = dir === 'asc' ? 1 : -1;
    return [...rows].sort((a, b) => {
      const x = a[key];
      const y = b[key];
      if (typeof x === 'number' && typeof y === 'number') return (x - y) * factor;
      return String(x ?? '').localeCompare(String(y ?? ''), 'en', { numeric: true }) * factor;
    });
  }, [rows, sort]);
  const toggle = (key) =>
    setSort((s) => (s.key === key ? { key, dir: s.dir === 'asc' ? 'desc' : 'asc' } : { key, dir: 'desc' }));
  return { sorted, sort, toggle };
}

/** Table header cell with a sort button and the matching aria-sort value. */
export function SortHeader({ label, column, sort, onSort, numeric = false }) {
  const active = sort.key === column;
  const Icon = !active ? ArrowUpDown : sort.dir === 'asc' ? ArrowUp : ArrowDown;
  return (
    <th
      scope="col"
      className={numeric ? 'num' : ''}
      aria-sort={active ? (sort.dir === 'asc' ? 'ascending' : 'descending') : 'none'}
    >
      <button type="button" className="sort-button" onClick={() => onSort(column)}>
        {label}
        <Icon size={13} aria-hidden="true" />
      </button>
    </th>
  );
}

/** Clickable finding id ("F-001") used across views. */
export function FindingRef({ id, title, onClick }) {
  if (!onClick) return <code className="ref">{id}</code>;
  return (
    <button type="button" className="ref ref-button" onClick={onClick} title={title ? `${id}: ${title}` : id}>
      {id}
    </button>
  );
}
