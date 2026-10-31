// Small shared presentational components. Every status is shown as colour AND text,
// never colour alone.
import { useMemo, useState } from 'react';
import { ArrowDown, ArrowUp, ArrowUpDown } from 'lucide-react';
import {
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

export function SeverityBadge({ severity }) {
  return (
    <span className={`badge sev sev-${severity}`} title={`Severity: ${severityLabel(severity)}`}>
      <span className="sev-dot" aria-hidden="true" />
      {severityLabel(severity)}
      <span className="sr-only"> severity</span>
    </span>
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

export function Panel({ title, eyebrow, actions, children, className = '', id, as: Tag = 'section' }) {
  return (
    <Tag className={`panel ${className}`} id={id} aria-labelledby={title && id ? `${id}-title` : undefined}>
      {(title || actions) && (
        <div className="panel-head">
          <div>
            {eyebrow && <div className="eyebrow">{eyebrow}</div>}
            {title && (
              <h2 className="panel-title" id={id ? `${id}-title` : undefined}>
                {title}
              </h2>
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
