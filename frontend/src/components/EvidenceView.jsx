import { useEffect, useMemo, useRef, useState } from 'react';
import { FileSearch, ShieldCheck, X } from 'lucide-react';
import { formatInt, formatOffset, humanize, plural } from '../format.js';
import { EmptyState, FindingRef, SeverityBadge } from './ui.jsx';

const PAGE_SIZE = 100;

/**
 * Evidence explorer: one row per (finding, packet). Shows what the packet is, why it was
 * used as evidence (the detector's role text) and which rule produced the finding.
 * Packet numbers are capture frame numbers, so they match Wireshark's "Go to packet".
 */
export default function EvidenceView({ result, index, filter, onFilterChange, onOpenIncident }) {
  const { incidentId = '', findingId = '', packet = null, query = '' } = filter;
  const [page, setPage] = useState(0);
  const highlightRef = useRef(null);

  const findingsForSelect = useMemo(() => {
    if (!incidentId) return result.findings;
    const inc = index.incidentsById.get(incidentId);
    return inc ? result.findings.filter((f) => inc.findings.includes(f.id)) : result.findings;
  }, [result.findings, index, incidentId]);

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    return index.evidenceRows.filter((r) =>
      (!incidentId || r.incident?.id === incidentId) &&
      (!findingId || r.finding.id === findingId) &&
      (!q || r.search.includes(q)));
  }, [index.evidenceRows, incidentId, findingId, query]);

  // Jump to the page holding the highlighted packet.
  useEffect(() => {
    if (packet == null) {
      setPage(0);
      return;
    }
    const pos = rows.findIndex((r) => r.packet === packet);
    setPage(pos >= 0 ? Math.floor(pos / PAGE_SIZE) : 0);
  }, [packet, rows]);

  useEffect(() => {
    highlightRef.current?.scrollIntoView({ block: 'center' });
  }, [page, packet]);

  const pages = Math.max(1, Math.ceil(rows.length / PAGE_SIZE));
  const visible = rows.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);
  const set = (patch) => onFilterChange({ ...filter, ...patch });
  const truncated = result.findings.filter((f) => f.evidence_truncated);

  return (
    <div className="view">
      <div className="view-head">
        <h1 id="view-title" tabIndex={-1}>
          Evidence explorer
        </h1>
        <p className="muted">
          Every packet NetSentinel used as evidence, why it was used, and which rule produced the finding. Packet numbers
          are the capture's frame numbers: use <span className="mono">Go to packet</span> in Wireshark to inspect the
          same frame.
        </p>
      </div>

      <div className="notice">
        <ShieldCheck size={16} aria-hidden="true" />
        <span>
          Only header metadata is shown. Packet payloads (which could contain passwords or messages) are never stored or
          displayed.
        </span>
      </div>

      <form className="filters panel" role="search" onSubmit={(e) => e.preventDefault()}>
        <label className="filter">
          <span className="field-label">Incident</span>
          <select value={incidentId} onChange={(e) => set({ incidentId: e.target.value, findingId: '', packet: null })}>
            <option value="">All incidents</option>
            {result.incidents.map((i) => (
              <option key={i.id} value={i.id}>
                {i.id}: {i.title}
              </option>
            ))}
          </select>
        </label>
        <label className="filter">
          <span className="field-label">Finding</span>
          <select value={findingId} onChange={(e) => set({ findingId: e.target.value, packet: null })}>
            <option value="">All findings</option>
            {findingsForSelect.map((f) => (
              <option key={f.id} value={f.id}>
                {f.id}: {f.title}
              </option>
            ))}
          </select>
        </label>
        <label className="filter filter-grow">
          <span className="field-label">Search</span>
          <input
            type="search"
            value={query}
            placeholder="IP, MAC, protocol, packet #, rule…"
            onChange={(e) => set({ query: e.target.value, packet: null })}
          />
        </label>
        {(incidentId || findingId || query || packet != null) && (
          <button type="button" className="button button-ghost"
                  onClick={() => onFilterChange({ incidentId: '', findingId: '', packet: null, query: '' })}>
            <X size={15} aria-hidden="true" /> Clear filters
          </button>
        )}
      </form>

      {packet != null && (
        <p className="muted" role="status">
          Highlighting packet <span className="mono">#{packet}</span>, opened from an incident timeline.
        </p>
      )}

      {!index.evidenceRows.length ? (
        <EmptyState icon={FileSearch} title="No evidence packets">
          <p>No findings were reported for this capture, so no packets were cited as evidence.</p>
        </EmptyState>
      ) : !rows.length ? (
        <EmptyState icon={FileSearch} title="No evidence matches these filters" />
      ) : (
        <>
          <p className="muted small" aria-live="polite">
            {plural(rows.length, 'evidence row')}
            {pages > 1 ? ` · page ${page + 1} of ${pages}` : ''}
          </p>
          <div className="table-wrap">
            <table className="table evidence-table">
              <thead>
                <tr>
                  <th scope="col" className="num">Packet</th>
                  <th scope="col" className="num">Time</th>
                  <th scope="col">Source → destination</th>
                  <th scope="col">Protocol</th>
                  <th scope="col" className="num">Length</th>
                  <th scope="col">What the packet is</th>
                  <th scope="col">Why it is evidence</th>
                  <th scope="col">Finding and rule</th>
                </tr>
              </thead>
              <tbody>
                {visible.map((r) => {
                  const hit = packet != null && r.packet === packet;
                  const p = r.pkt;
                  return (
                    <tr key={r.key} className={hit ? 'is-highlight' : ''} ref={hit ? highlightRef : undefined}
                        aria-current={hit ? 'true' : undefined}>
                      <td className="num mono">#{r.packet}</td>
                      <td className="num mono">{p && Number.isFinite(p.relative) ? formatOffset(p.relative) : '-'}</td>
                      <td className="mono small">
                        {p ? (
                          <>
                            {p.src || '?'}
                            {p.sport != null ? `:${p.sport}` : ''} → {p.dst || '?'}
                            {p.dport != null ? `:${p.dport}` : ''}
                            {p.src_mac && <div className="muted">{p.src_mac} → {p.dst_mac}</div>}
                          </>
                        ) : (
                          <span className="muted">summary not included</span>
                        )}
                      </td>
                      <td>{p?.protocol || '-'}</td>
                      <td className="num">{p && Number.isFinite(p.length) ? formatInt(p.length) : '-'}</td>
                      <td className="mono small">
                        {p?.info || '-'}
                        {p?.ttl != null && <span className="muted"> · TTL {p.ttl}</span>}
                        {p?.malformed && <div className="inline-error">malformed: {p.malformed}</div>}
                      </td>
                      <td>{r.role || <span className="muted">-</span>}</td>
                      <td className="small">
                        <div className="evidence-finding">
                          <FindingRef id={r.finding.id} title={r.finding.title}
                                      onClick={() => set({ findingId: r.finding.id, packet: null })} />
                          <SeverityBadge severity={r.finding.severity} />
                        </div>
                        <div>{r.finding.title}</div>
                        {r.finding.rule && <div className="muted rule">Rule: {r.finding.rule}</div>}
                        <div className="muted">
                          Detector: {humanize(r.finding.detector)}
                          {r.incident && (
                            <>
                              {' · '}
                              <button type="button" className="link-button" onClick={() => onOpenIncident(r.incident.id)}>
                                {r.incident.id}
                              </button>
                            </>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          {pages > 1 && (
            <nav className="pager" aria-label="Evidence pages">
              <button type="button" className="button button-secondary" disabled={page === 0}
                      onClick={() => setPage(page - 1)}>
                Previous
              </button>
              <span className="muted">
                Page {page + 1} of {pages}
              </span>
              <button type="button" className="button button-secondary" disabled={page >= pages - 1}
                      onClick={() => setPage(page + 1)}>
                Next
              </button>
            </nav>
          )}
          {truncated.length > 0 && (
            <p className="muted small">
              {truncated.map((f) => `${f.id} shows ${f.evidence.length} of ${formatInt(f.evidence_total)}`).join('; ')}{' '}
              evidence packets (the most relevant ones are kept to bound the response size).
            </p>
          )}
        </>
      )}
    </div>
  );
}
