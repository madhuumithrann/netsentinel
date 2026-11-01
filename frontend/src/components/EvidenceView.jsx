import { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import {
  ArrowLeft, ChevronLeft, ChevronRight, CornerDownLeft, FileSearch, MousePointerClick, ShieldCheck, TriangleAlert, X,
} from 'lucide-react';
import { captureQuality } from '../derive.js';
import { SEVERITY_LEVEL, assessmentLabel, formatInt, formatOffset, plural, severityLabel } from '../format.js';
import { Callout, EmptyState, SortHeader, useSorted } from './ui.jsx';
import PacketDetail from './PacketDetail.jsx';

const PAGE_SIZE = 100;
/** Finding chips per row before the rest fold into "+N" (all of them are in the row tooltip and the detail). */
const MAX_CHIPS = 1;

/** "192.168.1.10:443", or just the address when the frame has no port. */
function endpoint(ip, port) {
  if (!ip) return '';
  return Number.isFinite(port) ? `${ip}:${port}` : ip;
}

/**
 * One table row per unique evidence packet. A frame cited by two findings is one row with
 * two finding chips, so the table counts packets, not citations. Flat fields feed useSorted.
 */
function buildPacketRows(index) {
  return index.evidencePackets.map((n) => {
    const rows = index.evidenceByPacket.get(n) || [];
    const pkt = rows[0]?.pkt || null;
    const source = pkt ? endpoint(pkt.src, pkt.sport) : '';
    const destination = pkt ? endpoint(pkt.dst, pkt.dport) : '';
    return {
      packet: n,
      time: Number.isFinite(pkt?.relative) ? pkt.relative : null,
      source,
      destination,
      protocol: pkt?.protocol || '',
      length: Number.isFinite(pkt?.length) ? pkt.length : null,
      pkt,
      rows,
      findingIds: new Set(rows.map((r) => r.finding.id)),
      // The index's per-row search text already covers addresses, MACs, info, role, finding,
      // rule and incident; ports are added here so "443" or "10.0.0.5:53" also match.
      search: [source, destination, ...rows.map((r) => r.search)].join(' ').toLowerCase(),
    };
  });
}

/**
 * Height of the sticky report bar, so the packet detail can stick just below it. The bar
 * wraps on narrow screens, so it is measured rather than assumed.
 */
function useReportBarHeight() {
  const [height, setHeight] = useState(null);
  useLayoutEffect(() => {
    const bar = document.querySelector('.report-bar');
    if (!bar || typeof ResizeObserver === 'undefined') return undefined;
    const ro = new ResizeObserver(() => setHeight(bar.offsetHeight));
    ro.observe(bar);
    return () => ro.disconnect();
  }, []);
  return height;
}

/**
 * Evidence explorer: every packet a finding cites, filterable by incident, finding,
 * protocol and text, with a detail panel that explains why the frame is evidence.
 * Frame numbers are the capture's own, so they match Wireshark's "Go to packet".
 * All filters live in the URL (route.incident / finding / protocol / q / packet).
 */
export default function EvidenceView({ result, index, route, nav }) {
  const barHeight = useReportBarHeight();
  const wrapRef = useRef(null);
  const selectedRef = useRef(null);
  const sideRef = useRef(null);

  const packetRows = useMemo(() => buildPacketRows(index), [index]);
  const protocols = useMemo(() => {
    const counts = new Map();
    for (const r of packetRows) if (r.protocol) counts.set(r.protocol, (counts.get(r.protocol) || 0) + 1);
    return [...counts].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  }, [packetRows]);

  // Route parameters are only applied when they name something in this report.
  const incident = index.incidentsById.get(route.incident) || null;
  const findingKnown = index.findingsById.get(route.finding) || null;
  const finding = findingKnown && (!incident || incident.findings.includes(findingKnown.id)) ? findingKnown : null;
  const protocol = protocols.some(([p]) => p === route.protocol) ? route.protocol : '';
  const query = route.q.trim().toLowerCase();
  const ignored = [
    route.incident && !incident ? `incident ${route.incident}` : '',
    route.finding && !findingKnown ? `finding ${route.finding}` : '',
    findingKnown && !finding ? `finding ${route.finding} (it is not part of ${incident.id})` : '',
  ].filter(Boolean);

  const filtered = useMemo(() => {
    const scoped = incident ? new Set(incident.findings) : null;
    return packetRows.filter(
      (r) =>
        (!scoped || r.rows.some((row) => scoped.has(row.finding.id))) &&
        (!finding || r.findingIds.has(finding.id)) &&
        (!protocol || r.protocol === protocol) &&
        (!query || r.search.includes(query)),
    );
  }, [packetRows, incident, finding, protocol, query]);
  const visible = useMemo(() => new Set(filtered.map((r) => r.packet)), [filtered]);
  const { sorted, sort, toggle } = useSorted(filtered, 'packet', 'asc');

  // Paging: show the page holding the selected packet whenever the selection, filters or
  // sort change; manual paging only holds until one of those changes again.
  const selected = route.packet;
  const pages = Math.max(1, Math.ceil(sorted.length / PAGE_SIZE));
  const [pager, setPager] = useState({ rows: null, packet: null, page: 0 }); // rows: null = not paged by hand yet
  let page;
  if (pager.rows === sorted && pager.packet === selected) page = Math.min(pager.page, pages - 1);
  else {
    const pos = selected != null ? sorted.findIndex((r) => r.packet === selected) : -1;
    page = pos >= 0 ? Math.floor(pos / PAGE_SIZE) : 0;
  }
  const goToPage = (p) => {
    setPager({ rows: sorted, packet: selected, page: p });
    if (wrapRef.current) wrapRef.current.scrollTop = 0;
  };
  const pageRows = sorted.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);

  // Keep the selected row visible inside the table's own scroll area. The page itself only
  // moves when the row is outside the window (e.g. arriving from an incident timeline on a
  // short laptop screen); selecting a visible row never makes the page jump.
  useEffect(() => {
    const wrap = wrapRef.current;
    const row = selectedRef.current;
    if (!wrap || !row) return;
    // 1. Off-screen row: bring the table + detail block up to just under the report bar
    //    (not further, or the sticky detail panel would slide under the bar).
    const bar = document.querySelector('.report-bar')?.getBoundingClientRect().bottom || 0;
    const r0 = row.getBoundingClientRect();
    if (r0.top < bar || r0.bottom > window.innerHeight) {
      const layout = wrap.closest('.ev-layout');
      if (layout) window.scrollBy({ top: layout.getBoundingClientRect().top - bar - 12 });
    }
    // 2. Centre the row inside the table's own scroll area if it is outside it.
    const head = wrap.querySelector('thead')?.offsetHeight || 0;
    const w = wrap.getBoundingClientRect();
    const r = row.getBoundingClientRect();
    if (r.top < w.top + head || r.bottom > w.bottom) {
      wrap.scrollTop += r.top - w.top - head - (wrap.clientHeight - head - r.height) / 2;
    }
  }, [selected, page, sorted]);

  // A new packet starts at the top of the detail panel.
  useEffect(() => {
    sideRef.current?.scrollTo({ top: 0 });
  }, [selected]);

  const select = (n) => nav.set({ packet: n });
  const filtersActive = Boolean(route.incident || route.finding || route.protocol || route.q);
  const clearFilters = () => nav.set({ incident: '', finding: '', protocol: '', q: '' }, { replace: true });
  const hiddenSelected = selected != null && index.evidenceByPacket.has(selected) && !visible.has(selected);
  const citations = index.evidenceRows.length;
  const total = packetRows.length;
  const truncated = result.findings.filter((f) => f.evidence_truncated);
  const findingOptions = incident
    ? incident.findings.map((id) => index.findingsById.get(id)).filter(Boolean)
    : result.findings;

  const detail =
    selected != null ? (
      <PacketDetail packet={selected} result={result} index={index} route={route} nav={nav} visible={visible} />
    ) : (
      <Placeholder first={sorted[0]?.packet} onSelect={select} />
    );

  return (
    <div className="view ev-view">
      <div className="view-head">
        <div>
          {incident && (
            <button type="button" className="link-button ev-back" onClick={() => nav.openIncident(incident.id)}>
              <ArrowLeft size={14} aria-hidden="true" /> Back to {incident.id}
            </button>
          )}
          <h1 id="view-title" tabIndex={-1}>
            Evidence explorer
          </h1>
          <p className="view-sub">
            Every packet a finding cites, why the detector cited it, and the rule behind the finding.
          </p>
          <p className="ev-privacy">
            <ShieldCheck size={13} aria-hidden="true" />
            Header metadata only: payloads are never stored or shown. Frame numbers match Wireshark&rsquo;s
            &ldquo;Go to packet&rdquo;.
          </p>
        </div>
        <GoToPacket max={result.packets_analyzed} onGo={select} />
      </div>

      {total > 0 && (
        <form className="filters panel ev-filters" role="search" aria-label="Filter evidence packets"
              onSubmit={(e) => e.preventDefault()}>
          <label className="filter ev-f-incident">
            <span className="field-label">Incident</span>
            <select value={incident?.id || ''}
                    onChange={(e) => nav.set({ incident: e.target.value, finding: '' }, { replace: true })}>
              <option value="">All incidents</option>
              {result.incidents.map((i) => (
                <option key={i.id} value={i.id}>
                  {i.id} · {i.title}
                </option>
              ))}
            </select>
          </label>
          <label className="filter ev-f-finding">
            <span className="field-label">Finding</span>
            <select value={finding?.id || ''} onChange={(e) => nav.set({ finding: e.target.value }, { replace: true })}>
              <option value="">{incident ? `All findings in ${incident.id}` : 'All findings'}</option>
              {findingOptions.map((f) => (
                <option key={f.id} value={f.id}>
                  {f.id} · {f.title} ({formatInt(index.packetsByFinding.get(f.id)?.length ?? 0)})
                </option>
              ))}
            </select>
          </label>
          <label className="filter ev-f-proto">
            <span className="field-label">Protocol</span>
            <select value={protocol} onChange={(e) => nav.set({ protocol: e.target.value }, { replace: true })}>
              <option value="">All protocols</option>
              {protocols.map(([p, n]) => (
                <option key={p} value={p}>
                  {p} ({formatInt(n)})
                </option>
              ))}
            </select>
          </label>
          <label className="filter filter-grow">
            <span className="field-label">Search</span>
            <input type="search" value={route.q} placeholder="IP, MAC, port, info, F-001…"
                   onChange={(e) => nav.set({ q: e.target.value }, { replace: true })} />
          </label>
          <button type="button" className="button button-ghost ev-clear" onClick={clearFilters} disabled={!filtersActive}>
            <X size={15} aria-hidden="true" /> Clear filters
          </button>
        </form>
      )}

      {ignored.length > 0 && (
        <p className="ev-note" role="status">
          Not in this report, so not applied: {ignored.join('; ')}.
        </p>
      )}

      {total === 0 ? (
        <div className={selected != null ? 'ev-layout' : ''}
             style={barHeight ? { '--ev-top': `${barHeight}px` } : undefined}>
          <NoEvidence result={result} onTraffic={() => nav.go('traffic')} />
          {selected != null && <aside className="ev-side" ref={sideRef}>{detail}</aside>}
        </div>
      ) : (
        <div className="ev-layout" style={barHeight ? { '--ev-top': `${barHeight}px` } : undefined}>
          <div className="ev-main">
            {hiddenSelected && (
              <div className="ev-hidden" role="status">
                <span>
                  Packet <span className="mono">#{selected}</span> is selected but hidden by the current filters.
                </span>
                <button type="button" className="button button-xs" onClick={clearFilters}>
                  Show it
                </button>
              </div>
            )}

            <div className="ev-count" aria-live="polite">
              <span>
                {filtered.length === total ? (
                  <>
                    <strong>{plural(total, 'evidence packet')}</strong>
                    {citations > total && <span className="muted"> · {formatInt(citations)} citations (some frames support several findings)</span>}
                  </>
                ) : (
                  <>
                    <strong>{formatInt(filtered.length)}</strong> of {plural(total, 'evidence packet')} match
                  </>
                )}
              </span>
              {pages > 1 && (
                <span className="muted">
                  Rows {formatInt(page * PAGE_SIZE + 1)}–{formatInt(Math.min(sorted.length, (page + 1) * PAGE_SIZE))}
                </span>
              )}
            </div>

            {!filtered.length ? (
              <EmptyState icon={FileSearch} title="No evidence packets match these filters">
                <p>Try a shorter search or another protocol.</p>
                <button type="button" className="button button-sm ev-empty-action" onClick={clearFilters}>
                  <X size={14} aria-hidden="true" /> Clear filters
                </button>
              </EmptyState>
            ) : (
              <div className="ev-table-area">
                <div className="table-wrap is-scroll ev-table-wrap" ref={wrapRef}>
                  <table className="table table-dense ev-table">
                    <caption className="sr-only">
                      Evidence packets. Select a packet number to inspect it.
                    </caption>
                    <thead>
                      <tr>
                        <SortHeader label="Packet" column="packet" sort={sort} onSort={toggle} numeric />
                        <SortHeader label="Time" column="time" sort={sort} onSort={toggle} numeric />
                        <SortHeader label="Source" column="source" sort={sort} onSort={toggle} />
                        <SortHeader label="Destination" column="destination" sort={sort} onSort={toggle} />
                        <SortHeader label="Protocol" column="protocol" sort={sort} onSort={toggle} />
                        <SortHeader label="Length" column="length" sort={sort} onSort={toggle} numeric />
                        <th scope="col">Info</th>
                        <th scope="col">Evidence for</th>
                      </tr>
                    </thead>
                    <tbody>
                      {pageRows.map((r) => (
                        <EvidenceRow key={r.packet} row={r} selected={r.packet === selected} focusFinding={finding?.id}
                                     rowRef={r.packet === selected ? selectedRef : undefined} onSelect={select} />
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {pages > 1 && filtered.length > 0 && (
              <nav className="pager ev-pager" aria-label="Evidence pages">
                <button type="button" className="button button-sm" disabled={page === 0} onClick={() => goToPage(page - 1)}>
                  <ChevronLeft size={14} aria-hidden="true" /> Previous
                </button>
                <span className="muted small">
                  Page {page + 1} of {pages}
                </span>
                <button type="button" className="button button-sm" disabled={page >= pages - 1}
                        onClick={() => goToPage(page + 1)}>
                  Next <ChevronRight size={14} aria-hidden="true" />
                </button>
              </nav>
            )}

            {truncated.length > 0 && (
              <ul className="plain-list ev-caps">
                {truncated.map((f) => (
                  <li key={f.id}>
                    <span className="mono">{f.id}</span> cites {formatInt(f.evidence_total)} packets; the report keeps
                    the first {formatInt(f.evidence.length)} in capture order, so later ones are not listed here.
                  </li>
                ))}
              </ul>
            )}
          </div>

          <aside className="ev-side" ref={sideRef} aria-label="Packet detail">
            {detail}
          </aside>
        </div>
      )}
    </div>
  );
}

function EvidenceRow({ row, selected, focusFinding, rowRef, onSelect }) {
  const { packet, pkt } = row;
  // With a finding filter, that finding's chip and reason come first.
  const cites = focusFinding
    ? [...row.rows].sort((a, b) => (b.finding.id === focusFinding) - (a.finding.id === focusFinding))
    : row.rows;
  const chips = cites.slice(0, MAX_CHIPS);
  const more = cites.length - chips.length;
  const reasons = cites.map((c) => `${c.finding.id}: ${c.role || 'no reason recorded'}`).join('\n');

  const onRowClick = (e) => {
    // The packet button handles its own click; dragging to copy text is not a selection.
    if (e.target.closest('button') || window.getSelection()?.toString()) return;
    onSelect(packet);
  };

  return (
    <tr ref={rowRef} className={`is-clickable ${selected ? 'is-selected' : ''}`} onClick={onRowClick}>
      <td className="num">
        <button type="button" className="packet-ref ev-pkt" onClick={() => onSelect(packet)} aria-pressed={selected}
                aria-label={`Inspect packet ${packet}`}>
          #{packet}
        </button>
      </td>
      <td className="num mono">{pkt ? formatOffset(pkt.relative) : '–'}</td>
      <td className="mono" title={row.source}>
        <span className="truncate">{row.source || '–'}</span>
      </td>
      <td className="mono" title={row.destination}>
        <span className="truncate">{row.destination || '–'}</span>
      </td>
      <td>{row.protocol || '–'}</td>
      <td className="num">{Number.isFinite(row.length) ? formatInt(row.length) : '–'}</td>
      <td className="mono" title={pkt?.info}>
        <span className="truncate">
          {pkt?.malformed && <span className="ev-malformed">malformed</span>}
          {pkt ? pkt.info || <span className="faint">no decoded summary</span> : <span className="faint">header summary not in the report</span>}
        </span>
      </td>
      <td title={reasons}>
        <div className="ev-why-cell">
          {chips.map((c) => (
            <FindingChip key={c.key} finding={c.finding} />
          ))}
          {more > 0 && <span className="ev-fchip ev-more">+{more}</span>}
          <span className="ev-role truncate">{cites[0]?.role}</span>
        </div>
      </td>
    </tr>
  );
}

/** Finding id with a tiny severity meter (same scale as SeverityBadge). */
function FindingChip({ finding }) {
  const level = SEVERITY_LEVEL[finding.severity] ?? 0;
  return (
    <span className={`ev-fchip ${finding.severity === 'critical' ? 'is-critical' : ''}`}
          title={`${finding.id}: ${finding.title}. ${severityLabel(finding.severity)} severity; evidence: ${assessmentLabel(finding.assessment)}.`}>
      <span className="sev-meter" aria-hidden="true">
        {[1, 2, 3, 4].map((n) => (
          <i key={n} className={n <= level ? 'on' : ''} />
        ))}
      </span>
      {finding.id}
      <span className="sr-only">, {severityLabel(finding.severity)} severity</span>
    </span>
  );
}

/** Jump straight to a frame number, e.g. one seen in Wireshark or quoted in a report. */
function GoToPacket({ max, onGo }) {
  const [value, setValue] = useState('');
  const [error, setError] = useState('');
  const submit = (e) => {
    e.preventDefault();
    const n = Number(value);
    if (!Number.isInteger(n) || n < 1) return setError('Enter a frame number.');
    if (max > 0 && n > max) return setError(`This capture has ${formatInt(max)} packets.`);
    setError('');
    onGo(n);
  };
  return (
    <form className="ev-goto" onSubmit={submit} noValidate>
      <label className="filter">
        <span className="field-label">Go to packet #</span>
        <span className="ev-goto-row">
          <input className="input ev-goto-input" type="number" inputMode="numeric" min={1} max={max || undefined}
                 value={value} placeholder={max > 1 ? `1–${formatInt(max)}` : max === 1 ? '1' : 'frame no.'}
                 aria-invalid={error ? 'true' : undefined} aria-describedby={error ? 'ev-goto-error' : undefined}
                 onChange={(e) => {
                   setValue(e.target.value);
                   setError('');
                 }} />
          <button type="submit" className="button button-secondary">
            <CornerDownLeft size={14} aria-hidden="true" /> Go
          </button>
        </span>
      </label>
      {error && (
        <span className="ev-goto-error" id="ev-goto-error" role="alert">
          {error}
        </span>
      )}
    </form>
  );
}

function Placeholder({ first, onSelect }) {
  return (
    <section className="panel ev-placeholder" aria-labelledby="ev-ph-title">
      <MousePointerClick size={22} aria-hidden="true" />
      <h2 id="ev-ph-title">No packet selected</h2>
      <p>
        Click a row, or Tab to a packet number and press Enter. The detail shows the frame&rsquo;s header fields, why
        each finding cites it, its conversation and the hosts involved.
      </p>
      {Number.isFinite(first) && (
        <button type="button" className="button button-sm" onClick={() => onSelect(first)}>
          Inspect the first listed packet (#{first})
        </button>
      )}
    </section>
  );
}

function NoEvidence({ result, onTraffic }) {
  const quality = captureQuality(result);
  return (
    <div className="stack">
      <EmptyState icon={FileSearch} title="No packets were cited as evidence">
        <p>
          {result.findings.length
            ? 'The findings in this report did not cite individual packets.'
            : `No detector reported a finding in the ${plural(result.packets_analyzed, 'analysed packet')}, so nothing was cited as evidence.`}{' '}
          NetSentinel keeps header summaries only for evidence packets; conversation and protocol totals are on the
          Traffic page.
        </p>
        <button type="button" className="button button-sm ev-empty-action" onClick={onTraffic}>
          Open Traffic
        </button>
      </EmptyState>
      {quality.incomplete && !quality.empty && (
        <Callout tone="fault" icon={TriangleAlert} title="The capture was not fully readable">
          An empty evidence list only covers what could be read: {quality.reasons.join('; ')}.
        </Callout>
      )}
    </div>
  );
}
