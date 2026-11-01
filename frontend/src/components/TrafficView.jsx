import { useMemo } from 'react';
import { Search } from 'lucide-react';
import { conversationPackets } from '../derive.js';
import { formatBytes, formatDuration, formatInt, formatOffset, formatUtc, plural } from '../format.js';
import { ProtocolBars, TrafficChart } from './Charts.jsx';
import { Panel, SortHeader, Stat, useSorted } from './ui.jsx';

// List sizes the backend caps (analyzer.py); at the cap the UI says so instead of implying completeness.
const TALKER_CAP = 15;
const HOST_CAP = 50;
const MAC_LIST_CAP = 4; // MACs listed per address
const UNCONFIGURED = '0.0.0.0';

/**
 * Network traffic analysis: activity over time (with incident ranges), protocol mix, top
 * talkers, local hosts and the busiest conversations. Everything here is measured directly
 * from the capture by the backend; the only inferred column is the host role.
 */
export default function TrafficView({ result, index, route, nav }) {
  const { traffic, hosts } = result;
  const protocolCount = Object.keys(traffic.protocols).length;
  const shown = traffic.conversations.length;
  const capped = traffic.conversation_total > shown;

  return (
    <div className="view tr-view">
      <div className="view-head">
        <div>
          <h1 id="view-title" tabIndex={-1}>Traffic</h1>
          <p className="view-sub">Who talked to whom, how much and when. All values on this page are measured from the capture.</p>
        </div>
      </div>

      <div className="tr-stats">
        <Stat label="Packets" value={formatInt(result.packets_analyzed)} sub={packetsNote(result.parse)} />
        <Stat label="Duration" value={formatDuration(result.duration_seconds)}
              sub={result.capture_start != null ? `from ${formatUtc(result.capture_start)}` : 'start time not available'} />
        <Stat label="Conversations" value={formatInt(traffic.conversation_total)}
              sub={capped ? `busiest ${formatInt(shown)} listed` : 'address pairs per protocol'} />
        <Stat label="TCP connections" value={Number.isFinite(traffic.tcp_connections) ? formatInt(traffic.tcp_connections) : '–'}
              sub={Number.isFinite(traffic.tcp_connections) ? 'distinct TCP flows' : 'not available'} />
        <Stat label="Local hosts" value={formatInt(hosts.length)}
              sub={hosts.length >= HOST_CAP ? `list capped at ${HOST_CAP}` : 'private IPs seen sending'} />
        <Stat label="Protocols" value={formatInt(protocolCount)} sub={protocolCount ? 'seen in the capture' : 'none'} />
      </div>

      <Panel title="Activity over time" eyebrow="Packets per interval" id="traffic-activity">
        <TrafficChart traffic={traffic} duration={result.duration_seconds} incidents={result.incidents}
                      onOpenIncident={nav.openIncident} />
      </Panel>

      <div className="tr-pair">
        <Panel title="Protocol distribution" id="traffic-protocols"
               eyebrow={protocolCount ? `${plural(protocolCount, 'protocol')} · ${plural(result.packets_analyzed, 'packet')}` : 'Packets per protocol'}>
          <ProtocolBars protocols={traffic.protocols} />
          {protocolCount > 0 && (
            <p className="tr-panel-note">
              Each packet is counted once, under the highest layer decoded: a DNS query counts as DNS, not as UDP.
            </p>
          )}
        </Panel>
        <Panel title="Top talkers" id="traffic-talkers" flush
               eyebrow={traffic.top_talkers.length >= TALKER_CAP ? `Busiest ${TALKER_CAP} senders by packets` : 'By packets sent'}>
          <TalkersTable rows={traffic.top_talkers} />
        </Panel>
      </div>

      <Panel title="Local hosts" id="traffic-hosts" flush
             eyebrow={hosts.length >= HOST_CAP ? `Busiest ${HOST_CAP} private addresses` : 'Private addresses and the MACs they sent from'}>
        <HostsTable rows={hosts} />
      </Panel>

      <Panel title="Conversations" id="traffic-conversations" flush
             eyebrow={capped ? `Busiest ${formatInt(shown)} of ${formatInt(traffic.conversation_total)}` : 'Address pairs per transport protocol'}>
        <ConversationsTable result={result} index={index} query={route.q} nav={nav} capped={capped} />
      </Panel>
    </div>
  );
}

/** Sub-line for the packet count: says when the parser could not read the whole file. */
function packetsNote(parse) {
  if (parse.malformed_packets) return `analysed · ${formatInt(parse.malformed_packets)} malformed`;
  if (parse.truncated_file) return 'readable part only (file truncated)';
  if (parse.stopped_early) return 'analysis stopped early';
  return 'analysed';
}

/** Talkers with an inline bar scaled to the busiest sender, so the ranking reads at a glance. */
function TalkersTable({ rows }) {
  const { sorted, sort, toggle } = useSorted(rows, 'packets');
  if (!rows.length) return <p className="tr-empty muted small">No IP or ARP senders in this capture.</p>;
  const top = Math.max(...rows.map((r) => r.packets), 1);
  return (
    <div className="table-wrap">
      <table className="table table-dense">
        <thead>
          <tr>
            <SortHeader label="Address" column="ip" sort={sort} onSort={toggle} />
            <SortHeader label="Packets sent" column="packets" sort={sort} onSort={toggle} numeric />
            <SortHeader label="Bytes sent" column="bytes" sort={sort} onSort={toggle} numeric />
          </tr>
        </thead>
        <tbody>
          {sorted.map((t) => (
            <tr key={t.ip}>
              <td>
                <span className="tr-addr">
                  <span className="mono">{t.ip}</span>
                  <ScopeTag ip={t.ip} local={t.local} />
                </span>
              </td>
              <td className="num">
                <span className="tr-bar-cell">
                  <span className="tr-bar" aria-hidden="true">
                    <span style={{ width: `${Math.max(2, (t.packets / top) * 100)}%` }} />
                  </span>
                  {formatInt(t.packets)}
                </span>
              </td>
              <td className="num nowrap">{formatBytes(t.bytes)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/**
 * The backend's "local" flag means a private or link-local address, so the tag says exactly
 * that. 0.0.0.0 is flagged local too, but it is a sender without an address, not a host.
 */
function ScopeTag({ ip, local }) {
  if (ip === UNCONFIGURED) {
    return (
      <span className="tr-scope" title="Sender without an IP address yet (DHCP discovery or an ARP probe)">unassigned</span>
    );
  }
  return local ? (
    <span className="tr-scope" title="Private or link-local address range (normally inside the network)">private</span>
  ) : (
    <span className="tr-scope is-public" title="Public address (outside the local network)">public</span>
  );
}


function HostsTable({ rows }) {
  const { sorted, sort, toggle } = useSorted(rows, 'packets');
  if (!rows.length) {
    return <p className="tr-empty muted small">No private-range address sent IP traffic in this capture (ARP-only senders appear under Top talkers).</p>;
  }
  return (
    <div className="table-wrap">
      <table className="table table-dense">
        <thead>
          <tr>
            <SortHeader label="IP address" column="ip" sort={sort} onSort={toggle} />
            <th scope="col">MAC addresses</th>
            <th scope="col">Inferred roles</th>
            <SortHeader label="Packets sent" column="packets" sort={sort} onSort={toggle} numeric />
          </tr>
        </thead>
        <tbody>
          {sorted.map((h) => (
            <tr key={h.ip}>
              <td className="mono nowrap">{h.ip}</td>
              <td>
                <span className="tr-macs">
                  {h.macs.length ? h.macs.map((m) => <span key={m} className="mono">{m}</span>) : <span className="muted">–</span>}
                  {h.macs.length > 1 && <MacBadge ip={h.ip} count={h.macs.length} />}
                </span>
              </td>
              <td>
                {h.roles.length ? (
                  <span className="chips">
                    {h.roles.map((r) => (
                      <span key={r} className="chip">{r.charAt(0).toUpperCase() + r.slice(1)}</span>
                    ))}
                  </span>
                ) : (
                  <span className="faint">–</span>
                )}
              </td>
              <td className="num">{formatInt(h.packets)}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="table-note">
        Roles are inferred from what the capture shows (DHCP offers, DNS answers, routing of public traffic). One IP sending
        from several MACs can be a replaced device, failover or ARP spoofing; the Findings view says which the evidence supports.
      </p>
    </div>
  );
}

function MacBadge({ ip, count }) {
  const label = `${count}${count >= MAC_LIST_CAP ? '+' : ''} MACs`;
  if (ip === UNCONFIGURED) {
    return (
      <span className="badge tone-neutral" title="Clients without an address yet (DHCP) all send from 0.0.0.0, so several MACs are expected here.">
        {label} · expected
      </span>
    );
  }
  return (
    <span className="badge tone-inconclusive"
          title={`This address was used by ${count >= MAC_LIST_CAP ? 'at least ' : ''}${count} different MAC addresses${count >= MAC_LIST_CAP ? ' (the list is capped at four)' : ''}.`}>
      {label}
    </span>
  );
}

function ConversationsTable({ result, index, query, nav, capped }) {
  const rows = useMemo(
    () =>
      result.traffic.conversations.map((c) => {
        const evidence = conversationPackets(result, index, c);
        return {
          ...c,
          key: `${c.a}|${c.b}|${c.protocol}`,
          span: Number.isFinite(c.start) && Number.isFinite(c.end) ? Math.max(0, c.end - c.start) : null,
          evidence,
          evidenceCount: evidence.length,
          search: `${c.a} ${c.b} ${c.protocol}`.toLowerCase(),
        };
      }),
    [result, index],
  );
  const q = (query || '').trim().toLowerCase();
  const filtered = useMemo(() => (q ? rows.filter((r) => q.split(/\s+/).every((w) => r.search.includes(w))) : rows), [rows, q]);
  const { sorted, sort, toggle } = useSorted(filtered, 'packets');
  const total = result.traffic.conversation_total;

  if (!rows.length) return <p className="tr-empty muted small">No conversations in this capture.</p>;

  return (
    <>
      <div className="tr-toolbar">
        <label className="tr-search">
          <Search size={14} aria-hidden="true" />
          <span className="sr-only">Filter conversations</span>
          <input type="search" className="input" placeholder="Filter by address or protocol" value={query || ''}
                 onChange={(e) => nav.set({ q: e.target.value }, { replace: true })} />
        </label>
        <span className="muted small" aria-live="polite">
          {q ? `${formatInt(filtered.length)} of ${formatInt(rows.length)} shown` : plural(rows.length, 'conversation')}
        </span>
      </div>
      {sorted.length === 0 ? (
        <p className="tr-empty muted small">
          No listed conversation matches “{query.trim()}”.{' '}
          <button type="button" className="link-button" onClick={() => nav.set({ q: '' }, { replace: true })}>Clear filter</button>
        </p>
      ) : (
        <div className="table-wrap is-scroll">
          <table className="table table-dense tr-conv-table">
            <thead>
              <tr>
                <SortHeader label="Endpoint A" column="a" sort={sort} onSort={toggle} />
                <SortHeader label="Endpoint B" column="b" sort={sort} onSort={toggle} />
                <SortHeader label="Proto" column="protocol" sort={sort} onSort={toggle} />
                <SortHeader label="Packets" column="packets" sort={sort} onSort={toggle} numeric />
                <SortHeader label="Bytes" column="bytes" sort={sort} onSort={toggle} numeric />
                <SortHeader label="First #" column="first" sort={sort} onSort={toggle} numeric />
                <SortHeader label="First seen" column="start" sort={sort} onSort={toggle} numeric />
                <SortHeader label="Last seen" column="end" sort={sort} onSort={toggle} numeric />
                <SortHeader label="Duration" column="span" sort={sort} onSort={toggle} numeric />
                <SortHeader label="Evidence" column="evidenceCount" sort={sort} onSort={toggle} numeric />
              </tr>
            </thead>
            <tbody>
              {sorted.map((c) => (
                <tr key={c.key}>
                  <td className="mono nowrap">{c.a}</td>
                  <td className="mono nowrap">{c.b}</td>
                  <td><span className="chip">{c.protocol || '?'}</span></td>
                  <td className="num">{formatInt(c.packets)}</td>
                  <td className="num nowrap">{formatBytes(c.bytes)}</td>
                  <td className="num mono">{Number.isFinite(c.first) ? `#${c.first}` : '–'}</td>
                  <td className="num mono nowrap">{formatOffset(c.start)}</td>
                  <td className="num mono nowrap">{formatOffset(c.end)}</td>
                  <td className="num nowrap">{c.span == null ? '–' : formatDuration(c.span)}</td>
                  <td className="num nowrap">
                    {c.evidenceCount > 0 ? (
                      <span className="tr-evidence">
                        <span className="tabular">{formatInt(c.evidenceCount)}</span>
                        <button type="button" className="button button-xs"
                                title={`Inspect packet #${c.evidence[0]}, the first evidence packet in this conversation`}
                                onClick={() => nav.openPacket(c.evidence[0])}>
                          Inspect #{c.evidence[0]}
                        </button>
                      </span>
                    ) : (
                      <span className="faint">–</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <p className="table-note">
        Times are offsets from the first packet. Evidence counts packets cited by a finding.
        {capped ? ` Only the busiest ${formatInt(rows.length)} of ${formatInt(total)} conversations are listed; quieter ones are not shown.` : ''}
      </p>
    </>
  );
}
