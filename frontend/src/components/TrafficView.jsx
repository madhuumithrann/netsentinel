import { formatBytes, formatInt, formatOffset, plural } from '../format.js';
import { ProtocolChart, TrafficChart } from './Charts.jsx';
import { Panel, SortHeader, useSorted } from './ui.jsx';

/**
 * Network traffic analysis: activity over time (with incident time ranges), protocol mix,
 * top talkers, inferred host roles and the busiest conversations. Every number comes from
 * the backend's traffic summary.
 */
export default function TrafficView({ result, onOpenIncident }) {
  const { traffic, hosts } = result;
  return (
    <div className="view">
      <div className="view-head">
        <h1 id="view-title" tabIndex={-1}>
          Traffic
        </h1>
        <p className="muted">
          {formatInt(result.packets_analyzed)} packets over {formatOffset(result.duration_seconds)} ·{' '}
          {plural(traffic.conversation_total, 'conversation')}
          {Number.isFinite(traffic.tcp_connections) ? ` · ${plural(traffic.tcp_connections, 'TCP connection')}` : ''}
        </p>
      </div>

      <Panel title="Activity over time" eyebrow="Packets per interval">
        <TrafficChart traffic={traffic} duration={result.duration_seconds} incidents={result.incidents}
                      onOpenIncident={onOpenIncident} />
        <p className="chart-caption muted">
          Shaded bands are incident time ranges; select one to open the incident.
          {traffic.bucket_seconds ? ` Each step covers ${formatOffset(traffic.bucket_seconds)}.` : ''}
        </p>
      </Panel>

      <div className="grid-2">
        <Panel title="Protocol distribution" eyebrow="Packets per protocol">
          <ProtocolChart protocols={traffic.protocols} />
        </Panel>
        <Panel title="Top talkers" eyebrow="By packets sent">
          <TalkersTable rows={traffic.top_talkers} />
        </Panel>
      </div>

      <Panel title="Hosts on the local network" eyebrow="Inferred roles">
        <HostsTable rows={hosts} />
        <p className="chart-caption muted">
          Roles are inferred from the traffic (DHCP options, DNS queries, forwarding behaviour) and are only as reliable
          as what the capture shows.
        </p>
      </Panel>

      <Panel title="Conversations" eyebrow={traffic.conversation_total > traffic.conversations.length
        ? `Busiest ${traffic.conversations.length} of ${formatInt(traffic.conversation_total)}` : 'All conversations'}>
        <ConversationsTable rows={traffic.conversations} />
      </Panel>
    </div>
  );
}

function TalkersTable({ rows }) {
  const { sorted, sort, toggle } = useSorted(rows, 'packets');
  if (!rows.length) return <p className="muted">No IP traffic in this capture.</p>;
  return (
    <div className="table-wrap">
      <table className="table">
        <thead>
          <tr>
            <SortHeader label="Address" column="ip" sort={sort} onSort={toggle} />
            <SortHeader label="Packets" column="packets" sort={sort} onSort={toggle} numeric />
            <SortHeader label="Bytes" column="bytes" sort={sort} onSort={toggle} numeric />
          </tr>
        </thead>
        <tbody>
          {sorted.map((t) => (
            <tr key={t.ip}>
              <td className="mono">
                {t.ip} <span className="muted small">{t.local ? 'local' : 'remote'}</span>
              </td>
              <td className="num">{formatInt(t.packets)}</td>
              <td className="num">{formatBytes(t.bytes)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function HostsTable({ rows }) {
  const { sorted, sort, toggle } = useSorted(rows, 'packets');
  if (!rows.length) return <p className="muted">No local hosts were identified.</p>;
  return (
    <div className="table-wrap">
      <table className="table">
        <thead>
          <tr>
            <SortHeader label="IP address" column="ip" sort={sort} onSort={toggle} />
            <th scope="col">MAC address(es)</th>
            <th scope="col">Role</th>
            <SortHeader label="Packets sent" column="packets" sort={sort} onSort={toggle} numeric />
          </tr>
        </thead>
        <tbody>
          {sorted.map((h) => (
            <tr key={h.ip}>
              <td className="mono">{h.ip}</td>
              <td className="mono small">
                {h.macs.join(', ')}
                {h.macs.length > 1 && <span className="badge tone-fault"> {h.macs.length} MACs</span>}
              </td>
              <td>
                {h.roles.length ? (
                  <span className="chips">
                    {h.roles.map((r) => (
                      <span key={r} className="chip">
                        {r}
                      </span>
                    ))}
                  </span>
                ) : (
                  <span className="muted">-</span>
                )}
              </td>
              <td className="num">{formatInt(h.packets)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function ConversationsTable({ rows }) {
  const { sorted, sort, toggle } = useSorted(rows, 'packets');
  if (!rows.length) return <p className="muted">No conversations in this capture.</p>;
  return (
    <div className="table-wrap">
      <table className="table">
        <thead>
          <tr>
            <SortHeader label="Endpoint A" column="a" sort={sort} onSort={toggle} />
            <SortHeader label="Endpoint B" column="b" sort={sort} onSort={toggle} />
            <SortHeader label="Protocol" column="protocol" sort={sort} onSort={toggle} />
            <SortHeader label="Packets" column="packets" sort={sort} onSort={toggle} numeric />
            <SortHeader label="Bytes" column="bytes" sort={sort} onSort={toggle} numeric />
            <SortHeader label="First seen" column="start" sort={sort} onSort={toggle} numeric />
            <SortHeader label="Last seen" column="end" sort={sort} onSort={toggle} numeric />
          </tr>
        </thead>
        <tbody>
          {sorted.map((c) => (
            <tr key={`${c.a}|${c.b}|${c.protocol}`}>
              <td className="mono">{c.a}</td>
              <td className="mono">{c.b}</td>
              <td>{c.protocol}</td>
              <td className="num">{formatInt(c.packets)}</td>
              <td className="num">{formatBytes(c.bytes)}</td>
              <td className="num mono">{formatOffset(c.start)}</td>
              <td className="num mono">{formatOffset(c.end)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
