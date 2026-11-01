import { useState } from 'react';
import { ArrowLeftRight, ChevronLeft, ChevronRight, FileQuestion, ListTree, Network, Server, TriangleAlert, X } from 'lucide-react';
import { conversationPackets, findConversation } from '../derive.js';
import { formatBytes, formatInt, formatOffset, formatUtc, plural } from '../format.js';
import { AssessmentBadge, Badge, Callout, FindingRef, KV, PacketRef, RefText, SectionTitle, SeverityBadge } from './ui.jsx';

/** Conversation packet chips shown before "Show all" (a scan conversation can cite 100+). */
const CONV_WINDOW = 24;

/** "192.168.1.10:443", or just the address when the frame has no port. */
function endpoint(ip, port) {
  if (!ip) return '';
  return Number.isFinite(port) ? `${ip}:${port}` : ip;
}

/** Previous / next packet numbers around n in a sorted list, and n's position (-1 if absent). */
function neighbours(list, n) {
  let prev = null;
  let next = null;
  for (const m of list) {
    if (m < n) prev = m;
    else if (m > n) {
      next = m;
      break;
    }
  }
  return { prev, next, pos: list.indexOf(n) };
}

/** Small right-aligned tag that says where a section's content comes from. */
function Source({ children }) {
  return <span className="ev-src">{children}</span>;
}

/**
 * Everything the report knows about one capture frame: its header summary, every finding
 * that cites it (and why), the conversation it belongs to and the hosts involved.
 * Only fields present in the backend's packet summary are shown; nothing is reconstructed.
 * `visible` (optional) is the set of packets the explorer's filters currently show, so a
 * "#123" reference inside a reason keeps the filters when it can.
 */
export default function PacketDetail({ packet, result, index, route, nav, visible }) {
  const pkt = result.packets[String(packet)] || null;
  const scope = index.findingsById.has(route.finding) ? route.finding : '';
  // With a finding filter, that finding's reason is listed first.
  const rows = [...(index.evidenceByPacket.get(packet) || [])].sort(
    (a, b) => (b.finding.id === scope) - (a.finding.id === scope),
  );
  const list = (scope && index.packetsByFinding.get(scope)) || index.evidencePackets;
  const { prev, next, pos } = neighbours(list, packet);

  const select = (n) => nav.set({ packet: n });
  const openRef = (n) => (visible?.has(n) ? select(n) : nav.openPacket(n));

  return (
    <section className="panel panel-flush ev-pd" aria-labelledby="ev-pd-title">
      <header className="ev-pd-head">
        <div className="ev-pd-titlerow">
          <h2 id="ev-pd-title" className="ev-pd-title">
            Packet <span className="mono">#{packet}</span>
          </h2>
          {pkt?.protocol && <Badge className="ev-proto">{pkt.protocol}</Badge>}
          <button type="button" className="icon-button ev-pd-close" onClick={() => nav.set({ packet: null })}
                  aria-label="Close packet detail" title="Close">
            <X size={16} aria-hidden="true" />
          </button>
        </div>
        {pkt && (
          <div className="ev-pd-meta">
            <span className="mono">{formatOffset(pkt.relative)}</span>
            <span aria-hidden="true">·</span>
            <span>{formatUtc(pkt.time)}</span>
            {Number.isFinite(pkt.length) && (
              <>
                <span aria-hidden="true">·</span>
                <span>{plural(pkt.length, 'byte')}</span>
              </>
            )}
          </div>
        )}
        {list.length > 0 && (
          <div className="ev-pd-nav">
            <button type="button" className="button button-xs" disabled={prev == null} onClick={() => select(prev)}
                    aria-label={prev == null ? 'No previous evidence packet' : `Previous evidence packet, #${prev}`}>
              <ChevronLeft size={14} aria-hidden="true" /> Prev
            </button>
            <span className="ev-pd-pos">
              {pos >= 0
                ? `${formatInt(pos + 1)} of ${formatInt(list.length)} ${scope ? `in ${scope}` : 'evidence packets'}`
                : scope ? `Not one of ${scope}'s packets` : 'Not an evidence packet'}
            </span>
            <button type="button" className="button button-xs" disabled={next == null} onClick={() => select(next)}
                    aria-label={next == null ? 'No next evidence packet' : `Next evidence packet, #${next}`}>
              Next <ChevronRight size={14} aria-hidden="true" />
            </button>
          </div>
        )}
      </header>

      <div className="ev-pd-body">
        {pkt ? <HeaderFields pkt={pkt} /> : <UnknownPacket packet={packet} result={result} cited={rows.length > 0} />}

        {rows.length > 0 && (
          <section className="ev-pd-section" aria-labelledby="ev-pd-why">
            <div className="ev-pd-shead">
              <SectionTitle id="ev-pd-why" icon={ListTree} count={rows.length}>Why this packet is evidence</SectionTitle>
              <Source>detector output</Source>
            </div>
            <ul className="plain-list ev-why-list">
              {rows.map((r) => (
                <WhyBlock key={r.key} row={r} nav={nav} onOpenPacket={openRef} />
              ))}
            </ul>
          </section>
        )}

        {pkt && <ConversationContext pkt={pkt} packet={packet} result={result} index={index} onOpenPacket={openRef} />}
        {pkt && <HostContext pkt={pkt} hosts={result.hosts} />}
      </div>
    </section>
  );
}

function HeaderFields({ pkt }) {
  return (
    <section className="ev-pd-section" aria-labelledby="ev-pd-fields">
      <div className="ev-pd-shead">
        <SectionTitle id="ev-pd-fields">Header fields</SectionTitle>
        <Source>observed</Source>
      </div>
      <KV className="ev-kv" items={[
        ['Source', pkt.src && <span className="mono">{endpoint(pkt.src, pkt.sport)}</span>],
        ['Destination', pkt.dst && <span className="mono">{endpoint(pkt.dst, pkt.dport)}</span>],
        ['Source MAC', pkt.src_mac && <span className="mono">{pkt.src_mac}</span>],
        ['Destination MAC', pkt.dst_mac && <span className="mono">{pkt.dst_mac}</span>],
        ['Protocol', pkt.protocol],
        ['Length', Number.isFinite(pkt.length) ? `${formatInt(pkt.length)} bytes on the wire` : ''],
        ['IP TTL', Number.isFinite(pkt.ttl) ? String(pkt.ttl) : ''],
      ]} />
      {pkt.info && (
        <div className="ev-pd-info">
          <div className="field-label">Decoded summary</div>
          <p className="mono">{pkt.info}</p>
        </div>
      )}
      {pkt.malformed && (
        <Callout tone="fault" icon={TriangleAlert} title="Malformed packet">
          The parser could not fully decode this frame: <span className="mono">{pkt.malformed}</span>
        </Callout>
      )}
    </section>
  );
}

/** A frame number the report has no summary for: say why, never invent fields. */
function UnknownPacket({ packet, result, cited }) {
  const beyond = result.packets_analyzed > 0 && packet > result.packets_analyzed;
  // Truncated findings keep their first 200 packets in capture order, so only a frame after
  // a truncated finding's last listed packet can be one of its unlisted ones.
  const capped = result.findings.filter(
    (f) => f.evidence_truncated && f.evidence.length && packet > f.evidence[f.evidence.length - 1].packet,
  );
  return (
    <Callout icon={FileQuestion} title="No header summary for this frame" className="ev-unknown">
      {cited ? (
        <p>A finding cites this frame, but the report does not include its header summary.</p>
      ) : beyond ? (
        <p>
          Only {plural(result.packets_analyzed, 'packet')} {result.packets_analyzed === 1 ? 'was' : 'were'} analysed,
          so frame #{packet} is not part of this capture&rsquo;s analysis.
        </p>
      ) : (
        <p>
          Frame #{packet} was not cited as evidence by any finding
          {capped.length > 0 && (
            <>
              {' '}listed in this report (it may be one of the unlisted packets of {capped.map((f) => f.id).join(', ')},
              whose evidence is capped at {formatInt(capped[0].evidence.length)})
            </>
          )}
          . NetSentinel keeps header summaries only for evidence packets.
        </p>
      )}
      <p>
        To inspect it, open the capture in Wireshark and use <span className="mono">Go to packet</span> with {packet}.
      </p>
    </Callout>
  );
}

function WhyBlock({ row, nav, onOpenPacket }) {
  const f = row.finding;
  return (
    <li className="ev-why">
      <div className="ev-why-head">
        <FindingRef id={f.id} title={f.title} onClick={() => nav.openFinding(f.id)} />
        <span className="ev-why-title">{f.title}</span>
      </div>
      <div className="cluster" style={{ '--gap': '6px' }}>
        <SeverityBadge severity={f.severity} />
        <AssessmentBadge assessment={f.assessment} />
      </div>
      <div className="ev-why-role">
        <span className="field-label">Reason this frame was cited</span>
        <p>{row.role ? <RefText text={row.role} onOpenPacket={onOpenPacket} /> : <span className="muted">No reason was recorded.</span>}</p>
      </div>
      {f.rule && (
        <div className="ev-why-rule">
          <span className="field-label">Rule</span>
          <code>{f.rule}</code>
        </div>
      )}
      {row.incident && (
        <div className="ev-why-inc">
          <span className="muted nowrap">Part of</span>
          <button type="button" className="link-button" onClick={() => nav.openIncident(row.incident.id)}>
            {row.incident.id}
          </button>
          <span className="muted truncate" title={row.incident.title}>{row.incident.title}</span>
        </div>
      )}
      {f.evidence_truncated && (
        <p className="ev-why-cap">
          {f.id} cites {formatInt(f.evidence_total)} packets; the report keeps the first {formatInt(f.evidence.length)}{' '}
          in capture order.
        </p>
      )}
    </li>
  );
}

function ConversationContext({ pkt, packet, result, index, onOpenPacket }) {
  const { conversation, capped } = findConversation(result, pkt);
  return (
    <section className="ev-pd-section" aria-labelledby="ev-pd-conv">
      <div className="ev-pd-shead">
        <SectionTitle id="ev-pd-conv" icon={Network}>Conversation</SectionTitle>
        <Source>observed</Source>
      </div>
      {conversation ? (
        // Keyed so "Show all" resets when the next packet belongs to another conversation.
        <ConversationBody key={`${conversation.a}|${conversation.b}|${conversation.protocol}`} c={conversation}
                          packet={packet} cited={conversationPackets(result, index, conversation)} onOpenPacket={onOpenPacket} />
      ) : (
        <p className="ev-pd-none">
          {!pkt.src || !pkt.dst
            ? 'This frame has no source and destination address pair, so it belongs to no conversation.'
            : capped
              ? `Not among the busiest ${formatInt(result.traffic.conversations.length)} conversations listed in this report (of ${formatInt(result.traffic.conversation_total)}), so its totals are not available.`
              : 'No conversation with this address pair and protocol is listed in the traffic summary.'}
        </p>
      )}
    </section>
  );
}

function ConversationBody({ c, packet, cited, onOpenPacket }) {
  const [showAll, setShowAll] = useState(false);
  let shown = cited;
  if (!showAll && cited.length > CONV_WINDOW) {
    // A window around the current packet, so it is always on screen.
    const at = Math.max(0, cited.indexOf(packet));
    const start = Math.max(0, Math.min(at - CONV_WINDOW / 2, cited.length - CONV_WINDOW));
    shown = cited.slice(start, start + CONV_WINDOW);
  }
  return (
    <>
      <div className="ev-conv-pair mono">
        <span className="truncate" title={c.a}>{c.a}</span>
        <ArrowLeftRight size={13} aria-label="with" />
        <span className="truncate" title={c.b}>{c.b}</span>
        <Badge className="ev-proto">{c.protocol}</Badge>
      </div>
      <dl className="ev-conv-stats">
        <div><dt>Packets</dt><dd>{formatInt(c.packets)}</dd></div>
        <div><dt>Bytes</dt><dd>{formatBytes(c.bytes)}</dd></div>
        <div><dt>First seen</dt><dd>{formatOffset(c.start)}</dd></div>
        <div><dt>Last seen</dt><dd>{formatOffset(c.end)}</dd></div>
        {Number.isFinite(c.first) && <div><dt>First frame</dt><dd className="mono">#{c.first}</dd></div>}
      </dl>
      <div className="ev-conv-cited">
        <div className="field-label">Evidence packets in this conversation ({formatInt(cited.length)})</div>
        {cited.length ? (
          <div className="chips">
            {shown.map((n) =>
              n === packet ? (
                <span key={n} className="packet-ref ev-current" aria-current="true" title="The packet shown here">
                  #{n}
                </span>
              ) : (
                <PacketRef key={n} packet={n} onOpen={onOpenPacket} />
              ),
            )}
          </div>
        ) : (
          <p className="ev-pd-none">None besides this frame.</p>
        )}
        {cited.length > CONV_WINDOW && (
          <button type="button" className="link-button xs" onClick={() => setShowAll((v) => !v)}>
            {showAll ? `Show ${CONV_WINDOW} around this packet` : `Show all ${formatInt(cited.length)}`}
          </button>
        )}
      </div>
    </>
  );
}

/**
 * The report's host table: local addresses that sent IP traffic (busiest 50), the Ethernet
 * source MACs they used (up to four) and the network roles the backend recognised.
 */
function HostContext({ pkt, hosts }) {
  const sides = [
    ['Source', pkt.src],
    ['Destination', pkt.dst],
  ].filter(([, ip], i, all) => ip && all.findIndex(([, x]) => x === ip) === i);
  if (!sides.length) return null;

  return (
    <section className="ev-pd-section" aria-labelledby="ev-pd-hosts">
      <div className="ev-pd-shead">
        <SectionTitle id="ev-pd-hosts" icon={Server}>Hosts</SectionTitle>
        <Source>observed</Source>
      </div>
      <ul className="plain-list ev-hosts">
        {sides.map(([side, ip]) => {
          const host = hosts.find((h) => h.ip === ip);
          return (
            <li key={side} className="ev-host">
              <div className="ev-host-head">
                <span className="mono strong truncate" title={ip}>{ip}</span>
                <span className="xs muted">{side.toLowerCase()}</span>
                {host?.roles.map((role) => (
                  <Badge key={role} tone="neutral" title="Network role recognised by the analysis">{role}</Badge>
                ))}
              </div>
              {host ? (
                <>
                  {host.macs.length > 0 && (
                    <div className="ev-host-macs">
                      <span className="xs muted">Sent from</span>
                      {host.macs.map((mac) => (
                        <span key={mac} className="chip mono">
                          {mac}
                          {side === 'Source' && mac === pkt.src_mac && <span className="ev-tag">this frame</span>}
                        </span>
                      ))}
                      <span className="xs faint">{plural(host.packets, 'packet')}</span>
                    </div>
                  )}
                  {host.macs.length > 1 && (
                    <p className="ev-host-note">
                      <TriangleAlert size={13} aria-hidden="true" />
                      <span>
                        This address sent IP packets from {host.macs.length === 4 ? 'at least 4' : host.macs.length}{' '}
                        different MAC addresses in this capture. That is consistent with an address conflict, a
                        failover or spoofing; the findings above say which the evidence supports.
                      </span>
                    </p>
                  )}
                </>
              ) : (
                <p className="xs muted">
                  No host record. The host table lists local addresses that sent IP traffic (busiest 50).
                </p>
              )}
            </li>
          );
        })}
      </ul>
    </section>
  );
}
