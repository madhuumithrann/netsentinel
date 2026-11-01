import { FileSearch, FileText, LayoutDashboard, Network, Shield, ShieldAlert, Siren } from 'lucide-react';
import BackendStatus from './BackendStatus.jsx';

export const VIEWS = [
  { id: 'overview', label: 'Overview', icon: LayoutDashboard, needsResult: false },
  { id: 'incidents', label: 'Incidents', icon: Siren, needsResult: true, count: 'incidents', unit: ['incident', 'incidents'] },
  { id: 'findings', label: 'Faults & Threats', icon: ShieldAlert, needsResult: true, count: 'findings', unit: ['finding', 'findings'] },
  { id: 'traffic', label: 'Traffic', icon: Network, needsResult: true },
  { id: 'evidence', label: 'Evidence', icon: FileSearch, needsResult: true, count: 'evidence', unit: ['evidence packet', 'evidence packets'] },
  { id: 'report', label: 'Report', icon: FileText, needsResult: true },
];

/**
 * Left navigation (a top bar on narrow screens). Views that need an analysis result are
 * disabled until one exists; the active view is marked with aria-current="page".
 */
export default function Sidebar({ view, onNavigate, hasResult, counts, health }) {
  return (
    <aside className="sidebar">
      <div className="brand">
        <span className="brand-mark" aria-hidden="true">
          <Shield size={18} />
        </span>
        <span className="brand-text">
          <strong>NetSentinel</strong>
          <small>Packet capture investigation</small>
        </span>
      </div>

      <nav aria-label="Report views" className="nav">
        <div className="nav-section" aria-hidden="true">Investigation</div>
        <ul>
          {VIEWS.map(({ id, label, icon: Icon, needsResult, count, unit }) => {
            const disabled = needsResult && !hasResult;
            const n = count && counts ? counts[count] : null;
            const alarm = id === 'incidents' && counts?.attacks > 0;
            return (
              <li key={id}>
                <button
                  type="button"
                  className="nav-item"
                  aria-current={view === id ? 'page' : undefined}
                  disabled={disabled}
                  title={disabled ? 'Analyse a capture first' : label}
                  onClick={() => onNavigate(id)}
                >
                  <Icon size={16} aria-hidden="true" />
                  <span className="nav-label">{label}</span>
                  {Number.isFinite(n) && (
                    <span className={`nav-count ${alarm ? 'tone-attack' : ''}`}>
                      {n}
                      <span className="sr-only"> {n === 1 ? unit[0] : unit[1]}</span>
                    </span>
                  )}
                </button>
              </li>
            );
          })}
        </ul>
      </nav>

      <div className="sidebar-foot">
        <BackendStatus health={health} />
        <p className="sidebar-note">
          Offline analysis of uploaded captures. Nothing is captured live and no packets are sent.
        </p>
      </div>
    </aside>
  );
}
