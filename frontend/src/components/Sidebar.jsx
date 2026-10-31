import { FileSearch, LayoutDashboard, Network, ShieldAlert, Siren, Shield } from 'lucide-react';
import BackendStatus from './BackendStatus.jsx';

export const VIEWS = [
  { id: 'overview', label: 'Overview', icon: LayoutDashboard, needsResult: false },
  { id: 'incidents', label: 'Incidents', icon: Siren, needsResult: true, count: 'incidents' },
  { id: 'findings', label: 'Faults & Threats', icon: ShieldAlert, needsResult: true, count: 'findings' },
  { id: 'traffic', label: 'Traffic', icon: Network, needsResult: true },
  { id: 'evidence', label: 'Evidence', icon: FileSearch, needsResult: true, count: 'evidence' },
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
          <Shield size={20} />
        </span>
        <span className="brand-text">
          <strong>NetSentinel</strong>
          <small>Packet capture diagnosis</small>
        </span>
      </div>

      <nav aria-label="Report views" className="nav">
        <ul>
          {VIEWS.map(({ id, label, icon: Icon, needsResult, count }) => {
            const disabled = needsResult && !hasResult;
            const n = count && counts ? counts[count] : null;
            return (
              <li key={id}>
                <button
                  type="button"
                  className="nav-item"
                  aria-current={view === id ? 'page' : undefined}
                  disabled={disabled}
                  title={disabled ? 'Analyse a capture first' : undefined}
                  onClick={() => onNavigate(id)}
                >
                  <Icon size={17} aria-hidden="true" />
                  <span className="nav-label">{label}</span>
                  {Number.isFinite(n) && (
                    <span className="nav-count" aria-label={`${n} items`}>
                      {n}
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
