import { useCallback, useEffect, useState } from 'react';
import { getHealth } from './api.js';

export const VIEW_IDS = ['overview', 'incidents', 'findings', 'traffic', 'evidence', 'report'];
const ROUTE_KEYS = ['incident', 'finding', 'packet', 'tab', 'protocol', 'q'];

/**
 * Route <-> URL hash, e.g. "#/evidence?finding=F-002&packet=246". Only view names and
 * ids go into the URL (never capture data), so Back/Forward work and nothing sensitive
 * is persisted. Unknown views fall back to the overview.
 */
export function parseHash(hash) {
  const [path = '', qs = ''] = String(hash || '').replace(/^#\/?/, '').split('?');
  const p = new URLSearchParams(qs);
  const packet = Number(p.get('packet'));
  return {
    view: VIEW_IDS.includes(path) ? path : 'overview',
    incident: p.get('incident') || '',
    finding: p.get('finding') || '',
    packet: p.get('packet') && Number.isInteger(packet) && packet > 0 ? packet : null,
    tab: p.get('tab') || '',
    protocol: p.get('protocol') || '',
    q: p.get('q') || '',
  };
}

export function routeToHash(route) {
  const p = new URLSearchParams();
  for (const key of ROUTE_KEYS) {
    const v = route[key];
    if (v != null && v !== '') p.set(key, String(v));
  }
  const qs = p.toString();
  return `#/${route.view || 'overview'}${qs ? `?${qs}` : ''}`;
}

/** [route, navigate(route, {replace})]: pushes a history entry unless replace is set. */
export function useHashRoute() {
  const [route, setRoute] = useState(() => parseHash(window.location.hash));
  useEffect(() => {
    const sync = () => setRoute(parseHash(window.location.hash));
    window.addEventListener('popstate', sync);
    window.addEventListener('hashchange', sync);
    return () => {
      window.removeEventListener('popstate', sync);
      window.removeEventListener('hashchange', sync);
    };
  }, []);
  const navigate = useCallback((next, { replace = false } = {}) => {
    const hash = routeToHash(next);
    if (hash !== window.location.hash) {
      if (replace) window.history.replaceState(null, '', hash);
      else window.history.pushState(null, '', hash);
    }
    setRoute(parseHash(hash));
  }, []);
  return [route, navigate];
}

const HEALTH_INTERVAL_MS = 10_000;
const HEALTH_TIMEOUT_MS = 5_000;

/**
 * Polls GET /api/health every 10 s. The state is only "online" when the backend really
 * answered with status "ok"; a failed or slow request shows "offline". Requests never
 * overlap: the next poll is scheduled after the previous one settles.
 */
export function useHealth() {
  const [health, setHealth] = useState({ state: 'checking', data: null, checkedAt: null, error: '' });

  useEffect(() => {
    let timer = null;
    let controller = null;
    let stopped = false;

    async function check() {
      controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), HEALTH_TIMEOUT_MS);
      try {
        const data = await getHealth(controller.signal);
        if (stopped) return;
        const ok = data && data.status === 'ok';
        setHealth({
          state: ok ? 'online' : 'offline',
          data: ok ? data : null,
          checkedAt: Date.now(),
          error: ok ? '' : 'The backend answered but did not report status "ok".',
        });
      } catch (err) {
        if (stopped) return;
        const message = err && err.kind === 'abort' ? 'The health check timed out.' : err?.message || 'Health check failed.';
        setHealth((prev) => ({ state: 'offline', data: prev.data, checkedAt: Date.now(), error: message }));
      } finally {
        clearTimeout(timeout);
        if (!stopped) timer = setTimeout(check, HEALTH_INTERVAL_MS);
      }
    }

    check();
    return () => {
      stopped = true;
      clearTimeout(timer);
      controller?.abort();
    };
  }, []);

  return health;
}

/** Whole seconds elapsed since `startedAt` (ms), ticking while `active`. */
export function useElapsed(startedAt, active) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!active) return undefined;
    setNow(Date.now());
    const id = setInterval(() => setNow(Date.now()), 250);
    return () => clearInterval(id);
  }, [active, startedAt]);
  return active && startedAt ? Math.max(0, Math.floor((now - startedAt) / 1000)) : 0;
}
