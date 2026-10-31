import { useEffect, useState } from 'react';
import { getHealth } from './api.js';

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
