// Thin client for the NetSentinel FastAPI backend.
//
// Every URL is relative (/api/...). In development Vite proxies /api to the backend
// (see vite.config.js), so the backend address is never hard-coded in the UI and no
// credentials or secrets are involved.

export class ApiError extends Error {
  /**
   * @param {string} message  text that is safe to show to the user
   * @param {{status?: number, kind?: 'http'|'network'|'abort'|'invalid'}} info
   */
  constructor(message, { status = 0, kind = 'http' } = {}) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.kind = kind;
  }
}

export const UNREACHABLE_MESSAGE =
  'The NetSentinel backend is unreachable. Check that it is running (uvicorn app.main:app --port 8000) and try again.';

/**
 * Turn an error response body into a user-facing message.
 * - FastAPI / NetSentinel errors: {"detail": "..."}  -> the detail text, unchanged.
 * - FastAPI validation errors:   {"detail": [{loc, msg}, ...]} -> "file: Field required".
 * - Anything else (proxy errors, HTML pages, empty bodies) -> the HTTP status, plus a
 *   short plain-text excerpt when one exists.
 */
export function messageFromErrorBody(status, statusText, text) {
  let parsed;
  let isJson = false;
  if (text) {
    try {
      parsed = JSON.parse(text);
      isJson = true;
    } catch {
      // not JSON - handled below
    }
  }
  const detail = isJson && parsed && typeof parsed === 'object' ? parsed.detail : undefined;
  if (typeof detail === 'string' && detail.trim()) return detail;
  if (Array.isArray(detail) && detail.length) {
    return detail
      .map((item) => {
        if (typeof item === 'string') return item;
        if (item && typeof item.msg === 'string') {
          const loc = Array.isArray(item.loc) ? item.loc.filter((p) => p !== 'body').join('.') : '';
          return loc ? `${loc}: ${item.msg}` : item.msg;
        }
        return JSON.stringify(item);
      })
      .join('; ');
  }
  if (detail != null && typeof detail === 'object') return JSON.stringify(detail);

  const label = `HTTP ${status}${statusText ? ` ${statusText}` : ''}`;
  const snippet = !isJson && text ? text.replace(/\s+/g, ' ').trim().slice(0, 200) : '';
  if (snippet && !/^<(!doctype|html)/i.test(snippet)) {
    return `The server responded with ${label}: ${snippet}`;
  }
  const hint =
    status >= 500 ? ' If you are using the development server, check that the backend is running on port 8000.' : '';
  return `The server responded with ${label} and no error message.${hint}`;
}

function isAbort(err) {
  return err && (err.name === 'AbortError' || err.kind === 'abort');
}

async function request(path, { method = 'GET', body, signal } = {}) {
  let response;
  try {
    response = await fetch(path, { method, body, signal, cache: 'no-store', headers: { Accept: 'application/json' } });
  } catch (err) {
    if (isAbort(err)) throw new ApiError('The request was cancelled.', { kind: 'abort' });
    // fetch() itself failed: no HTTP response at all.
    throw new ApiError(UNREACHABLE_MESSAGE, { kind: 'network' });
  }
  let text = '';
  try {
    text = await response.text();
  } catch (err) {
    if (isAbort(err)) throw new ApiError('The request was cancelled.', { kind: 'abort' });
    throw new ApiError('The connection was interrupted while the response was being received.', {
      status: response.status,
      kind: 'network',
    });
  }
  if (!response.ok) {
    throw new ApiError(messageFromErrorBody(response.status, response.statusText, text), { status: response.status });
  }
  try {
    return JSON.parse(text);
  } catch {
    throw new ApiError('The server returned a response that is not valid JSON.', {
      status: response.status,
      kind: 'invalid',
    });
  }
}

export const getHealth = (signal) => request('/api/health', { signal });

export async function getSamples(signal) {
  const data = await request('/api/samples', { signal });
  return Array.isArray(data) ? data.filter((s) => s && typeof s.id === 'string') : [];
}

export function analyzeCapture(file, signal) {
  const body = new FormData();
  body.append('file', file, file.name);
  return request('/api/analyze', { method: 'POST', body, signal });
}

export const analyzeSample = (id, signal) =>
  request(`/api/samples/${encodeURIComponent(id)}/analyze`, { method: 'POST', signal });
