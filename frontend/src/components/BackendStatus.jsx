/**
 * Live backend status, driven by the /api/health poll in useHealth(). It never shows a
 * static "ready": the text is derived from the last real response.
 */
export default function BackendStatus({ health }) {
  const { state, data, checkedAt, error } = health;
  const checked = checkedAt ? new Date(checkedAt).toLocaleTimeString() : 'not yet';
  let text;
  let detail;
  if (state === 'online') {
    const detectors = Array.isArray(data?.detectors) ? data.detectors.length : 0;
    text = 'Backend online';
    detail = `v${data?.version || '?'} · ${detectors} detector${detectors === 1 ? '' : 's'}`;
  } else if (state === 'offline') {
    text = 'Backend offline';
    detail = 'Retrying every 10 s';
  } else {
    text = 'Checking backend…';
    detail = '';
  }
  return (
    <div
      className={`backend-status status-${state}`}
      role="status"
      title={`Last health check: ${checked}${error ? ` – ${error}` : ''}`}
    >
      <span className="status-dot" aria-hidden="true" />
      <span className="status-text">
        <strong>{text}</strong>
        {detail && <small>{detail}</small>}
      </span>
    </div>
  );
}
