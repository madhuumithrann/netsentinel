// Pure formatting and labelling helpers. No React, no DOM: these are imported by the
// components and by the Node smoke test (scripts/smoke-test.mjs).

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

const SEVERITY_LABEL = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' };
const STRENGTH_LABEL = { strong: 'Strong', moderate: 'Moderate', weak: 'Weak' };
const ASSESSMENT_LABEL = { attack: 'Attack', fault: 'Fault', benign: 'Benign', inconclusive: 'Inconclusive' };

// Fallback labels, used only if the backend omits verdict_label (they mirror correlate.py).
const INCIDENT_VERDICT_LABEL = {
  attack: 'Likely attack',
  mixed: 'Attack and fault together',
  fault: 'Network fault',
  inconclusive: 'Needs investigation',
  benign: 'Expected behaviour',
};

const LINK_TYPE_LABEL = {
  chain: 'attack chain',
  side_effect: 'side effect',
  cause: 'likely cause',
  same_problem: 'same problem',
};

const SAMPLE_KIND_LABEL = {
  benign: 'Benign',
  attack: 'Attack',
  fault: 'Fault',
  incident: 'Incident',
  malformed: 'Malformed input',
};

/** Rank used for sorting by severity (critical first). Unknown values sort last. */
export function severityRank(severity) {
  const i = SEVERITIES.indexOf(severity);
  return i === -1 ? SEVERITIES.length : i;
}

export const severityLabel = (s) => SEVERITY_LABEL[s] || humanize(s) || 'Unknown';
export const strengthLabel = (s) => STRENGTH_LABEL[s] || humanize(s) || 'Unknown';
export const assessmentLabel = (s) => ASSESSMENT_LABEL[s] || humanize(s) || 'Unknown';
export const incidentVerdictLabel = (v, label) => label || INCIDENT_VERDICT_LABEL[v] || humanize(v) || 'Unknown';
export const linkTypeLabel = (t) => LINK_TYPE_LABEL[t] || humanize(t) || 'related';
export const sampleKindLabel = (k) => SAMPLE_KIND_LABEL[k] || humanize(k) || 'Sample';

/**
 * Colour "tone" for a verdict. Incident verdicts (attack, mixed, fault, inconclusive,
 * benign) and the overall capture status (attack, fault, inconclusive, clean) share
 * one scale so the same colour always means the same thing.
 */
export function verdictTone(verdict) {
  switch (verdict) {
    case 'attack':
    case 'mixed':
      return 'attack';
    case 'fault':
      return 'fault';
    case 'inconclusive':
      return 'inconclusive';
    case 'benign':
    case 'clean':
      return 'clean';
    default:
      return 'neutral';
  }
}

/** Tone for a finding's assessment (attack / fault / inconclusive / benign). */
export function assessmentTone(assessment) {
  return verdictTone(assessment === 'benign' ? 'clean' : assessment);
}

/** "side_effect" -> "side effect", "DNS_SERVER_FAILURE" -> "DNS server failure". */
export function humanize(value) {
  if (value == null || value === '') return '';
  const text = String(value).replace(/_/g, ' ').trim();
  if (text === text.toUpperCase()) {
    // ALL_CAPS kinds: keep well-known acronyms, lower-case the rest.
    const acronyms = new Set(['TCP', 'UDP', 'DNS', 'ARP', 'DHCP', 'MTU', 'IP', 'ICMP', 'DGA', 'RST', 'SYN']);
    const words = text.split(/\s+/).map((w) => (acronyms.has(w) ? w : w.toLowerCase()));
    const first = words[0] || '';
    words[0] = acronyms.has(first) ? first : first.charAt(0).toUpperCase() + first.slice(1);
    return words.join(' ');
  }
  return text;
}

export function plural(n, singular, pluralForm = `${singular}s`) {
  return `${formatInt(n)} ${n === 1 ? singular : pluralForm}`;
}

export function formatInt(n) {
  return Number.isFinite(n) ? Math.round(n).toLocaleString('en-US') : '–';
}

export function formatBytes(n) {
  if (!Number.isFinite(n)) return '–';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`;
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

/** Human duration: 0.0042 -> "4 ms", 38.76 -> "38.8 s", 125 -> "2 min 5 s". */
export function formatDuration(seconds) {
  if (!Number.isFinite(seconds)) return '–';
  if (seconds < 0) seconds = 0;
  if (seconds < 1) return `${Math.round(seconds * 1000)} ms`;
  if (seconds < 10) return `${seconds.toFixed(2)} s`;
  if (seconds < 60) return `${seconds.toFixed(1)} s`;
  if (seconds < 3600) {
    const m = Math.floor(seconds / 60);
    const s = Math.round(seconds - m * 60);
    return s ? `${m} min ${s} s` : `${m} min`;
  }
  const h = Math.floor(seconds / 3600);
  const m = Math.round((seconds - h * 3600) / 60);
  return m ? `${h} h ${m} min` : `${h} h`;
}

/** Offset from the start of the capture, Wireshark-style: 5.01 -> "5.010 s". */
export function formatOffset(seconds) {
  return Number.isFinite(seconds) ? `${seconds.toFixed(3)} s` : '–';
}

/** Range of offsets: "5.010 – 25.610 s" (or a single value when both ends are equal). */
export function formatOffsetRange(start, end) {
  if (!Number.isFinite(start)) return 'time unknown';
  if (!Number.isFinite(end) || Math.abs(end - start) < 0.0005) return formatOffset(start);
  return `${start.toFixed(3)} – ${end.toFixed(3)} s`;
}

/** Absolute capture time in UTC (capture files carry UTC epoch timestamps). */
export function formatUtc(epochSeconds) {
  if (!Number.isFinite(epochSeconds)) return '–';
  const d = new Date(epochSeconds * 1000);
  if (Number.isNaN(d.getTime())) return '–';
  return `${d.toISOString().replace('T', ' ').slice(0, 19)} UTC`;
}

/** Axis tick label for seconds from the capture start. */
export function formatAxisSeconds(v) {
  if (!Number.isFinite(v)) return '';
  if (v >= 100) return `${Math.round(v)}s`;
  if (v >= 10) return `${v.toFixed(0)}s`;
  return `${Number(v.toFixed(1))}s`;
}

/** Percentage of a total, one decimal, never NaN. */
export function percent(part, total) {
  if (!Number.isFinite(part) || !Number.isFinite(total) || total <= 0) return '0%';
  const p = (part / total) * 100;
  return p > 0 && p < 0.1 ? '<0.1%' : `${p.toFixed(1)}%`;
}

/**
 * Explains how a finding's assessment (what the evidence says) relates to its category
 * (which official challenge list the detector belongs to). Returns { text, agrees }.
 */
export function categoryNote(category, assessment) {
  const listed = category === 'attack' ? 'threat' : category === 'fault' ? 'fault' : humanize(category) || 'uncategorised';
  if (category === assessment) {
    return { text: `Listed as a ${listed} type; the evidence agrees.`, agrees: true };
  }
  const says = {
    attack: 'points to an attack',
    fault: 'points to an ordinary fault',
    benign: 'says this is expected behaviour (benign)',
    inconclusive: 'is not conclusive either way',
  }[assessment] || `says "${humanize(assessment) || 'unknown'}"`;
  return { text: `Listed as a ${listed} type, but the evidence ${says}.`, agrees: false };
}

/** Render an arbitrary metric value as plain text (never markup). */
export function formatMetric(value) {
  if (value == null) return '–';
  if (typeof value === 'number') return Number.isInteger(value) ? formatInt(value) : String(Number(value.toFixed(4)));
  if (typeof value === 'boolean') return value ? 'yes' : 'no';
  if (Array.isArray(value)) return value.map(formatMetric).join(', ');
  if (typeof value === 'object') {
    try {
      return JSON.stringify(value);
    } catch {
      return '[object]';
    }
  }
  return String(value);
}

export const CAPTURE_EXTENSIONS = ['.pcap', '.pcapng', '.cap'];

/**
 * Client-side pre-checks before an upload. The backend repeats every check (and
 * verifies the magic number), so this only saves the user a round trip.
 * Returns an error message, or null when the file looks acceptable.
 */
export function validateCaptureFile(file, maxUploadMb) {
  if (!file) return 'Choose a capture file first.';
  const name = String(file.name || '').toLowerCase();
  if (!CAPTURE_EXTENSIONS.some((ext) => name.endsWith(ext))) {
    return `"${file.name}" is not a packet capture. Choose a .pcap, .pcapng or .cap file.`;
  }
  if (!Number.isFinite(file.size) || file.size <= 0) return 'The selected file is empty.';
  if (Number.isFinite(maxUploadMb) && maxUploadMb > 0 && file.size > maxUploadMb * 1024 * 1024) {
    return `The file is ${formatBytes(file.size)}; this server accepts captures up to ${maxUploadMb} MB.`;
  }
  return null;
}

/** File-name-safe stem for downloads: "office capture (1).pcapng" -> "office_capture_1". */
export function safeFileStem(name) {
  const base = String(name || 'capture').replace(/\.(pcapng|pcap|cap)$/i, '');
  const cleaned = base.replace(/[^A-Za-z0-9._-]+/g, '_').replace(/^_+|_+$/g, '');
  return (cleaned || 'capture').slice(0, 80);
}
