/**
 * NetVis UI utilities.
 */

export function getDeviceType(device) {
  const hostname = (device.hostname || '').toLowerCase();
  const vendor = (device.vendor || '').toLowerCase();
  const deviceType = (device.os || '').toLowerCase();
  if (device.is_gateway) return 'gateway';
  if (deviceType.includes('router')) return 'gateway';
  if (deviceType.includes('server') || deviceType.includes('nas')) return 'server';
  if (deviceType.includes('macbook') || deviceType.includes('laptop') || deviceType.includes('computer')) return 'laptop';
  if (deviceType.includes('phone') || deviceType.includes('smartphone')) return 'phone';
  if (deviceType.includes('printer')) return 'printer';
  if (deviceType.includes('iot') || deviceType.includes('smart') || deviceType.includes('esp')) return 'iot';
  if (hostname.includes('server') || hostname.includes('nas')) return 'server';
  if (device.is_local) return 'workstation';
  return 'unknown';
}

export function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

export function formatNumber(num) {
  if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M';
  if (num >= 1000) return (num / 1000).toFixed(1) + 'K';
  return num.toString();
}

export function humanizeKey(key) {
  return String(key || '')
    .replace(/[_-]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

export function compactValue(value) {
  if (value === null || value === undefined || value === '') return '-';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') {
    if (Number.isFinite(value) && Math.abs(value) >= 1024 && Number.isInteger(value)) {
      return formatNumber(value);
    }
    return Number.isFinite(value) ? String(Math.round(value * 1000) / 1000) : String(value);
  }
  if (typeof value === 'string') {
    return value.length > 140 ? `${value.slice(0, 137)}...` : value;
  }
  if (Array.isArray(value)) return `${value.length} item(s)`;
  if (typeof value === 'object') return `${Object.keys(value || {}).length} field(s)`;
  return String(value);
}

export function compactObjectLine(obj) {
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return compactValue(obj);
  const pairs = Object.entries(obj)
    .filter(([k]) => !String(k).startsWith('_'))
    .slice(0, 6)
    .map(([k, v]) => `${k}=${compactValue(v)}`);
  return pairs.length ? pairs.join('  |  ') : '{}';
}

/**
 * Extract structured insights from a coursework/log payload for LogParsedView.
 */
export function extractLogInsights(payload) {
  const root = payload && typeof payload === 'object' ? payload : {};
  const result = (root.result && typeof root.result === 'object') ? root.result : {};

  const metadata = [];
  const pushMeta = (label, value) => {
    if (value === undefined || value === null || value === '') return;
    metadata.push({ label, value: compactValue(value), raw: value });
  };
  pushMeta('Session', root.session_id);
  pushMeta('Module', root.module);
  pushMeta('Technique', result.technique || root.technique);
  pushMeta('Generated', root.generated_at);
  pushMeta('Started', root.started_at);
  pushMeta('Finished', root.finished_at);
  pushMeta('Scanner IP', root.scanner_local_ip);
  pushMeta('Target', result.target || result.host || result.ip || result.network);
  pushMeta('Interface', result.interface);

  const countCards = [];
  const seenLabels = new Set();
  const addCount = (label, value, tone = 'neutral') => {
    if (value === undefined || value === null || value === '' || value === 0) return;
    if (seenLabels.has(label)) return;
    seenLabels.add(label);
    countCards.push({ label, value: compactValue(value), tone });
  };

  const arrayCandidates = [
    ['Hosts', 'hosts', 'neutral'],
    ['Alive Hosts', 'alive_hosts', 'neutral'],
    ['Open Ports', 'open_ports', 'warning'],
    ['Fingerprints', 'fingerprints', 'neutral'],
    ['Alerts', 'alerts', 'danger'],
    ['Matches', 'matches', 'warning'],
    ['Suspicious Domains', 'suspicious_domains', 'danger'],
    ['Risk Entries', 'device_risk', 'warning'],
    ['Clusters', 'clusters', 'neutral'],
    ['Timeline Events', 'timeline', 'neutral'],
    ['Leases', 'leases', 'neutral'],
    ['Queries', 'queries', 'neutral'],
    ['Flows', 'flows', 'neutral'],
  ];
  for (const [label, key, tone] of arrayCandidates) {
    const v = result[key];
    if (Array.isArray(v) && v.length) addCount(label, v.length, tone);
  }

  for (const [k, v] of Object.entries(result)) {
    if (typeof v !== 'number' || !Number.isFinite(v)) continue;
    if (!/(count|total|duration|elapsed|observed|windows|nodes|edges|matches|packets|bytes|rate)/i.test(k)) continue;
    const label = humanizeKey(k);
    if (/bytes/i.test(k)) addCount(label, formatBytes(Math.max(0, Number(v))), 'neutral');
    else addCount(label, v, 'neutral');
  }

  const sections = [];
  const addSection = (title, items) => {
    if (!Array.isArray(items) || items.length === 0) return;
    sections.push({
      title,
      total: items.length,
      rows: items.slice(0, 25),
      truncated: items.length > 25,
    });
  };

  addSection('Discovered Hosts', result.hosts || result.alive_hosts || []);
  addSection('Open Services/Ports', result.open_ports || result.services || []);
  addSection('Protocol Fingerprints', result.fingerprints || []);
  addSection('Risk Findings', result.device_risk || []);
  addSection('Threat Matches', result.matches || []);
  addSection('Suspicious DNS', result.suspicious_domains || []);
  addSection('Attack Chain Phases', result.phases || []);
  addSection('Timeline', result.timeline || []);
  addSection('Clusters', result.clusters || []);
  addSection('DHCP Leases', result.leases || []);
  addSection('Top Domains', result.top_domains || []);
  addSection('Queries', result.queries || []);
  addSection('Alerts', result.alerts || []);

  const highlights = [];
  if (Array.isArray(result.suspicious_domains) && result.suspicious_domains.length > 0) {
    highlights.push({ tone: 'danger', text: `${result.suspicious_domains.length} suspicious DNS domain(s) flagged.` });
  }
  if (Array.isArray(result.matches) && result.matches.length > 0) {
    highlights.push({ tone: 'warning', text: `${result.matches.length} threat/intel match(es) detected.` });
  }
  if (Array.isArray(result.open_ports) && result.open_ports.length > 0) {
    highlights.push({ tone: 'warning', text: `${result.open_ports.length} open port/service finding(s) reported.` });
  }
  if (Array.isArray(result.device_risk) && result.device_risk.length > 0) {
    const high = result.device_risk.filter((r) => Number(r?.score || 0) >= 0.6).length;
    if (high > 0) highlights.push({ tone: 'danger', text: `${high} device(s) have risk score >= 0.60.` });
  }
  if (result.ok === false || root.error) {
    highlights.push({ tone: 'danger', text: 'This run reported a failure or partial error condition.' });
  }
  if (highlights.length === 0) {
    highlights.push({ tone: 'success', text: 'No high-severity indicators detected in this log summary.' });
  }

  const primitives = Object.entries(result)
    .filter(([_k, v]) => ['string', 'number', 'boolean'].includes(typeof v))
    .slice(0, 20)
    .map(([k, v]) => ({ key: humanizeKey(k), value: compactValue(v) }));

  return { metadata, countCards, sections, highlights, primitives };
}
