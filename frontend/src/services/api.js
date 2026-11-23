const BASE_URL = '/api';

export async function fetchAlerts({ page = 1, limit = 15, severity = '', search = '', status = '' } = {}) {
  const params = new URLSearchParams({ page, limit });
  if (severity) params.append('severity', severity);
  if (search) params.append('search', search);
  if (status) params.append('status', status);

  const res = await fetch(`${BASE_URL}/alerts?${params.toString()}`);
  if (!res.ok) throw new Error(`Failed to fetch alerts: ${res.statusText}`);
  return res.json();
}

export async function fetchBlocked(activeOnly = true) {
  const res = await fetch(`${BASE_URL}/blocked?active=${activeOnly}`);
  if (!res.ok) throw new Error(`Failed to fetch blocked IPs: ${res.statusText}`);
  return res.json();
}

export async function blockIp(ip, reason) {
  const res = await fetch(`${BASE_URL}/block`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ip, reason }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Failed to block IP');
  return data;
}

export async function unblockIp(ip) {
  const res = await fetch(`${BASE_URL}/unblock`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ip }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Failed to unblock IP');
  return data;
}

export async function fetchStats() {
  const res = await fetch(`${BASE_URL}/stats`);
  if (!res.ok) throw new Error(`Failed to fetch stats: ${res.statusText}`);
  return res.json();
}

export async function fetchSystemStatus() {
  const res = await fetch(`${BASE_URL}/simulator/status`);
  if (!res.ok) throw new Error(`Failed to fetch system status`);
  return res.json();
}

export async function injectSimulatedAlert({ presetKey, rawLine, customSourceIp, customSeverity }) {
  const res = await fetch(`${BASE_URL}/simulator/inject`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ presetKey, rawLine, customSourceIp, customSeverity }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Failed to inject alert');
  return data;
}
