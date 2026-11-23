/**
 * Dashboard API client. Every request goes to the same origin and sends the
 * HttpOnly session cookie automatically. A 401 anywhere means the session has
 * ended: the registered handler sends the user back to the login screen once.
 */
const BASE_URL = '/api';
let unauthorizedHandler = null;

export function onUnauthorized(handler) {
  unauthorizedHandler = handler;
}

async function request(path, { method = 'GET', body } = {}) {
  const res = await fetch(`${BASE_URL}${path}`, {
    method,
    credentials: 'same-origin',
    headers: body !== undefined ? { 'Content-Type': 'application/json' } : undefined,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  let data = null;
  try {
    data = await res.json();
  } catch {
    // empty or non-JSON body
  }
  if (res.status === 401 && path !== '/auth/login' && unauthorizedHandler) unauthorizedHandler();
  if (!res.ok) {
    const err = new Error((data && data.error) || `Request failed (${res.status})`);
    err.status = res.status;
    throw err;
  }
  return data;
}

// ---- Session ---------------------------------------------------------------
export const login = (username, password) => request('/auth/login', { method: 'POST', body: { username, password } });
export const logout = () => request('/auth/logout', { method: 'POST', body: {} });
export const me = () => request('/auth/me');

// ---- Data ------------------------------------------------------------------
export function fetchAlerts({ page = 1, limit = 12, severity = '', search = '', status = '' } = {}) {
  const params = new URLSearchParams({ page, limit });
  if (severity) params.append('severity', severity);
  if (search) params.append('search', search);
  if (status) params.append('status', status);
  return request(`/alerts?${params}`);
}
export const updateAlertStatus = (id, status) => request(`/alerts/${id}`, { method: 'PATCH', body: { status } });
export const fetchBlocked = (activeOnly = true) => request(`/blocked?active=${activeOnly}`);
export const blockIp = (ip, reason) => request('/block', { method: 'POST', body: { ip, reason } });
export const unblockIp = (ip) => request('/unblock', { method: 'POST', body: { ip } });
export const fetchStats = () => request('/stats');
export const fetchAudit = (limit = 200) => request(`/audit?limit=${limit}`);
export const fetchSettings = () => request('/settings');
export const injectSimulatedAlert = (payload) => request('/simulator/inject', { method: 'POST', body: payload });

/**
 * Live updates via Server-Sent Events. Calls onEvent(type, payload) for
 * "alert", "block" and "unblock"; onStatus(true|false) when the link goes up/down.
 * Returns a function that closes the stream.
 */
export function subscribeEvents(onEvent, onStatus = () => {}) {
  const source = new EventSource(`${BASE_URL}/events`);
  source.onopen = () => onStatus(true);
  source.onerror = () => onStatus(false);
  for (const type of ['alert', 'block', 'unblock']) {
    source.addEventListener(type, (e) => {
      try {
        onEvent(type, JSON.parse(e.data));
      } catch {
        onEvent(type, null);
      }
    });
  }
  return () => source.close();
}
