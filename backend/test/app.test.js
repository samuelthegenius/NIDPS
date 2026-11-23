const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { createApp } = require('../src/app');
const { loadSettings } = require('../src/config/settings');
const { createMemoryStore } = require('../src/store/memoryStore');
const { createAllowlist } = require('../src/lib/allowlist');
const { createFirewall } = require('../src/services/firewall');
const { createDetector } = require('../src/services/detector');
const { createEventBus } = require('../src/services/events');
const { hashPassword } = require('../src/auth/password');

const PASSWORD = 'demo-password-123';
const HASH = hashPassword(PASSWORD);
const SECRET = 'f'.repeat(64);

async function startApp({ env = {}, storeOverride } = {}) {
  const settings = loadSettings({ ADMIN_PASSWORD_HASH: HASH, SESSION_SECRET: SECRET, DEMO_MODE: 'true', ...env });
  const store = storeOverride || createMemoryStore();
  const events = createEventBus();
  const allowlist = createAllowlist({ entries: settings.allowlist, includeLocal: false });
  const firewall = createFirewall({ settings, store, allowlist, events });
  const detector = createDetector({ store, firewall, settings, events });
  const logPath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'nidps-app-')), 'alert.fast');
  const watcher = { status: () => ({ active: true, path: logPath }) };
  const app = createApp({ settings, store, firewall, detector, events, watcher, allowlist });
  const server = await new Promise((resolve) => {
    const s = app.listen(0, '127.0.0.1', () => resolve(s));
  });
  const base = `http://127.0.0.1:${server.address().port}`;
  let cookie = '';

  async function call(method, url, { body, headers = {}, auth = true } = {}) {
    const h = { ...headers };
    if (body !== undefined) h['Content-Type'] = h['Content-Type'] || 'application/json';
    if (auth && cookie) h.Cookie = cookie;
    const res = await fetch(base + url, { method, headers: h, body: body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body) });
    const text = await res.text();
    let json = null;
    try {
      json = JSON.parse(text);
    } catch {
      // not JSON
    }
    return { status: res.status, headers: res.headers, json, text };
  }

  async function login(password = PASSWORD) {
    const r = await call('POST', '/api/auth/login', { body: { username: 'admin', password }, auth: false });
    const setCookie = r.headers.get('set-cookie');
    if (r.status === 200) cookie = setCookie.split(';')[0];
    return { ...r, setCookie };
  }

  return {
    call,
    login,
    store,
    events,
    base,
    logPath,
    close: () =>
      new Promise((r) => {
        server.closeAllConnections();
        server.close(r);
      }),
  };
}

test('health is public and identifies NIDPS', async () => {
  const app = await startApp();
  const r = await app.call('GET', '/api/health');
  assert.equal(r.status, 200);
  assert.equal(r.json.system, 'NIDPS');
  await app.close();
});

test('protected endpoints require login', async () => {
  const app = await startApp();
  for (const url of ['/api/alerts', '/api/blocked', '/api/stats', '/api/audit', '/api/settings']) {
    assert.equal((await app.call('GET', url)).status, 401, url);
  }
  assert.equal((await app.call('POST', '/api/block', { body: { ip: '1.2.3.4' } })).status, 401);
  await app.close();
});

test('login sets a hardened session cookie and unlocks the API', async () => {
  const app = await startApp();
  const r = await app.login();
  assert.equal(r.status, 200);
  assert.match(r.setCookie, /nidps_session=/);
  assert.match(r.setCookie, /HttpOnly/);
  assert.match(r.setCookie, /SameSite=Strict/);
  assert.equal((await app.call('GET', '/api/alerts')).status, 200);
  assert.equal((await app.call('GET', '/api/auth/me')).json.user, 'admin');
  await app.close();
});

test('wrong passwords get 401 and the 6th attempt gets 429', async () => {
  const app = await startApp();
  for (let i = 0; i < 5; i++) assert.equal((await app.login('wrong')).status, 401);
  const blocked = await app.login('wrong');
  assert.equal(blocked.status, 429);
  assert.equal((await app.login()).status, 429, 'even the right password is refused while locked out');
  await app.close();
});

test('logout ends the session', async () => {
  const app = await startApp();
  await app.login();
  const r = await app.call('POST', '/api/auth/logout', { body: {} });
  assert.match(r.headers.get('set-cookie'), /Max-Age=0/);
  await app.close();
});

test('manual block: protected 409, invalid 400, valid 201 with audit', async () => {
  const app = await startApp({ env: { NIDPS_ALLOWLIST: '192.168.50.1' } });
  await app.login();
  const prot = await app.call('POST', '/api/block', { body: { ip: '192.168.50.1' } });
  assert.equal(prot.status, 409);
  assert.match(prot.json.error, /protected/i);
  assert.equal((await app.call('POST', '/api/block', { body: { ip: 'bad; reboot' } })).status, 400);
  const ok = await app.call('POST', '/api/block', { body: { ip: '203.0.113.5', reason: 'Examiner demo' } });
  assert.equal(ok.status, 201);
  assert.equal((await app.call('POST', '/api/block', { body: { ip: '203.0.113.5' } })).status, 200);
  const audit = await app.call('GET', '/api/audit');
  assert.ok(audit.json.data.some((a) => a.action === 'block' && a.actor === 'admin' && a.target === '203.0.113.5'));
  assert.equal((await app.call('GET', '/api/blocked')).json.data.length, 1);
  assert.equal((await app.call('POST', '/api/unblock', { body: { ip: '203.0.113.5' } })).status, 200);
  assert.equal((await app.call('POST', '/api/unblock', { body: { ip: '203.0.113.5' } })).status, 404);
  await app.close();
});

test('state changes need JSON and a same-origin Origin', async () => {
  const app = await startApp();
  await app.login();
  const cross = await app.call('POST', '/api/block', { body: { ip: '203.0.113.5' }, headers: { Origin: 'http://evil.example' } });
  assert.equal(cross.status, 403);
  const form = await app.call('POST', '/api/block', { body: 'ip=203.0.113.5', headers: { 'Content-Type': 'application/x-www-form-urlencoded' } });
  assert.equal(form.status, 415);
  await app.close();
});

test('alert triage updates status and is audited', async () => {
  const app = await startApp();
  await app.login();
  const a = await app.store.insertAlert({ timestamp: new Date(), source_ip: '1.1.1.1', dest_ip: '2.2.2.2', protocol: 'TCP', alert_message: 'x', severity: 2, status: 'unresolved' });
  assert.equal((await app.call('PATCH', `/api/alerts/${a.id}`, { body: { status: 'false_positive' } })).json.data.status, 'false_positive');
  assert.equal((await app.call('PATCH', `/api/alerts/${a.id}`, { body: { status: 'hacked' } })).status, 400);
  assert.equal((await app.call('PATCH', '/api/alerts/999', { body: { status: 'resolved' } })).status, 404);
  assert.ok((await app.call('GET', '/api/audit')).json.data.some((r) => r.action === 'alert_status'));
  await app.close();
});

test('simulator only exists in demo mode and only accepts valid Snort lines', async () => {
  const off = await startApp({ env: { DEMO_MODE: 'false' } });
  await off.login();
  assert.equal((await off.call('POST', '/api/simulator/inject', { body: { presetKey: 'log4j' } })).status, 404);
  await off.close();

  const on = await startApp();
  await on.login();
  assert.equal((await on.call('POST', '/api/simulator/inject', { body: { rawLine: 'hello' } })).status, 400);
  assert.equal((await on.call('POST', '/api/simulator/inject', { body: { presetKey: 'log4j', customSourceIp: 'x;y' } })).status, 400);
  const ok = await on.call('POST', '/api/simulator/inject', { body: { presetKey: 'log4j', customSourceIp: '203.0.113.77' } });
  assert.equal(ok.status, 200);
  assert.match(fs.readFileSync(on.logPath, 'utf8'), /203\.0\.113\.77/);
  await on.close();
});

test('settings never expose secrets', async () => {
  const app = await startApp();
  await app.login();
  const r = await app.call('GET', '/api/settings');
  assert.equal(r.status, 200);
  assert.equal(r.json.mode, 'host');
  assert.ok(!r.text.includes('scrypt$'));
  assert.ok(!r.text.includes(SECRET));
  await app.close();
});

test('internal errors return a generic message', async () => {
  const broken = createMemoryStore();
  broken.getStats = async () => {
    throw new Error('relation "secret_table" does not exist');
  };
  const app = await startApp({ storeOverride: broken });
  await app.login();
  const r = await app.call('GET', '/api/stats');
  assert.equal(r.status, 500);
  assert.equal(r.json.error, 'Internal server error');
  assert.ok(!r.text.includes('secret_table'));
  await app.close();
});

test('security headers are set and x-powered-by is hidden', async () => {
  const app = await startApp();
  const r = await app.call('GET', '/api/health');
  assert.match(r.headers.get('content-security-policy'), /default-src 'self'/);
  assert.equal(r.headers.get('x-frame-options'), 'DENY');
  assert.equal(r.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(r.headers.get('x-powered-by'), null);
  assert.equal(r.headers.get('access-control-allow-origin'), null);
  await app.close();
});

test('the event stream requires login and sends events', async () => {
  const app = await startApp();
  assert.equal((await app.call('GET', '/api/events')).status, 401);
  const { setCookie } = await app.login();
  const controller = new AbortController();
  const res = await fetch(`${app.base}/api/events`, { headers: { Cookie: setCookie.split(';')[0] }, signal: controller.signal });
  assert.equal(res.headers.get('content-type'), 'text/event-stream');
  const reader = res.body.getReader();
  await reader.read(); // retry preamble
  app.events.publish('alert', { id: 42 });
  let received = '';
  while (!received.includes('event: alert')) received += new TextDecoder().decode((await reader.read()).value);
  assert.match(received, /data: \{"id":42\}/);
  controller.abort();
  await app.close();
});
