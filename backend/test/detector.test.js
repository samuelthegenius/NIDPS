const test = require('node:test');
const assert = require('node:assert/strict');
const { createDetector } = require('../src/services/detector');
const { createEventBus } = require('../src/services/events');
const { createFirewall } = require('../src/services/firewall');
const { createMemoryStore } = require('../src/store/memoryStore');
const { createAllowlist } = require('../src/lib/allowlist');
const { loadSettings } = require('../src/config/settings');

const NOW = new Date('2026-11-23T12:00:00Z');
const line = (priority, src = '198.51.100.7', msg = 'ET TEST Alert') =>
  `[**] [1:1000:1] ${msg} [**] [Classification: Test] [Priority: ${priority}] {TCP} ${src}:4444 -> 10.0.0.5:22`;

function setup({ env = {}, firewallOverride } = {}) {
  const settings = loadSettings(env); // simulated firewall
  const store = createMemoryStore();
  const events = createEventBus();
  const seen = [];
  events.subscribe((type, payload) => seen.push({ type, payload }));
  const firewall =
    firewallOverride ||
    createFirewall({ settings, store, events, allowlist: createAllowlist({ entries: ['10.0.0.1'], includeLocal: false }), now: () => NOW });
  const detector = createDetector({ store, firewall, settings, events, now: () => NOW });
  return { detector, store, seen };
}

test('a Priority 1 alert blocks the source and is stored as blocked', async () => {
  const { detector, store, seen } = setup();
  const r = await detector.handleLine(line(1));
  assert.equal(r.action, 'blocked');
  assert.equal(r.alert.status, 'blocked');
  assert.ok(await store.getActiveBlock('198.51.100.7'));
  assert.deepEqual(seen.map((e) => e.type), ['block', 'alert']);
});

test('a Priority 1 alert from a protected IP is logged, not blocked', async () => {
  const { detector, store } = setup();
  const r = await detector.handleLine(line(1, '10.0.0.1'));
  assert.equal(r.action, 'protected');
  assert.equal(r.alert.status, 'unresolved');
  assert.equal(await store.getActiveBlock('10.0.0.1'), null);
});

test('Priority 2 alerts escalate to a block on the 5th within the window', async () => {
  const { detector, store } = setup();
  for (let i = 0; i < 4; i++) assert.equal((await detector.handleLine(line(2))).action, 'logged');
  const fifth = await detector.handleLine(line(2));
  assert.equal(fifth.action, 'escalated');
  assert.equal(fifth.alert.status, 'blocked');
  const block = await store.getActiveBlock('198.51.100.7');
  assert.match(block.block_reason, /Escalation: 5 P2 alerts in 5 min/);
  const { data } = await store.listAlerts({ page: 1, limit: 10 });
  assert.ok(data.every((a) => a.status === 'blocked'), 'earlier P2 alerts are marked blocked too');
});

test('escalation counts arrival time, not Snort clock (review #6)', async () => {
  // Snort's clock is 5 hours behind NIDPS (e.g. WSL on UTC, Windows on UTC+5).
  const { detector, store } = setup();
  const stale = (src) => `${new Date(NOW.getTime() - 5 * 3600000).toLocaleString('en-US', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }).replace(/(\d+)\/(\d+), (\d+:\d+:\d+)/, '$1/$2-$3')} ${line(2, src)}`;
  for (let i = 0; i < 4; i++) await detector.handleLine(stale('198.51.100.9'));
  assert.equal((await detector.handleLine(stale('198.51.100.9'))).action, 'escalated');
  assert.ok(await store.getActiveBlock('198.51.100.9'));
});

test('ESCALATE_COUNT=0 disables escalation', async () => {
  const { detector } = setup({ env: { ESCALATE_COUNT: '0' } });
  for (let i = 0; i < 6; i++) assert.equal((await detector.handleLine(line(2))).action, 'logged');
});

test('a Priority 3 alert is only logged', async () => {
  const { detector, store } = setup();
  const r = await detector.handleLine(line(3));
  assert.equal(r.action, 'logged');
  assert.equal(await store.getActiveBlock('198.51.100.7'), null);
});

test('an unparseable line is ignored', async () => {
  const { detector, store } = setup();
  assert.equal(await detector.handleLine('not a snort line'), null);
  assert.equal((await store.listAlerts({ page: 1, limit: 10 })).total, 0);
});

test('a firewall failure still stores the alert as unresolved', async () => {
  const failing = { block: async () => { throw Object.assign(new Error('boom'), { code: 'EXEC_FAILED' }); } };
  const { detector, store } = setup({ firewallOverride: failing });
  const r = await detector.handleLine(line(1));
  assert.equal(r.action, 'logged');
  assert.equal(r.alert.status, 'unresolved');
  assert.equal((await store.listAlerts({ page: 1, limit: 10 })).total, 1);
});
