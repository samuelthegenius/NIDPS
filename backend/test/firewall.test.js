const test = require('node:test');
const assert = require('node:assert/strict');
const { buildCommands } = require('../src/services/firewall/commands');
const { createFirewall } = require('../src/services/firewall');
const { createMemoryStore } = require('../src/store/memoryStore');
const { createAllowlist } = require('../src/lib/allowlist');
const { loadSettings } = require('../src/config/settings');

const NOW = new Date('2026-11-23T12:00:00Z');

function setup({ env = {}, failOn = null } = {}) {
  const settings = loadSettings({ ENABLE_REAL_IPTABLES: 'true', ...env });
  const store = createMemoryStore();
  const calls = [];
  const rules = new Set();
  // Fake iptables: tracks rules so -C (check) behaves like the real thing.
  const run = async (argv) => {
    calls.push(argv);
    const args = argv.slice(argv.findIndex((a) => a.endsWith('tables')) + 1);
    // Rule identity = args without the operation flag and without the -I position number.
    const key = args.filter((a, i) => i !== 0 && !(args[0] === '-I' && i === 2 && /^\d+$/.test(a))).join(' ');
    if (failOn && failOn(argv)) throw Object.assign(new Error('iptables: Permission denied'), { stderr: 'Permission denied' });
    if (args[0] === '-C') {
      if (!rules.has(key)) throw new Error('Bad rule');
    } else if (args[0] === '-I') rules.add(key);
    else if (args[0] === '-D') rules.delete(key);
    await new Promise((r) => setImmediate(r));
    return { stdout: '', stderr: '' };
  };
  const events = [];
  const firewall = createFirewall({
    settings,
    store,
    allowlist: createAllowlist({ entries: ['10.0.0.1'], includeLocal: false }),
    run,
    platform: 'linux',
    isRoot: true,
    events: { publish: (type, payload) => events.push({ type, payload }) },
    now: () => NOW,
  });
  const blockCalls = () => calls.filter((c) => c.includes('-I') && c.includes('DROP'));
  return { firewall, store, calls, blockCalls, events, rules };
}

test('host mode jumps to NIDPS from INPUT, gateway mode from FORWARD', () => {
  const host = buildCommands({ mode: 'host', platform: 'linux', isRoot: true }).setup('ipv4');
  const gw = buildCommands({ mode: 'gateway', platform: 'linux', isRoot: true }).setup('ipv4');
  assert.deepEqual(host.insertJump, ['iptables', '-I', 'INPUT', '1', '-j', 'NIDPS']);
  assert.deepEqual(gw.insertJump, ['iptables', '-I', 'FORWARD', '1', '-j', 'NIDPS']);
  assert.deepEqual(gw.create, ['iptables', '-N', 'NIDPS']);
});

test('uses sudo when not root, wsl on Windows, ip6tables for IPv6', () => {
  assert.deepEqual(buildCommands({ mode: 'host', platform: 'linux', isRoot: false }).block('1.2.3.4'), [
    'sudo', '-n', 'iptables', '-I', 'NIDPS', '1', '-s', '1.2.3.4', '-j', 'DROP',
  ]);
  assert.deepEqual(buildCommands({ mode: 'host', platform: 'win32', wslDistro: 'Ubuntu-24.04' }).block('1.2.3.4').slice(0, 6), [
    'wsl', '-d', 'Ubuntu-24.04', '-u', 'root', 'iptables',
  ]);
  assert.equal(buildCommands({ mode: 'host', platform: 'linux', isRoot: true }).block('2001:db8::1')[0], 'ip6tables');
  assert.deepEqual(buildCommands({ mode: 'host', platform: 'linux', isRoot: true }).flush('ipv4'), ['iptables', '-F', 'NIDPS']);
});

test('rejects an invalid IP before running anything', async () => {
  const { firewall, calls } = setup();
  await assert.rejects(firewall.block('1.2.3.4; reboot', 'x', 'admin'), { code: 'INVALID_IP' });
  assert.equal(calls.length, 0);
});

test('refuses to block a protected address and audits the refusal', async () => {
  const { firewall, calls, store } = setup();
  assert.equal((await firewall.block('127.0.0.1', 'x', 'admin')).status, 'protected');
  assert.equal((await firewall.block('10.0.0.1', 'x', 'system')).status, 'protected');
  assert.equal(calls.length, 0);
  assert.equal((await store.listAudit())[0].action, 'block_refused');
});

test('blocks with an expiry, records audit and publishes an event', async () => {
  const { firewall, blockCalls, store, events } = setup();
  const r = await firewall.block('198.51.100.7', 'P1 alert', 'admin');
  assert.equal(r.status, 'blocked');
  assert.equal(new Date(r.block.expires_at).getTime(), NOW.getTime() + 60 * 60000);
  assert.equal(r.block.created_by, 'admin');
  assert.equal(blockCalls().length, 1);
  assert.deepEqual((await store.listAudit()).map((a) => [a.action, a.actor]), [['block', 'admin']]);
  assert.equal(events[0].type, 'block');
});

test('BLOCK_DURATION_MIN=0 means a permanent block', async () => {
  const { firewall } = setup({ env: { BLOCK_DURATION_MIN: '0' } });
  assert.equal((await firewall.block('198.51.100.7', 'x', 'admin')).block.expires_at, null);
});

test('blocking an already-blocked IP is a no-op', async () => {
  const { firewall, blockCalls } = setup();
  await firewall.block('198.51.100.7', 'x', 'admin');
  assert.equal((await firewall.block('198.51.100.7', 'x', 'admin')).status, 'already');
  assert.equal(blockCalls().length, 1);
});

test('concurrent blocks for same ip produce one rule', async () => {
  const { firewall, blockCalls, store } = setup();
  const results = await Promise.all([firewall.block('198.51.100.8', 'a', 'system'), firewall.block('198.51.100.8', 'b', 'system')]);
  assert.deepEqual(results.map((r) => r.status).sort(), ['already', 'blocked']);
  assert.equal(blockCalls().length, 1);
  assert.equal((await store.listBlocks(true)).length, 1);
});

test('a failed iptables command raises EXEC_FAILED and stores nothing', async () => {
  const { firewall, store } = setup({ failOn: (argv) => argv.includes('-I') });
  await assert.rejects(firewall.block('198.51.100.9', 'x', 'admin'), { code: 'EXEC_FAILED' });
  assert.equal((await store.listBlocks(true)).length, 0);
});

test('unblock removes the rule; unblocking an unknown IP reports not_blocked', async () => {
  const { firewall, rules, store } = setup();
  await firewall.block('198.51.100.7', 'x', 'admin');
  assert.equal((await firewall.unblock('198.51.100.7', 'admin')).status, 'unblocked');
  assert.equal(rules.size, 0);
  assert.equal((await firewall.unblock('198.51.100.7', 'admin')).status, 'not_blocked');
  assert.equal((await store.listAudit())[0].action, 'unblock');
});

test('sweepExpired unblocks only expired blocks', async () => {
  const { firewall, store } = setup();
  await store.insertBlock({ ip_address: '1.1.1.1', block_reason: 'x', expires_at: new Date(NOW.getTime() - 1000), created_by: 'system' });
  await store.insertBlock({ ip_address: '2.2.2.2', block_reason: 'x', expires_at: new Date(NOW.getTime() + 1000), created_by: 'system' });
  assert.equal(await firewall.sweepExpired(), 1);
  assert.deepEqual((await store.listBlocks(true)).map((b) => b.ip_address), ['2.2.2.2']);
});

test('init creates the chain and re-applies active blocks after a reboot', async () => {
  const { firewall, store, rules } = setup();
  await store.insertBlock({ ip_address: '1.1.1.1', block_reason: 'x', expires_at: null, created_by: 'system' });
  await store.insertBlock({ ip_address: '2.2.2.2', block_reason: 'x', expires_at: null, created_by: 'system' });
  await firewall.init();
  assert.ok(rules.has('INPUT -j NIDPS'));
  assert.ok(rules.has('NIDPS -s 1.1.1.1 -j DROP'));
  assert.ok(rules.has('NIDPS -s 2.2.2.2 -j DROP'));
  await firewall.init();
  assert.equal(rules.size, 3, 'init is idempotent');
});

test('simulated mode never runs commands but still records the block', async () => {
  const { firewall, calls, store } = setup({ env: { ENABLE_REAL_IPTABLES: 'false' } });
  await firewall.init();
  const r = await firewall.block('198.51.100.7', 'x', 'admin');
  assert.equal(r.status, 'blocked');
  assert.equal(r.simulated, true);
  assert.equal(calls.length, 0);
  assert.equal((await store.listBlocks(true)).length, 1);
});
