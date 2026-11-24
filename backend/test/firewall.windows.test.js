const test = require('node:test');
const assert = require('node:assert/strict');
const { buildWindowsCommands } = require('../src/services/firewall/windows');
const { resolveBackend, backendWarnings } = require('../src/services/firewall/backend');
const { createFirewall } = require('../src/services/firewall');
const { createMemoryStore } = require('../src/store/memoryStore');
const { createAllowlist } = require('../src/lib/allowlist');
const { loadSettings } = require('../src/config/settings');

const arg = (argv, key) => (argv.find((a) => a.startsWith(`${key}=`)) || '').slice(key.length + 1);

/** Fake Windows: netsh keeps a rule table, `net session` fails unless admin. */
function setup({ env = {}, admin = true } = {}) {
  const clock = { t: new Date('2026-11-24T12:00:00Z').getTime() };
  const settings = loadSettings({ ENABLE_REAL_FIREWALL: 'true', ...env });
  const store = createMemoryStore();
  const calls = [];
  const rules = new Set(); // "<name>|<dir>"
  const fail = (msg) => Object.assign(new Error(msg), { code: 1, stderr: msg });
  const runOptions = [];
  const run = async (argv, options) => {
    calls.push(argv);
    runOptions.push(options);
    const [cmd] = argv;
    if (cmd === 'fltmc') {
      if (!admin) throw fail('System error 5 has occurred. Access is denied.');
    } else if (cmd === 'powershell.exe') {
      for (const r of [...rules]) if (r.startsWith('NIDPS-block-')) rules.delete(r);
    } else if (cmd === 'netsh') {
      const op = argv[3];
      const name = arg(argv, 'name');
      const dir = arg(argv, 'dir');
      if (op === 'show') {
        if (!rules.has(`${name}|${dir}`)) throw fail('No rules match the specified criteria.');
      } else if (op === 'add') rules.add(`${name}|${dir}`);
      else if (op === 'delete') {
        const matching = [...rules].filter((r) => r.startsWith(`${name}|`));
        if (!matching.length) throw fail('No rules match the specified criteria.');
        for (const r of matching) rules.delete(r);
      }
    } else throw new Error(`unexpected command ${cmd}`);
    return { stdout: '', stderr: '' };
  };
  const firewall = createFirewall({
    settings,
    store,
    allowlist: createAllowlist({ entries: ['10.0.0.1'], includeLocal: false }),
    run,
    platform: 'win32',
    now: () => new Date(clock.t),
  });
  return { firewall, store, calls, rules, runOptions, clock };
}

test('windows commands are netsh argv arrays with one named rule per direction', () => {
  const c = buildWindowsCommands();
  assert.deepEqual(c.add('198.51.100.7', 'in'), [
    'netsh', 'advfirewall', 'firewall', 'add', 'rule', 'name=NIDPS-block-198.51.100.7', 'dir=in', 'action=block', 'remoteip=198.51.100.7', 'profile=any',
  ]);
  assert.deepEqual(c.check('2001:db8::1', 'out'), ['netsh', 'advfirewall', 'firewall', 'show', 'rule', 'name=NIDPS-block-2001:db8::1', 'dir=out']);
  assert.deepEqual(c.remove('198.51.100.7'), ['netsh', 'advfirewall', 'firewall', 'delete', 'rule', 'name=NIDPS-block-198.51.100.7']);
  assert.deepEqual(c.adminCheck(), ['fltmc']);
  const flush = c.flush();
  assert.equal(flush[0], 'powershell.exe');
  assert.match(flush.at(-1), /Get-NetFirewallRule -DisplayName 'NIDPS-block-\*'.*\| Remove-NetFirewallRule/);
});

test('auto picks windows on Windows host mode, wsl on Windows gateway mode, iptables elsewhere', () => {
  assert.equal(resolveBackend({ firewall: 'auto', platform: 'win32', mode: 'host' }), 'windows');
  assert.equal(resolveBackend({ firewall: 'auto', platform: 'win32', mode: 'gateway' }), 'wsl');
  assert.equal(resolveBackend({ firewall: 'auto', platform: 'linux', mode: 'host' }), 'iptables');
  assert.equal(resolveBackend({ firewall: 'auto', platform: 'linux', mode: 'gateway' }), 'iptables');
  assert.equal(resolveBackend({ firewall: 'wsl', platform: 'win32', mode: 'host' }), 'wsl');
  assert.equal(resolveBackend({ firewall: 'iptables', platform: 'linux', mode: 'host' }), 'iptables');
});

test('refuses windows firewall in gateway mode and Windows-only drivers on other systems', () => {
  assert.throws(() => resolveBackend({ firewall: 'windows', platform: 'win32', mode: 'gateway' }), /gateway mode.*Linux/i);
  assert.throws(() => resolveBackend({ firewall: 'windows', platform: 'linux', mode: 'host' }), /only on Windows/);
  assert.throws(() => resolveBackend({ firewall: 'wsl', platform: 'linux', mode: 'host' }), /only on Windows/);
  assert.throws(() => resolveBackend({ firewall: 'iptables', platform: 'win32', mode: 'host' }), /Linux/);
});

test('linux keeps using iptables through createFirewall', () => {
  const fw = createFirewall({
    settings: loadSettings({}),
    store: createMemoryStore(),
    allowlist: createAllowlist({ entries: [], includeLocal: false }),
    platform: 'linux',
    isRoot: true,
  });
  assert.equal(fw.backend, 'iptables');
});

test('block adds an inbound and an outbound rule; unblock deletes them', async () => {
  const { firewall, rules, store } = setup();
  assert.equal(firewall.backend, 'windows');
  const r = await firewall.block('198.51.100.7', 'Log4j', 'system');
  assert.equal(r.status, 'blocked');
  assert.deepEqual([...rules].sort(), ['NIDPS-block-198.51.100.7|in', 'NIDPS-block-198.51.100.7|out']);
  assert.equal((await firewall.unblock('198.51.100.7', 'admin')).status, 'unblocked');
  assert.equal(rules.size, 0);
  assert.equal((await store.listBlocks(true)).length, 0);
});

test('IPv6 attackers are blocked by name and remoteip', async () => {
  const { firewall, rules, calls } = setup();
  await firewall.block('2001:db8::7', 'scan', 'system');
  assert.ok(rules.has('NIDPS-block-2001:db8::7|in'));
  assert.ok(calls.some((c) => c.includes('remoteip=2001:db8::7')));
});

test('a half-present block (only the inbound rule) is completed, not duplicated', async () => {
  const { firewall, rules, calls, clock } = setup();
  await firewall.block('198.51.100.7', 'x', 'system');
  rules.delete('NIDPS-block-198.51.100.7|out');
  clock.t += 31000; // past the re-check interval
  calls.length = 0;
  assert.equal((await firewall.block('198.51.100.7', 'again', 'system')).status, 'already');
  const adds = calls.filter((c) => c[3] === 'add');
  assert.deepEqual(adds.map((c) => arg(c, 'dir')), ['out']);
  assert.equal(rules.size, 2);
});

test('init checks for admin, removes stale NIDPS rules and re-applies active blocks', async () => {
  const { firewall, rules, store, calls } = setup();
  rules.add('NIDPS-block-9.9.9.9|in'); // left over from an earlier run
  rules.add('Someone else|in'); // not ours: must survive
  await store.insertBlock({ ip_address: '1.1.1.1', block_reason: 'x', expires_at: null, created_by: 'system' });
  await firewall.init();
  assert.deepEqual(calls[0], ['fltmc']);
  assert.ok(!rules.has('NIDPS-block-9.9.9.9|in'));
  assert.ok(rules.has('Someone else|in'));
  assert.ok(rules.has('NIDPS-block-1.1.1.1|in') && rules.has('NIDPS-block-1.1.1.1|out'));
});

test('init without Administrator rights fails clearly and changes nothing', async () => {
  const { firewall, calls } = setup({ admin: false });
  await assert.rejects(firewall.init(), (err) => err.code === 'NOT_ADMIN' && /Run as administrator/.test(err.message));
  assert.equal(calls.length, 1, 'only the admin check ran');
});

test('simulated mode on Windows logs netsh commands and runs nothing', async () => {
  const { firewall, calls } = setup({ env: { ENABLE_REAL_FIREWALL: 'false', ENABLE_REAL_IPTABLES: 'false' } });
  await firewall.init();
  assert.equal((await firewall.block('198.51.100.7', 'x', 'admin')).simulated, true);
  await firewall.unblock('198.51.100.7', 'admin');
  assert.equal(calls.length, 0);
});

test('a refused gateway + windows combination stops createFirewall', () => {
  assert.throws(
    () =>
      createFirewall({
        settings: loadSettings({ NIDPS_MODE: 'gateway', NIDPS_FIREWALL: 'windows' }),
        store: createMemoryStore(),
        allowlist: createAllowlist({ entries: [], includeLocal: false }),
        platform: 'win32',
      }),
    /gateway mode/i
  );
});

test('the start-up flush gets a long timeout (PowerShell is slow to start)', async () => {
  const { firewall, calls, runOptions } = setup();
  await firewall.init();
  const i = calls.findIndex((c) => c[0] === 'powershell.exe');
  assert.ok(runOptions[i] && runOptions[i].timeout >= 60000, 'flush timeout >= 60 s');
});

test('repeated alerts from an already-blocked IP re-check Windows Firewall at most every 30 s', async () => {
  const { firewall, calls, clock } = setup();
  await firewall.block('198.51.100.7', 'scan', 'system');
  calls.length = 0;
  for (let i = 0; i < 50; i++) await firewall.block('198.51.100.7', 'scan', 'system');
  assert.equal(calls.length, 0, 'no netsh calls within 30 s of the last check');
  clock.t += 31000;
  await firewall.block('198.51.100.7', 'scan', 'system');
  assert.equal(calls.length, 2, 'one show-rule per direction after 30 s');
});

test('warns when Windows Firewall is used but Snort writes inside WSL', () => {
  const w = backendWarnings({ backend: 'windows', snortLogPath: String.raw`\\wsl.localhost\Ubuntu-24.04\var\log\snort\snort.alert.fast` });
  assert.equal(w.length, 1);
  assert.match(w[0], /WSL/);
  assert.deepEqual(backendWarnings({ backend: 'windows', snortLogPath: String.raw`C:\Snort\log\snort.alert.fast` }), []);
  assert.deepEqual(backendWarnings({ backend: 'wsl', snortLogPath: String.raw`\\wsl$\Ubuntu\x` }), []);
});
