const test = require('node:test');
const assert = require('node:assert/strict');
const { createAllowlist } = require('../src/lib/allowlist');

test('protects addresses inside a configured subnet', () => {
  const a = createAllowlist({ entries: ['192.168.0.0/24'], includeLocal: false });
  assert.equal(a.isProtected('192.168.0.77'), true);
  assert.equal(a.isProtected('192.168.1.77'), false);
});

test('protects an exact address', () => {
  const a = createAllowlist({ entries: ['10.0.0.1'], includeLocal: false });
  assert.equal(a.isProtected('10.0.0.1'), true);
  assert.equal(a.isProtected('10.0.0.2'), false);
});

test('always protects loopback even without local interfaces', () => {
  const a = createAllowlist({ entries: [], includeLocal: false });
  assert.equal(a.isProtected('127.0.0.1'), true);
  assert.equal(a.isProtected('::1'), true);
  assert.equal(a.isProtected('8.8.8.8'), false);
});

test('protects this machine\'s own interface addresses', () => {
  const os = require('os');
  const own = Object.values(os.networkInterfaces()).flat().find((i) => i && i.family === 'IPv4' && !i.internal);
  const a = createAllowlist({ entries: [] });
  if (own) assert.equal(a.isProtected(own.address), true);
});

test('protects IPv6 subnets', () => {
  const a = createAllowlist({ entries: ['2001:db8::/32'], includeLocal: false });
  assert.equal(a.isProtected('2001:db8::5'), true);
});

test('rejects a malformed entry and names it', () => {
  assert.throws(() => createAllowlist({ entries: ['nonsense'] }), /nonsense/);
  assert.throws(() => createAllowlist({ entries: ['10.0.0.0/99'] }), /10\.0\.0\.0\/99/);
});

test('invalid input is never protected (and never throws)', () => {
  const a = createAllowlist({ entries: [], includeLocal: false });
  assert.equal(a.isProtected('garbage'), false);
});

test('describe lists configured and built-in entries', () => {
  const d = createAllowlist({ entries: ['10.9.9.9'], includeLocal: false }).describe();
  assert.ok(d.includes('10.9.9.9'));
  assert.ok(d.includes('127.0.0.0/8'));
});
