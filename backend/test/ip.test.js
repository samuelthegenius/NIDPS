const test = require('node:test');
const assert = require('node:assert/strict');
const { isValidIp, normalizeIp } = require('../src/lib/ip');

test('accepts real IPv4 and IPv6 addresses', () => {
  assert.equal(isValidIp('10.0.0.1'), true);
  assert.equal(isValidIp(' 10.0.0.1 '), true);
  assert.equal(isValidIp('2001:db8::1'), true);
});

test('rejects junk, injection attempts and non-strings', () => {
  for (const bad of [':::::', '1.2.3.4; rm -rf /', '256.1.1.1', '', '10.0.0.1/24', undefined, null, 42]) {
    assert.equal(isValidIp(bad), false, `expected ${String(bad)} to be invalid`);
  }
});

test('normalizes IPv4-mapped IPv6 to plain IPv4', () => {
  assert.equal(normalizeIp('::ffff:10.0.0.9'), '10.0.0.9');
  assert.equal(normalizeIp(' 2001:DB8::1 '), '2001:db8::1');
});
