const test = require('node:test');
const assert = require('node:assert/strict');
const { hashPassword, verifyPassword } = require('../src/auth/password');
const { signSession, verifySession } = require('../src/auth/session');
const { createLoginLimiter } = require('../src/auth/middleware');

const SECRET = 'a'.repeat(64);
const NOW = new Date('2026-11-23T12:00:00Z').getTime();

test('password hash round-trips and uses scrypt with a random salt', () => {
  const h1 = hashPassword('correct horse');
  const h2 = hashPassword('correct horse');
  assert.match(h1, /^scrypt\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$/);
  assert.notEqual(h1, h2);
  assert.equal(verifyPassword('correct horse', h1), true);
});

test('wrong password and malformed hashes are rejected without throwing', () => {
  const h = hashPassword('correct horse');
  assert.equal(verifyPassword('wrong', h), false);
  assert.equal(verifyPassword('x', ''), false);
  assert.equal(verifyPassword('x', 'scrypt$bad'), false);
  assert.equal(verifyPassword('x', 'md5$abc$def'), false);
  assert.equal(verifyPassword(undefined, h), false);
});

test('a signed session verifies and carries the user', () => {
  const token = signSession({ user: 'admin' }, SECRET, 8 * 3600000, NOW);
  const s = verifySession(token, SECRET, NOW + 1000);
  assert.equal(s.user, 'admin');
  assert.equal(s.exp, NOW + 8 * 3600000);
});

test('tampered, wrongly-signed and expired sessions are rejected', () => {
  const token = signSession({ user: 'admin' }, SECRET, 1000, NOW);
  const [payload, sig] = token.split('.');
  const forged = Buffer.from(JSON.stringify({ user: 'root', exp: NOW + 1e9 })).toString('base64url');
  assert.equal(verifySession(`${forged}.${sig}`, SECRET, NOW), null);
  assert.equal(verifySession(`${payload}.${sig}x`, SECRET, NOW), null);
  assert.equal(verifySession(token, 'b'.repeat(64), NOW), null);
  assert.equal(verifySession(token, SECRET, NOW + 2000), null);
  assert.equal(verifySession('garbage', SECRET, NOW), null);
  assert.equal(verifySession(undefined, SECRET, NOW), null);
});

test('login limiter blocks the 6th failure in the window and reset clears it', () => {
  let t = NOW;
  const limiter = createLoginLimiter({ max: 5, windowMs: 15 * 60000, now: () => t });
  for (let i = 0; i < 5; i++) {
    assert.equal(limiter.check('10.0.0.9'), true);
    limiter.fail('10.0.0.9');
  }
  assert.equal(limiter.check('10.0.0.9'), false);
  assert.equal(limiter.check('10.0.0.10'), true, 'other clients are unaffected');
  limiter.reset('10.0.0.9');
  assert.equal(limiter.check('10.0.0.9'), true);
  for (let i = 0; i < 5; i++) limiter.fail('10.0.0.9');
  t += 15 * 60000 + 1;
  assert.equal(limiter.check('10.0.0.9'), true, 'window expires');
});
