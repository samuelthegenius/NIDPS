/**
 * Stateless session tokens: base64url(JSON payload) + "." + HMAC-SHA256 signature.
 * Anyone can read the payload, but nobody without SESSION_SECRET can forge or
 * extend one. Tokens live in an HttpOnly cookie so page scripts cannot read them.
 */
const crypto = require('crypto');

const sign = (data, secret) => crypto.createHmac('sha256', secret).update(data).digest('base64url');

function signSession({ user }, secret, ttlMs, now = Date.now()) {
  const payload = Buffer.from(JSON.stringify({ user, exp: now + ttlMs })).toString('base64url');
  return `${payload}.${sign(payload, secret)}`;
}

function verifySession(token, secret, now = Date.now()) {
  if (typeof token !== 'string' || !secret) return null;
  const [payload, signature, extra] = token.split('.');
  if (!payload || !signature || extra !== undefined) return null;

  const expected = Buffer.from(sign(payload, secret));
  const given = Buffer.from(signature);
  if (expected.length !== given.length || !crypto.timingSafeEqual(expected, given)) return null;

  try {
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    if (typeof data.user !== 'string' || typeof data.exp !== 'number' || data.exp <= now) return null;
    return { user: data.user, exp: data.exp };
  } catch {
    return null;
  }
}

module.exports = { signSession, verifySession };
