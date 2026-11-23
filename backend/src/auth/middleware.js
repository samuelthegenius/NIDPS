/**
 * Express helpers: session cookie handling, the requireAuth guard, and a
 * per-client login rate limiter (brute-force protection).
 */
const { verifySession } = require('./session');

const COOKIE_NAME = 'nidps_session';
const SESSION_TTL_MS = 8 * 3600 * 1000;

function readCookie(req, name) {
  const header = req.headers.cookie || '';
  for (const part of header.split(';')) {
    const [key, ...rest] = part.trim().split('=');
    if (key === name) return decodeURIComponent(rest.join('='));
  }
  return null;
}

function sessionCookie(token, { secure, maxAgeMs = SESSION_TTL_MS }) {
  const attrs = [`${COOKIE_NAME}=${token}`, 'HttpOnly', 'SameSite=Strict', 'Path=/', `Max-Age=${Math.floor(maxAgeMs / 1000)}`];
  if (secure) attrs.push('Secure');
  return attrs.join('; ');
}

function requireAuth(secret) {
  return (req, res, next) => {
    const session = verifySession(readCookie(req, COOKIE_NAME), secret);
    if (!session) return res.status(401).json({ error: 'Authentication required' });
    req.user = session.user;
    return next();
  };
}

function createLoginLimiter({ max = 5, windowMs = 15 * 60 * 1000, now = () => Date.now() } = {}) {
  const failures = new Map(); // client -> { count, start }

  function current(client) {
    const entry = failures.get(client);
    if (entry && now() - entry.start > windowMs) {
      failures.delete(client);
      return null;
    }
    return entry;
  }

  return {
    check: (client) => {
      const entry = current(client);
      return !entry || entry.count < max;
    },
    fail: (client) => {
      const entry = current(client) || { count: 0, start: now() };
      entry.count++;
      failures.set(client, entry);
    },
    reset: (client) => failures.delete(client),
  };
}

module.exports = { COOKIE_NAME, SESSION_TTL_MS, readCookie, sessionCookie, requireAuth, createLoginLimiter };
