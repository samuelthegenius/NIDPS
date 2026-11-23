const express = require('express');
const { verifyPassword } = require('../auth/password');
const { signSession } = require('../auth/session');
const { COOKIE_NAME, SESSION_TTL_MS, sessionCookie, requireAuth, createLoginLimiter } = require('../auth/middleware');

module.exports = function authRoutes({ settings, store, limiter = createLoginLimiter() }) {
  const router = express.Router();
  const secure = Boolean(settings.tlsCert && settings.tlsKey);

  router.post('/login', async (req, res, next) => {
    try {
      const client = req.socket.remoteAddress || 'unknown';
      if (!limiter.check(client)) {
        return res.status(429).json({ error: 'Too many failed attempts. Try again in 15 minutes.' });
      }
      const { username, password } = req.body || {};
      const passwordOk = verifyPassword(typeof password === 'string' ? password : '', settings.adminPasswordHash);
      if (!passwordOk || username !== settings.adminUsername) {
        limiter.fail(client);
        await store.insertAudit({ actor: String(username || '').slice(0, 64) || 'unknown', action: 'login_failed', target: client, detail: null });
        return res.status(401).json({ error: 'Invalid username or password' });
      }
      limiter.reset(client);
      const token = signSession({ user: settings.adminUsername }, settings.sessionSecret, SESSION_TTL_MS);
      res.setHeader('Set-Cookie', sessionCookie(token, { secure }));
      await store.insertAudit({ actor: settings.adminUsername, action: 'login', target: client, detail: null });
      return res.json({ user: settings.adminUsername });
    } catch (err) {
      return next(err);
    }
  });

  router.post('/logout', requireAuth(settings.sessionSecret), async (req, res, next) => {
    try {
      res.setHeader('Set-Cookie', `${COOKIE_NAME}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0${secure ? '; Secure' : ''}`);
      await store.insertAudit({ actor: req.user, action: 'logout', target: null, detail: null });
      res.json({ ok: true });
    } catch (err) {
      next(err);
    }
  });

  router.get('/me', requireAuth(settings.sessionSecret), (req, res) => res.json({ user: req.user }));

  return router;
};
