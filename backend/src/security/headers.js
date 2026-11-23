/**
 * HTTP hardening:
 *  - security headers (CSP, anti-framing, no MIME sniffing, no referrer leaks)
 *  - same-origin guard for state-changing requests (CSRF defence in depth on top of
 *    SameSite=Strict cookies): JSON body required, and Origin must match Host.
 */
function securityHeaders(req, res, next) {
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
  );
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  next();
}

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

function sameOriginGuard(req, res, next) {
  if (SAFE_METHODS.has(req.method)) return next();
  const origin = req.headers.origin;
  if (origin) {
    let host = null;
    try {
      host = new URL(origin).host;
    } catch {
      // malformed Origin
    }
    if (host !== req.headers.host) return res.status(403).json({ error: 'Cross-origin request refused' });
  }
  if (!req.is('application/json')) return res.status(415).json({ error: 'Content-Type must be application/json' });
  return next();
}

module.exports = { securityHeaders, sameOriginGuard };
