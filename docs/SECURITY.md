# NIDPS security and privacy

## Threat model

| Who | Wants to | Defence |
|---|---|---|
| A student on the same LAN | Open the dashboard and unblock themselves or block others | Admin login (scrypt hash, signed HttpOnly cookie, 8 h expiry), 5 failed logins → 15-minute lockout |
| A malicious web page the admin visits | Make the admin's browser call `/api/block` (CSRF) | `SameSite=Strict` cookie, JSON-only state changes, and an `Origin` header that must match `Host` |
| An attacker sending spoofed packets | Get NIDPS to block the gateway/DNS/admin (self-DoS) | Allowlist + own interface addresses + loopback are never blocked; blocks expire |
| Anyone who can write to the Snort log | Forge alerts | Log directory `750 root:nidps`, file `640`; simulator only exists in demo mode, needs login, and accepts only valid Snort lines |
| Command injection via an "IP address" | Run commands as root | `net.isIP` validation + `execFile` with argument arrays (no shell, ever) |
| Someone on the network | Read the database | PostgreSQL bound to `127.0.0.1`; password comes from `.env` |
| Eavesdropper on campus Wi-Fi | Steal the session or password | Optional HTTPS (`scripts/gen-cert.sh`, `TLS_CERT`/`TLS_KEY`); `Secure` cookie flag when HTTPS is on |

## What the audit found and how it was fixed

| # | Finding (original NIPS code) | Fix |
|---|---|---|
| 1 | No authentication on any endpoint | Admin login; every API route except `/api/health` requires a session |
| 2 | `rawLine` let anyone inject forged alerts and get any IP blocked | Simulator only in `DEMO_MODE`, behind login; lines must parse as real Snort alerts |
| 3 | No allowlist: auto-block could cut off the gateway, DNS or itself | Protected-address list checked before every block, manual or automatic |
| 4 | Shell `exec` with interpolated IP; weak IPv6 regex (`:::::` passed) | `execFile` argument arrays + `net.isIP` |
| 5 | PostgreSQL on `0.0.0.0:5432` with `postgres/postgres` | Bound to `127.0.0.1`; password must be set in `.env` |
| 6 | `cors()` allowed any origin; errors returned internal messages | CORS removed (same-origin); clients get generic errors, details stay in the log |
| 7 | No security headers | CSP, `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: no-referrer`, COOP |
| 8 | `chmod 777 /var/log/snort` (anyone could forge alerts) | `750` / `640`, group `nidps` |
| 9 | Login over plain HTTP | Optional HTTPS with a generated certificate |
| 10 | Watcher status always reported "inactive" | Watcher exposes `status()`; the Settings tab shows it |
| 11 | Snort local timestamps parsed as UTC; wrong year across New Year | Parsed as local time; the year rolls back when needed |
| 12 | In-memory fallback guessed from SQL strings (ignored updates, filters) | Real store interface, two implementations, one contract test suite |
| 13 | Rules appended with `-A`; lost on reboot; reset ran `iptables -F INPUT` | Own `NIDPS` chain, inserted at the top, resynced on start-up; reset flushes only `NIDPS` |
| 14 | WSL distro name hard-coded in three places | `WSL_DISTRO` setting |
| 15 | Stale React effects caused racing refreshes | Single query state; event-driven refresh |
| 16 | IP addresses (personal data) kept forever | `RETENTION_DAYS` (default 30) deletes old alerts, closed blocks and audit entries daily |
| 17 | Google Fonts loaded from the internet | System fonts; the dashboard makes no third-party requests |

## Privacy

- **What is stored:** source/destination IPs, alert text, timestamps, block records, and an audit
  log of admin actions (including the IP of each login attempt).
- **Why:** to detect and stop attacks and to account for every block. IP addresses can identify
  a person, so treat the database as personal data.
- **How long:** `RETENTION_DAYS` (default 30). Active blocks are kept until they expire or are lifted.
- **Who can see it:** only the admin account. Nothing is sent to any external service.
- **In a demo:** the simulator uses documentation addresses (RFC 5737: `192.0.2.x`,
  `198.51.100.x`, `203.0.113.x`), which never belong to real people. Run `npm run reset`
  after a demo.

## Remaining risks (be honest about these)

- **Sessions are stateless.** Logging out clears the cookie, but a copied cookie stays valid until it
  expires (8 h). Changing `SESSION_SECRET` invalidates every session at once.
- **Single admin account**, with no per-user accounts or roles.
- **The login rate limit is in memory**, so it resets when NIDPS restarts.
- **Snort rules are signatures.** New or encrypted attacks (HTTPS payloads) are not seen.
- **Fail-open by design.** If NIDPS stops, traffic flows normally; existing DROP rules stay until removed.
- **IP spoofing** can still cause blocks of unprotected, innocent addresses, but they expire.
- **The PostgreSQL contract tests have not yet been run against a live database** in this repository's
  history (no database was available). Run `TEST_DATABASE_URL=postgres://… npm test` once Docker is up.
