# NIDPS — Design (rename, hardening, campus-LAN deployment, handoff)

Date: 2026-11-23 · Status: awaiting approval

## Intent

This is a **final-year project** that will be shown live to examiners. Success means:

- the demo works reliably on the day;
- the system is safe to run on a campus network;
- the owner and a collaborator can explain every part of it.

The project is renamed from **NIPS** to **NIDPS** (Network Intrusion Detection and Prevention System).

## Goals

1. Rename to NIDPS everywhere: code, UI, database name, Docker names, scripts and docs.
2. Fix the bugs, security holes and privacy issues found in the audit (listed below).
3. Make the app better in ways that show up in a demo and stand up to examiner questions.
4. Support campus-LAN deployment in two modes, chosen by `NIDPS_MODE`:
   - `host` (default): protects the machine NIDPS runs on (`INPUT` chain).
   - `gateway`: a dual-NIC Linux box routes a small demo network and blocks traffic passing through it (`FORWARD` chain).
5. Make the project self-explanatory so a collaborator can run and understand it with nobody present.

## Non-goals

- Multiple user accounts or roles. There is one admin account.
- Replacing Snort, or supporting Snort 3 / Suricata.
- Production-grade high availability.
- Watching a mirrored switch port (SPAN). Students rarely get access to campus switch configuration.

## Anti-goals (failure even if it "works")

- Anyone on the LAN can block or unblock hosts, or fake alerts.
- NIDPS blocks the gateway, the DNS server, the admin's own machine or itself, and cuts the demo network off.
- The demo depends on internet access, such as fonts or CDNs loaded from outside.
- New features make the code harder to explain.

## Constraints

- Keep the current stack: Node/Express, React/Vite/Tailwind, PostgreSQL and Snort 2.9 (Ubuntu 24.04 `apt`). Prefer Node built-ins over new dependencies (`crypto`, `net.BlockList`, `node:test`).
- The app must still run on Windows with no PostgreSQL (in-memory fallback) and with the firewall simulated, so it can be developed and rehearsed on a laptop.
- The working folder `Desktop\NIPS` is **not** renamed by this work, because renaming it would break the open session. The owner can rename it afterwards; nothing depends on the folder name.

## Approaches considered (deployment)

| Approach | Trade-off | Decision |
|---|---|---|
| A. Host mode (`INPUT`) | Works on any campus network without IT. Protects one machine only. | **Chosen, default** |
| B. Gateway mode (`FORWARD`) | True network prevention. Needs a second NIC and more setup. | **Chosen, opt-in via setting** |
| C. SPAN/mirror sensor | Sees the whole LAN but can't block it. Needs switch access. | Rejected |

The owner picked A + B together, selected by one setting.

## Audit findings → fixes

Security
1. **No authentication.** Every endpoint is open, including block, unblock and inject. → Add an admin login: credentials come from `.env`, the password is stored as a scrypt hash, and the session is an HMAC-signed `HttpOnly; SameSite=Strict` cookie with an 8 h expiry. Failed logins are rate-limited. All `/api/*` routes except `/api/health` and `/api/auth/*` require login.
2. **Forged alerts via `rawLine`** let anyone get any IP blocked. → The simulator exists only when `DEMO_MODE=true` and requires login. Injected lines must parse as valid Snort alerts.
3. **No allowlist.** Auto-block can hit the gateway, DNS, the admin's machine or NIDPS itself. → Add a protected set built from three sources: `NIDPS_ALLOWLIST` (CIDRs), all of the host's own interface addresses, and loopback/link-local ranges. It uses `net.BlockList`. Protected IPs are never blocked, by automation or by hand; the alert is still logged.
4. **Shell `exec` with string interpolation.** → Use `execFile` with an argument array, and validate IPs with `net.isIP` (the current IPv6 regex accepts junk such as `:::::`).
5. **PostgreSQL exposed on the LAN** with `postgres/postgres`. → Compose binds `127.0.0.1:5432`, and the password comes from `.env`.
6. **Open CORS; internal error messages returned to clients.** → The backend serves the built frontend from the same port, so CORS is removed. Errors return generic messages; details go to the server log only.
7. **No security headers.** → Set CSP, `X-Frame-Options`, `X-Content-Type-Options` and `Referrer-Policy` by hand.
8. **`chmod 777 /var/log/snort`** lets any local user write forged alerts. → Set `750`, owned by root, with a group the backend runs in.
9. **Login over plain HTTP** on campus Wi‑Fi. → Optional HTTPS when `TLS_CERT`/`TLS_KEY` are set. A script generates a self-signed certificate.

Bugs
10. `/api/simulator/status` reads `logWatcher.watcher` and `pollInterval`, which don't exist, so the watcher always shows as inactive.
11. Snort timestamps are local time but are parsed as UTC, and a December alert read in January gets the wrong year.
12. The in-memory fallback guesses from SQL strings. It ignores `UPDATE alerts`, `COUNT(*)` with filters and more. → Replace it with a store interface that has a PostgreSQL implementation and an in-memory implementation.
13. Rules are appended with `-A`, which can land after an existing ACCEPT and never match. Blocks are lost when the machine reboots, and `reset` runs `iptables -F INPUT`, which wipes unrelated rules. → Add a dedicated `NIDPS` chain jumped to from `INPUT` or `FORWARD` (depending on mode), insert at the top, and use `-C` for idempotency. On startup, the chain is resynced from the database's active blocks. Reset flushes only the `NIDPS` chain.
14. The WSL distro name `Ubuntu-24.04` is hard-coded in three places. → Make it the `WSL_DISTRO` setting.
15. React effect dependencies are stale: page changes and polling race each other.

Privacy
16. Students' IPs are kept forever. → `RETENTION_DAYS` (default 30) deletes old alerts and old inactive blocks daily. The retention policy is stated in the docs.
17. Google Fonts loads from the internet, which leaks visitors to a third party and breaks offline. → Use the system font stack.

## Improvements (demo-visible)

- **Live updates over SSE** (`/api/events`), with polling as the fallback. The dashboard updates the moment Snort fires.
- **Escalation rule:** `ESCALATE_COUNT` Priority‑2 alerts from one IP within `ESCALATE_WINDOW_MIN` trigger a block. The defaults are 5 alerts in 5 minutes, so an SSH brute force gets blocked even though it isn't Priority 1.
- **Blocks expire** after `BLOCK_DURATION_MIN` (default 60; 0 means permanent). An expiry sweeper unblocks them and the UI shows a countdown.
- **Audit log:** every block, unblock, login and alert-status change is recorded with who did it, when and why. It has its own tab.
- **Alert triage:** mark alerts resolved or false-positive.
- **Mode badges** in the UI: Host or Gateway, Live or Simulated firewall, and Demo mode.
- **Settings view (read-only)** showing the effective allowlist, thresholds and mode.
- **Automated tests** with `node:test`: parser, IP validation and allowlist, firewall command builder, auth and escalation.

## Gateway mode (how it works)

`scripts/setup_gateway.sh <wan_if> <lan_if>` turns on `ip_forward`, sets MASQUERADE NAT from the LAN to the WAN, and creates the `NIDPS` chain jumped to from `FORWARD`. Snort listens on `lan_if` (setting `SNORT_INTERFACE`). For the demo topology, the attacker PC and victim PC sit behind the NIDPS box on a cheap switch, or the attacker sits on the WAN side. The guide gives step-by-step addressing.

## Handoff to collaborator

- `git init`, with a `.gitignore` covering `.env`, `node_modules`, `dist` and logs, and `.env.example` updated with every setting.
- Docs:
  - `README.md` (quick start in 5 commands)
  - `docs/ARCHITECTURE.md` (how data flows and why)
  - `docs/LAN_DEPLOYMENT.md` (host and gateway)
  - `docs/DEMO_SCRIPT.md` (minute-by-minute defence demo and likely examiner questions)
  - `docs/SECURITY.md` (threat model and the fixes above)
  - `HANDOFF.md` (start here)
- A published private explainer page the owner can share.
- Push to a **private** GitHub repo and invite the collaborator. This is done only with the owner's go-ahead, and needs their GitHub sign-in and the collaborator's username.

## Builder calls (my decisions; owner may override)

- Single admin account. No user database.
- The session secret is generated into `.env` on first run if it's missing.
- Default `DEMO_MODE=true` in `.env.example`, because this is a demo project. Docs explain switching it off.
- The repo folder is not renamed.
- No new runtime dependencies unless unavoidable.
