# NIDPS architecture

## The path of one attack

```
 1. Packet on the wire
        │  Snort (signature rules in /etc/snort/rules/local.rules)
        ▼
 2. One line appended to the fast-alert log
    [**] [1:1000003:2] NIDPS - Possible Nmap SYN Scan [**] [Priority: 1] {TCP} 192.168.1.20:4433 -> 192.168.1.10:22
        │  services/logWatcher.js   follows the file like `tail -F`
        ▼
 3. services/snortParser.js        line → { source_ip, dest_ip, protocol, severity, message, timestamp }
        │
        ▼
 4. services/detector.js           store the alert, then apply the policy:
        │                            P1 → block now · P2 → block after N in M minutes · P3 → log
        ▼
 5. services/firewall/index.js     refuse protected IPs → per-IP lock → driver: iptables -I NIDPS 1 -s IP -j DROP (Linux)
                                  or netsh add rule NIDPS-block-IP dir=in/out (Windows)
        │                            → save block + audit entry
        ▼
 6. services/events.js             publishes "alert" / "block" events
        │
        ▼
 7. routes/events.js (SSE)         pushes the event to every open dashboard → it refreshes instantly
```

## Backend modules (`backend/src`)

| File | Responsibility |
|---|---|
| `server.js` | Entry point: loads settings, builds every service, starts HTTP/HTTPS |
| `app.js` | Express app: security headers, routes, serves the built dashboard |
| `config/settings.js` | Reads and validates every `.env` setting in one place |
| `lib/ip.js` | IP validation (`net.isIP`) and normalisation |
| `lib/allowlist.js` | Protected addresses (configured + own interfaces + loopback) via `net.BlockList` |
| `services/snortParser.js` | Parses Snort fast-alert lines (IPv4/IPv6, local timestamps) |
| `services/logWatcher.js` | Follows the alert file; survives truncation and rotation |
| `services/detector.js` | Detection policy (P1 / P2 escalation / P3) |
| `services/firewall/backend.js` | Picks the firewall driver from `NIDPS_FIREWALL` and the OS (Windows Firewall, iptables, or iptables in WSL) |
| `services/firewall/commands.js` | Builds iptables argument lists for host/gateway, Linux/WSL, IPv4/IPv6 |
| `services/firewall/windows.js` | Builds netsh/PowerShell argument lists for Windows Firewall rules named `NIDPS-block-<ip>` |
| `services/firewall/index.js` | Block/unblock/expire/resync with locking, auditing and events; the same engine drives either OS through a small driver (`prepare`, `apply`, `remove`) |
| `services/events.js` | In-process event bus |
| `store/memoryStore.js`, `store/pgStore.js` | The same data API over memory or PostgreSQL |
| `auth/*` | scrypt password hashing, signed session cookies, login rate limiting |
| `routes/*` | REST API, login, live events, simulator (demo mode only) |
| `security/headers.js` | CSP and other headers; same-origin check on state changes |
| `jobs/maintenance.js` | Lifts expired blocks (30 s), deletes old data (daily) |

The tests in `backend/test` mirror these files one-to-one.

## Design decisions (and the reasons to give an examiner)

| Decision | Why |
|---|---|
| **A dedicated `NIDPS` iptables chain** | All NIDPS rules sit in one place, reached by one jump from `INPUT` or `FORWARD`. Reset flushes only NIDPS's rules, never the machine's other firewall rules. Switching host ↔ gateway mode only changes which chain jumps to it. On Windows the equivalent is the `NIDPS-block-` name prefix: only rules with that prefix are ever removed. |
| **Rules inserted at the top (`-I … 1`)** | An appended rule (`-A`) can sit behind an earlier ACCEPT and never match. |
| **`execFile` with argument arrays, never a shell** | Together with strict IP validation, this makes command injection impossible: an "IP" like `1.2.3.4; reboot` is rejected before anything runs, and could never reach a shell anyway. |
| **Allowlist checked before every block** | Attackers can spoof source addresses. Without an allowlist, a forged alert "from" the gateway would make NIDPS cut off the whole network (self-inflicted denial of service). |
| **Blocks expire** | IPs on campus are reassigned by DHCP; a permanent block could punish the next innocent user of that address. |
| **Escalation for Priority 2** | One failed SSH login is normal; five in five minutes is an attack. This lowers false positives while still stopping brute force. |
| **Read Snort's log file rather than run inline** | Snort stays a standard, unmodified sensor; NIDPS adds the prevention layer. If NIDPS stops, traffic is not interrupted (fail-open). |
| **Server-Sent Events** | One-way live updates without polling, using plain HTTP. 15 s polling remains as a fallback. |
| **Store interface with memory + PostgreSQL** | The demo still works if the database is down; both pass the same contract tests. |
| **Dependency injection (`createX({ ... })`)** | Every part can be tested with fakes, for example a fake iptables, with no root and no network. |
| **Resync on start-up** | iptables rules do not survive a reboot (Windows Firewall rules do, but may be stale); either way NIDPS removes its own old rules and re-applies every active block from the database. |
| **One engine, two operating systems** | Locking, the allowlist, expiry and auditing are shared; only the few commands that change the firewall differ, so Linux and Windows behave the same and are tested the same way. |

## Data model (`backend/db/init.sql`)

- `alerts` (id, timestamp, source_ip, dest_ip, protocol, alert_message, severity 1–4, status)
- `blocked_ips` (id, ip_address, block_reason, timestamp, expires_at, unblocked_at, is_active, created_by)
- `audit_log` (id, timestamp, actor, action, target, detail)

The schema is applied automatically every time NIDPS connects, so upgrades need no manual step.

## Frontend (`frontend/src`)

`App.jsx` holds the session and data state. `services/api.js` is the only file that talks to the
server. Components are presentational: `AlertsTable`, `FirewallTable`, `StatsCharts`,
`MetricCards`, `AuditLog`, `SettingsPanel`, `LoginScreen`, `BlockModal`, `LogSimulatorModal`.
In production, the backend serves the built files from `frontend/dist` on the same port as
the API. Same-origin serving is what lets the session cookie be `SameSite=Strict`, and it
means no CORS is needed.
