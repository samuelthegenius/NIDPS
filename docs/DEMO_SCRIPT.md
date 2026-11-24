# NIDPS defence demo script

Two versions of the demo:
- **A. Simulated** (any laptop, no network needed): always works; use it as the main demo or the backup.
- **B. Live LAN** (Linux or Windows machine + attacker PC): the strongest proof; see [LAN_DEPLOYMENT.md](LAN_DEPLOYMENT.md).

Plan to run B, and keep A ready in a second browser tab in case the network misbehaves.

---

## Pre-flight checklist (the day before, and 30 minutes before)

- [ ] `cd backend && npm test` passes.
- [ ] `cd frontend && npm run build` done after the last change.
- [ ] You can sign in, and you know the admin password (`npm run setup` resets it).
- [ ] `npm run reset` run, so the dashboard starts at zero.
- [ ] `backend/.env`: `DEMO_MODE=true`; `BLOCK_DURATION_MIN=5` (short, so the expiry can be shown); `NIDPS_ALLOWLIST` holds your own laptop's IP.
- [ ] Live demo only: Snort running, attacker PC can ping the target, `ENABLE_REAL_FIREWALL=true`.
  Linux: `sudo ./backend/scripts/start_snort.sh <if>`. Windows: `start-snort.ps1 -Interface <n>`, NIDPS started from an **elevated** PowerShell, and `check-windows.ps1` says "All 9 checks passed".
- [ ] Gateway demo only: `sudo ./backend/scripts/check_gateway.sh <wan_if> <lan_if> <lan_cidr> <victim_ip>` says "All 9 checks passed", and the 7-point pre-flight in [LAN_DEPLOYMENT.md](LAN_DEPLOYMENT.md#gateway-mode-without-a-switch-phone-hotspot) is done. Re-run it after every hotspot reconnect.
- [ ] Browser zoom set so the whole dashboard fits on the projector.
- [ ] A terminal open on the NIDPS machine (live demo). Linux: `watch -n1 sudo iptables -L NIDPS -n -v`.
  Windows: `while ($true) { cls; Get-NetFirewallRule -DisplayName 'NIDPS-block-*' | ft DisplayName,Direction,Action; sleep 1 }`.

---

## The demo (about 10 minutes)

| Time | Do | Say |
|---|---|---|
| 0:00 | Show the login page, then sign in | "The console is protected: scrypt-hashed password, signed HttpOnly session cookie, and lock-out after 5 failed attempts." |
| 0:45 | Dashboard: point at the badges (Host/Gateway, Live/Simulated firewall) and the LIVE indicator | "NIDPS has two parts: Snort detects, and our engine prevents. The dashboard receives events live from the server." |
| 1:30 | **P1 attack.** Simulated: *Simulate Attack → Apache Log4j → Inject*. Live: on the attacker, `nmap -sS <target>` | "A Priority-1 signature. Watch: it appears, and the source is blocked automatically, with no refresh." |
| 2:30 | Firewall tab: the block, "Automatic", the expiry countdown. Live: show the terminal (Linux: `iptables -L NIDPS` counters rising; Windows: the `NIDPS-block-<ip>` rules), and the attacker's `ping` timing out | "NIDPS added a block rule for the attacker: on Linux at the top of its own iptables chain, on Windows as an inbound and an outbound Windows Firewall rule. The attacker's packets are now dropped by the operating system." |
| 3:30 | **P2 escalation.** Simulated: inject *SSH Brute Force* 5 times. Live: run `ssh x@<target>` repeatedly | "One failed SSH attempt is normal, so Priority 2 is only logged, but 5 in 5 minutes is brute force. The 5th alert triggers an escalation block." |
| 4:30 | **Safety.** *Manual Block IP* → enter the gateway or `127.0.0.1` → refused | "Attackers can spoof addresses. If NIDPS believed a forged alert from the gateway, it would cut off the whole network. Protected addresses are never blocked." |
| 5:15 | Alerts tab: mark one alert *False +*, then search by IP | "Analysts triage alerts; every action is recorded." |
| 5:45 | Audit tab | "Accountability: who blocked what, when, and why — automatic or human." |
| 6:15 | Analytics tab: severity, top sources, protocols | "Trend analysis for attacker profiling." |
| 6:45 | Settings tab: mode, allowlist, retention | "Configuration at a glance, including the 30-day data retention: IP addresses are personal data." |
| 7:15 | Firewall tab: *Unblock* (or wait for the expiry) | "Blocks expire, because campus IPs are reassigned by DHCP, and the next user should not be punished." |
| 8:00 | Explain host vs gateway mode with the diagram in LAN_DEPLOYMENT.md | "Host mode protects this server; gateway mode protects a whole network routed through it, using the FORWARD chain." |
| 9:00 | `npm test` in a terminal | "101 automated tests cover the parser, the firewall engine on Linux and Windows, detector, authentication and the HTTP API." |

---

## Likely examiner questions

1. **Is this IDS or IPS?**
   Both. Snort is the IDS. NIDPS turns its alerts into firewall actions, which is the prevention part. It acts on Snort's alerts rather than sitting inline, so it is "reactive IPS". The trade-off is that the first malicious packet gets through, but if NIDPS crashes, traffic keeps flowing (fail-open).
2. **What stops an attacker from making you block legitimate users?**
   Three things. First, the allowlist of critical hosts and the machine's own addresses. Second, blocks expire. Third, only Priority-1 or escalated Priority-2 alerts trigger blocks. Spoofed TCP cannot complete a handshake, so the established-flow web rules cannot be triggered by spoofing.
3. **How do you prevent command injection when running iptables as root?**
   The IP is validated with Node's `net.isIP`, and the command (iptables, or netsh on Windows) runs through `execFile` with an argument array, so no shell is ever involved.
4. **What happens after a reboot?**
   On Linux, iptables rules are lost; on Windows, firewall rules survive but may be stale. Either way, on start-up NIDPS removes its own old rules and re-applies every active block from the database.
5. **Why a separate iptables chain?**
   It keeps NIDPS's rules isolated. A reset flushes only them, and switching host/gateway mode changes only which built-in chain jumps to `NIDPS`.
6. **How is the dashboard secured?**
   Login, a scrypt hash, an HMAC-signed HttpOnly SameSite=Strict cookie, rate-limited login, a same-origin check on changes, a CSP, and optional HTTPS. Details are in [SECURITY.md](SECURITY.md).
7. **What about privacy?**
   IP addresses are personal data. Retention is 30 days by default, only the admin can see them, and nothing leaves the machine.
8. **What are the limitations?**
   Signature-based detection misses new or encrypted attacks. The system has a single admin account, and prevention is reactive (the first packet gets through). See "Remaining risks" in SECURITY.md.
9. **How did you test it?**
   Unit and integration tests with a fake iptables and an in-memory database (`npm test`), plus a live end-to-end run with Snort.
10. **How would it scale to a whole campus?**
    Run several sensors on SPAN/mirror ports writing to a central NIDPS, and push blocks to the campus edge firewall through its API instead of local iptables. The detector and firewall interfaces are already separate, so that is a new firewall adapter, not a rewrite.

---

## If something goes wrong

| Problem | Recovery |
|---|---|
| Live attack produces no alert | Switch to the simulator: "same pipeline, simulated sensor input". |
| You blocked yourself | Linux: `sudo iptables -F NIDPS`. Windows (elevated): `Get-NetFirewallRule -DisplayName 'NIDPS-block-*' \| Remove-NetFirewallRule`. |
| Dashboard shows POLLING instead of LIVE | Still works (refreshes every 15 s); press the refresh button. |
| Forgot the password | `cd backend && npm run setup`, then restart. |
