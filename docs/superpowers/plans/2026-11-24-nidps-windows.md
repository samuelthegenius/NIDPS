# NIDPS native Windows — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Run NIDPS host mode natively on Windows with Windows Firewall, without changing Linux behaviour.
**Architecture:** The firewall engine delegates rule changes to a driver (`iptables` or `windows`), picked by `resolveBackend`.
**Tech Stack:** Node 18+ (CommonJS, node:test), netsh, PowerShell 5.1, Snort 2.9 for Windows.
**Spec:** docs/superpowers/specs/2026-11-24-nidps-windows-design.md

## Global Constraints
- No shell: every command is an argv array run with `execFile`.
- Linux: all 84 existing tests and 32 shell checks still pass unchanged in meaning.
- Rule names: `NIDPS-block-<ip>`; only rules with that prefix are ever removed.

## Review Focus
- Non-admin Windows start with live firewall → clear error, no partial state.
- Explicit `NIDPS_FIREWALL=windows` + gateway → refused with guidance.
- Half-present rule (only `in` exists) → apply adds the missing `out` rule.
- IPv6 addresses in rule names and `remoteip=`.
- Simulated mode on Windows → logs netsh commands, runs nothing.

---

### Task 1: Settings
**Files:** `backend/src/config/settings.js`, `backend/test/settings.test.js`
- Produces: `settings.firewall` ∈ {auto, windows, iptables, wsl} (throws `/NIDPS_FIREWALL/` otherwise); `realFirewall` true if `ENABLE_REAL_FIREWALL` or `ENABLE_REAL_IPTABLES` is true.
- [ ] Failing tests → implement → `npm test` green → commit.

### Task 2: Windows driver + backend resolution
**Files:** create `backend/src/services/firewall/windows.js`, `backend/src/services/firewall/backend.js`; modify `firewall/index.js`, `firewall/commands.js`; tests `backend/test/firewall.windows.test.js`.
- Produces: `buildWindowsCommands()` → `{check(ip,dir), add(ip,dir), remove(ip), flush(), adminCheck()}`; `resolveBackend({firewall, platform, mode})` → 'windows'|'iptables'|'wsl' or throws; `createFirewall` exposes `backend`; init throws `FirewallError('NOT_ADMIN')` when `net session` fails.
- Tests: argv shapes; auto resolution table; windows+gateway refused; non-Windows refusal; block/unblock/init against a fake netsh; half-present rule healed; non-admin init rejects and runs nothing else; simulated runs nothing.
- [ ] Failing tests → implement → green → commit.

### Task 3: Wiring
**Files:** `scripts/resetData.js` (Windows flush), `routes/api.js` (`firewall` field in /settings), frontend `SettingsPanel.jsx`/`Navbar.jsx` labels, `.env.example`.
- [ ] `npm test` green, `npm run build` ok → commit.

### Task 4: PowerShell scripts
**Files:** `backend/scripts/windows/{setup-snort,start-snort,check-windows,install-task,start-snort-wsl}.ps1` (move root `start-snort.ps1`).
- Verify: every script parses (PowerShell parser, 0 errors); `check-windows.ps1` runs read-only here; Snort minimal config passes `snort -T` in WSL with Linux paths.
- [ ] Commit.

### Task 5: Docs
README, HANDOFF, LAN_DEPLOYMENT ("Windows (native)"), DEMO_SCRIPT, SECURITY, ARCHITECTURE: Windows and Linux side by side.
- [ ] Final full test run, review, commit.
