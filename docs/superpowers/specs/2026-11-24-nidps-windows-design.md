# NIDPS on native Windows — design (short)

**Approved:** 2026-11-24 ("go ahead, but don't forgo Linux also").

## Intent
Let NIDPS protect a Windows machine with no WSL and no Linux: Snort for Windows
detects, Windows Firewall blocks. Linux stays a first-class platform: iptables
host and gateway modes keep working exactly as before.

## Goals / non-goals
- Goal: host mode on Windows 10/11 with live blocking through Windows Firewall.
- Goal: unchanged Linux behaviour (iptables, sudo wrapper, gateway mode, all tests).
- Goal: the WSL bridge stays available as an explicit choice.
- Non-goal: gateway mode on Windows (Windows is not a practical router here; use
  Linux or the VirtualBox guide).
- Anti-goal: anything that touches firewall rules NIDPS did not create.

## Approaches considered
1. **netsh/PowerShell backend behind a firewall-driver interface (chosen).** One
   driver per platform, chosen by `NIDPS_FIREWALL`; the engine (locks, allowlist,
   audit, expiry) is shared.
2. Keep WSL iptables only. Rejected: under WSL2 NAT it does not protect Windows.
3. PowerShell for every call. Rejected: ~3.5 s per call versus ~0.1 s for netsh.

## Design
- `NIDPS_FIREWALL=auto|windows|iptables|wsl` (default auto). auto = `windows` on
  Windows in host mode, `wsl` on Windows in gateway mode (the old behaviour), and
  `iptables` everywhere else. `windows` + gateway is refused at start-up;
  `windows`/`wsl` on a non-Windows OS is refused.
- `ENABLE_REAL_FIREWALL` is accepted as an alias of `ENABLE_REAL_IPTABLES`.
- Windows driver, all through `execFile` (no shell):
  - rule name `NIDPS-block-<ip>`, one rule per direction (in, out), `action=block remoteip=<ip>`;
  - apply = for each direction, `show rule name=… dir=…` (exit 1 = missing) then `add rule`;
  - remove = `delete rule name=…`;
  - start-up = `net session` admin check (clear error if not elevated), then one
    PowerShell call removing every `NIDPS-block-*` rule, then re-apply active blocks.
- PowerShell scripts in `backend/scripts/windows/`: `setup-snort.ps1` (writes a
  self-contained `nidps.conf` + rules, lists adapters), `start-snort.ps1`,
  `check-windows.ps1` (read-only pre-flight), `install-task.ps1` (start at log-on,
  elevated). The old root `start-snort.ps1` moves to `start-snort-wsl.ps1` there.
- Dashboard shows which firewall driver is in use.

## Left to the builder
Exact wording of messages and docs; Snort minimal config contents (validated with
`snort -T` in WSL using Linux paths, since Snort for Windows is not installed here).
