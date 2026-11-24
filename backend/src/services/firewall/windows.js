/**
 * Builds Windows Firewall argument vectors (never shell strings).
 *
 * Every NIDPS block is two Windows Firewall rules (inbound and outbound) that share
 * one name, NIDPS-block-<ip>. Only rules whose name starts with NIDPS-block- are
 * ever deleted, so firewall rules made by anyone else are never touched.
 * netsh is used for per-IP work because it takes ~0.1 s per call; PowerShell
 * (~3.5 s to start) is used once, at start-up, to remove every NIDPS rule.
 */
const RULE_PREFIX = 'NIDPS-block-';
const DIRECTIONS = ['in', 'out'];

function buildWindowsCommands() {
  const netsh = ['netsh', 'advfirewall', 'firewall'];
  const name = (ip) => `name=${RULE_PREFIX}${ip}`;
  return {
    prefix: RULE_PREFIX,
    directions: DIRECTIONS,
    check: (ip, dir) => [...netsh, 'show', 'rule', name(ip), `dir=${dir}`],
    add: (ip, dir) => [...netsh, 'add', 'rule', name(ip), `dir=${dir}`, 'action=block', `remoteip=${ip}`, 'profile=any'],
    remove: (ip) => [...netsh, 'delete', 'rule', name(ip)],
    flush: () => [
      'powershell.exe',
      '-NoProfile',
      '-NonInteractive',
      '-Command',
      `Get-NetFirewallRule -DisplayName '${RULE_PREFIX}*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule`,
    ],
    // `net session` succeeds only in an elevated (Run as administrator) process.
    adminCheck: () => ['net', 'session'],
  };
}

module.exports = { buildWindowsCommands, RULE_PREFIX };
