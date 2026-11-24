/**
 * Chooses how NIDPS changes the firewall, from NIDPS_FIREWALL and the platform:
 *   windows  - Windows Firewall (netsh), host mode on Windows
 *   iptables - Linux iptables/ip6tables (host or gateway mode)
 *   wsl      - iptables inside WSL, driven from Windows (the older setup)
 * "auto" means windows on Windows in host mode, wsl on Windows in gateway mode,
 * and iptables everywhere else.
 */
function resolveBackend({ firewall = 'auto', platform = process.platform, mode = 'host' }) {
  const onWindows = platform === 'win32';
  const choice = firewall === 'auto' ? (onWindows ? (mode === 'gateway' ? 'wsl' : 'windows') : 'iptables') : firewall;

  if ((choice === 'windows' || choice === 'wsl') && !onWindows) {
    throw new Error(`NIDPS_FIREWALL=${choice} works only on Windows. Use NIDPS_FIREWALL=auto or iptables on this system.`);
  }
  if (choice === 'iptables' && onWindows) {
    throw new Error('NIDPS_FIREWALL=iptables needs Linux. On Windows use NIDPS_FIREWALL=windows (or wsl).');
  }
  if (choice === 'windows' && mode === 'gateway') {
    throw new Error(
      'Gateway mode is not supported with the Windows firewall: Windows is not used as a router here. ' +
        'Run gateway mode on Linux (or a Linux VirtualBox VM, see docs/LAN_DEPLOYMENT.md), or use NIDPS_MODE=host.'
    );
  }
  return choice;
}

/** Start-up warnings for setups that run but will not do what the user expects. */
function backendWarnings({ backend, snortLogPath = '' }) {
  const warnings = [];
  if (backend === 'windows' && /^[\\/]{2}wsl(\.localhost|\$)/i.test(snortLogPath)) {
    warnings.push(
      "Windows Firewall blocks traffic to Windows, but SNORT_LOG_PATH points inside WSL, so Snort is watching WSL's network. " +
        'Use native Snort for Windows (docs/LAN_DEPLOYMENT.md, "Host mode on native Windows"), or set NIDPS_FIREWALL=wsl for the old WSL setup.'
    );
  }
  return warnings;
}

module.exports = { resolveBackend, backendWarnings };
