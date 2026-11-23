/**
 * Allowlist ("never block") of protected addresses: the configured entries,
 * this machine's own interface addresses, and loopback/link-local ranges.
 * NIDPS refuses to block any protected address, so a spoofed or mistaken alert
 * cannot cut off the gateway, DNS server, the admin's PC or NIDPS itself.
 */
const net = require('net');
const os = require('os');
const { isValidIp, normalizeIp } = require('./ip');

const BUILT_IN = ['127.0.0.0/8', '::1/128', '169.254.0.0/16', 'fe80::/10'];

function familyOf(address) {
  return net.isIPv6(address) ? 'ipv6' : 'ipv4';
}

function addEntry(list, entry) {
  const [addr, prefixText, extra] = entry.split('/');
  const address = normalizeIp(addr);
  if (extra !== undefined || !isValidIp(address)) {
    throw new Error(`Invalid allowlist entry "${entry}"`);
  }
  const family = familyOf(address);
  if (prefixText === undefined) {
    list.addAddress(address, family);
    return;
  }
  const prefix = Number(prefixText);
  const max = family === 'ipv6' ? 128 : 32;
  if (!/^\d+$/.test(prefixText) || prefix > max) {
    throw new Error(`Invalid allowlist entry "${entry}"`);
  }
  list.addSubnet(address, prefix, family);
}

function localAddresses() {
  return Object.values(os.networkInterfaces())
    .flat()
    .filter(Boolean)
    .map((i) => normalizeIp(i.address.split('%')[0]))
    .filter(isValidIp);
}

function createAllowlist({ entries = [], includeLocal = true } = {}) {
  const list = new net.BlockList();
  const described = [];
  for (const entry of [...BUILT_IN, ...entries]) {
    addEntry(list, entry);
    described.push(entry);
  }
  if (includeLocal) {
    for (const addr of localAddresses()) {
      addEntry(list, addr);
      described.push(`${addr} (this machine)`);
    }
  }

  return {
    isProtected(ip) {
      if (!isValidIp(ip)) return false;
      const address = normalizeIp(ip);
      return list.check(address, familyOf(address));
    },
    describe() {
      return [...described];
    },
  };
}

module.exports = { createAllowlist };
