/**
 * IP address helpers. Validation uses Node's own parser (net.isIP), so anything
 * that is not a real IPv4/IPv6 address - including shell metacharacters - is rejected.
 */
const net = require('net');

function isValidIp(ip) {
  if (typeof ip !== 'string') return false;
  return net.isIP(ip.trim()) !== 0;
}

function normalizeIp(ip) {
  let value = String(ip).trim().toLowerCase();
  if (value.startsWith('::ffff:') && net.isIPv4(value.slice(7))) value = value.slice(7);
  return value;
}

module.exports = { isValidIp, normalizeIp };
