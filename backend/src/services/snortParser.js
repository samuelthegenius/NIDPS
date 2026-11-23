/**
 * Snort "fast alert" line parser.
 *
 * Example lines:
 *   [**] [1:2001219:1] ET EXPLOIT Log4j [**] [Classification: X] [Priority: 1] {TCP} 198.51.100.99:51234 -> 10.0.0.5:8080
 *   05/24-10:15:32.123456 [**] [1:1000001:1] SSH Brute Force [**] [Priority: 2] {TCP} 192.168.1.50:54321 -> 10.0.0.5:22
 *   [**] [1:384:8] ICMP PING [**] [Priority: 3] {ICMP} 192.168.1.100 -> 8.8.8.8
 *   [**] [1:1:1] IPv6 [**] [Priority: 2] {TCP} 2001:db8::5:443 -> 2001:db8::1:22
 */
const { isValidIp, normalizeIp } = require('../lib/ip');

const LINE_REGEX =
  /\[\*\*\]\s*(?:\[(\d+:\d+:\d+)\])?\s*([^[]+?)\s*\[\*\*\](?:\s*\[Classification:\s*([^\]]+)\])?(?:\s*\[Priority:\s*(\d+)\])?\s*\{([A-Za-z0-9_-]+)\}\s*(\S+)\s*->\s*(\S+)/;
const TIMESTAMP_REGEX = /^(\d{2})\/(\d{2})-(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?/;
const ONE_DAY_MS = 24 * 3600 * 1000;

const PROTOCOLS_WITH_PORTS = new Set(['TCP', 'UDP', 'SCTP']);

/**
 * Extracts the IP from "ip", "ip:port", "[v6]:port" or "v6:port".
 * An unbracketed IPv6 token like "2001:db8::5:443" is ambiguous (it is itself a
 * valid address), so for port-carrying protocols the last ":digits" is always the port.
 */
function endpointIp(token, hasPort) {
  const bracketed = token.match(/^\[([^\]]+)\](?::\d+)?$/);
  if (bracketed) return isValidIp(bracketed[1]) ? normalizeIp(bracketed[1]) : null;
  if (hasPort) {
    const withoutPort = token.replace(/:\d{1,5}$/, '');
    if (withoutPort !== token && isValidIp(withoutPort)) return normalizeIp(withoutPort);
  }
  return isValidIp(token) ? normalizeIp(token) : null;
}

/** Snort prints local time without a year; pick the year that is not in the future. */
function parseTimestamp(line, now) {
  const m = line.match(TIMESTAMP_REGEX);
  if (!m) return now.toISOString();
  const [, month, day, hour, minute, second, fraction = '0'] = m;
  const ms = Math.floor(Number(`0.${fraction}`) * 1000);
  let date = new Date(now.getFullYear(), month - 1, day, hour, minute, second, ms);
  if (date.getTime() - now.getTime() > ONE_DAY_MS) {
    date = new Date(now.getFullYear() - 1, month - 1, day, hour, minute, second, ms);
  }
  return Number.isNaN(date.getTime()) ? now.toISOString() : date.toISOString();
}

function parseSnortAlert(line, now = new Date()) {
  if (typeof line !== 'string') return null;
  const trimmed = line.trim();
  if (!trimmed.includes('[**]') || !trimmed.includes('->')) return null;

  const match = trimmed.match(LINE_REGEX);
  if (!match) return null;
  const [, sid, message, classification, priority, protocol, src, dst] = match;

  const hasPort = PROTOCOLS_WITH_PORTS.has(protocol.toUpperCase());
  const source_ip = endpointIp(src, hasPort);
  const dest_ip = endpointIp(dst, hasPort);
  if (!source_ip || !dest_ip) return null;

  let severity = priority ? Number(priority) : 3;
  if (!(severity >= 1 && severity <= 4)) severity = 3;

  return {
    timestamp: parseTimestamp(trimmed, now),
    sid: sid || null,
    source_ip,
    dest_ip,
    protocol: protocol.toUpperCase(),
    alert_message: message.trim(),
    classification: classification ? classification.trim() : 'Unclassified',
    severity,
  };
}

module.exports = { parseSnortAlert };
