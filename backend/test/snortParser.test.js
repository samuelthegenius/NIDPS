const test = require('node:test');
const assert = require('node:assert/strict');
const { parseSnortAlert } = require('../src/services/snortParser');

const LOG4J =
  '[**] [1:2001219:1] ET EXPLOIT Apache Log4j RCE Attempt [**] [Classification: Attempted Administrator Privilege Gain] [Priority: 1] {TCP} 198.51.100.99:51234 -> 10.0.0.5:8080';

test('parses a standard fast-alert line', () => {
  const a = parseSnortAlert(LOG4J);
  assert.equal(a.severity, 1);
  assert.equal(a.source_ip, '198.51.100.99');
  assert.equal(a.dest_ip, '10.0.0.5');
  assert.equal(a.protocol, 'TCP');
  assert.equal(a.sid, '1:2001219:1');
  assert.equal(a.alert_message, 'ET EXPLOIT Apache Log4j RCE Attempt');
  assert.equal(a.classification, 'Attempted Administrator Privilege Gain');
});

test('parses ICMP lines without ports', () => {
  const a = parseSnortAlert('[**] [1:384:8] ICMP PING [**] [Classification: Misc activity] [Priority: 3] {ICMP} 192.168.1.100 -> 8.8.8.8');
  assert.equal(a.source_ip, '192.168.1.100');
  assert.equal(a.dest_ip, '8.8.8.8');
  assert.equal(a.protocol, 'ICMP');
});

test('parses unbracketed IPv6 endpoints with ports', () => {
  const a = parseSnortAlert('[**] [1:1:1] V6 test [**] [Priority: 2] {TCP} 2001:db8::5:443 -> 2001:db8::1:22');
  assert.equal(a.source_ip, '2001:db8::5');
  assert.equal(a.dest_ip, '2001:db8::1');
});

test('parses bracketed IPv6 endpoints', () => {
  const a = parseSnortAlert('[**] [1:1:1] V6 test [**] [Priority: 2] {TCP} [2001:db8::5]:443 -> [2001:db8::1]:22');
  assert.equal(a.source_ip, '2001:db8::5');
  assert.equal(a.dest_ip, '2001:db8::1');
});

test('defaults a missing or out-of-range priority to 3', () => {
  assert.equal(parseSnortAlert('[**] [1:1:1] X [**] {TCP} 1.2.3.4:1 -> 5.6.7.8:2').severity, 3);
  assert.equal(parseSnortAlert('[**] [1:1:1] X [**] [Priority: 9] {TCP} 1.2.3.4:1 -> 5.6.7.8:2').severity, 3);
});

test('reads the leading timestamp as local time', () => {
  const now = new Date(2026, 5, 10, 12, 0);
  const a = parseSnortAlert('06/10-09:15:32.123456 ' + LOG4J, now);
  const t = new Date(a.timestamp);
  assert.equal(t.getFullYear(), 2026);
  assert.equal(t.getMonth(), 5);
  assert.equal(t.getHours(), 9);
  assert.equal(t.getMinutes(), 15);
});

test('a December alert read in January belongs to the previous year', () => {
  const now = new Date(2027, 0, 1, 0, 5);
  const t = new Date(parseSnortAlert('12/31-23:59:00.1 ' + LOG4J, now).timestamp);
  assert.equal(t.getFullYear(), 2026);
  assert.equal(t.getHours(), 23);
});

test('uses now when there is no timestamp', () => {
  const now = new Date(2026, 1, 2, 3, 4, 5);
  assert.equal(parseSnortAlert(LOG4J, now).timestamp, now.toISOString());
});

test('returns null for garbage and invalid IPs', () => {
  for (const line of ['', 'hello', '[**] no arrow [**]', '[**] [1:1:1] X [**] {TCP} 999.1.1.1:1 -> 5.6.7.8:2', null]) {
    assert.equal(parseSnortAlert(line), null, `expected null for ${line}`);
  }
});
