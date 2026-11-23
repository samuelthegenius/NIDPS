const test = require('node:test');
const assert = require('node:assert/strict');
const { loadSettings } = require('../src/config/settings');

test('defaults match the spec', () => {
  const s = loadSettings({});
  assert.equal(s.mode, 'host');
  assert.equal(s.port, 5000);
  assert.equal(s.host, '0.0.0.0');
  assert.equal(s.blockDurationMin, 60);
  assert.equal(s.escalateCount, 5);
  assert.equal(s.escalateWindowMin, 5);
  assert.equal(s.retentionDays, 30);
  assert.equal(s.demoMode, false);
  assert.equal(s.realFirewall, false);
  assert.equal(s.wslDistro, 'Ubuntu-24.04');
  assert.equal(s.adminUsername, 'admin');
  assert.ok(Object.isFrozen(s));
});

test('rejects an unknown mode', () => {
  assert.throws(() => loadSettings({ NIDPS_MODE: 'router' }), /NIDPS_MODE/);
});

test('accepts gateway mode case-insensitively', () => {
  assert.equal(loadSettings({ NIDPS_MODE: 'Gateway' }).mode, 'gateway');
});

test('parses the allowlist and trims entries', () => {
  const s = loadSettings({ NIDPS_ALLOWLIST: ' 10.0.0.1, 192.168.0.0/24 ,' });
  assert.deepEqual(s.allowlist, ['10.0.0.1', '192.168.0.0/24']);
});

test('parses booleans and numbers', () => {
  const s = loadSettings({ DEMO_MODE: 'true', ENABLE_REAL_IPTABLES: 'true', BLOCK_DURATION_MIN: '0' });
  assert.equal(s.demoMode, true);
  assert.equal(s.realFirewall, true);
  assert.equal(s.blockDurationMin, 0);
});

test('relative SNORT_LOG_PATH resolves against backend/, not the current directory', () => {
  const path = require('path');
  const backendDir = path.resolve(__dirname, '..');
  assert.equal(loadSettings({ SNORT_LOG_PATH: './mock_snort.log' }).snortLogPath, path.join(backendDir, 'mock_snort.log'));
  assert.equal(loadSettings({}).snortLogPath, path.join(backendDir, 'mock_snort.log'));
  const abs = path.resolve('/var/log/snort/snort.alert.fast');
  assert.equal(loadSettings({ SNORT_LOG_PATH: abs }).snortLogPath, abs);
});

test('rejects a negative or non-numeric number setting', () => {
  assert.throws(() => loadSettings({ ESCALATE_COUNT: 'lots' }), /ESCALATE_COUNT/);
  assert.throws(() => loadSettings({ RETENTION_DAYS: '-1' }), /RETENTION_DAYS/);
});
