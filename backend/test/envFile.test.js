const test = require('node:test');
const assert = require('node:assert/strict');
const { setEnvValues } = require('../src/lib/envFile');

test('replaces existing keys, keeps comments and other lines, appends new keys', () => {
  const input = '# comment\nPORT=5000\nSESSION_SECRET=old\n\nDB_NAME=nidps_db\n';
  const out = setEnvValues(input, { SESSION_SECRET: 'new', ADMIN_PASSWORD_HASH: 'scrypt$a$b' });
  assert.equal(out, '# comment\nPORT=5000\nSESSION_SECRET=new\n\nDB_NAME=nidps_db\nADMIN_PASSWORD_HASH=scrypt$a$b\n');
});

test('handles CRLF files and empty input', () => {
  assert.equal(setEnvValues('A=1\r\nB=2\r\n', { B: '3' }), 'A=1\nB=3\n');
  assert.equal(setEnvValues('', { A: '1' }), 'A=1\n');
});
