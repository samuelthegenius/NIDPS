const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { createLogWatcher } = require('../src/services/logWatcher');

function waitFor(predicate, timeoutMs = 4000) {
  return new Promise((resolve, reject) => {
    const started = Date.now();
    const timer = setInterval(() => {
      if (predicate()) {
        clearInterval(timer);
        resolve();
      } else if (Date.now() - started > timeoutMs) {
        clearInterval(timer);
        reject(new Error('timed out waiting for line'));
      }
    }, 50);
  });
}

test('creates a missing log file, reports status, and delivers new lines', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'nidps-'));
  const file = path.join(dir, 'sub', 'alert.fast');
  const lines = [];
  const watcher = createLogWatcher({ path: file, onLine: (l) => lines.push(l) });
  watcher.start();
  try {
    assert.equal(fs.existsSync(file), true);
    assert.deepEqual(watcher.status(), { active: true, path: path.resolve(file) });
    await new Promise((r) => setTimeout(r, 300));
    fs.appendFileSync(file, 'first line\n');
    await waitFor(() => lines.includes('first line'));
  } finally {
    watcher.stop();
  }
  assert.equal(watcher.status().active, false);
});

test('continues after truncation', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'nidps-'));
  const file = path.join(dir, 'alert.fast');
  fs.writeFileSync(file, 'old line that should not be replayed\n');
  const lines = [];
  const watcher = createLogWatcher({ path: file, onLine: (l) => lines.push(l) });
  watcher.start();
  try {
    await new Promise((r) => setTimeout(r, 300));
    fs.appendFileSync(file, 'before reset\n');
    await waitFor(() => lines.includes('before reset'));
    fs.writeFileSync(file, ''); // what `npm run reset` does
    await new Promise((r) => setTimeout(r, 1200));
    fs.appendFileSync(file, 'after reset\n');
    await waitFor(() => lines.includes('after reset'));
    assert.ok(!lines.includes('old line that should not be replayed'));
  } finally {
    watcher.stop();
  }
});
