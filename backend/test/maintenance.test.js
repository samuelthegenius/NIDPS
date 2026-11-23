const test = require('node:test');
const assert = require('node:assert/strict');
const { createMaintenance } = require('../src/jobs/maintenance');

test('sweeps expired blocks and purges data older than the retention period', async () => {
  const now = new Date('2026-11-23T12:00:00Z');
  let swept = 0;
  let cutoff = null;
  const m = createMaintenance({
    firewall: { sweepExpired: async () => ++swept },
    store: { purgeBefore: async (c) => { cutoff = c; return { alerts: 0, blocks: 0, audit: 0 }; } },
    settings: { retentionDays: 30 },
    now: () => now,
  });
  await m.sweep();
  await m.purge();
  assert.equal(swept, 1);
  assert.equal(cutoff.toISOString(), '2026-10-24T12:00:00.000Z');
});

test('RETENTION_DAYS=0 keeps data forever', async () => {
  let called = false;
  const m = createMaintenance({
    firewall: { sweepExpired: async () => 0 },
    store: { purgeBefore: async () => { called = true; } },
    settings: { retentionDays: 0 },
  });
  await m.purge();
  assert.equal(called, false);
});
