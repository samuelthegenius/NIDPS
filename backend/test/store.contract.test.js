/**
 * Contract tests every store implementation must pass.
 * Memory store always runs; PostgreSQL runs when TEST_DATABASE_URL is set
 * (it TRUNCATEs the tables, so never point it at real data).
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const { createMemoryStore } = require('../src/store/memoryStore');

const factories = [['memory', async () => createMemoryStore()]];
if (process.env.TEST_DATABASE_URL) {
  const { createPgStore } = require('../src/store/pgStore');
  factories.push([
    'postgres',
    async () => {
      const store = await createPgStore({ connectionString: process.env.TEST_DATABASE_URL });
      await store.pool.query('TRUNCATE alerts, blocked_ips, audit_log RESTART IDENTITY');
      return store;
    },
  ]);
}

const NOW = new Date('2026-11-23T12:00:00Z');
const minutesAgo = (m) => new Date(NOW.getTime() - m * 60000);

function alert(overrides = {}) {
  return {
    timestamp: NOW.toISOString(),
    source_ip: '198.51.100.1',
    dest_ip: '10.0.0.5',
    protocol: 'TCP',
    alert_message: 'ET SCAN Test',
    severity: 2,
    status: 'unresolved',
    ...overrides,
  };
}

for (const [name, make] of factories) {
  test(`${name}: alerts list newest first with pagination and total`, async () => {
    const s = await make();
    for (let i = 0; i < 5; i++) await s.insertAlert(alert({ timestamp: minutesAgo(10 - i).toISOString(), alert_message: `m${i}` }));
    const page = await s.listAlerts({ page: 1, limit: 2 });
    assert.equal(page.total, 5);
    assert.deepEqual(page.data.map((a) => a.alert_message), ['m4', 'm3']);
    const page3 = await s.listAlerts({ page: 3, limit: 2 });
    assert.deepEqual(page3.data.map((a) => a.alert_message), ['m0']);
    await s.close();
  });

  test(`${name}: alert filters (severity, status, case-insensitive search)`, async () => {
    const s = await make();
    await s.insertAlert(alert({ severity: 1, alert_message: 'Log4j RCE' }));
    await s.insertAlert(alert({ severity: 2, source_ip: '203.0.113.9', status: 'resolved' }));
    await s.insertAlert(alert({ severity: 3 }));
    assert.equal((await s.listAlerts({ page: 1, limit: 10, severity: 1 })).total, 1);
    assert.equal((await s.listAlerts({ page: 1, limit: 10, status: 'resolved' })).total, 1);
    assert.equal((await s.listAlerts({ page: 1, limit: 10, search: 'log4J' })).total, 1);
    assert.equal((await s.listAlerts({ page: 1, limit: 10, search: '203.0.113' })).total, 1);
    await s.close();
  });

  test(`${name}: updateAlertStatus and markAlertsBlocked`, async () => {
    const s = await make();
    const a = await s.insertAlert(alert());
    assert.equal((await s.updateAlertStatus(a.id, 'false_positive')).status, 'false_positive');
    assert.equal(await s.updateAlertStatus(99999, 'resolved'), null);
    await s.insertAlert(alert());
    await s.insertAlert(alert({ source_ip: '198.51.100.2' }));
    assert.equal(await s.markAlertsBlocked('198.51.100.1'), 1);
    await s.close();
  });

  test(`${name}: countAlertsSince respects ip, severity and time`, async () => {
    const s = await make();
    await s.insertAlert(alert({ timestamp: minutesAgo(1).toISOString() }));
    await s.insertAlert(alert({ timestamp: minutesAgo(2).toISOString() }));
    await s.insertAlert(alert({ timestamp: minutesAgo(30).toISOString() }));
    await s.insertAlert(alert({ timestamp: minutesAgo(1).toISOString(), severity: 1 }));
    await s.insertAlert(alert({ timestamp: minutesAgo(1).toISOString(), source_ip: '198.51.100.2' }));
    assert.equal(await s.countAlertsSince('198.51.100.1', 2, minutesAgo(5)), 2);
    await s.close();
  });

  test(`${name}: block lifecycle`, async () => {
    const s = await make();
    const b = await s.insertBlock({ ip_address: '198.51.100.1', block_reason: 'test', expires_at: null, created_by: 'admin' });
    assert.equal(b.is_active, true);
    assert.equal(b.created_by, 'admin');
    assert.equal((await s.getActiveBlock('198.51.100.1')).id, b.id);
    assert.equal((await s.listBlocks(true)).length, 1);
    const off = await s.deactivateBlock('198.51.100.1');
    assert.equal(off.is_active, false);
    assert.ok(off.unblocked_at);
    assert.equal(await s.getActiveBlock('198.51.100.1'), null);
    assert.equal(await s.deactivateBlock('198.51.100.1'), null);
    assert.equal((await s.listBlocks(true)).length, 0);
    assert.equal((await s.listBlocks(false)).length, 1);
    await s.close();
  });

  test(`${name}: listExpiredBlocks returns only active, expired blocks`, async () => {
    const s = await make();
    await s.insertBlock({ ip_address: '1.1.1.1', block_reason: 'x', expires_at: minutesAgo(1), created_by: 'system' });
    await s.insertBlock({ ip_address: '2.2.2.2', block_reason: 'x', expires_at: new Date(NOW.getTime() + 60000), created_by: 'system' });
    await s.insertBlock({ ip_address: '3.3.3.3', block_reason: 'x', expires_at: null, created_by: 'system' });
    await s.insertBlock({ ip_address: '4.4.4.4', block_reason: 'x', expires_at: minutesAgo(1), created_by: 'system' });
    await s.deactivateBlock('4.4.4.4');
    assert.deepEqual((await s.listExpiredBlocks(NOW)).map((b) => b.ip_address), ['1.1.1.1']);
    await s.close();
  });

  test(`${name}: audit log`, async () => {
    const s = await make();
    await s.insertAudit({ actor: 'admin', action: 'block', target: '1.1.1.1', detail: 'why' });
    await s.insertAudit({ actor: 'system', action: 'unblock', target: '1.1.1.1', detail: 'expired' });
    const rows = await s.listAudit({ limit: 10 });
    assert.deepEqual(rows.map((r) => r.action), ['unblock', 'block']);
    assert.equal((await s.listAudit({ limit: 1 })).length, 1);
    await s.close();
  });

  test(`${name}: stats`, async () => {
    const s = await make();
    await s.insertAlert(alert({ severity: 1, source_ip: '9.9.9.9', timestamp: minutesAgo(10).toISOString() }));
    await s.insertAlert(alert({ severity: 1, source_ip: '9.9.9.9', protocol: 'UDP', timestamp: minutesAgo(5).toISOString() }));
    await s.insertAlert(alert({ severity: 3, timestamp: new Date(NOW.getTime() - 48 * 3600000).toISOString() }));
    await s.insertBlock({ ip_address: '9.9.9.9', block_reason: 'x', expires_at: null, created_by: 'system' });
    const st = await s.getStats(NOW);
    assert.equal(st.totalAlertsOverall, 3);
    assert.equal(st.totalAlerts24h, 2);
    assert.equal(st.activeBlocksCount, 1);
    assert.equal(st.highSeverityThreats, 2);
    assert.deepEqual(st.severityBreakdown, { priority1: 2, priority2: 0, priority3: 1, other: 0 });
    assert.equal(st.topAttackSources[0].source_ip, '9.9.9.9');
    assert.equal(st.topAttackSources[0].alert_count, 2);
    assert.equal(st.topAttackSources[0].is_blocked, true);
    assert.deepEqual(st.protocolDistribution.find((p) => p.protocol === 'TCP'), { protocol: 'TCP', count: 2 });
    assert.equal(st.timeline.reduce((n, t) => n + t.count, 0), 2);
    assert.match(st.timeline[0].time, /^\d{4}-\d{2}-\d{2} \d{2}:00$/);
    await s.close();
  });

  test(`${name}: purgeBefore removes only old rows`, async () => {
    const s = await make();
    const cutoff = minutesAgo(60);
    await s.insertAlert(alert({ timestamp: minutesAgo(120).toISOString() }));
    await s.insertAlert(alert({ timestamp: minutesAgo(10).toISOString() }));
    await s.insertBlock({ ip_address: '5.5.5.5', block_reason: 'x', expires_at: null, created_by: 'system' });
    const result = await s.purgeBefore(cutoff);
    assert.equal(result.alerts, 1);
    assert.equal(result.blocks, 0, 'active blocks are never purged');
    assert.equal((await s.listAlerts({ page: 1, limit: 10 })).total, 1);
    await s.close();
  });
}
