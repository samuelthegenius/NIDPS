/**
 * Background housekeeping:
 *  - every 30 s: lift blocks whose time is up (BLOCK_DURATION_MIN)
 *  - at start and every 24 h: delete alerts, closed blocks and audit entries older
 *    than RETENTION_DAYS (privacy: student IP addresses are not kept forever)
 */
const SWEEP_MS = 30 * 1000;
const PURGE_MS = 24 * 3600 * 1000;

function createMaintenance({ firewall, store, settings, now = () => new Date() }) {
  const timers = [];

  async function sweep() {
    const n = await firewall.sweepExpired();
    if (n) console.log(`[MAINTENANCE] Lifted ${n} expired block(s).`);
  }

  async function purge() {
    if (!(settings.retentionDays > 0)) return;
    const cutoff = new Date(now().getTime() - settings.retentionDays * 24 * 3600 * 1000);
    const r = await store.purgeBefore(cutoff);
    if (r && (r.alerts || r.blocks || r.audit)) {
      console.log(`[MAINTENANCE] Retention: removed ${r.alerts} alert(s), ${r.blocks} block record(s), ${r.audit} audit entr(ies).`);
    }
  }

  const safe = (fn) => () => fn().catch((err) => console.error('[MAINTENANCE]', err.message));

  return {
    sweep,
    purge,
    start() {
      safe(purge)();
      timers.push(setInterval(safe(sweep), SWEEP_MS), setInterval(safe(purge), PURGE_MS));
    },
    stop() {
      timers.splice(0).forEach(clearInterval);
    },
  };
}

module.exports = { createMaintenance };
