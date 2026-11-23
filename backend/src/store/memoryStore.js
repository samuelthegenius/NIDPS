/**
 * In-memory store: same contract as the PostgreSQL store, used for development
 * and rehearsals when no database is running. Data is lost on restart.
 */
const { pad, toDate } = require('./util');

function createMemoryStore() {
  const db = { alerts: [], blocks: [], audit: [], ids: { alert: 1, block: 1, audit: 1 } };
  const time = (row) => toDate(row.timestamp).getTime();
  const newestFirst = (a, b) => time(b) - time(a) || b.id - a.id;

  function filterAlerts({ severity, status, search }) {
    const needle = search ? String(search).toLowerCase() : null;
    return db.alerts.filter(
      (a) =>
        (severity == null || a.severity === Number(severity)) &&
        (!status || a.status === status) &&
        (!needle ||
          a.source_ip.toLowerCase().includes(needle) ||
          a.dest_ip.toLowerCase().includes(needle) ||
          a.alert_message.toLowerCase().includes(needle))
    );
  }

  return {
    kind: 'memory',

    async insertAlert(a) {
      const row = { id: db.ids.alert++, ...a, timestamp: toDate(a.timestamp).toISOString(), severity: Number(a.severity) };
      db.alerts.push(row);
      return { ...row };
    },

    async listAlerts({ page = 1, limit = 20, severity = null, status = null, search = null }) {
      const rows = filterAlerts({ severity, status, search }).sort(newestFirst);
      const offset = (page - 1) * limit;
      return { data: rows.slice(offset, offset + limit).map((r) => ({ ...r })), total: rows.length };
    },

    async updateAlertStatus(id, status) {
      const row = db.alerts.find((a) => a.id === Number(id));
      if (!row) return null;
      row.status = status;
      return { ...row };
    },

    async markAlertsBlocked(ip) {
      let n = 0;
      for (const a of db.alerts) {
        if (a.source_ip === ip && a.status === 'unresolved') {
          a.status = 'blocked';
          n++;
        }
      }
      return n;
    },

    async insertBlock({ ip_address, block_reason, expires_at, created_by }) {
      const row = {
        id: db.ids.block++,
        ip_address,
        block_reason,
        timestamp: new Date().toISOString(),
        expires_at: expires_at ? toDate(expires_at).toISOString() : null,
        unblocked_at: null,
        is_active: true,
        created_by: created_by || 'system',
      };
      db.blocks.push(row);
      return { ...row };
    },

    async getActiveBlock(ip) {
      const row = db.blocks.find((b) => b.ip_address === ip && b.is_active);
      return row ? { ...row } : null;
    },

    async listBlocks(activeOnly) {
      return db.blocks
        .filter((b) => !activeOnly || b.is_active)
        .sort(newestFirst)
        .map((b) => ({ ...b }));
    },

    async deactivateBlock(ip) {
      const row = db.blocks.find((b) => b.ip_address === ip && b.is_active);
      if (!row) return null;
      row.is_active = false;
      row.unblocked_at = new Date().toISOString();
      return { ...row };
    },

    async listExpiredBlocks(now) {
      const t = toDate(now).getTime();
      return db.blocks
        .filter((b) => b.is_active && b.expires_at && toDate(b.expires_at).getTime() <= t)
        .map((b) => ({ ...b }));
    },

    async insertAudit({ actor, action, target, detail }) {
      const row = { id: db.ids.audit++, timestamp: new Date().toISOString(), actor, action, target: target || null, detail: detail || null };
      db.audit.push(row);
      return { ...row };
    },

    async listAudit({ limit = 100 } = {}) {
      return [...db.audit].sort(newestFirst).slice(0, limit).map((r) => ({ ...r }));
    },

    async getStats(now = new Date()) {
      const nowMs = toDate(now).getTime();
      const dayAgo = nowMs - 24 * 3600 * 1000;
      const all = db.alerts;
      const recent = all.filter((a) => time(a) >= dayAgo);
      const active = db.blocks.filter((b) => b.is_active);
      const blocked = new Set(active.map((b) => b.ip_address));
      const bySeverity = (n) => all.filter((a) => a.severity === n).length;

      const sources = new Map();
      for (const a of all) {
        const s = sources.get(a.source_ip) || { source_ip: a.source_ip, alert_count: 0, last_seen: a.timestamp };
        s.alert_count++;
        if (time(a) > toDate(s.last_seen).getTime()) s.last_seen = a.timestamp;
        sources.set(a.source_ip, s);
      }

      const count = (rows, key) => {
        const m = new Map();
        for (const r of rows) m.set(key(r), (m.get(key(r)) || 0) + 1);
        return m;
      };
      const hourKey = (a) => {
        const d = toDate(a.timestamp);
        return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:00`;
      };

      return {
        totalAlerts24h: recent.length,
        totalAlertsOverall: all.length,
        activeBlocksCount: active.length,
        highSeverityThreats: bySeverity(1),
        severityBreakdown: {
          priority1: bySeverity(1),
          priority2: bySeverity(2),
          priority3: bySeverity(3),
          other: all.filter((a) => a.severity > 3).length,
        },
        topAttackSources: [...sources.values()]
          .sort((a, b) => b.alert_count - a.alert_count)
          .slice(0, 5)
          .map((s) => ({ ...s, is_blocked: blocked.has(s.source_ip) })),
        protocolDistribution: [...count(all, (a) => a.protocol)]
          .map(([protocol, c]) => ({ protocol, count: c }))
          .sort((a, b) => b.count - a.count),
        timeline: [...count(recent, hourKey)]
          .map(([t, c]) => ({ time: t, count: c }))
          .sort((a, b) => a.time.localeCompare(b.time)),
      };
    },

    async purgeBefore(cutoff) {
      const t = toDate(cutoff).getTime();
      const before = { alerts: db.alerts.length, blocks: db.blocks.length, audit: db.audit.length };
      db.alerts = db.alerts.filter((a) => time(a) >= t);
      db.blocks = db.blocks.filter((b) => b.is_active || !b.unblocked_at || toDate(b.unblocked_at).getTime() >= t);
      db.audit = db.audit.filter((r) => time(r) >= t);
      return {
        alerts: before.alerts - db.alerts.length,
        blocks: before.blocks - db.blocks.length,
        audit: before.audit - db.audit.length,
      };
    },

    async close() {},
  };
}

module.exports = { createMemoryStore };
