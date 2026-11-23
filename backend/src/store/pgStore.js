/**
 * PostgreSQL store. Every query is parameterised ($1, $2 ...), never string-built
 * from user input. The schema in db/init.sql is applied on connect.
 */
const fs = require('fs');
const path = require('path');
const { Pool } = require('pg');

const SCHEMA_PATH = path.join(__dirname, '../../db/init.sql');
const int = (v) => parseInt(v, 10);

async function createPgStore(dbConfig) {
  const pool = new Pool({ ...dbConfig, connectionTimeoutMillis: 3000, max: 10 });
  pool.on('error', (err) => console.error('[DB] Idle client error:', err.message));
  await pool.query(fs.readFileSync(SCHEMA_PATH, 'utf8'));
  const q = (text, params) => pool.query(text, params);
  const one = async (text, params) => (await q(text, params)).rows[0] || null;

  function alertWhere({ severity, status, search }) {
    const conditions = [];
    const params = [];
    if (severity != null) {
      params.push(Number(severity));
      conditions.push(`severity = $${params.length}`);
    }
    if (status) {
      params.push(status);
      conditions.push(`status = $${params.length}`);
    }
    if (search) {
      params.push(`%${search}%`);
      conditions.push(`(source_ip ILIKE $${params.length} OR dest_ip ILIKE $${params.length} OR alert_message ILIKE $${params.length})`);
    }
    return { where: conditions.length ? `WHERE ${conditions.join(' AND ')}` : '', params };
  }

  return {
    kind: 'postgres',
    pool,

    insertAlert: (a) =>
      one(
        `INSERT INTO alerts (timestamp, source_ip, dest_ip, protocol, alert_message, severity, status)
         VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
        [a.timestamp, a.source_ip, a.dest_ip, a.protocol, a.alert_message, a.severity, a.status]
      ),

    async listAlerts({ page = 1, limit = 20, severity = null, status = null, search = null }) {
      const { where, params } = alertWhere({ severity, status, search });
      const total = int((await one(`SELECT COUNT(*) AS total FROM alerts ${where}`, params)).total);
      const n = params.length;
      const data = (
        await q(`SELECT * FROM alerts ${where} ORDER BY timestamp DESC, id DESC LIMIT $${n + 1} OFFSET $${n + 2}`, [
          ...params,
          limit,
          (page - 1) * limit,
        ])
      ).rows;
      return { data, total };
    },

    updateAlertStatus: (id, status) => one('UPDATE alerts SET status = $2 WHERE id = $1 RETURNING *', [id, status]),

    async markAlertsBlocked(ip) {
      return (await q(`UPDATE alerts SET status = 'blocked' WHERE source_ip = $1 AND status = 'unresolved'`, [ip])).rowCount;
    },

    insertBlock: ({ ip_address, block_reason, expires_at, created_by }) =>
      one(
        `INSERT INTO blocked_ips (ip_address, block_reason, expires_at, created_by, is_active)
         VALUES ($1, $2, $3, $4, true) RETURNING *`,
        [ip_address, block_reason, expires_at, created_by || 'system']
      ),

    getActiveBlock: (ip) => one('SELECT * FROM blocked_ips WHERE ip_address = $1 AND is_active = true LIMIT 1', [ip]),

    async listBlocks(activeOnly) {
      const where = activeOnly ? 'WHERE is_active = true' : '';
      return (await q(`SELECT * FROM blocked_ips ${where} ORDER BY timestamp DESC, id DESC`)).rows;
    },

    deactivateBlock: (ip) =>
      one(
        `UPDATE blocked_ips SET is_active = false, unblocked_at = NOW()
         WHERE ip_address = $1 AND is_active = true RETURNING *`,
        [ip]
      ),

    async listExpiredBlocks(now) {
      return (await q('SELECT * FROM blocked_ips WHERE is_active = true AND expires_at IS NOT NULL AND expires_at <= $1', [now])).rows;
    },

    insertAudit: ({ actor, action, target, detail }) =>
      one('INSERT INTO audit_log (actor, action, target, detail) VALUES ($1, $2, $3, $4) RETURNING *', [actor, action, target || null, detail || null]),

    async listAudit({ limit = 100 } = {}) {
      return (await q('SELECT * FROM audit_log ORDER BY timestamp DESC, id DESC LIMIT $1', [limit])).rows;
    },

    async getStats(now = new Date()) {
      const since = new Date(now.getTime() - 24 * 3600 * 1000);
      const [totals, severities, sources, protocols, timeline] = await Promise.all([
        one(
          `SELECT
             (SELECT COUNT(*) FROM alerts) AS overall,
             (SELECT COUNT(*) FROM alerts WHERE timestamp >= $1) AS day,
             (SELECT COUNT(*) FROM blocked_ips WHERE is_active = true) AS blocks`,
          [since]
        ),
        q('SELECT severity, COUNT(*) AS n FROM alerts GROUP BY severity'),
        q(`SELECT a.source_ip, COUNT(*) AS alert_count, MAX(a.timestamp) AS last_seen,
                  EXISTS (SELECT 1 FROM blocked_ips b WHERE b.ip_address = a.source_ip AND b.is_active = true) AS is_blocked
           FROM alerts a GROUP BY a.source_ip ORDER BY alert_count DESC LIMIT 5`),
        q('SELECT protocol, COUNT(*) AS n FROM alerts GROUP BY protocol ORDER BY n DESC'),
        q(
          `SELECT TO_CHAR(DATE_TRUNC('hour', timestamp), 'YYYY-MM-DD HH24:00') AS bucket, COUNT(*) AS n
           FROM alerts WHERE timestamp >= $1 GROUP BY bucket ORDER BY bucket`,
          [since]
        ),
      ]);

      const breakdown = { priority1: 0, priority2: 0, priority3: 0, other: 0 };
      for (const r of severities.rows) {
        const key = r.severity <= 3 ? `priority${r.severity}` : 'other';
        breakdown[key] += int(r.n);
      }

      return {
        totalAlerts24h: int(totals.day),
        totalAlertsOverall: int(totals.overall),
        activeBlocksCount: int(totals.blocks),
        highSeverityThreats: breakdown.priority1,
        severityBreakdown: breakdown,
        topAttackSources: sources.rows.map((r) => ({
          source_ip: r.source_ip,
          alert_count: int(r.alert_count),
          last_seen: r.last_seen,
          is_blocked: Boolean(r.is_blocked),
        })),
        protocolDistribution: protocols.rows.map((r) => ({ protocol: r.protocol, count: int(r.n) })),
        timeline: timeline.rows.map((r) => ({ time: r.bucket, count: int(r.n) })),
      };
    },

    async purgeBefore(cutoff) {
      const alerts = (await q('DELETE FROM alerts WHERE timestamp < $1', [cutoff])).rowCount;
      const blocks = (await q('DELETE FROM blocked_ips WHERE is_active = false AND unblocked_at < $1', [cutoff])).rowCount;
      const audit = (await q('DELETE FROM audit_log WHERE timestamp < $1', [cutoff])).rowCount;
      return { alerts, blocks, audit };
    },

    close: () => pool.end(),
  };
}

module.exports = { createPgStore };
