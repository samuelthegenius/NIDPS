const { Pool } = require('pg');
require('dotenv').config();

const isProduction = process.env.NODE_ENV === 'production';

// Support full connection string or individual env vars
const poolConfig = process.env.DATABASE_URL
  ? { connectionString: process.env.DATABASE_URL }
  : {
      host: process.env.DB_HOST || 'localhost',
      port: parseInt(process.env.DB_PORT || '5432', 10),
      user: process.env.DB_USER || 'postgres',
      password: process.env.DB_PASSWORD || 'postgres',
      database: process.env.DB_NAME || 'nidps_db',
    };

const pool = new Pool(poolConfig);

let isConnected = false;

// In-memory fallback store if PostgreSQL is temporarily unavailable (Clean slate)
const inMemoryStore = {
  alerts: [],
  blocked_ips: [],
  nextAlertId: 1,
  nextBlockId: 1
};

async function testConnection() {
  try {
    const res = await pool.query('SELECT NOW()');
    isConnected = true;
    console.log(`[DB] PostgreSQL connected successfully at ${res.rows[0].now}`);
    return true;
  } catch (err) {
    isConnected = false;
    console.warn(`[DB WARNING] PostgreSQL connection failed (${err.message}).`);
    console.warn('[DB NOTICE] Operating in in-memory fallback mode for local development. Connect PostgreSQL for persistent production storage.');
    return false;
  }
}

/**
 * Standard query function executing SQL against PostgreSQL if connected,
 * or using simulated in-memory store if DB is offline.
 */
async function query(text, params = []) {
  if (isConnected) {
    try {
      return await pool.query(text, params);
    } catch (err) {
      console.error('[DB ERROR] Query execution error:', err.message);
      throw err;
    }
  }

  // Fallback in-memory handler for development resilience
  return executeInMemory(text, params);
}

function executeInMemory(text, params) {
  const normalized = text.trim();

  // INSERT INTO alerts (timestamp, source_ip, dest_ip, protocol, alert_message, severity, status) VALUES ...
  if (normalized.startsWith('INSERT INTO alerts')) {
    const newAlert = {
      id: inMemoryStore.nextAlertId++,
      timestamp: params[0] || new Date().toISOString(),
      source_ip: params[1],
      dest_ip: params[2],
      protocol: params[3],
      alert_message: params[4],
      severity: parseInt(params[5], 10),
      status: params[6] || 'unresolved'
    };
    inMemoryStore.alerts.unshift(newAlert);
    return { rows: [newAlert], rowCount: 1 };
  }

  // INSERT INTO blocked_ips
  if (normalized.startsWith('INSERT INTO blocked_ips')) {
    const newBlock = {
      id: inMemoryStore.nextBlockId++,
      ip_address: params[0],
      block_reason: params[1],
      timestamp: new Date().toISOString(),
      unblocked_at: null,
      is_active: true
    };
    inMemoryStore.blocked_ips.unshift(newBlock);
    return { rows: [newBlock], rowCount: 1 };
  }

  // UPDATE blocked_ips SET is_active = false, unblocked_at = NOW() WHERE ip_address = $1
  if (normalized.includes('UPDATE blocked_ips SET is_active = false')) {
    const ip = params[0];
    let updated = null;
    for (const b of inMemoryStore.blocked_ips) {
      if ((b.ip_address === ip || b.id === Number(ip)) && b.is_active) {
        b.is_active = false;
        b.unblocked_at = new Date().toISOString();
        updated = b;
      }
    }
    return { rows: updated ? [updated] : [], rowCount: updated ? 1 : 0 };
  }

  // SELECT FROM blocked_ips
  if (normalized.startsWith('SELECT') && normalized.includes('FROM blocked_ips')) {
    let rows = [...inMemoryStore.blocked_ips];
    if (normalized.includes('is_active = true') || normalized.includes('is_active = $1')) {
      rows = rows.filter(b => b.is_active);
    }
    if (normalized.includes('ip_address = $1') && params[0]) {
      rows = rows.filter(b => b.ip_address === params[0]);
    }
    if (normalized.includes('LIMIT 1')) {
      rows = rows.slice(0, 1);
    }
    return { rows, rowCount: rows.length };
  }

  // SELECT FROM alerts
  if (normalized.startsWith('SELECT') && normalized.includes('FROM alerts')) {
    let rows = [...inMemoryStore.alerts];

    if (normalized.includes('COUNT(*)')) {
      let filtered = rows;
      if (params.length > 0 && typeof params[0] === 'number') {
        filtered = filtered.filter(a => a.severity === params[0]);
      }
      return { rows: [{ count: filtered.length }] };
    }

    // Handle severity filter
    if (normalized.includes('severity = $')) {
      const sev = params[0];
      rows = rows.filter(a => a.severity === Number(sev));
    }

    // Pagination
    const limit = params[params.length - 2] || 50;
    const offset = params[params.length - 1] || 0;
    const paginated = rows.slice(offset, offset + limit);

    return { rows: paginated, rowCount: paginated.length };
  }

  return { rows: [], rowCount: 0 };
}

module.exports = {
  pool,
  query,
  testConnection,
  getIsConnected: () => isConnected,
  inMemoryStore
};
