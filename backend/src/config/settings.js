/**
 * Central configuration. Every setting NIDPS reads from the environment is
 * parsed and validated here, once, so the rest of the code never touches process.env.
 */
const path = require('path');

const BACKEND_DIR = path.join(__dirname, '../..');

function bool(value, fallback = false) {
  if (value === undefined || value === '') return fallback;
  return String(value).trim().toLowerCase() === 'true';
}

function number(env, name, fallback) {
  const raw = env[name];
  if (raw === undefined || raw === '') return fallback;
  const value = Number(raw);
  if (!Number.isFinite(value) || value < 0) {
    throw new Error(`${name} must be a non-negative number (got "${raw}")`);
  }
  return value;
}

function list(value) {
  return String(value || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

function loadSettings(env = process.env) {
  const mode = String(env.NIDPS_MODE || 'host').trim().toLowerCase();
  if (!['host', 'gateway'].includes(mode)) {
    throw new Error(`NIDPS_MODE must be "host" or "gateway" (got "${env.NIDPS_MODE}")`);
  }

  return Object.freeze({
    port: number(env, 'PORT', 5000),
    host: env.HOST || '0.0.0.0',
    mode,
    demoMode: bool(env.DEMO_MODE),
    realFirewall: bool(env.ENABLE_REAL_IPTABLES),
    wslDistro: env.WSL_DISTRO || 'Ubuntu-24.04',
    // Relative paths are relative to backend/, whatever directory NIDPS is started from.
    snortLogPath: path.resolve(BACKEND_DIR, env.SNORT_LOG_PATH || 'mock_snort.log'),
    snortInterface: env.SNORT_INTERFACE || 'eth0',
    allowlist: list(env.NIDPS_ALLOWLIST),
    blockDurationMin: number(env, 'BLOCK_DURATION_MIN', 60),
    escalateCount: number(env, 'ESCALATE_COUNT', 5),
    escalateWindowMin: number(env, 'ESCALATE_WINDOW_MIN', 5),
    retentionDays: number(env, 'RETENTION_DAYS', 30),
    adminUsername: env.ADMIN_USERNAME || 'admin',
    adminPasswordHash: env.ADMIN_PASSWORD_HASH || '',
    sessionSecret: env.SESSION_SECRET || '',
    tlsCert: env.TLS_CERT || '',
    tlsKey: env.TLS_KEY || '',
    db: Object.freeze(
      env.DATABASE_URL
        ? { connectionString: env.DATABASE_URL }
        : {
            host: env.DB_HOST || 'localhost',
            port: number(env, 'DB_PORT', 5432),
            user: env.DB_USER || 'postgres',
            password: env.DB_PASSWORD || '',
            database: env.DB_NAME || 'nidps_db',
          }
    ),
  });
}

module.exports = { loadSettings };
