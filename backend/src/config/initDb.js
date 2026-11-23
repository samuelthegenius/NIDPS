const fs = require('fs');
const path = require('path');
const { pool } = require('./db');

async function runInit() {
  const sqlPath = path.join(__dirname, '../../db/init.sql');
  console.log(`[DB INIT] Reading schema from: ${sqlPath}`);
  
  try {
    const sql = fs.readFileSync(sqlPath, 'utf8');
    console.log('[DB INIT] Executing schema script on PostgreSQL...');
    await pool.query(sql);
    console.log('[DB INIT] SUCCESS: Tables (alerts, blocked_ips) and seed data initialized successfully!');
    process.exit(0);
  } catch (err) {
    console.error('[DB INIT ERROR] Failed to initialize database schema:', err.message);
    process.exit(1);
  }
}

runInit();
