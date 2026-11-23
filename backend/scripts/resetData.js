/**
 * NIPS Reset Utility
 * Cleans the database, resets Snort logs, and flushes active firewall rules.
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const { pool, testConnection, inMemoryStore, getIsConnected } = require('../src/config/db');

async function resetAll() {
  console.log('==================================================');
  console.log('   Resetting NIPS Engine to Pure Zero State       ');
  console.log('==================================================');

  // 1. Reset Database
  const isPostgresUp = await testConnection();
  if (isPostgresUp) {
    console.log('[RESET] Truncating PostgreSQL tables: alerts & blocked_ips...');
    await pool.query('TRUNCATE TABLE alerts RESTART IDENTITY CASCADE;');
    await pool.query('TRUNCATE TABLE blocked_ips RESTART IDENTITY CASCADE;');
    console.log('[RESET] PostgreSQL tables cleared.');
  } else {
    console.log('[RESET] In-memory store reset to empty arrays.');
    inMemoryStore.alerts = [];
    inMemoryStore.blocked_ips = [];
    inMemoryStore.nextAlertId = 1;
    inMemoryStore.nextBlockId = 1;
  }

  // 2. Truncate local mock_snort.log
  const localLogPath = path.resolve(__dirname, '../mock_snort.log');
  if (fs.existsSync(localLogPath)) {
    fs.writeFileSync(localLogPath, '', 'utf8');
    console.log(`[RESET] Cleared local log file: ${localLogPath}`);
  }

  // 3. Truncate Snort alert log in WSL and flush iptables
  try {
    console.log('[RESET] Truncating WSL Snort log (/var/log/snort/snort.alert.fast)...');
    execSync('wsl -d Ubuntu-24.04 -u root bash -c "> /var/log/snort/snort.alert.fast"', { stdio: 'pipe' });
    console.log('[RESET] WSL Snort log cleared.');

    console.log('[RESET] Flushing active iptables rules in WSL (iptables -F INPUT)...');
    execSync('wsl -d Ubuntu-24.04 -u root iptables -F INPUT', { stdio: 'pipe' });
    console.log('[RESET] Firewall rules flushed.');
  } catch (wslErr) {
    console.warn(`[RESET NOTICE] WSL reset skipped or not running: ${wslErr.message}`);
  }

  console.log('==================================================');
  console.log(' SUCCESS: NIPS is completely clean (0 alerts, 0 blocks).');
  console.log('==================================================');
  process.exit(0);
}

resetAll().catch((err) => {
  console.error('[RESET ERROR]', err);
  process.exit(1);
});
