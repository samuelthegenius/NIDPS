/**
 * `npm run reset` - return NIDPS to a clean state before a demo:
 *   - empties the PostgreSQL tables (alerts, blocked_ips, audit_log)
 *   - empties the Snort alert log that NIDPS watches
 *   - flushes ONLY the NIDPS iptables chain (other firewall rules are untouched)
 * Stop NIDPS first: a running in-memory store is not affected by this script.
 */
const fs = require('fs');
const path = require('path');
const { execFile } = require('child_process');
const { promisify } = require('util');
require('dotenv').config({ path: path.join(__dirname, '../.env') });
const { loadSettings } = require('../src/config/settings');
const { createPgStore } = require('../src/store/pgStore');
const { buildCommands } = require('../src/services/firewall/commands');

const run = promisify(execFile);

async function main() {
  const settings = loadSettings();
  console.log('Resetting NIDPS...');

  try {
    const store = await createPgStore(settings.db);
    await store.pool.query('TRUNCATE alerts, blocked_ips, audit_log RESTART IDENTITY');
    await store.close();
    console.log('  - PostgreSQL: alerts, blocked_ips and audit_log emptied');
  } catch (err) {
    console.log(`  - PostgreSQL not reachable (${err.message}); nothing to empty`);
  }

  const logPath = settings.snortLogPath;
  try {
    fs.writeFileSync(logPath, '', 'utf8');
    console.log(`  - Emptied Snort alert log: ${logPath}`);
  } catch (err) {
    console.log(`  - Could not empty ${logPath}: ${err.message}`);
  }

  if (settings.realFirewall) {
    const isRoot = typeof process.getuid === 'function' && process.getuid() === 0;
    const commands = buildCommands({ mode: settings.mode, wslDistro: settings.wslDistro, isRoot });
    for (const family of ['ipv4', 'ipv6']) {
      const argv = commands.flush(family);
      try {
        await run(argv[0], argv.slice(1), { timeout: 15000, windowsHide: true });
        console.log(`  - Flushed ${family} NIDPS chain`);
      } catch (err) {
        console.log(`  - ${family} NIDPS chain not flushed (${(err.stderr || err.message).trim()})`);
      }
    }
  } else {
    console.log('  - Firewall is simulated (ENABLE_REAL_IPTABLES=false); no rules to flush');
  }
  console.log('Done.');
}

main().catch((err) => {
  console.error('Reset failed:', err.message);
  process.exitCode = 1;
});
