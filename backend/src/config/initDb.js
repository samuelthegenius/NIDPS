/**
 * `npm run db:init` - applies db/init.sql to the configured PostgreSQL database.
 * (The server also does this automatically on start-up.)
 */
require('dotenv').config({ path: require('path').join(__dirname, '../../.env') });
const { loadSettings } = require('./settings');
const { createPgStore } = require('../store/pgStore');

createPgStore(loadSettings().db)
  .then(async (store) => {
    console.log('[DB INIT] Schema applied: alerts, blocked_ips, audit_log.');
    await store.close();
  })
  .catch((err) => {
    console.error('[DB INIT] Failed:', err.message);
    process.exitCode = 1;
  });
