/**
 * NIDPS entry point: loads settings, builds every service, and starts the
 * HTTP(S) server that serves both the API and the dashboard.
 */
const path = require('path');
const fs = require('fs');
const http = require('http');
const https = require('https');
require('dotenv').config({ path: path.join(__dirname, '../.env') });

const { loadSettings } = require('./config/settings');
const { createStore } = require('./store');
const { createAllowlist } = require('./lib/allowlist');
const { createEventBus } = require('./services/events');
const { createFirewall } = require('./services/firewall');
const { createDetector } = require('./services/detector');
const { createLogWatcher } = require('./services/logWatcher');
const { createMaintenance } = require('./jobs/maintenance');
const { createApp } = require('./app');

function lanAddresses() {
  return Object.values(require('os').networkInterfaces())
    .flat()
    .filter((i) => i && i.family === 'IPv4' && !i.internal)
    .map((i) => i.address);
}

async function main() {
  const settings = loadSettings();
  if (!settings.adminPasswordHash || !settings.sessionSecret) {
    console.error('NIDPS is not set up yet: no admin password. Run:  npm run setup');
    process.exit(1);
  }

  console.log('------------------------------------------------------------');
  console.log(' NIDPS - Network Intrusion Detection and Prevention System');
  console.log(` Mode: ${settings.mode} | Firewall: ${settings.realFirewall ? 'LIVE' : 'simulated'} | Demo mode: ${settings.demoMode ? 'on' : 'off'}`);
  console.log('------------------------------------------------------------');

  const store = await createStore(settings);
  const events = createEventBus();
  const allowlist = createAllowlist({ entries: settings.allowlist });
  const firewall = createFirewall({ settings, store, allowlist, events });
  await firewall.init();
  const detector = createDetector({ store, firewall, settings, events });
  const watcher = createLogWatcher({ path: settings.snortLogPath, onLine: (line) => detector.handleLine(line) });
  watcher.start();
  const maintenance = createMaintenance({ firewall, store, settings });
  maintenance.start();

  const app = createApp({ settings, store, firewall, detector, events, watcher, allowlist });
  const useTls = Boolean(settings.tlsCert && settings.tlsKey);
  const server = useTls
    ? https.createServer({ cert: fs.readFileSync(settings.tlsCert), key: fs.readFileSync(settings.tlsKey) }, app)
    : http.createServer(app);

  server.listen(settings.port, settings.host, () => {
    const scheme = useTls ? 'https' : 'http';
    console.log(`[NIDPS] Dashboard: ${scheme}://localhost:${settings.port}`);
    if (settings.host === '0.0.0.0') {
      for (const ip of lanAddresses()) console.log(`[NIDPS] On the LAN:  ${scheme}://${ip}:${settings.port}`);
    }
  });

  const shutdown = () => {
    console.log('\n[NIDPS] Shutting down...');
    maintenance.stop();
    watcher.stop();
    server.closeAllConnections();
    server.close(async () => {
      await store.close();
      process.exit(0);
    });
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

main().catch((err) => {
  console.error('[NIDPS] Failed to start:', err.message);
  process.exit(1);
});
