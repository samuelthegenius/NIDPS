/**
 * Follows the Snort fast-alert file (like `tail -F`) and hands each new line to
 * onLine. Polling (watchFile) is used because it works on WSL/UNC paths, Docker
 * mounts and log rotation, where native file events are unreliable.
 */
const fs = require('fs');
const path = require('path');
const { Tail } = require('tail');

function createLogWatcher({ path: filePath, onLine, pollMs = 500 }) {
  const resolved = path.resolve(filePath);
  let tail = null;
  let retryTimer = null;

  function ensureFile() {
    fs.mkdirSync(path.dirname(resolved), { recursive: true });
    if (!fs.existsSync(resolved)) fs.writeFileSync(resolved, '', 'utf8');
  }

  function scheduleRestart() {
    if (retryTimer) return;
    stop();
    console.warn('[LOG WATCHER] Restarting in 3 seconds...');
    retryTimer = setTimeout(() => {
      retryTimer = null;
      start();
    }, 3000);
  }

  function start() {
    if (tail) return;
    try {
      ensureFile();
      tail = new Tail(resolved, {
        separator: /\r?\n/,
        fromBeginning: false,
        follow: true,
        useWatchFile: true,
        fsWatchOptions: { interval: pollMs },
      });
      tail.on('line', (line) => {
        if (line && line.trim()) Promise.resolve(onLine(line)).catch((err) => console.error('[LOG WATCHER] Line handler failed:', err.message));
      });
      tail.on('error', (err) => {
        console.error(`[LOG WATCHER] ${err.message || err}`);
        scheduleRestart();
      });
      console.log(`[LOG WATCHER] Following ${resolved}`);
    } catch (err) {
      console.error(`[LOG WATCHER] Could not watch ${resolved}: ${err.message}`);
      tail = null;
      scheduleRestart();
    }
  }

  function stop() {
    if (!tail) return;
    try {
      tail.unwatch();
    } catch {
      // already stopped
    }
    tail = null;
  }

  return {
    start,
    stop() {
      clearTimeout(retryTimer);
      retryTimer = null;
      stop();
    },
    status: () => ({ active: Boolean(tail), path: resolved }),
  };
}

module.exports = { createLogWatcher };
