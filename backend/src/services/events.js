/**
 * Tiny in-process event bus. The detector and firewall publish "alert", "block"
 * and "unblock" events; the /api/events route streams them to dashboards (SSE).
 */
function createEventBus() {
  const listeners = new Set();
  return {
    publish(type, payload) {
      for (const fn of listeners) {
        try {
          fn(type, payload);
        } catch (err) {
          console.error('[EVENTS] Listener failed:', err.message);
        }
      }
    },
    subscribe(fn) {
      listeners.add(fn);
      return () => listeners.delete(fn);
    },
  };
}

module.exports = { createEventBus };
