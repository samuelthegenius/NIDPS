/**
 * Chooses the data store: PostgreSQL when reachable, otherwise the in-memory
 * store so the dashboard still works for development and rehearsals.
 */
const { createPgStore } = require('./pgStore');
const { createMemoryStore } = require('./memoryStore');

async function createStore(settings) {
  try {
    const store = await createPgStore(settings.db);
    console.log('[DB] Connected to PostgreSQL; schema is up to date.');
    return store;
  } catch (err) {
    console.warn(`[DB] PostgreSQL unavailable (${err.message}).`);
    console.warn('[DB] Using the in-memory store: data will be lost when NIDPS stops.');
    return createMemoryStore();
  }
}

module.exports = { createStore };
