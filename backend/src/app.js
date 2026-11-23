/**
 * Builds the Express application from already-constructed services (dependency
 * injection), so tests can run it with an in-memory store and a fake firewall.
 */
const fs = require('fs');
const path = require('path');
const express = require('express');
const morgan = require('morgan');
const { securityHeaders, sameOriginGuard } = require('./security/headers');
const { requireAuth } = require('./auth/middleware');
const authRoutes = require('./routes/auth');
const apiRoutes = require('./routes/api');
const eventsRoute = require('./routes/events');
const simulatorRoutes = require('./routes/simulator');
const { version } = require('../package.json');

const FRONTEND_DIST = path.join(__dirname, '../../frontend/dist');

function createApp(deps) {
  const { settings } = deps;
  const app = express();
  app.disable('x-powered-by');

  app.use(securityHeaders);
  if (process.env.NODE_ENV !== 'test') app.use(morgan('tiny', { skip: (req) => req.path === '/api/events' }));
  app.use(express.json({ limit: '10kb' }));

  app.get('/api/health', (req, res) => res.json({ status: 'online', system: 'NIDPS', version, timestamp: new Date().toISOString() }));

  app.use('/api', sameOriginGuard);
  app.use('/api/auth', authRoutes(deps));

  const auth = requireAuth(settings.sessionSecret);
  app.get('/api/events', auth, eventsRoute(deps));
  if (settings.demoMode) app.use('/api/simulator', auth, simulatorRoutes(deps));
  app.use('/api', auth, apiRoutes(deps));

  app.use('/api', (req, res) => res.status(404).json({ error: 'Endpoint not found' }));

  // Serve the built dashboard (frontend/dist) on the same port as the API.
  if (fs.existsSync(path.join(FRONTEND_DIST, 'index.html'))) {
    app.use(express.static(FRONTEND_DIST, { index: false, maxAge: '1h' }));
    app.get(/^(?!\/api\/).*/, (req, res) => res.sendFile(path.join(FRONTEND_DIST, 'index.html')));
  } else {
    app.get('/', (req, res) => res.type('text').send('NIDPS API is running. Build the dashboard with: cd frontend && npm run build'));
  }

  // Malformed JSON bodies -> 400; anything else -> generic 500 (details stay in the server log).
  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    if (err.type === 'entity.parse.failed' || err.type === 'entity.too.large') {
      return res.status(400).json({ error: 'Malformed request body' });
    }
    console.error('[SERVER ERROR]', err);
    return res.status(500).json({ error: 'Internal server error' });
  });

  return app;
}

module.exports = { createApp };
