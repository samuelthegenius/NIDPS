const express = require('express');
const cors = require('cors');
const morgan = require('morgan');
const path = require('path');
require('dotenv').config();

const { testConnection } = require('./config/db');
const logWatcher = require('./services/logWatcher');

const alertsRoutes = require('./routes/alerts');
const firewallRoutes = require('./routes/firewall');
const statsRoutes = require('./routes/stats');
const simulatorRoutes = require('./routes/simulator');

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(morgan('dev'));

// API Routes
app.use('/api/alerts', alertsRoutes);
app.use('/api', firewallRoutes); // Provides /api/blocked, /api/block, /api/unblock
app.use('/api/stats', statsRoutes);
app.use('/api/simulator', simulatorRoutes);

// System Health & Diagnostics
app.get('/api/health', (req, res) => {
  res.json({
    status: 'online',
    timestamp: new Date().toISOString(),
    system: 'Network Intrusion Prevention System (NIPS)',
    version: '1.0.0'
  });
});

// Root informational endpoint
app.get('/', (req, res) => {
  res.json({
    name: 'NIPS Control Server API',
    endpoints: {
      alerts: '/api/alerts',
      blocked: '/api/blocked',
      block: 'POST /api/block',
      unblock: 'POST /api/unblock',
      stats: '/api/stats',
      simulator: '/api/simulator'
    }
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('[SERVER UNHANDLED ERROR]', err);
  res.status(500).json({ error: 'Internal Server Error', message: err.message });
});

// Initialize server and background services
async function startServer() {
  console.log('----------------------------------------------------');
  console.log('   Starting NIPS Control Server & Prevention Engine  ');
  console.log('----------------------------------------------------');

  // Test PostgreSQL connection
  await testConnection();

  // Start Snort Log Watcher
  const logFile = process.env.SNORT_LOG_PATH || path.join(__dirname, '../mock_snort.log');
  logWatcher.startWatching(logFile);

  const server = app.listen(PORT, () => {
    console.log(`[NIPS SERVER] Server running on http://localhost:${PORT}`);
    console.log(`[NIPS SERVER] Snort Log Watcher active on: ${logFile}`);
  });

  // Graceful shutdown
  const handleShutdown = () => {
    console.log('\n[NIPS SERVER] Shutting down gracefully...');
    logWatcher.stopWatching();
    server.close(() => {
      console.log('[NIPS SERVER] HTTP server closed.');
      process.exit(0);
    });
  };

  process.on('SIGINT', handleShutdown);
  process.on('SIGTERM', handleShutdown);
}

startServer();
