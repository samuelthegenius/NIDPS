const express = require('express');
const router = express.Router();
const fs = require('fs');
const path = require('path');
const logWatcher = require('../services/logWatcher');
const { getIsConnected } = require('../config/db');

// Preset attacks for quick UI testing
const PRESETS = {
  log4j: {
    message: 'ET EXPLOIT Apache Log4j RCE Attempt (CVE-2021-44228)',
    priority: 1,
    protocol: 'TCP',
    class: 'Attempted Administrator Privilege Gain',
    sourceIp: '185.220.101.5',
    destIp: '10.0.0.80',
    destPort: 8080
  },
  ssh_brute: {
    message: 'ET SCAN Potential SSH Brute Force Login Attempt',
    priority: 2,
    protocol: 'TCP',
    class: 'Attempted Login',
    sourceIp: '192.168.1.50',
    destIp: '10.0.0.5',
    destPort: 22
  },
  sqli: {
    message: 'ET WEB_SERVER Possible SQL Injection Attempt UNION SELECT',
    priority: 1,
    protocol: 'TCP',
    class: 'Web Application Attack',
    sourceIp: '45.146.165.37',
    destIp: '10.0.0.80',
    destPort: 443
  },
  nmap: {
    message: 'ET SCAN Nmap Scripting Engine User-Agent Detected',
    priority: 3,
    protocol: 'TCP',
    class: 'Information Leak',
    sourceIp: '194.26.29.112',
    destIp: '10.0.0.1',
    destPort: 80
  },
  dns_amp: {
    message: 'ET DOS DNS Amplification Reflection Attack Detected',
    priority: 2,
    protocol: 'UDP',
    class: 'Denial of Service',
    sourceIp: '198.51.100.77',
    destIp: '10.0.0.53',
    destPort: 53
  }
};

// POST /api/simulator/inject
router.post('/inject', async (req, res) => {
  try {
    const { rawLine, presetKey, customSourceIp, customSeverity } = req.body;
    const logPath = logWatcher.filePath || path.resolve(process.env.SNORT_LOG_PATH || './mock_snort.log');

    let lineToWrite = '';

    if (rawLine) {
      lineToWrite = rawLine.trim();
    } else if (presetKey && PRESETS[presetKey]) {
      const p = PRESETS[presetKey];
      const srcIp = customSourceIp || p.sourceIp;
      const sev = customSeverity || p.priority;
      const srcPort = Math.floor(Math.random() * 50000) + 1024;
      
      // Standard Snort Fast Alert Format:
      // [**] [1:1000001:1] Alert Message [**] [Classification: Class] [Priority: P] {TCP} 1.2.3.4:1234 -> 5.6.7.8:80
      lineToWrite = `[**] [1:${Math.floor(Math.random() * 899999) + 100000}:1] ${p.message} [**] [Classification: ${p.class}] [Priority: ${sev}] {${p.protocol}} ${srcIp}:${srcPort} -> ${p.destIp}:${p.destPort}`;
    } else {
      // Default sample alert
      const randomIp = `198.51.${Math.floor(Math.random() * 200)}.${Math.floor(Math.random() * 250) + 1}`;
      lineToWrite = `[**] [1:2001219:1] SSH Brute Force [**] [Classification: Attempted Login] [Priority: 2] {TCP} ${randomIp}:54321 -> 10.0.0.5:22`;
    }

    // Append line to mock_snort.log
    fs.appendFileSync(logPath, lineToWrite + '\n', 'utf8');

    res.json({
      success: true,
      injectedLine: lineToWrite,
      logPath,
      message: 'Snort alert line written to log file. Watcher will parse and process it shortly.'
    });
  } catch (err) {
    console.error('[SIMULATOR INJECT ERROR]', err);
    res.status(500).json({ error: 'Failed to inject log line', details: err.message });
  }
});

// GET /api/simulator/presets
router.get('/presets', (req, res) => {
  res.json({ presets: PRESETS });
});

// GET /api/simulator/status
router.get('/status', (req, res) => {
  res.json({
    databaseConnected: getIsConnected(),
    logWatcherActive: Boolean(logWatcher.watcher || logWatcher.pollInterval),
    logFilePath: logWatcher.filePath,
    mockFirewallEnabled: process.env.ENABLE_REAL_IPTABLES !== 'true'
  });
});

module.exports = router;
