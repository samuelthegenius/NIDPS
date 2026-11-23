/**
 * Attack simulator (DEMO_MODE only). Appends a Snort-format line to the watched
 * alert file, so a simulated attack travels the exact same path as a real one:
 * file -> log watcher -> detector -> firewall -> dashboard.
 */
const express = require('express');
const fs = require('fs');
const { parseSnortAlert } = require('../services/snortParser');
const { isValidIp } = require('../lib/ip');

// Source addresses come from the documentation ranges (RFC 5737), which are never real hosts.
const PRESETS = {
  log4j: { message: 'ET EXPLOIT Apache Log4j RCE Attempt (CVE-2021-44228)', priority: 1, protocol: 'TCP', class: 'Attempted Administrator Privilege Gain', sourceIp: '203.0.113.5', destIp: '10.0.0.80', destPort: 8080 },
  sqli: { message: 'ET WEB_SERVER Possible SQL Injection Attempt UNION SELECT', priority: 1, protocol: 'TCP', class: 'Web Application Attack', sourceIp: '198.51.100.37', destIp: '10.0.0.80', destPort: 443 },
  ssh_brute: { message: 'ET SCAN Potential SSH Brute Force Login Attempt', priority: 2, protocol: 'TCP', class: 'Attempted Login', sourceIp: '192.0.2.50', destIp: '10.0.0.5', destPort: 22 },
  dns_amp: { message: 'ET DOS DNS Amplification Reflection Attack Detected', priority: 2, protocol: 'UDP', class: 'Denial of Service', sourceIp: '198.51.100.77', destIp: '10.0.0.53', destPort: 53 },
  nmap: { message: 'ET SCAN Nmap Scripting Engine User-Agent Detected', priority: 3, protocol: 'TCP', class: 'Information Leak', sourceIp: '203.0.113.112', destIp: '10.0.0.1', destPort: 80 },
};

function presetLine(p, sourceIp, severity) {
  const sid = Math.floor(Math.random() * 899999) + 100000;
  const srcPort = Math.floor(Math.random() * 50000) + 1024;
  return `[**] [1:${sid}:1] ${p.message} [**] [Classification: ${p.class}] [Priority: ${severity}] {${p.protocol}} ${sourceIp}:${srcPort} -> ${p.destIp}:${p.destPort}`;
}

module.exports = function simulatorRoutes({ watcher }) {
  const router = express.Router();

  router.get('/presets', (req, res) => res.json({ presets: PRESETS }));

  router.post('/inject', (req, res, next) => {
    try {
      const { rawLine, presetKey, customSourceIp, customSeverity } = req.body || {};
      let line;
      if (typeof rawLine === 'string' && rawLine.trim()) {
        line = rawLine.trim().replace(/[\r\n]+/g, ' ');
      } else if (PRESETS[presetKey]) {
        const p = PRESETS[presetKey];
        if (customSourceIp && !isValidIp(customSourceIp)) return res.status(400).json({ error: 'Invalid source IP' });
        const severity = [1, 2, 3, 4].includes(Number(customSeverity)) ? Number(customSeverity) : p.priority;
        line = presetLine(p, customSourceIp ? customSourceIp.trim() : p.sourceIp, severity);
      } else {
        return res.status(400).json({ error: 'Provide a known presetKey or a rawLine' });
      }
      if (line.length > 1000 || !parseSnortAlert(line)) {
        return res.status(400).json({ error: 'Not a valid Snort fast-alert line' });
      }
      fs.appendFileSync(watcher.status().path, `${line}\n`, 'utf8');
      return res.json({ success: true, injectedLine: line });
    } catch (err) {
      return next(err);
    }
  });

  return router;
};
