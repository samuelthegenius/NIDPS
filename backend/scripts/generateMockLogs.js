/**
 * Snort Alert Generator Script
 * Appends simulated intrusion alerts to mock_snort.log for real-time testing
 * Usage: node scripts/generateMockLogs.js [--continuous] [--interval=3000]
 */

const fs = require('fs');
const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '../.env') });

const logFilePath = path.resolve(process.env.SNORT_LOG_PATH || path.join(__dirname, '../mock_snort.log'));

const SAMPLE_ATTACKS = [
  {
    msg: 'ET EXPLOIT Apache Log4j RCE Attempt (CVE-2021-44228)',
    classification: 'Attempted Administrator Privilege Gain',
    priority: 1,
    proto: 'TCP',
    destPort: 8080,
    destIp: '10.0.0.5',
    srcIps: ['185.220.101.5', '194.26.29.112', '91.240.118.172']
  },
  {
    msg: 'ET WEB_SERVER Possible SQL Injection Attempt UNION SELECT',
    classification: 'Web Application Attack',
    priority: 1,
    proto: 'TCP',
    destPort: 443,
    destIp: '10.0.0.80',
    srcIps: ['45.146.165.37', '185.191.171.12', '103.251.167.20']
  },
  {
    msg: 'ET SCAN Potential SSH Brute Force Login Attempt',
    classification: 'Attempted Login',
    priority: 2,
    proto: 'TCP',
    destPort: 22,
    destIp: '10.0.0.10',
    srcIps: ['192.168.1.50', '212.102.40.89', '185.244.25.18']
  },
  {
    msg: 'ET DOS DNS Amplification Reflection Attack Detected',
    classification: 'Denial of Service',
    priority: 2,
    proto: 'UDP',
    destPort: 53,
    destIp: '10.0.0.53',
    srcIps: ['198.51.100.77', '203.0.113.14']
  },
  {
    msg: 'ET SCAN Nmap Scripting Engine User-Agent Detected',
    classification: 'Information Leak',
    priority: 3,
    proto: 'TCP',
    destPort: 80,
    destIp: '10.0.0.1',
    srcIps: ['192.0.2.77', '198.51.100.99']
  },
  {
    msg: 'GPL ICMP Large ICMP Packet Ping of Death Candidate',
    classification: 'Potentially Bad Traffic',
    priority: 3,
    proto: 'ICMP',
    destPort: 0,
    destIp: '10.0.0.1',
    srcIps: ['192.168.1.200', '198.51.100.12']
  }
];

function generateAlertLine() {
  const attack = SAMPLE_ATTACKS[Math.floor(Math.random() * SAMPLE_ATTACKS.length)];
  const srcIp = attack.srcIps[Math.floor(Math.random() * attack.srcIps.length)];
  const srcPort = attack.proto === 'ICMP' ? '' : `:${Math.floor(Math.random() * 55000) + 1024}`;
  const destPort = attack.proto === 'ICMP' ? '' : `:${attack.destPort}`;
  const sid = Math.floor(Math.random() * 899999) + 2000000;

  // Snort fast format:
  // [**] [1:2001219:1] SSH Brute Force [**] [Classification: Attempted Login] [Priority: 2] {TCP} 192.168.1.50:54321 -> 10.0.0.5:22
  return `[**] [1:${sid}:1] ${attack.msg} [**] [Classification: ${attack.classification}] [Priority: ${attack.priority}] {${attack.proto}} ${srcIp}${srcPort} -> ${attack.destIp}${destPort}`;
}

function appendAlert() {
  const line = generateAlertLine();
  fs.appendFileSync(logFilePath, line + '\n', 'utf8');
  console.log(`[SIMULATOR] Appended: ${line}`);
}

const args = process.argv.slice(2);
const continuous = args.includes('--continuous');
const intervalArg = args.find(a => a.startsWith('--interval='));
const intervalMs = intervalArg ? parseInt(intervalArg.split('=')[1], 10) : 4000;

console.log(`[MOCK SNORT LOG GENERATOR] Target log file: ${logFilePath}`);

if (continuous) {
  console.log(`[SIMULATOR] Running in continuous mode (new alert every ${intervalMs / 1000}s). Press Ctrl+C to stop.`);
  appendAlert();
  setInterval(appendAlert, intervalMs);
} else {
  console.log('[SIMULATOR] Generating batch of 3 alerts...');
  for (let i = 0; i < 3; i++) {
    appendAlert();
  }
  console.log('[SIMULATOR] Done! Watch the NIPS backend or dashboard for updates.');
}
