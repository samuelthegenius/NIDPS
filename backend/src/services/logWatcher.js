/**
 * NIDPS Snort Fast-Alert Log Watcher Service
 * Continuously monitors Snort fast-alert log file using the 'tail' package,
 * parses intrusion alerts, records them to PostgreSQL, and triggers automated
 * firewall mitigation on Priority 1 (High Severity) threats.
 */

const fs = require('fs');
const path = require('path');
const { Tail } = require('tail');
const { query } = require('../config/db');
const firewall = require('./firewall');

class LogWatcher {
  constructor() {
    this.tail = null;
    this.filePath = null;
    this.isWatching = false;
    this.reconnectTimer = null;
  }

  /**
   * Helper to strip ports and brackets from endpoints
   * e.g. "198.51.100.99:51234" -> "198.51.100.99"
   * e.g. "[2001:db8::1]:8080" -> "2001:db8::1"
   */
  cleanIpEndpoint(endpoint) {
    if (!endpoint || typeof endpoint !== 'string') return '';
    const trimmed = endpoint.trim();

    // Check bracketed IPv6: [2001:db8::1]:8080
    if (trimmed.startsWith('[') && trimmed.includes(']')) {
      return trimmed.slice(1, trimmed.indexOf(']'));
    }

    // Check IPv4 with port: 192.168.1.1:80
    if (trimmed.includes('.') && trimmed.includes(':')) {
      return trimmed.split(':')[0];
    }

    return trimmed;
  }

  /**
   * Robust Regex Parser for Snort Fast-Alert Log lines
   *
   * Example formats supported:
   * 1. [**] [1:2001219:1] ET EXPLOIT Apache Log4j RCE Attempt [**] [Classification: Attempted Administrator Privilege Gain] [Priority: 1] {TCP} 198.51.100.99:51234 -> 10.0.0.5:8080
   * 2. 05/24-10:15:32.123456 [**] [1:1000001:1] SSH Brute Force [**] [Classification: Attempted Login] [Priority: 2] {TCP} 192.168.1.50:54321 -> 10.0.0.5:22
   * 3. [**] [1:384:8] ICMP PING [**] [Classification: Misc activity] [Priority: 3] {ICMP} 192.168.1.100 -> 8.8.8.8
   *
   * @param {string} line - Raw log line from Snort
   * @returns {Object|null} Parsed alert data or null if invalid
   */
  parseSnortAlert(line) {
    if (!line || typeof line !== 'string') return null;
    const trimmed = line.trim();
    if (!trimmed) return null;

    // Fast check: Snort fast-alert logs always contain '[**]' and '->'
    if (!trimmed.includes('[**]') || !trimmed.includes('->')) {
      return null;
    }

    // Robust regular expression extracting alert components
    const regex = /\[\*\*\]\s*(?:\[\d+:\d+:\d+\])?\s*([^\[]+?)\s*\[\*\*\](?:\s*\[Classification:\s*([^\]]+)\])?(?:\s*\[Priority:\s*(\d+)\])?\s*\{([A-Za-z0-9_-]+)\}\s*([0-9a-fA-F\.\:\[\]]+)\s*->\s*([0-9a-fA-F\.\:\[\]]+)/;
    const match = trimmed.match(regex);

    if (!match) {
      console.warn(`[LOG WATCHER WARNING] Line failed regex parsing: "${trimmed}"`);
      return null;
    }

    const alert_message = match[1].trim();
    const classification = match[2] ? match[2].trim() : 'Unclassified';
    let severity = match[3] ? parseInt(match[3], 10) : 3;
    if (isNaN(severity) || severity < 1 || severity > 4) {
      severity = 3;
    }

    const protocol = match[4].trim().toUpperCase();
    const source_ip = this.cleanIpEndpoint(match[5]);
    const dest_ip = this.cleanIpEndpoint(match[6]);

    // Validate extracted IP addresses
    if (!firewall.isValidIpAddress(source_ip)) {
      console.warn(`[LOG WATCHER WARNING] Extracted invalid source IP "${source_ip}" from line: ${trimmed}`);
      return null;
    }

    // Optional: Extract leading timestamp if present (e.g. 05/24-10:15:32.123456)
    let timestamp = new Date().toISOString();
    const tsMatch = trimmed.match(/^(\d{2}\/\d{2}-\d{2}:\d{2}:\d{2}(?:\.\d+)?)/);
    if (tsMatch) {
      try {
        const year = new Date().getFullYear();
        const normalized = `${year}-${tsMatch[1].replace('/', '-').replace('-', 'T')}Z`;
        const parsed = new Date(normalized);
        if (!isNaN(parsed.getTime())) {
          timestamp = parsed.toISOString();
        }
      } catch (err) {
        // Fallback to current timestamp
        timestamp = new Date().toISOString();
      }
    }

    return {
      timestamp,
      source_ip,
      dest_ip,
      protocol,
      alert_message,
      classification,
      severity,
      status: severity === 1 ? 'blocked' : 'unresolved'
    };
  }

  /**
   * Processes a single incoming alert line:
   * 1. Parses raw string
   * 2. Triggers Prevention Engine if Priority 1
   * 3. Saves record into PostgreSQL alerts table
   */
  async processAlertLine(line) {
    const alertData = this.parseSnortAlert(line);
    if (!alertData) return null;

    console.log(`[LOG WATCHER INGEST] [Priority ${alertData.severity}] ${alertData.alert_message} | ${alertData.source_ip} -> ${alertData.dest_ip} (${alertData.protocol})`);

    // THE TRIGGER: If Priority 1 (High Severity), automatically block attacking IP
    let mitigationResult = null;
    if (alertData.severity === 1) {
      console.log(`[PREVENTION TRIGGER ACTIVATED] High severity alert (P1) from ${alertData.source_ip}! Initiating automated mitigation.`);
      try {
        mitigationResult = await firewall.blockIp(
          alertData.source_ip,
          `Automated mitigation: High severity alert "${alertData.alert_message}"`
        );
        alertData.status = 'blocked';
      } catch (fwErr) {
        console.error(`[PREVENTION TRIGGER ERROR] Failed to mitigate ${alertData.source_ip}:`, fwErr.message);
      }
    }

    // Persist alert into PostgreSQL
    try {
      const insertSql = `
        INSERT INTO alerts (timestamp, source_ip, dest_ip, protocol, alert_message, severity, status)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING *;
      `;
      const res = await query(insertSql, [
        alertData.timestamp,
        alertData.source_ip,
        alertData.dest_ip,
        alertData.protocol,
        alertData.alert_message,
        alertData.severity,
        alertData.status
      ]);

      const savedAlert = res.rows[0];
      return { alert: savedAlert, mitigationResult };
    } catch (dbErr) {
      console.error(`[LOG WATCHER DB ERROR] Failed saving alert to PostgreSQL:`, dbErr.message);
      return null;
    }
  }

  /**
   * Initializes the file tail watcher on the specified path
   * Handles log rotation, file interruptions, and non-existent file initialization
   */
  startWatching(logFilePath = process.env.SNORT_LOG_PATH || './mock_snort.log') {
    if (this.isWatching) {
      console.warn('[LOG WATCHER] Already running.');
      return;
    }

    this.filePath = path.resolve(logFilePath);

    // Ensure the parent directory exists
    const dir = path.dirname(this.filePath);
    if (!fs.existsSync(dir)) {
      try {
        fs.mkdirSync(dir, { recursive: true });
      } catch (err) {
        console.error(`[LOG WATCHER ERROR] Could not create directory ${dir}:`, err.message);
      }
    }

    // Ensure target log file exists so Tail does not throw an immediate ENOENT
    if (!fs.existsSync(this.filePath)) {
      try {
        console.log(`[LOG WATCHER] Log file does not exist. Initializing empty file at: ${this.filePath}`);
        fs.writeFileSync(this.filePath, '', 'utf8');
      } catch (err) {
        console.error(`[LOG WATCHER ERROR] Could not initialize log file ${this.filePath}:`, err.message);
      }
    }

    try {
      console.log(`[LOG WATCHER] Starting tail on Snort alert file: ${this.filePath}`);
      
      // Initialize Tail with file watch options for resilience
      this.tail = new Tail(this.filePath, {
        separator: /[\r]{0,1}\n/,
        fromBeginning: false, // Only capture new alerts
        follow: true,
        useWatchFile: true // Ensures polling fallback across Docker, VM mounts & log rotations
      });

      // Stream Event: New line appended to log
      this.tail.on('line', (data) => {
        if (data && data.trim()) {
          this.processAlertLine(data).catch((err) => {
            console.error('[LOG WATCHER UNHANDLED PROCESS ERROR]', err);
          });
        }
      });

      // Stream Event: Error handling & stream interruption
      this.tail.on('error', (err) => {
        console.error(`[LOG WATCHER STREAM ERROR] File stream error on ${this.filePath}:`, err);
        this.handleStreamInterruption();
      });

      this.isWatching = true;
      console.log('[LOG WATCHER] Tail watcher active and ready.');
    } catch (tailErr) {
      console.error(`[LOG WATCHER INIT ERROR] Failed to start tail watcher:`, tailErr.message);
      this.handleStreamInterruption();
    }
  }

  /**
   * Handles stream interruption, file deletion, or log rotations
   * with automatic exponential recovery
   */
  handleStreamInterruption() {
    if (this.reconnectTimer) return;

    console.warn('[LOG WATCHER] Attempting stream recovery in 3 seconds...');
    this.stopWatching();

    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.startWatching(this.filePath);
    }, 3000);
  }

  /**
   * Gracefully shuts down the tail watcher
   */
  stopWatching() {
    if (this.tail) {
      try {
        this.tail.unwatch();
      } catch (e) {
        // Ignore unwatch errors during shutdown
      }
      this.tail = null;
    }
    this.isWatching = false;
    console.log('[LOG WATCHER] Log watcher stopped.');
  }
}

// Export singleton instance
const logWatcherInstance = new LogWatcher();
module.exports = logWatcherInstance;
