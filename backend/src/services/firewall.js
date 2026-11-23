/**
 * NIDPS Firewall Prevention Engine
 * Executes kernel-level iptables blocking/unblocking and synchronizes with PostgreSQL.
 */

const { exec } = require('child_process');
const { query } = require('../config/db');

// Read environment toggle: defaults to false if not strictly 'true'
const isRealIptablesEnabled = () => process.env.ENABLE_REAL_IPTABLES === 'true';

/**
 * Strict IP address validation to guard against command injection vulnerabilities
 * Accepts valid IPv4 and IPv6 addresses.
 */
function isValidIpAddress(ip) {
  if (!ip || typeof ip !== 'string') return false;
  const trimmed = ip.trim();
  
  // Standard IPv4 regex (0-255 per octet)
  const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  // Standard IPv6 regex (hexadecimal segments separated by colons)
  const ipv6Regex = /^(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}$|^::1$|^[A-F0-9:]+$/i;

  return ipv4Regex.test(trimmed) || ipv6Regex.test(trimmed);
}

/**
 * Executes a shell command wrapped in a Promise
 * Handles errors and logs outputs.
 */
function executeShellCommand(cmd) {
  return new Promise((resolve, reject) => {
    exec(cmd, (error, stdout, stderr) => {
      if (error) {
        return reject({
          error,
          stderr: stderr ? stderr.trim() : null,
          cmd
        });
      }
      resolve({
        stdout: stdout ? stdout.trim() : '',
        stderr: stderr ? stderr.trim() : '',
        cmd
      });
    });
  });
}

/**
 * Checks if an IP is already actively blocked in PostgreSQL
 */
async function isIpActivelyBlocked(ipAddress) {
  try {
    const res = await query(
      'SELECT id, ip_address, is_active FROM blocked_ips WHERE ip_address = $1 AND is_active = true LIMIT 1',
      [ipAddress]
    );
    return res.rows.length > 0;
  } catch (err) {
    console.error(`[FIREWALL DB ERROR] Failed to check active block status for ${ipAddress}:`, err.message);
    throw err;
  }
}

/**
 * Blocks an attacking IP address using iptables and logs to database.
 * 
 * @param {string} ipAddress - The source IP to block
 * @param {string} reason - Justification or alert signature
 * @returns {Promise<Object>} Execution result and persisted record
 */
async function blockIp(ipAddress, reason = 'Automated NIDPS High Severity Rule Trigger') {
  if (!ipAddress) {
    throw new Error('IP address is required for firewall block.');
  }

  const cleanIp = ipAddress.trim();

  // 1. Strict Input Validation (Prevents shell injection vulnerabilities)
  if (!isValidIpAddress(cleanIp)) {
    throw new Error(`Invalid IP address format: "${cleanIp}". Aborting block command.`);
  }

  // 2. Prevent Duplicate Active Blocks
  const alreadyBlocked = await isIpActivelyBlocked(cleanIp);
  if (alreadyBlocked) {
    console.log(`[FIREWALL NOTICE] IP ${cleanIp} is already actively blocked in the firewall. Skipping duplicate block.`);
    return {
      success: true,
      alreadyBlocked: true,
      ip: cleanIp,
      message: `IP ${cleanIp} is already in the active blocked list.`
    };
  }

  // Format command (supports both native Linux sudo and WSL2 bridge from Windows)
  const isWindows = process.platform === 'win32';
  const iptablesCmd = isWindows
    ? `wsl -d Ubuntu-24.04 -u root iptables -A INPUT -s ${cleanIp} -j DROP`
    : `sudo iptables -A INPUT -s ${cleanIp} -j DROP`;
  let execResult = null;

  // 3. Execution (Kernel iptables vs. Simulation)
  if (isRealIptablesEnabled()) {
    console.log(`[FIREWALL KERNEL EXEC] Applying rule: ${iptablesCmd}`);
    try {
      execResult = await executeShellCommand(iptablesCmd);
      console.log(`[FIREWALL KERNEL SUCCESS] Rule applied for ${cleanIp}`);
    } catch (cmdErr) {
      console.error(`[FIREWALL KERNEL ERROR] Failed executing command "${iptablesCmd}":`, cmdErr.stderr || cmdErr.error.message);
      throw new Error(`Firewall command execution failed: ${cmdErr.stderr || cmdErr.error.message}`);
    }
  } else {
    // Simulated Mode: Safely log exact command
    console.log(`[FIREWALL SIMULATION] ENABLE_REAL_IPTABLES is false. Simulated command: "${iptablesCmd}"`);
    execResult = { simulated: true, cmd: iptablesCmd };
  }

  // 4. Record block in PostgreSQL
  try {
    const insertSql = `
      INSERT INTO blocked_ips (ip_address, block_reason, timestamp, unblocked_at, is_active)
      VALUES ($1, $2, NOW(), NULL, true)
      RETURNING *;
    `;
    const dbRes = await query(insertSql, [cleanIp, reason]);
    const record = dbRes.rows[0];

    // Mark any existing unresolved alerts from this source_ip as 'blocked'
    await query(
      `UPDATE alerts SET status = 'blocked' WHERE source_ip = $1 AND status = 'unresolved'`,
      [cleanIp]
    ).catch(e => console.warn(`[FIREWALL DB WARNING] Could not update alerts status: ${e.message}`));

    console.log(`[FIREWALL DB SUCCESS] Block logged in database for ${cleanIp} (ID: ${record.id})`);

    return {
      success: true,
      alreadyBlocked: false,
      ip: cleanIp,
      record,
      command: iptablesCmd,
      simulated: !isRealIptablesEnabled()
    };
  } catch (dbErr) {
    console.error(`[FIREWALL DB ERROR] Failed to record block in PostgreSQL for ${cleanIp}:`, dbErr.message);
    throw dbErr;
  }
}

/**
 * Unblocks an IP address, removes iptables rule, and marks record inactive in database.
 * 
 * @param {string} ipAddress - The source IP to unblock
 * @returns {Promise<Object>} Execution result and updated DB records
 */
async function unblockIp(ipAddress) {
  if (!ipAddress) {
    throw new Error('IP address is required for firewall unblock.');
  }

  const cleanIp = ipAddress.trim();

  // 1. Strict Input Validation
  if (!isValidIpAddress(cleanIp)) {
    throw new Error(`Invalid IP address format: "${cleanIp}". Aborting unblock command.`);
  }

  const isWindows = process.platform === 'win32';
  const iptablesCmd = isWindows
    ? `wsl -d Ubuntu-24.04 -u root iptables -D INPUT -s ${cleanIp} -j DROP`
    : `sudo iptables -D INPUT -s ${cleanIp} -j DROP`;
  let execResult = null;

  // 2. Execution (Kernel iptables vs. Simulation)
  if (isRealIptablesEnabled()) {
    console.log(`[FIREWALL KERNEL EXEC] Removing rule: ${iptablesCmd}`);
    try {
      execResult = await executeShellCommand(iptablesCmd);
      console.log(`[FIREWALL KERNEL SUCCESS] Rule removed for ${cleanIp}`);
    } catch (cmdErr) {
      console.warn(`[FIREWALL KERNEL WARNING] iptables -D returned error (rule may not exist):`, cmdErr.stderr || cmdErr.error.message);
    }
  } else {
    console.log(`[FIREWALL SIMULATION] ENABLE_REAL_IPTABLES is false. Simulated command: "${iptablesCmd}"`);
    execResult = { simulated: true, cmd: iptablesCmd };
  }

  // 3. Update PostgreSQL blocked_ips status
  try {
    const updateSql = `
      UPDATE blocked_ips
      SET is_active = false, unblocked_at = NOW()
      WHERE ip_address = $1 AND is_active = true
      RETURNING *;
    `;
    const dbRes = await query(updateSql, [cleanIp]);
    console.log(`[FIREWALL DB SUCCESS] Marked ${dbRes.rowCount} active rule(s) as inactive for ${cleanIp}`);

    return {
      success: true,
      ip: cleanIp,
      recordsUpdated: dbRes.rowCount,
      record: dbRes.rows[0] || null,
      command: iptablesCmd,
      simulated: !isRealIptablesEnabled()
    };
  } catch (dbErr) {
    console.error(`[FIREWALL DB ERROR] Failed to update unblock status for ${cleanIp}:`, dbErr.message);
    throw dbErr;
  }
}

/**
 * Retrieve list of blocked IPs from database
 */
async function getBlockedIps(activeOnly = true) {
  try {
    let sql = 'SELECT * FROM blocked_ips';
    if (activeOnly) {
      sql += ' WHERE is_active = true';
    }
    sql += ' ORDER BY timestamp DESC';
    const res = await query(sql);
    return res.rows;
  } catch (err) {
    console.error('[FIREWALL DB ERROR] getBlockedIps failed:', err.message);
    throw err;
  }
}

module.exports = {
  blockIp,
  unblockIp,
  isIpActivelyBlocked,
  getBlockedIps,
  isValidIpAddress,
  isRealIptablesEnabled
};
