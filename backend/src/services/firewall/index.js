/**
 * NIDPS prevention engine.
 *
 * block()/unblock() are the only way rules change. Each call:
 *   1. validates the IP (no shell is ever involved: commands run via execFile),
 *   2. refuses protected (allowlisted) addresses,
 *   3. runs at most one operation per IP at a time (per-IP lock),
 *   4. applies the iptables rule (or only logs it in simulated mode),
 *   5. records the block, an audit entry, and a live event for the dashboard.
 */
const { execFile } = require('child_process');
const { promisify } = require('util');
const { isValidIp, normalizeIp } = require('../../lib/ip');
const { buildCommands } = require('./commands');

const execFileAsync = promisify(execFile);
const defaultRun = (argv) => execFileAsync(argv[0], argv.slice(1), { timeout: 10000, windowsHide: true });

class FirewallError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

function createFirewall({
  settings,
  store,
  allowlist,
  run = defaultRun,
  events = { publish() {} },
  now = () => new Date(),
  platform = process.platform,
  isRoot = typeof process.getuid === 'function' && process.getuid() === 0,
}) {
  const commands = buildCommands({ mode: settings.mode, platform, wslDistro: settings.wslDistro, isRoot });
  const simulated = !settings.realFirewall;
  const locks = new Map();

  function withLock(ip, fn) {
    const previous = locks.get(ip) || Promise.resolve();
    const next = previous.catch(() => {}).then(fn);
    locks.set(ip, next);
    return next.finally(() => {
      if (locks.get(ip) === next) locks.delete(ip);
    });
  }

  function cleanIp(ip) {
    if (!isValidIp(ip)) throw new FirewallError('INVALID_IP', 'Invalid IP address');
    return normalizeIp(ip);
  }

  const describe = (err) => (err && (err.stderr || err.message)) || String(err);

  /** Adds the DROP rule unless it is already present (-C succeeds). */
  async function applyRule(ip) {
    try {
      await run(commands.check(ip));
      return;
    } catch {
      // rule not present yet
    }
    await run(commands.block(ip));
  }

  async function block(ip, reason, actor = 'system') {
    const address = cleanIp(ip);
    return withLock(address, async () => {
      if (allowlist.isProtected(address)) {
        await store.insertAudit({ actor, action: 'block_refused', target: address, detail: `Protected address. Reason given: ${reason}` });
        console.warn(`[FIREWALL] Refused to block protected address ${address}`);
        return { status: 'protected' };
      }

      const existing = await store.getActiveBlock(address);
      if (existing) {
        // Self-heal: the record says "blocked" but the rule may have been flushed
        // (reset, reboot, manual iptables -F). applyRule checks with -C first.
        if (!simulated) await applyRule(address).catch((err) => console.error(`[FIREWALL] Could not re-apply ${address}: ${describe(err)}`));
        return { status: 'already', block: existing };
      }

      if (simulated) {
        console.log(`[FIREWALL SIMULATED] ${commands.block(address).join(' ')}`);
      } else {
        try {
          await applyRule(address);
        } catch (err) {
          console.error(`[FIREWALL] Block command failed for ${address}: ${describe(err)}`);
          throw new FirewallError('EXEC_FAILED', 'Firewall command failed');
        }
      }

      const minutes = settings.blockDurationMin;
      const record = await store.insertBlock({
        ip_address: address,
        block_reason: reason,
        expires_at: minutes > 0 ? new Date(now().getTime() + minutes * 60000) : null,
        created_by: actor,
      });
      await store.markAlertsBlocked(address);
      await store.insertAudit({ actor, action: 'block', target: address, detail: reason });
      events.publish('block', record);
      console.log(`[FIREWALL] Blocked ${address} (${reason})`);
      return { status: 'blocked', block: record, simulated };
    });
  }

  async function unblock(ip, actor = 'system', reason = 'Manual unblock') {
    const address = cleanIp(ip);
    return withLock(address, async () => {
      const existing = await store.getActiveBlock(address);
      if (!existing) return { status: 'not_blocked' };

      if (simulated) {
        console.log(`[FIREWALL SIMULATED] ${commands.unblock(address).join(' ')}`);
      } else {
        try {
          await run(commands.unblock(address));
        } catch (err) {
          // The rule may already be gone (e.g. after a reboot); the record is still closed.
          console.warn(`[FIREWALL] Unblock command for ${address} reported: ${describe(err)}`);
        }
      }

      const record = await store.deactivateBlock(address);
      await store.insertAudit({ actor, action: 'unblock', target: address, detail: reason });
      events.publish('unblock', record);
      console.log(`[FIREWALL] Unblocked ${address} (${reason})`);
      return { status: 'unblocked', block: record, simulated };
    });
  }

  async function sweepExpired() {
    const expired = await store.listExpiredBlocks(now());
    let count = 0;
    for (const b of expired) {
      const r = await unblock(b.ip_address, 'system', 'Block expired');
      if (r.status === 'unblocked') count++;
    }
    return count;
  }

  /**
   * Creates the chain + jump (idempotent), empties the NIDPS chain (only NIDPS's own
   * rules - nothing else is touched), then re-applies exactly the active blocks, so the
   * kernel and the database always agree after a start-up.
   */
  async function init() {
    if (simulated) {
      console.log(`[FIREWALL] Simulated mode (${settings.mode}): rules are logged, not applied.`);
      return;
    }
    for (const family of ['ipv4', 'ipv6']) {
      const steps = commands.setup(family);
      try {
        await run(steps.create).catch(() => {}); // already exists
        await run(commands.flush(family));
        try {
          await run(steps.checkJump);
        } catch {
          await run(steps.insertJump);
        }
      } catch (err) {
        const level = family === 'ipv4' ? 'error' : 'warn';
        console[level](`[FIREWALL] Could not set up ${family} NIDPS chain: ${describe(err)}`);
      }
    }
    const active = await store.listBlocks(true);
    for (const b of active) {
      try {
        await applyRule(b.ip_address);
      } catch (err) {
        console.error(`[FIREWALL] Could not restore block for ${b.ip_address}: ${describe(err)}`);
      }
    }
    console.log(`[FIREWALL] Live mode (${settings.mode}, chain ${commands.chain} <- ${commands.parent}); restored ${active.length} block(s).`);
  }

  return {
    init,
    block,
    unblock,
    sweepExpired,
    list: (activeOnly) => store.listBlocks(activeOnly),
    mode: settings.mode,
    simulated,
    commands,
  };
}

module.exports = { createFirewall, FirewallError };
