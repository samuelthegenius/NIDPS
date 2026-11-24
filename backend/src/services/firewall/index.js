/**
 * NIDPS prevention engine.
 *
 * block()/unblock() are the only way rules change. Each call:
 *   1. validates the IP (no shell is ever involved: commands run via execFile),
 *   2. refuses protected (allowlisted) addresses,
 *   3. runs at most one operation per IP at a time (per-IP lock),
 *   4. applies the rule through the platform driver - iptables on Linux, Windows
 *      Firewall on Windows - or only logs it in simulated mode,
 *   5. records the block, an audit entry, and a live event for the dashboard.
 */
const { execFile } = require('child_process');
const { promisify } = require('util');
const { isValidIp, normalizeIp } = require('../../lib/ip');
const { buildCommands } = require('./commands');
const { buildWindowsCommands } = require('./windows');
const { resolveBackend } = require('./backend');

const execFileAsync = promisify(execFile);
const defaultRun = (argv, options = {}) => execFileAsync(argv[0], argv.slice(1), { timeout: 10000, windowsHide: true, ...options });
// Windows: re-checking an already-blocked IP costs two netsh processes, and Snort keeps
// alerting on a blocked scanner (it sees packets before the firewall drops them), so the
// check is repeated at most this often per IP.
const WINDOWS_RECHECK_MS = 30000;

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
  const backend = resolveBackend({ firewall: settings.firewall, platform, mode: settings.mode });
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
  const driver = backend === 'windows' ? windowsDriver() : iptablesDriver();

  /** Runs `check`; if it fails (rule missing), runs `add`. */
  async function ensure(check, add) {
    try {
      await run(check);
    } catch {
      await run(add);
    }
  }

  function iptablesDriver() {
    const commands = buildCommands({ mode: settings.mode, platform, wslDistro: settings.wslDistro, isRoot, useWsl: backend === 'wsl' });
    return {
      commands,
      label: `chain ${commands.chain} <- ${commands.parent}`,
      blockText: (ip) => commands.block(ip).join(' '),
      unblockText: (ip) => commands.unblock(ip).join(' '),
      apply: (ip) => ensure(commands.check(ip), commands.block(ip)),
      heal: (ip) => ensure(commands.check(ip), commands.block(ip)), // one cheap `iptables -C`
      remove: (ip) => run(commands.unblock(ip)),
      /** Creates the chain + jump (idempotent) and empties the NIDPS chain only. */
      async prepare() {
        for (const family of ['ipv4', 'ipv6']) {
          const steps = commands.setup(family);
          try {
            await run(steps.create).catch(() => {}); // already exists
            await run(commands.flush(family));
            await ensure(steps.checkJump, steps.insertJump);
          } catch (err) {
            const level = family === 'ipv4' ? 'error' : 'warn';
            console[level](`[FIREWALL] Could not set up ${family} NIDPS chain: ${describe(err)}`);
          }
        }
      },
    };
  }

  function windowsDriver() {
    const commands = buildWindowsCommands();
    const verifiedAt = new Map();
    async function apply(ip) {
      for (const dir of commands.directions) await ensure(commands.check(ip, dir), commands.add(ip, dir));
      verifiedAt.set(ip, now().getTime());
    }
    return {
      commands,
      label: `Windows Firewall rules ${commands.prefix}*`,
      blockText: (ip) => commands.directions.map((d) => commands.add(ip, d).join(' ')).join(' && '),
      unblockText: (ip) => commands.remove(ip).join(' '),
      /** One rule per direction; each is added only if missing, so a half-present block is completed. */
      apply,
      async heal(ip) {
        const last = verifiedAt.get(ip);
        if (last !== undefined && now().getTime() - last < WINDOWS_RECHECK_MS) return;
        await apply(ip);
      },
      remove: (ip) => {
        verifiedAt.delete(ip);
        return run(commands.remove(ip));
      },
      /** Needs an elevated process; then removes every NIDPS-block-* rule (and nothing else). */
      async prepare() {
        try {
          await run(commands.adminCheck());
        } catch {
          throw new FirewallError(
            'NOT_ADMIN',
            'The live Windows firewall needs Administrator rights. Open PowerShell with "Run as administrator" and start NIDPS again, ' +
              'or set ENABLE_REAL_FIREWALL=false to use the simulated firewall.'
          );
        }
        try {
          await run(commands.flush(), { timeout: 120000 });
        } catch (err) {
          console.error(`[FIREWALL] Could not remove old NIDPS rules: ${describe(err)}`);
        }
      },
    };
  }

  const applyRule = (ip) => driver.apply(ip);

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
        if (!simulated) await driver.heal(address).catch((err) => console.error(`[FIREWALL] Could not re-apply ${address}: ${describe(err)}`));
        return { status: 'already', block: existing };
      }

      if (simulated) {
        console.log(`[FIREWALL SIMULATED] ${driver.blockText(address)}`);
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
        console.log(`[FIREWALL SIMULATED] ${driver.unblockText(address)}`);
      } else {
        try {
          await driver.remove(address);
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
   * Lets the driver remove NIDPS's own old rules (nothing else is touched), then
   * re-applies exactly the active blocks, so the firewall and the database always
   * agree after a start-up.
   */
  async function init() {
    if (simulated) {
      console.log(`[FIREWALL] Simulated mode (${settings.mode}, ${backend}): rules are logged, not applied.`);
      return;
    }
    await driver.prepare();
    const active = await store.listBlocks(true);
    for (const b of active) {
      try {
        await applyRule(b.ip_address);
      } catch (err) {
        console.error(`[FIREWALL] Could not restore block for ${b.ip_address}: ${describe(err)}`);
      }
    }
    console.log(`[FIREWALL] Live mode (${settings.mode}, ${driver.label}); restored ${active.length} block(s).`);
  }

  return {
    init,
    block,
    unblock,
    sweepExpired,
    list: (activeOnly) => store.listBlocks(activeOnly),
    mode: settings.mode,
    simulated,
    backend,
    commands: driver.commands,
  };
}

module.exports = { createFirewall, FirewallError };
