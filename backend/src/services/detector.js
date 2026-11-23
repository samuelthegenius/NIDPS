/**
 * Detection policy: turns one Snort line into a stored alert and, when the
 * policy says so, a firewall block.
 *
 *   Priority 1            -> block the source immediately
 *   Priority 2            -> log; block once ESCALATE_COUNT P2 alerts arrive from the
 *                            same source within ESCALATE_WINDOW_MIN minutes
 *   Priority 3 and lower  -> log only
 */
const { parseSnortAlert } = require('./snortParser');

function createDetector({ store, firewall, settings, events = { publish() {} }, now = () => new Date() }) {
  // Escalation counts when NIDPS *received* each P2 alert, not Snort's printed time:
  // Snort's clock/timezone may differ from this machine's (e.g. WSL on UTC).
  const recentP2 = new Map(); // source ip -> arrival times (ms)

  function countRecentP2(ip) {
    const t = now().getTime();
    const cutoff = t - settings.escalateWindowMin * 60000;
    const times = (recentP2.get(ip) || []).filter((x) => x >= cutoff);
    times.push(t);
    recentP2.set(ip, times);
    for (const [key, list] of recentP2) if (list[list.length - 1] < cutoff) recentP2.delete(key);
    return times.length;
  }

  async function tryBlock(ip, reason) {
    try {
      return (await firewall.block(ip, reason, 'system')).status;
    } catch (err) {
      console.error(`[DETECTOR] Automatic block of ${ip} failed: ${err.message}`);
      return 'failed';
    }
  }

  async function handleLine(line) {
    const parsed = parseSnortAlert(line, now());
    if (!parsed) return null;

    let alert = await store.insertAlert({
      timestamp: parsed.timestamp,
      source_ip: parsed.source_ip,
      dest_ip: parsed.dest_ip,
      protocol: parsed.protocol,
      alert_message: parsed.alert_message,
      severity: parsed.severity,
      status: 'unresolved',
    });
    console.log(`[DETECTOR] P${alert.severity} ${alert.alert_message} | ${alert.source_ip} -> ${alert.dest_ip} (${alert.protocol})`);

    let action = 'logged';
    let outcome = null;

    if (alert.severity === 1) {
      outcome = await tryBlock(alert.source_ip, `Automated: P1 "${alert.alert_message}"`);
      if (outcome === 'blocked' || outcome === 'already') action = 'blocked';
    } else if (alert.severity === 2 && settings.escalateCount > 0) {
      const count = countRecentP2(alert.source_ip);
      if (count >= settings.escalateCount) {
        recentP2.delete(alert.source_ip);
        outcome = await tryBlock(alert.source_ip, `Escalation: ${count} P2 alerts in ${settings.escalateWindowMin} min`);
        if (outcome === 'blocked' || outcome === 'already') action = 'escalated';
      }
    }

    if (outcome === 'protected') action = 'protected';
    if (action === 'blocked' || action === 'escalated') {
      await store.markAlertsBlocked(alert.source_ip);
      alert = (await store.updateAlertStatus(alert.id, 'blocked')) || alert;
    }

    events.publish('alert', alert);
    return { alert, action };
  }

  return { handleLine };
}

module.exports = { createDetector };
