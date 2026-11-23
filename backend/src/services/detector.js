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
      const since = new Date(now().getTime() - settings.escalateWindowMin * 60000);
      const count = await store.countAlertsSince(alert.source_ip, 2, since);
      if (count >= settings.escalateCount) {
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
