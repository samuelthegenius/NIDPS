/**
 * Authenticated REST API: alerts, firewall, stats, audit, settings.
 */
const express = require('express');
const { FirewallError } = require('../services/firewall');

const TRIAGE_STATUSES = new Set(['unresolved', 'investigating', 'resolved', 'false_positive', 'blocked']);
const intIn = (value, min, max, fallback) => {
  const n = parseInt(value, 10);
  return Number.isInteger(n) && n >= min && n <= max ? n : fallback;
};
const text = (value, max) => (typeof value === 'string' ? value.trim().slice(0, max) : '');

function firewallErrorStatus(err) {
  if (err instanceof FirewallError && err.code === 'INVALID_IP') return [400, 'Invalid IP address'];
  if (err instanceof FirewallError && err.code === 'EXEC_FAILED') return [502, 'Firewall command failed - check the server log'];
  return null;
}

module.exports = function apiRoutes({ settings, store, firewall, watcher, allowlist }) {
  const router = express.Router();
  const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res)).catch(next);

  // ---- Alerts -------------------------------------------------------------
  router.get(
    '/alerts',
    wrap(async (req, res) => {
      const page = intIn(req.query.page, 1, 100000, 1);
      const limit = intIn(req.query.limit, 1, 100, 20);
      const severity = intIn(req.query.severity, 1, 4, null);
      const status = TRIAGE_STATUSES.has(req.query.status) ? req.query.status : null;
      const search = text(req.query.search, 100) || null;
      const { data, total } = await store.listAlerts({ page, limit, severity, status, search });
      res.json({ data, pagination: { total, page, limit, totalPages: Math.max(1, Math.ceil(total / limit)) } });
    })
  );

  router.patch(
    '/alerts/:id',
    wrap(async (req, res) => {
      const id = intIn(req.params.id, 1, Number.MAX_SAFE_INTEGER, null);
      const status = req.body && req.body.status;
      if (!id || !TRIAGE_STATUSES.has(status)) return res.status(400).json({ error: 'Invalid alert id or status' });
      const alert = await store.updateAlertStatus(id, status);
      if (!alert) return res.status(404).json({ error: 'Alert not found' });
      await store.insertAudit({ actor: req.user, action: 'alert_status', target: String(id), detail: status });
      return res.json({ data: alert });
    })
  );

  // ---- Firewall -----------------------------------------------------------
  router.get(
    '/blocked',
    wrap(async (req, res) => {
      const data = await firewall.list(req.query.active !== 'false');
      res.json({ count: data.length, data });
    })
  );

  router.post(
    '/block',
    wrap(async (req, res) => {
      const ip = text(req.body && req.body.ip, 64);
      const reason = text(req.body && req.body.reason, 200) || 'Manual administrative block';
      try {
        const result = await firewall.block(ip, reason, req.user);
        if (result.status === 'protected') {
          return res.status(409).json({ error: `${ip} is protected by the allowlist and cannot be blocked` });
        }
        if (result.status === 'already') return res.json({ message: `${ip} is already blocked`, data: result.block });
        return res.status(201).json({ message: `${ip} blocked`, data: result.block, simulated: result.simulated });
      } catch (err) {
        const mapped = firewallErrorStatus(err);
        if (!mapped) throw err;
        return res.status(mapped[0]).json({ error: mapped[1] });
      }
    })
  );

  router.post(
    '/unblock',
    wrap(async (req, res) => {
      const ip = text(req.body && req.body.ip, 64);
      try {
        const result = await firewall.unblock(ip, req.user);
        if (result.status === 'not_blocked') return res.status(404).json({ error: `${ip} is not currently blocked` });
        return res.json({ message: `${ip} unblocked`, data: result.block });
      } catch (err) {
        const mapped = firewallErrorStatus(err);
        if (!mapped) throw err;
        return res.status(mapped[0]).json({ error: mapped[1] });
      }
    })
  );

  // ---- Analytics, audit, settings ----------------------------------------
  router.get('/stats', wrap(async (req, res) => res.json(await store.getStats(new Date()))));

  router.get(
    '/audit',
    wrap(async (req, res) => {
      res.json({ data: await store.listAudit({ limit: intIn(req.query.limit, 1, 500, 100) }) });
    })
  );

  router.get('/settings', (req, res) => {
    res.json({
      mode: settings.mode,
      demoMode: settings.demoMode,
      realFirewall: settings.realFirewall,
      firewall: firewall.backend,
      platform: process.platform,
      allowlist: allowlist.describe(),
      blockDurationMin: settings.blockDurationMin,
      escalateCount: settings.escalateCount,
      escalateWindowMin: settings.escalateWindowMin,
      retentionDays: settings.retentionDays,
      store: store.kind,
      watcher: watcher.status(),
      https: Boolean(settings.tlsCert && settings.tlsKey),
    });
  });

  return router;
};
