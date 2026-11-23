const firewall = require('../services/firewall');

exports.getBlocked = async (req, res) => {
  try {
    const activeOnly = req.query.active !== 'false';
    const list = await firewall.getBlockedIps(activeOnly);
    res.json({
      count: list.length,
      data: list
    });
  } catch (err) {
    console.error('[FIREWALL CONTROLLER ERROR] getBlocked:', err);
    res.status(500).json({ error: 'Failed to fetch blocked IPs', details: err.message });
  }
};

exports.block = async (req, res) => {
  try {
    const { ip, reason } = req.body;
    if (!ip) {
      return res.status(400).json({ error: 'IP address is required' });
    }

    // Basic IP validation (IPv4 or IPv6 format)
    const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    const ipv6Regex = /^[0-9a-fA-F:]+$/;
    if (!ipv4Regex.test(ip) && !ipv6Regex.test(ip)) {
      return res.status(400).json({ error: 'Invalid IP address format' });
    }

    const blockReason = reason || 'Manual administrative block';
    const result = await firewall.blockIp(ip, blockReason);

    res.status(201).json({
      message: result.alreadyBlocked ? `IP ${ip} is already blocked` : `IP ${ip} blocked successfully`,
      data: result
    });
  } catch (err) {
    console.error('[FIREWALL CONTROLLER ERROR] block:', err);
    res.status(500).json({ error: 'Failed to execute IP block', details: err.message });
  }
};

exports.unblock = async (req, res) => {
  try {
    const { ip } = req.body;
    if (!ip) {
      return res.status(400).json({ error: 'IP address is required to unblock' });
    }

    const result = await firewall.unblockIp(ip);
    res.json({
      message: `IP ${ip} unblocked successfully`,
      data: result
    });
  } catch (err) {
    console.error('[FIREWALL CONTROLLER ERROR] unblock:', err);
    res.status(500).json({ error: 'Failed to execute IP unblock', details: err.message });
  }
};
