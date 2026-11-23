const { query, inMemoryStore, getIsConnected } = require('../config/db');

exports.getAlerts = async (req, res) => {
  try {
    const page = Math.max(1, parseInt(req.query.page || '1', 10));
    const limit = Math.min(100, Math.max(1, parseInt(req.query.limit || '20', 10)));
    const offset = (page - 1) * limit;

    const severity = req.query.severity ? parseInt(req.query.severity, 10) : null;
    const status = req.query.status || null;
    const search = req.query.search ? req.query.search.trim() : null;

    if (getIsConnected()) {
      const conditions = [];
      const params = [];

      if (severity !== null && !isNaN(severity)) {
        params.push(severity);
        conditions.push(`severity = $${params.length}`);
      }

      if (status) {
        params.push(status);
        conditions.push(`status = $${params.length}`);
      }

      if (search) {
        params.push(`%${search}%`);
        conditions.push(`(source_ip ILIKE $${params.length} OR dest_ip ILIKE $${params.length} OR alert_message ILIKE $${params.length})`);
      }

      const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

      const countResult = await query(`SELECT COUNT(*) as total FROM alerts ${whereClause}`, params);
      const total = parseInt(countResult.rows[0].total, 10);

      params.push(limit);
      const limitIdx = params.length;
      params.push(offset);
      const offsetIdx = params.length;

      const dataResult = await query(
        `SELECT * FROM alerts ${whereClause} ORDER BY timestamp DESC LIMIT $${limitIdx} OFFSET $${offsetIdx}`,
        params
      );

      return res.json({
        data: dataResult.rows,
        pagination: {
          total,
          page,
          limit,
          totalPages: Math.ceil(total / limit) || 1
        }
      });
    }

    // Fallback store handling
    let rows = [...inMemoryStore.alerts];
    if (severity !== null && !isNaN(severity)) {
      rows = rows.filter(a => a.severity === severity);
    }
    if (status) {
      rows = rows.filter(a => a.status === status);
    }
    if (search) {
      const s = search.toLowerCase();
      rows = rows.filter(a => 
        a.source_ip.toLowerCase().includes(s) || 
        a.dest_ip.toLowerCase().includes(s) || 
        a.alert_message.toLowerCase().includes(s)
      );
    }

    const total = rows.length;
    const paginated = rows.slice(offset, offset + limit);

    return res.json({
      data: paginated,
      pagination: {
        total,
        page,
        limit,
        totalPages: Math.ceil(total / limit) || 1
      }
    });
  } catch (err) {
    console.error('[ALERTS CONTROLLER ERROR]', err);
    res.status(500).json({ error: 'Failed to retrieve alerts', details: err.message });
  }
};
