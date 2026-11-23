const { query, inMemoryStore, getIsConnected } = require('../config/db');

exports.getStats = async (req, res) => {
  try {
    if (getIsConnected()) {
      // 1. Total alerts 24h
      const total24hRes = await query(`
        SELECT COUNT(*) as count 
        FROM alerts 
        WHERE timestamp >= NOW() - INTERVAL '24 hours'
      `);
      const totalAlerts24h = parseInt(total24hRes.rows[0].count, 10);

      // 2. Total alerts overall
      const totalOverallRes = await query('SELECT COUNT(*) as count FROM alerts');
      const totalAlertsOverall = parseInt(totalOverallRes.rows[0].count, 10);

      // 3. Active blocks
      const activeBlocksRes = await query(`
        SELECT COUNT(*) as count 
        FROM blocked_ips 
        WHERE is_active = true
      `);
      const activeBlocksCount = parseInt(activeBlocksRes.rows[0].count, 10);

      // 4. High severity threats (Priority 1)
      const highSevRes = await query(`
        SELECT COUNT(*) as count 
        FROM alerts 
        WHERE severity = 1
      `);
      const highSeverityThreats = parseInt(highSevRes.rows[0].count, 10);

      // 5. Severity distribution
      const sevDistRes = await query(`
        SELECT severity, COUNT(*) as count 
        FROM alerts 
        GROUP BY severity 
        ORDER BY severity ASC
      `);
      const severityBreakdown = {
        priority1: 0,
        priority2: 0,
        priority3: 0,
        other: 0
      };
      sevDistRes.rows.forEach(r => {
        const count = parseInt(r.count, 10);
        if (r.severity === 1) severityBreakdown.priority1 = count;
        else if (r.severity === 2) severityBreakdown.priority2 = count;
        else if (r.severity === 3) severityBreakdown.priority3 = count;
        else severityBreakdown.other += count;
      });

      // 6. Top attack sources
      const topSourcesRes = await query(`
        SELECT 
          a.source_ip, 
          COUNT(*) as alert_count,
          MAX(a.timestamp) as last_seen,
          EXISTS(SELECT 1 FROM blocked_ips b WHERE b.ip_address = a.source_ip AND b.is_active = true) as is_blocked
        FROM alerts a
        GROUP BY a.source_ip
        ORDER BY alert_count DESC
        LIMIT 5
      `);
      const topAttackSources = topSourcesRes.rows.map(r => ({
        source_ip: r.source_ip,
        alert_count: parseInt(r.alert_count, 10),
        last_seen: r.last_seen,
        is_blocked: Boolean(r.is_blocked)
      }));

      // 7. Protocol distribution
      const protoRes = await query(`
        SELECT protocol, COUNT(*) as count 
        FROM alerts 
        GROUP BY protocol 
        ORDER BY count DESC
      `);
      const protocolDistribution = protoRes.rows.map(r => ({
        protocol: r.protocol,
        count: parseInt(r.count, 10)
      }));

      // 8. Alerts timeline (recent activity grouped by 4-hour windows or days)
      const timelineRes = await query(`
        SELECT 
          TO_CHAR(DATE_TRUNC('hour', timestamp), 'YYYY-MM-DD HH24:00') as time_bucket,
          COUNT(*) as count
        FROM alerts
        WHERE timestamp >= NOW() - INTERVAL '24 hours'
        GROUP BY time_bucket
        ORDER BY time_bucket ASC
      `);

      return res.json({
        totalAlerts24h,
        totalAlertsOverall,
        activeBlocksCount,
        highSeverityThreats,
        severityBreakdown,
        topAttackSources,
        protocolDistribution,
        timeline: timelineRes.rows.map(r => ({
          time: r.time_bucket,
          count: parseInt(r.count, 10)
        }))
      });
    }

    // In-memory stats fallback calculation
    const now = Date.now();
    const twentyFourHoursAgo = now - 24 * 3600 * 1000;

    const allAlerts = inMemoryStore.alerts;
    const totalAlertsOverall = allAlerts.length;
    const alerts24h = allAlerts.filter(a => new Date(a.timestamp).getTime() >= twentyFourHoursAgo);
    const totalAlerts24h = alerts24h.length;

    const activeBlocks = inMemoryStore.blocked_ips.filter(b => b.is_active);
    const activeBlocksCount = activeBlocks.length;
    const blockedIpSet = new Set(activeBlocks.map(b => b.ip_address));

    const highSeverityThreats = allAlerts.filter(a => a.severity === 1).length;

    const severityBreakdown = {
      priority1: allAlerts.filter(a => a.severity === 1).length,
      priority2: allAlerts.filter(a => a.severity === 2).length,
      priority3: allAlerts.filter(a => a.severity === 3).length,
      other: allAlerts.filter(a => a.severity > 3).length
    };

    // Top attack sources
    const countsByIp = {};
    const lastSeenByIp = {};
    allAlerts.forEach(a => {
      countsByIp[a.source_ip] = (countsByIp[a.source_ip] || 0) + 1;
      if (!lastSeenByIp[a.source_ip] || new Date(a.timestamp) > new Date(lastSeenByIp[a.source_ip])) {
        lastSeenByIp[a.source_ip] = a.timestamp;
      }
    });

    const topAttackSources = Object.keys(countsByIp)
      .map(ip => ({
        source_ip: ip,
        alert_count: countsByIp[ip],
        last_seen: lastSeenByIp[ip],
        is_blocked: blockedIpSet.has(ip)
      }))
      .sort((a, b) => b.alert_count - a.alert_count)
      .slice(0, 5);

    // Protocol distribution
    const protoCounts = {};
    allAlerts.forEach(a => {
      protoCounts[a.protocol] = (protoCounts[a.protocol] || 0) + 1;
    });
    const protocolDistribution = Object.keys(protoCounts).map(p => ({
      protocol: p,
      count: protoCounts[p]
    }));

    // Timeline
    const timelineMap = {};
    allAlerts.forEach(a => {
      const d = new Date(a.timestamp);
      const hourStr = `${d.getHours().toString().padStart(2, '0')}:00`;
      timelineMap[hourStr] = (timelineMap[hourStr] || 0) + 1;
    });
    const timeline = Object.keys(timelineMap).map(k => ({
      time: k,
      count: timelineMap[k]
    }));

    res.json({
      totalAlerts24h,
      totalAlertsOverall,
      activeBlocksCount,
      highSeverityThreats,
      severityBreakdown,
      topAttackSources,
      protocolDistribution,
      timeline
    });
  } catch (err) {
    console.error('[STATS CONTROLLER ERROR]', err);
    res.status(500).json({ error: 'Failed to compute dashboard stats', details: err.message });
  }
};
