import React from 'react';
import { 
  ShieldAlert, 
  Flame, 
  Search, 
  ChevronLeft, 
  ChevronRight, 
  Clock, 
  ShieldCheck, 
  AlertTriangle 
} from 'lucide-react';

export default function AlertsTable({
  alerts = [],
  pagination = { page: 1, limit: 15, total: 0, totalPages: 1 },
  onPageChange,
  severityFilter,
  setSeverityFilter,
  searchTerm,
  setSearchTerm,
  onBlockIp,
  onTriage,
  blockedIpsSet = new Set(),
  loading = false
}) {
  const getSeverityBadge = (sev) => {
    switch (sev) {
      case 1:
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-mono font-bold bg-red-500/20 text-red-400 border border-red-500/40 glow-red">
            <span className="h-1.5 w-1.5 rounded-full bg-red-400 animate-ping"></span>
            PRIORITY 1 (HIGH)
          </span>
        );
      case 2:
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-mono font-semibold bg-amber-500/15 text-amber-400 border border-amber-500/30">
            PRIORITY 2 (MED)
          </span>
        );
      case 3:
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-mono font-semibold bg-sky-500/15 text-sky-400 border border-sky-500/30">
            PRIORITY 3 (LOW)
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-mono bg-slate-800 text-slate-400 border border-slate-700">
            PRIORITY {sev || 'INFO'}
          </span>
        );
    }
  };

  const getRowHighlight = (sev) => {
    if (sev === 1) return 'bg-red-950/15 hover:bg-red-950/25 border-l-4 border-l-red-500';
    if (sev === 2) return 'hover:bg-slate-800/40 border-l-4 border-l-amber-500/60';
    return 'hover:bg-slate-800/30 border-l-4 border-l-transparent';
  };

  const formatTimestamp = (ts) => {
    try {
      const date = new Date(ts);
      return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) + ' ' + date.toLocaleDateString([], { month: 'short', day: 'numeric' });
    } catch {
      return ts;
    }
  };

  return (
    <div className="bg-[#111726] border border-slate-800 rounded-xl overflow-hidden shadow-lg">
      {/* Header & Controls */}
      <div className="p-4 sm:p-5 border-b border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2">
            <h2 className="text-base font-semibold text-white tracking-wide">
              Snort Fast-Alert Feed
            </h2>
            <span className="px-2 py-0.5 rounded text-xs font-mono bg-slate-800 text-slate-300 border border-slate-700">
              {pagination.total} records
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Real-time intrusion alerts parsed from the Snort fast-alert log
          </p>
        </div>

        {/* Filter and Search */}
        <div className="flex flex-wrap items-center gap-3">
          {/* Search Box */}
          <div className="relative">
            <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search IP or alert..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="pl-9 pr-3 py-1.5 text-xs rounded-lg bg-[#0a0e17] border border-slate-700 text-slate-200 placeholder-slate-500 focus:outline-none focus:border-sky-500 w-44 sm:w-56"
            />
          </div>

          {/* Severity Selector */}
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="px-3 py-1.5 text-xs rounded-lg bg-[#0a0e17] border border-slate-700 text-slate-200 focus:outline-none focus:border-sky-500 font-mono"
          >
            <option value="">All Severities</option>
            <option value="1">Priority 1 (High)</option>
            <option value="2">Priority 2 (Medium)</option>
            <option value="3">Priority 3 (Low)</option>
          </select>
        </div>
      </div>

      {/* Alerts Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse text-xs">
          <thead>
            <tr className="bg-[#0b101c] border-b border-slate-800 text-slate-400 font-mono uppercase text-[11px] tracking-wider">
              <th className="py-3 px-4">Severity</th>
              <th className="py-3 px-4">Timestamp</th>
              <th className="py-3 px-4">Source IP</th>
              <th className="py-3 px-4">Destination IP</th>
              <th className="py-3 px-4">Protocol</th>
              <th className="py-3 px-4">Alert Description</th>
              <th className="py-3 px-4">Status</th>
              <th className="py-3 px-4 text-right">Mitigation</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 font-mono">
            {loading ? (
              <tr>
                <td colSpan="8" className="py-12 text-center text-slate-500">
                  <div className="flex flex-col items-center justify-center space-y-2">
                    <div className="w-6 h-6 border-2 border-sky-500 border-t-transparent rounded-full animate-spin"></div>
                    <span>Streaming alerts from engine...</span>
                  </div>
                </td>
              </tr>
            ) : alerts.length === 0 ? (
              <tr>
                <td colSpan="8" className="py-12 text-center text-slate-500">
                  <div className="flex flex-col items-center justify-center space-y-2">
                    <ShieldCheck className="w-8 h-8 text-slate-600" />
                    <span>No intrusion alerts matching criteria.</span>
                  </div>
                </td>
              </tr>
            ) : (
              alerts.map((alert) => {
                const isBlocked = blockedIpsSet.has(alert.source_ip) || alert.status === 'blocked';
                return (
                  <tr
                    key={alert.id}
                    className={`transition-colors ${getRowHighlight(alert.severity)}`}
                  >
                    {/* Severity */}
                    <td className="py-3 px-4 whitespace-nowrap">
                      {getSeverityBadge(alert.severity)}
                    </td>

                    {/* Timestamp */}
                    <td className="py-3 px-4 text-slate-400 whitespace-nowrap">
                      <div className="flex items-center space-x-1.5">
                        <Clock className="w-3.5 h-3.5 text-slate-600" />
                        <span>{formatTimestamp(alert.timestamp)}</span>
                      </div>
                    </td>

                    {/* Source IP */}
                    <td className="py-3 px-4 font-bold text-slate-200 whitespace-nowrap">
                      <span className="px-2 py-0.5 rounded bg-slate-800/80 border border-slate-700/60">
                        {alert.source_ip}
                      </span>
                    </td>

                    {/* Destination IP */}
                    <td className="py-3 px-4 text-slate-400 whitespace-nowrap">
                      {alert.dest_ip}
                    </td>

                    {/* Protocol */}
                    <td className="py-3 px-4 whitespace-nowrap">
                      <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-slate-800 text-slate-300 border border-slate-700">
                        {alert.protocol}
                      </span>
                    </td>

                    {/* Message */}
                    <td className="py-3 px-4 text-slate-200 font-sans max-w-xs sm:max-w-md truncate" title={alert.alert_message}>
                      {alert.alert_message}
                    </td>

                    {/* Status */}
                    <td className="py-3 px-4 whitespace-nowrap">
                      <span
                        className={`inline-block px-2 py-0.5 rounded text-[11px] font-semibold uppercase ${
                          alert.status === 'blocked'
                            ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                            : alert.status === 'investigating'
                              ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                              : alert.status === 'resolved'
                                ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                                : alert.status === 'false_positive'
                                  ? 'bg-violet-500/15 text-violet-300 border border-violet-500/30'
                                  : 'bg-slate-800 text-slate-400 border border-slate-700'
                        }`}
                      >
                        {alert.status.replace('_', ' ')}
                      </span>
                    </td>

                    {/* Triage + Quick Action Buttons */}
                    <td className="py-3 px-4 text-right whitespace-nowrap space-x-1.5">
                      {onTriage && (alert.status === 'unresolved' || alert.status === 'investigating') && (
                        <>
                          <button
                            onClick={() => onTriage(alert.id, 'resolved')}
                            className="text-[11px] px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-emerald-300 border border-slate-700"
                            title="Mark as handled"
                          >
                            Resolve
                          </button>
                          <button
                            onClick={() => onTriage(alert.id, 'false_positive')}
                            className="text-[11px] px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-violet-300 border border-slate-700"
                            title="Not a real attack"
                          >
                            False +
                          </button>
                        </>
                      )}
                      {isBlocked ? (
                        <span className="inline-flex items-center gap-1 text-[11px] text-red-400 font-semibold px-2 py-1 rounded bg-red-500/10 border border-red-500/20">
                          <Flame className="w-3 h-3" /> BLOCKED
                        </span>
                      ) : (
                        <button
                          onClick={() => onBlockIp(alert.source_ip, `Manual block from alert: ${alert.alert_message}`)}
                          className="inline-flex items-center gap-1 text-[11px] px-2.5 py-1 rounded font-medium bg-red-600/80 hover:bg-red-600 text-white transition-all shadow-sm"
                          title="Block this source IP immediately"
                        >
                          <Flame className="w-3 h-3" /> Block IP
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination Controls */}
      <div className="p-4 border-t border-slate-800 bg-[#0d131f] flex items-center justify-between text-xs text-slate-400 font-mono">
        <div>
          Showing page <span className="text-white font-semibold">{pagination.page}</span> of{' '}
          <span className="text-white font-semibold">{pagination.totalPages}</span>
        </div>

        <div className="flex items-center space-x-2">
          <button
            onClick={() => onPageChange(pagination.page - 1)}
            disabled={pagination.page <= 1}
            className="flex items-center space-x-1 px-3 py-1.5 rounded-lg bg-slate-800 border border-slate-700 hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed transition-all text-slate-200"
          >
            <ChevronLeft className="w-3.5 h-3.5" />
            <span>Previous</span>
          </button>
          <button
            onClick={() => onPageChange(pagination.page + 1)}
            disabled={pagination.page >= pagination.totalPages}
            className="flex items-center space-x-1 px-3 py-1.5 rounded-lg bg-slate-800 border border-slate-700 hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed transition-all text-slate-200"
          >
            <span>Next</span>
            <ChevronRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>
    </div>
  );
}
