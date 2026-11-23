import React, { useState, useEffect } from 'react';

function useNow(intervalMs = 1000) {
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), intervalMs);
    return () => clearInterval(t);
  }, [intervalMs]);
  return now;
}

function remaining(expiresAt, now) {
  if (!expiresAt) return 'Permanent';
  const ms = new Date(expiresAt).getTime() - now;
  if (ms <= 0) return 'Expiring…';
  const total = Math.floor(ms / 1000);
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;
  return h > 0 ? `${h}h ${String(m).padStart(2, '0')}m` : `${m}:${String(s).padStart(2, '0')}`;
}
import { 
  Flame, 
  ShieldCheck, 
  Plus, 
  Unlock, 
  Clock, 
  Search, 
  CheckCircle2, 
  AlertCircle 
} from 'lucide-react';

export default function FirewallTable({
  blockedIps = [],
  onUnblock,
  onOpenBlockModal,
  loading = false,
  showActiveOnly,
  setShowActiveOnly
}) {
  const [search, setSearch] = useState('');
  const [unblockingIp, setUnblockingIp] = useState(null);
  const now = useNow();

  const handleUnblock = async (ip) => {
    setUnblockingIp(ip);
    try {
      await onUnblock(ip);
    } catch {
      // the toast already reports the error
    } finally {
      setUnblockingIp(null);
    }
  };

  const filteredIps = blockedIps.filter((b) => {
    if (!b) return false;
    const matchSearch =
      b.ip_address.toLowerCase().includes(search.toLowerCase()) ||
      b.block_reason.toLowerCase().includes(search.toLowerCase());
    return matchSearch;
  });

  const formatTimestamp = (ts) => {
    if (!ts) return '—';
    try {
      const d = new Date(ts);
      return (
        d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) +
        ' ' +
        d.toLocaleDateString([], { month: 'short', day: 'numeric', year: 'numeric' })
      );
    } catch {
      return ts;
    }
  };

  return (
    <div className="bg-[#111726] border border-slate-800 rounded-xl overflow-hidden shadow-lg">
      {/* Table Header */}
      <div className="p-4 sm:p-5 border-b border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2">
            <Flame className="w-5 h-5 text-red-400" />
            <h2 className="text-base font-semibold text-white tracking-wide">
              Active Firewall Blocks (iptables DROP Rules)
            </h2>
            <span className="px-2 py-0.5 rounded text-xs font-mono bg-red-500/15 text-red-300 border border-red-500/30">
              {filteredIps.filter(b => b.is_active).length} active
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            IP addresses dynamically or manually blocked by the prevention engine.
          </p>
        </div>

        {/* Action Controls */}
        <div className="flex flex-wrap items-center gap-3">
          {/* Active / All Toggle */}
          <div className="flex bg-[#0a0e17] p-0.5 rounded-lg border border-slate-700 text-xs font-mono">
            <button
              onClick={() => setShowActiveOnly(true)}
              className={`px-3 py-1 rounded-md transition-all ${
                showActiveOnly
                  ? 'bg-sky-500/20 text-sky-300 font-semibold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Active Only
            </button>
            <button
              onClick={() => setShowActiveOnly(false)}
              className={`px-3 py-1 rounded-md transition-all ${
                !showActiveOnly
                  ? 'bg-sky-500/20 text-sky-300 font-semibold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              All History
            </button>
          </div>

          {/* Search Filter */}
          <div className="relative">
            <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search IP or reason..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-9 pr-3 py-1.5 text-xs rounded-lg bg-[#0a0e17] border border-slate-700 text-slate-200 placeholder-slate-500 focus:outline-none focus:border-sky-500 w-44"
            />
          </div>

          {/* Manual Block Button */}
          <button
            onClick={() => onOpenBlockModal('')}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-red-600 hover:bg-red-500 text-white text-xs font-medium transition-all shadow-md shadow-red-600/20"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Manual Block IP</span>
          </button>
        </div>
      </div>

      {/* Table Data */}
      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse text-xs">
          <thead>
            <tr className="bg-[#0b101c] border-b border-slate-800 text-slate-400 font-mono uppercase text-[11px] tracking-wider">
              <th className="py-3 px-4">Blocked IP</th>
              <th className="py-3 px-4">Status</th>
              <th className="py-3 px-4">Reason / Rule Trigger</th>
              <th className="py-3 px-4">By</th>
              <th className="py-3 px-4">Blocked At</th>
              <th className="py-3 px-4">{showActiveOnly ? 'Expires In' : 'Unblocked At'}</th>
              <th className="py-3 px-4 text-right">Firewall Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 font-mono">
            {loading ? (
              <tr>
                <td colSpan="7" className="py-12 text-center text-slate-500">
                  <div className="flex flex-col items-center justify-center space-y-2">
                    <div className="w-6 h-6 border-2 border-red-500 border-t-transparent rounded-full animate-spin"></div>
                    <span>Loading firewall state...</span>
                  </div>
                </td>
              </tr>
            ) : filteredIps.length === 0 ? (
              <tr>
                <td colSpan="7" className="py-12 text-center text-slate-500">
                  <div className="flex flex-col items-center justify-center space-y-2">
                    <ShieldCheck className="w-8 h-8 text-emerald-500/70" />
                    <span>No IP addresses currently blocked.</span>
                  </div>
                </td>
              </tr>
            ) : (
              filteredIps.map((entry) => {
                const isCurrentlyUnblocking = unblockingIp === entry.ip_address;
                return (
                  <tr
                    key={entry.id || entry.ip_address}
                    className={`transition-colors ${
                      entry.is_active ? 'hover:bg-slate-800/30' : 'opacity-60 bg-slate-900/40'
                    }`}
                  >
                    {/* IP */}
                    <td className="py-3 px-4 whitespace-nowrap">
                      <span className="font-bold text-sm text-slate-100 px-2 py-0.5 rounded bg-slate-800 border border-slate-700">
                        {entry.ip_address}
                      </span>
                    </td>

                    {/* Status */}
                    <td className="py-3 px-4 whitespace-nowrap">
                      {entry.is_active ? (
                        <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-red-500/20 text-red-400 border border-red-500/40 glow-red">
                          <span className="h-1.5 w-1.5 rounded-full bg-red-400 animate-pulse"></span>
                          ENFORCED
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-slate-800 text-slate-400 border border-slate-700">
                          RELEASED
                        </span>
                      )}
                    </td>

                    {/* Reason */}
                    <td className="py-3 px-4 text-slate-300 font-sans max-w-sm truncate" title={entry.block_reason}>
                      {entry.block_reason}
                    </td>

                    {/* Who */}
                    <td className="py-3 px-4 text-slate-400 whitespace-nowrap">
                      {entry.created_by === 'system' ? 'Automatic' : entry.created_by || '—'}
                    </td>

                    {/* Blocked At */}
                    <td className="py-3 px-4 text-slate-400 whitespace-nowrap">
                      <div className="flex items-center space-x-1.5">
                        <Clock className="w-3.5 h-3.5 text-slate-600" />
                        <span>{formatTimestamp(entry.timestamp)}</span>
                      </div>
                    </td>

                    {/* Expiry countdown (active) or unblock time (history) */}
                    <td className="py-3 px-4 text-slate-400 whitespace-nowrap tabular-nums">
                      {entry.is_active ? remaining(entry.expires_at, now) : formatTimestamp(entry.unblocked_at)}
                    </td>

                    {/* Unblock Action Button */}
                    <td className="py-3 px-4 text-right whitespace-nowrap">
                      {entry.is_active ? (
                        <button
                          onClick={() => handleUnblock(entry.ip_address)}
                          disabled={isCurrentlyUnblocking}
                          className="inline-flex items-center gap-1 text-xs px-3 py-1 rounded font-medium bg-emerald-600/80 hover:bg-emerald-600 text-white transition-all shadow-sm disabled:opacity-50"
                          title="Remove iptables DROP rule and restore traffic"
                        >
                          <Unlock className={`w-3.5 h-3.5 ${isCurrentlyUnblocking ? 'animate-spin' : ''}`} />
                          <span>{isCurrentlyUnblocking ? 'Unblocking...' : 'Unblock'}</span>
                        </button>
                      ) : (
                        <button
                          onClick={() => onOpenBlockModal(entry.ip_address)}
                          className="inline-flex items-center gap-1 text-xs px-2.5 py-1 rounded font-medium bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition-all"
                          title="Re-block this IP"
                        >
                          <Flame className="w-3 h-3 text-red-400" /> Re-block
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
    </div>
  );
}
