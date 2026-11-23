import React from 'react';
import { 
  BarChart3, 
  ShieldAlert, 
  Flame, 
  Layers, 
  TrendingUp, 
  Clock, 
  ArrowRight 
} from 'lucide-react';

export default function StatsCharts({ stats, onBlockIp, onNavigate }) {
  const topSources = stats?.topAttackSources || [];
  const sevBreakdown = stats?.severityBreakdown || { priority1: 0, priority2: 0, priority3: 0, other: 0 };
  const protoDist = stats?.protocolDistribution || [];
  const timeline = stats?.timeline || [];

  const totalSev = (sevBreakdown.priority1 + sevBreakdown.priority2 + sevBreakdown.priority3 + sevBreakdown.other) || 1;
  const p1Pct = Math.round((sevBreakdown.priority1 / totalSev) * 100);
  const p2Pct = Math.round((sevBreakdown.priority2 / totalSev) * 100);
  const p3Pct = Math.round((sevBreakdown.priority3 / totalSev) * 100);

  const totalProto = protoDist.reduce((acc, p) => acc + p.count, 0) || 1;

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
      {/* 1. Threat Severity Breakdown */}
      <div className="bg-[#111726] border border-slate-800 rounded-xl p-5 shadow-lg flex flex-col justify-between">
        <div>
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center space-x-2">
              <ShieldAlert className="w-4 h-4 text-sky-400" />
              <h3 className="text-sm font-semibold text-white tracking-wide">
                Severity Distribution
              </h3>
            </div>
            <span className="text-[11px] font-mono text-slate-400">Snort Priorities</span>
          </div>

          <div className="space-y-4 font-mono text-xs">
            {/* Priority 1 */}
            <div>
              <div className="flex items-center justify-between mb-1.5">
                <span className="text-red-400 font-bold flex items-center gap-1.5">
                  <span className="h-2 w-2 rounded-full bg-red-400"></span> Priority 1 (High Threat)
                </span>
                <span className="text-white font-bold">{sevBreakdown.priority1} ({p1Pct}%)</span>
              </div>
              <div className="w-full h-2 rounded-full bg-slate-800 overflow-hidden">
                <div
                  className="h-full bg-red-500 rounded-full transition-all duration-500"
                  style={{ width: `${p1Pct}%` }}
                ></div>
              </div>
            </div>

            {/* Priority 2 */}
            <div>
              <div className="flex items-center justify-between mb-1.5">
                <span className="text-amber-400 font-semibold flex items-center gap-1.5">
                  <span className="h-2 w-2 rounded-full bg-amber-400"></span> Priority 2 (Medium Threat)
                </span>
                <span className="text-white font-semibold">{sevBreakdown.priority2} ({p2Pct}%)</span>
              </div>
              <div className="w-full h-2 rounded-full bg-slate-800 overflow-hidden">
                <div
                  className="h-full bg-amber-500 rounded-full transition-all duration-500"
                  style={{ width: `${p2Pct}%` }}
                ></div>
              </div>
            </div>

            {/* Priority 3 */}
            <div>
              <div className="flex items-center justify-between mb-1.5">
                <span className="text-sky-400 font-semibold flex items-center gap-1.5">
                  <span className="h-2 w-2 rounded-full bg-sky-400"></span> Priority 3 (Low Threat)
                </span>
                <span className="text-white font-semibold">{sevBreakdown.priority3} ({p3Pct}%)</span>
              </div>
              <div className="w-full h-2 rounded-full bg-slate-800 overflow-hidden">
                <div
                  className="h-full bg-sky-400 rounded-full transition-all duration-500"
                  style={{ width: `${p3Pct}%` }}
                ></div>
              </div>
            </div>
          </div>
        </div>

        <div className="mt-5 p-3 rounded-lg bg-[#0b101c] border border-slate-800 text-[11px] text-slate-400 font-mono">
          <span className="text-red-400 font-semibold">Policy:</span> Priority 1 threats trigger automatic prevention (iptables DROP).
        </div>
      </div>

      {/* 2. Top Attack Sources */}
      <div className="bg-[#111726] border border-slate-800 rounded-xl p-5 shadow-lg flex flex-col justify-between">
        <div>
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center space-x-2">
              <Flame className="w-4 h-4 text-red-400" />
              <h3 className="text-sm font-semibold text-white tracking-wide">
                Top Attack Origin IPs
              </h3>
            </div>
            <button
              onClick={() => onNavigate && onNavigate('firewall')}
              className="text-xs text-sky-400 hover:text-sky-300 flex items-center gap-1 font-mono"
            >
              <span>Manage Rules</span>
              <ArrowRight className="w-3 h-3" />
            </button>
          </div>

          <div className="space-y-2.5 font-mono text-xs">
            {topSources.length === 0 ? (
              <p className="text-slate-500 py-6 text-center">No attack sources recorded yet.</p>
            ) : (
              topSources.map((item, idx) => (
                <div
                  key={idx}
                  className="flex items-center justify-between p-2.5 rounded-lg bg-[#0b101c] border border-slate-800 hover:border-slate-700 transition-colors"
                >
                  <div className="flex items-center space-x-2.5">
                    <span className="text-slate-500 font-bold text-[11px] w-4">#{idx + 1}</span>
                    <span className="text-slate-200 font-semibold">{item.source_ip}</span>
                  </div>

                  <div className="flex items-center space-x-2">
                    <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 text-[11px]">
                      {item.alert_count} hits
                    </span>

                    {item.is_blocked ? (
                      <span className="text-[10px] uppercase font-bold px-2 py-0.5 rounded bg-red-500/20 text-red-400 border border-red-500/30">
                        Blocked
                      </span>
                    ) : (
                      <button
                        onClick={() => onBlockIp(item.source_ip, `Mitigation for top attack source (${item.alert_count} hits)`)}
                        className="text-[10px] uppercase font-bold px-2 py-0.5 rounded bg-red-600/80 hover:bg-red-600 text-white transition-all"
                      >
                        Block
                      </button>
                    )}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        <div className="mt-4 text-[11px] text-slate-500 font-mono text-right">
          Ranked by alert volume
        </div>
      </div>

      {/* 3. Protocol Breakdown & Threat Activity */}
      <div className="bg-[#111726] border border-slate-800 rounded-xl p-5 shadow-lg flex flex-col justify-between">
        <div>
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center space-x-2">
              <Layers className="w-4 h-4 text-emerald-400" />
              <h3 className="text-sm font-semibold text-white tracking-wide">
                Protocol & Traffic Breakdown
              </h3>
            </div>
            <span className="text-[11px] font-mono text-slate-400">Captured Packets</span>
          </div>

          <div className="space-y-3 font-mono text-xs">
            {protoDist.map((p, idx) => {
              const pct = Math.round((p.count / totalProto) * 100);
              const color =
                p.protocol === 'TCP' ? 'bg-sky-500' : p.protocol === 'UDP' ? 'bg-amber-500' : 'bg-emerald-500';
              return (
                <div key={idx}>
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-slate-300 font-semibold">{p.protocol}</span>
                    <span className="text-slate-400">{p.count} alerts ({pct}%)</span>
                  </div>
                  <div className="w-full h-2 rounded-full bg-slate-800 overflow-hidden">
                    <div
                      className={`h-full ${color} rounded-full transition-all duration-500`}
                      style={{ width: `${pct}%` }}
                    ></div>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Timeline spark preview */}
          {timeline.length > 0 && (
            <div className="mt-6 pt-4 border-t border-slate-800">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
                  <TrendingUp className="w-3.5 h-3.5 text-sky-400" /> Attack Velocity Trend
                </span>
                <span className="text-[11px] font-mono text-slate-500">{timeline.length} time slots</span>
              </div>
              <div className="flex items-end gap-1.5 h-12 pt-2">
                {timeline.slice(-10).map((t, idx) => {
                  const maxCount = Math.max(...timeline.map((x) => x.count), 1);
                  const hPct = Math.max(15, Math.round((t.count / maxCount) * 100));
                  return (
                    <div
                      key={idx}
                      className="flex-1 bg-sky-500/30 hover:bg-sky-400 rounded-t transition-all group relative cursor-pointer"
                      style={{ height: `${hPct}%` }}
                      title={`${t.time}: ${t.count} alerts`}
                    ></div>
                  );
                })}
              </div>
            </div>
          )}
        </div>

        <div className="mt-4 p-3 rounded-lg bg-[#0b101c] border border-slate-800 text-[11px] text-slate-400 font-mono flex items-center justify-between">
          <span>Active Snort Sensors: 1</span>
          <span className="text-emerald-400 font-semibold">Status: INLINE</span>
        </div>
      </div>
    </div>
  );
}
