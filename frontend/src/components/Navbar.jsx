import React from 'react';
import { RefreshCw, Play, ShieldAlert, Zap, Radio } from 'lucide-react';

export default function Navbar({ 
  autoRefresh, 
  setAutoRefresh, 
  onRefresh, 
  isRefreshing, 
  onOpenSimulator, 
  stats 
}) {
  const highThreatCount = stats?.highSeverityThreats || 0;
  const threatLevel = highThreatCount > 5 ? 'CRITICAL' : highThreatCount > 0 ? 'ELEVATED' : 'NOMINAL';
  const threatColor = 
    threatLevel === 'CRITICAL' 
      ? 'bg-red-500/10 border-red-500/30 text-red-400' 
      : threatLevel === 'ELEVATED' 
        ? 'bg-amber-500/10 border-amber-500/30 text-amber-400' 
        : 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400';

  return (
    <header className="h-16 bg-[#0d131f]/90 backdrop-blur border-b border-slate-800 px-6 flex items-center justify-between sticky top-0 z-20">
      <div className="flex items-center space-x-4">
        <div>
          <h1 className="text-base font-semibold text-white tracking-wide">
            Network Intrusion Detection & Prevention Console
          </h1>
          <p className="text-xs text-slate-400 hidden sm:block">
            Automated Snort Alert Ingestion & Dynamic iptables Mitigation
          </p>
        </div>
      </div>

      <div className="flex items-center space-x-3">
        {/* Threat Level Badge */}
        <div className={`hidden md:flex items-center space-x-2 px-3 py-1 rounded-full border text-xs font-mono font-semibold ${threatColor}`}>
          <span className="h-2 w-2 rounded-full bg-current animate-pulse"></span>
          <span>THREAT LEVEL: {threatLevel}</span>
        </div>

        {/* Live Auto-Refresh Toggle */}
        <button
          onClick={() => setAutoRefresh(!autoRefresh)}
          className={`flex items-center space-x-2 px-3 py-1.5 rounded-lg text-xs font-mono border transition-all ${
            autoRefresh
              ? 'bg-sky-500/15 border-sky-500/30 text-sky-400'
              : 'bg-slate-800/60 border-slate-700 text-slate-400 hover:text-slate-200'
          }`}
          title={autoRefresh ? 'Click to pause auto-polling' : 'Click to enable real-time polling'}
        >
          <Radio className={`w-3.5 h-3.5 ${autoRefresh ? 'animate-pulse text-sky-400' : ''}`} />
          <span>LIVE {autoRefresh ? '3s' : 'OFF'}</span>
        </button>

        {/* Manual Refresh Button */}
        <button
          onClick={onRefresh}
          disabled={isRefreshing}
          className="p-2 rounded-lg bg-slate-800/60 border border-slate-700 hover:bg-slate-800 text-slate-300 hover:text-white transition-all disabled:opacity-50"
          title="Manual Refresh"
        >
          <RefreshCw className={`w-4 h-4 ${isRefreshing ? 'animate-spin text-sky-400' : ''}`} />
        </button>

        {/* Attack Simulator Trigger */}
        <button
          onClick={onOpenSimulator}
          className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-sky-600 hover:bg-sky-500 text-white text-xs font-medium font-sans shadow-md shadow-sky-600/20 transition-all"
        >
          <Zap className="w-3.5 h-3.5" />
          <span>Simulate Attack</span>
        </button>
      </div>
    </header>
  );
}
