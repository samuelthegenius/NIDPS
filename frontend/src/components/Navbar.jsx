import React from 'react';
import { RefreshCw, Zap, Radio, LogOut } from 'lucide-react';

function Badge({ className, children, title }) {
  return (
    <span title={title} className={`hidden lg:inline-flex items-center px-2 py-0.5 rounded border text-[10px] font-mono font-semibold uppercase tracking-wider ${className}`}>
      {children}
    </span>
  );
}

export default function Navbar({ live, onRefresh, isRefreshing, onOpenSimulator, stats, settings, user, onLogout }) {
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
      <div className="flex items-center space-x-3 min-w-0">
        <div className="min-w-0">
          <h1 className="text-base font-semibold text-white tracking-wide truncate">NIDPS Console</h1>
          <p className="text-xs text-slate-400 hidden sm:block truncate">Snort detection · automated iptables prevention</p>
        </div>
        {settings && (
          <div className="flex items-center gap-1.5">
            <Badge className="bg-sky-500/10 border-sky-500/30 text-sky-300" title="Deployment mode">
              {settings.mode === 'gateway' ? 'Gateway mode' : 'Host mode'}
            </Badge>
            <Badge
              className={settings.realFirewall ? 'bg-red-500/10 border-red-500/30 text-red-300' : 'bg-slate-800 border-slate-700 text-slate-300'}
              title={settings.realFirewall ? 'iptables rules are really applied' : 'iptables commands are logged, not applied'}
            >
              {settings.realFirewall ? 'Live firewall' : 'Simulated firewall'}
            </Badge>
            {settings.demoMode && <Badge className="bg-amber-500/10 border-amber-500/30 text-amber-300">Demo</Badge>}
          </div>
        )}
      </div>

      <div className="flex items-center space-x-3">
        <div className={`hidden md:flex items-center space-x-2 px-3 py-1 rounded-full border text-xs font-mono font-semibold ${threatColor}`}>
          <span className="h-2 w-2 rounded-full bg-current animate-pulse"></span>
          <span>THREAT LEVEL: {threatLevel}</span>
        </div>

        <span
          className={`flex items-center space-x-2 px-3 py-1.5 rounded-lg text-xs font-mono border ${
            live ? 'bg-sky-500/15 border-sky-500/30 text-sky-400' : 'bg-slate-800/60 border-slate-700 text-slate-400'
          }`}
          title={live ? 'Receiving live events from the server' : 'Live stream unavailable; refreshing every 15 s'}
        >
          <Radio className={`w-3.5 h-3.5 ${live ? 'animate-pulse' : ''}`} />
          <span>{live ? 'LIVE' : 'POLLING'}</span>
        </span>

        <button
          onClick={onRefresh}
          disabled={isRefreshing}
          aria-label="Refresh now"
          className="p-2 rounded-lg bg-slate-800/60 border border-slate-700 hover:bg-slate-800 text-slate-300 hover:text-white transition-all disabled:opacity-50"
          title="Refresh now"
        >
          <RefreshCw className={`w-4 h-4 ${isRefreshing ? 'animate-spin text-sky-400' : ''}`} />
        </button>

        {onOpenSimulator && (
          <button
            onClick={onOpenSimulator}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-sky-600 hover:bg-sky-500 text-white text-xs font-medium shadow-md shadow-sky-600/20 transition-all"
          >
            <Zap className="w-3.5 h-3.5" />
            <span>Simulate Attack</span>
          </button>
        )}

        <button
          onClick={onLogout}
          className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-slate-800/60 border border-slate-700 hover:bg-slate-800 text-slate-300 text-xs"
          title={`Signed in as ${user}`}
        >
          <LogOut className="w-3.5 h-3.5" />
          <span className="hidden sm:inline">Sign out</span>
        </button>
      </div>
    </header>
  );
}
