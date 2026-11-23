import React from 'react';
import { 
  ShieldAlert, 
  LayoutDashboard, 
  Radio, 
  Flame, 
  BarChart3, 
  Terminal, 
  Activity,
  CheckCircle2,
  AlertTriangle
} from 'lucide-react';

export default function Sidebar({ currentTab, setCurrentTab, systemStatus, onOpenSimulator }) {
  const navItems = [
    { id: 'dashboard', label: 'Dashboard Overview', icon: LayoutDashboard },
    { id: 'alerts', label: 'Real-Time Alert Feed', icon: Radio },
    { id: 'firewall', label: 'Firewall Management', icon: Flame },
    { id: 'analytics', label: 'Threat Analytics', icon: BarChart3 },
  ];

  return (
    <aside className="w-64 bg-[#0d131f] border-r border-slate-800 flex flex-col justify-between shrink-0 min-h-screen">
      {/* Brand Header */}
      <div>
        <div className="p-6 border-b border-slate-800/80 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="w-10 h-10 rounded-lg bg-sky-500/10 border border-sky-500/30 flex items-center justify-center text-sky-400 shadow-lg shadow-sky-500/10">
              <ShieldAlert className="w-6 h-6 text-sky-400" />
            </div>
            <div>
              <div className="flex items-center space-x-1.5">
                <span className="font-bold text-white tracking-wider text-base">NIPS</span>
                <span className="text-[10px] uppercase font-bold px-1.5 py-0.5 rounded bg-sky-500/20 text-sky-300 border border-sky-500/30">
                  SHIELD
                </span>
              </div>
              <p className="text-xs text-slate-400 font-mono">IPS / Firewall Engine</p>
            </div>
          </div>
        </div>

        {/* Navigation Links */}
        <nav className="p-4 space-y-1.5">
          <div className="px-3 py-2 text-[11px] font-semibold uppercase tracking-wider text-slate-400 font-mono">
            Navigation
          </div>
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = currentTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setCurrentTab(item.id)}
                className={`w-full flex items-center space-x-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all ${
                  isActive
                    ? 'bg-sky-500/15 text-sky-400 border border-sky-500/30 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                }`}
              >
                <Icon className={`w-4 h-4 ${isActive ? 'text-sky-400' : 'text-slate-400'}`} />
                <span>{item.label}</span>
              </button>
            );
          })}

          <div className="pt-4 px-3 py-2 text-[11px] font-semibold uppercase tracking-wider text-slate-400 font-mono">
            Testing Tools
          </div>
          <button
            onClick={onOpenSimulator}
            className="w-full flex items-center space-x-3 px-3 py-2.5 rounded-lg text-sm font-medium text-amber-400/90 bg-amber-500/10 border border-amber-500/20 hover:bg-amber-500/20 transition-all group"
          >
            <Terminal className="w-4 h-4 text-amber-400 group-hover:scale-110 transition-transform" />
            <span>Snort Attack Simulator</span>
          </button>
        </nav>
      </div>

      {/* System Status Footer */}
      <div className="p-4 border-t border-slate-800/80 bg-[#090d16]">
        <div className="text-[11px] font-mono uppercase tracking-wider text-slate-400 mb-2 flex items-center justify-between">
          <span>Engine Status</span>
          <span className="flex h-2 w-2 relative">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
          </span>
        </div>

        <div className="space-y-2 text-xs font-mono">
          <div className="flex items-center justify-between text-slate-300">
            <span className="text-slate-400">Log Watcher:</span>
            <span className="text-emerald-400 flex items-center gap-1 font-semibold">
              <CheckCircle2 className="w-3 h-3" /> ACTIVE
            </span>
          </div>
          <div className="flex items-center justify-between text-slate-300">
            <span className="text-slate-400">Database:</span>
            <span className={`font-semibold flex items-center gap-1 ${systemStatus?.databaseConnected ? 'text-emerald-400' : 'text-amber-400'}`}>
              {systemStatus?.databaseConnected ? 'PostgreSQL' : 'In-Memory DB'}
            </span>
          </div>
          <div className="flex items-center justify-between text-slate-300">
            <span className="text-slate-400">Firewall Engine:</span>
            <span className="text-sky-400 font-semibold">
              {systemStatus?.mockFirewallEnabled ? 'iptables (Mock)' : 'iptables (Kernel)'}
            </span>
          </div>
        </div>
      </div>
    </aside>
  );
}
