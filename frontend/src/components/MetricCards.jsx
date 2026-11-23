import React from 'react';
import { ShieldAlert, Flame, AlertOctagon, Activity, ArrowUpRight } from 'lucide-react';

export default function MetricCards({ stats, settings, onNavigate }) {
  const totalAlerts = stats?.totalAlerts24h ?? 0;
  const activeBlocks = stats?.activeBlocksCount ?? 0;
  const highThreats = stats?.highSeverityThreats ?? 0;
  const totalOverall = stats?.totalAlertsOverall ?? 0;

  const cards = [
    {
      title: 'Total Alerts (24h)',
      value: totalAlerts,
      subtitle: `${totalOverall} total captured`,
      icon: ShieldAlert,
      color: 'text-sky-400',
      bgColor: 'bg-sky-500/10',
      borderColor: 'border-sky-500/20',
      tab: 'alerts'
    },
    {
      title: 'Active Blocks',
      value: activeBlocks,
      subtitle: 'Enforced via iptables DROP',
      icon: Flame,
      color: 'text-amber-400',
      bgColor: 'bg-amber-500/10',
      borderColor: 'border-amber-500/20',
      tab: 'firewall'
    },
    {
      title: 'High Severity Threats',
      value: highThreats,
      subtitle: 'Priority 1 (Auto-mitigated)',
      icon: AlertOctagon,
      color: 'text-red-400',
      bgColor: 'bg-red-500/10',
      borderColor: 'border-red-500/20',
      tab: 'alerts'
    },
    {
      title: 'Prevention Engine Status',
      value: settings?.watcher?.active === false ? 'STOPPED' : 'ACTIVE',
      subtitle: settings
        ? `${settings.mode === 'gateway' ? 'Gateway' : 'Host'} mode · ${settings.realFirewall ? 'live' : 'simulated'} firewall`
        : 'Continuous Snort monitoring',
      icon: Activity,
      color: 'text-emerald-400',
      bgColor: 'bg-emerald-500/10',
      borderColor: 'border-emerald-500/20',
      tab: 'dashboard'
    }
  ];

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
      {cards.map((card, idx) => {
        const Icon = card.icon;
        return (
          <div
            key={idx}
            onClick={() => onNavigate && onNavigate(card.tab)}
            className={`p-5 rounded-xl bg-[#111726] border ${card.borderColor} shadow-sm hover:border-slate-600 transition-all cursor-pointer relative overflow-hidden group`}
          >
            {/* Background Glow */}
            <div className={`absolute top-0 right-0 w-28 h-28 -mr-6 -mt-6 rounded-full blur-2xl opacity-15 ${card.bgColor}`}></div>

            <div className="flex items-center justify-between mb-3">
              <span className="text-xs font-medium uppercase tracking-wider text-slate-400 font-mono">
                {card.title}
              </span>
              <div className={`p-2 rounded-lg ${card.bgColor} ${card.color} border ${card.borderColor}`}>
                <Icon className="w-4 h-4" />
              </div>
            </div>

            <div className="flex items-baseline justify-between">
              <div className="text-2xl font-bold font-mono tracking-tight text-white group-hover:text-sky-300 transition-colors">
                {card.value}
              </div>
              <ArrowUpRight className="w-4 h-4 text-slate-600 group-hover:text-slate-300 transition-colors" />
            </div>

            <p className="text-xs text-slate-400 mt-1 font-mono">
              {card.subtitle}
            </p>
          </div>
        );
      })}
    </div>
  );
}
