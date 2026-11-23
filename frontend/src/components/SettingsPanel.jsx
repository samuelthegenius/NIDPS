import React from 'react';
import { Settings, ShieldCheck } from 'lucide-react';

function Row({ label, value, hint }) {
  return (
    <div className="flex items-start justify-between gap-4 py-2.5 border-b border-slate-800/60 last:border-0">
      <div>
        <div className="text-slate-200">{label}</div>
        {hint && <div className="text-[11px] text-slate-500 font-sans">{hint}</div>}
      </div>
      <div className="text-right text-sky-300">{value}</div>
    </div>
  );
}

export default function SettingsPanel({ settings }) {
  if (!settings) return <p className="text-sm text-slate-400">Loading settings…</p>;
  const minutes = (n) => (n > 0 ? `${n} min` : 'permanent');

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
      <div className="bg-[#111726] border border-slate-800 rounded-xl p-5 text-xs font-mono">
        <h3 className="flex items-center gap-2 text-sm font-semibold text-white mb-3 font-sans">
          <Settings className="w-4 h-4 text-sky-400" /> Engine configuration
        </h3>
        <Row label="Deployment mode" value={settings.mode === 'gateway' ? 'Gateway (FORWARD)' : 'Host (INPUT)'} hint="Host protects this machine; gateway protects the network routed through it." />
        <Row label="Firewall" value={settings.realFirewall ? 'LIVE iptables' : 'Simulated'} hint="Simulated mode logs the exact iptables command without running it." />
        <Row label="Demo mode" value={settings.demoMode ? 'On (simulator enabled)' : 'Off'} />
        <Row label="Block duration" value={minutes(settings.blockDurationMin)} hint="Blocks are lifted automatically after this time." />
        <Row label="Escalation rule" value={settings.escalateCount > 0 ? `${settings.escalateCount} × P2 in ${settings.escalateWindowMin} min` : 'Disabled'} hint="Repeated medium-severity alerts from one source trigger a block." />
        <Row label="Data retention" value={settings.retentionDays > 0 ? `${settings.retentionDays} days` : 'Forever'} hint="Older alerts and audit entries are deleted automatically." />
        <Row label="Database" value={settings.store === 'postgres' ? 'PostgreSQL' : 'In-memory (not persistent)'} />
        <Row label="Snort log" value={settings.watcher?.active ? 'Watching' : 'Not watching'} hint={settings.watcher?.path} />
        <Row label="HTTPS" value={settings.https ? 'Enabled' : 'Off'} />
      </div>

      <div className="bg-[#111726] border border-slate-800 rounded-xl p-5 text-xs font-mono">
        <h3 className="flex items-center gap-2 text-sm font-semibold text-white mb-1 font-sans">
          <ShieldCheck className="w-4 h-4 text-emerald-400" /> Protected addresses (never blocked)
        </h3>
        <p className="text-[11px] text-slate-500 font-sans mb-3">
          Set extra entries with <code className="text-slate-300">NIDPS_ALLOWLIST</code> in backend/.env, e.g. the gateway, DNS server and admin PCs.
        </p>
        <ul className="space-y-1">
          {settings.allowlist.map((entry) => (
            <li key={entry} className="px-2 py-1 rounded bg-[#0a0e17] border border-slate-800 text-emerald-300">{entry}</li>
          ))}
        </ul>
        <p className="text-[11px] text-slate-500 font-sans mt-4">Settings are read-only here: change backend/.env and restart NIDPS.</p>
      </div>
    </div>
  );
}
