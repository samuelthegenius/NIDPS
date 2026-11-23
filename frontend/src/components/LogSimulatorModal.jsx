import React, { useState } from 'react';
import { X, Terminal, Zap, ShieldAlert, CheckCircle2, Play, Flame } from 'lucide-react';

export default function LogSimulatorModal({ isOpen, onClose, onInject }) {
  const [selectedPreset, setSelectedPreset] = useState('log4j');
  const [customIp, setCustomIp] = useState('');
  const [rawSnortLine, setRawSnortLine] = useState('');
  const [mode, setMode] = useState('preset'); // 'preset' or 'custom'
  const [loading, setLoading] = useState(false);
  const [lastInjected, setLastInjected] = useState(null);

  if (!isOpen) return null;

  const presets = [
    {
      id: 'log4j',
      name: 'Apache Log4j RCE (CVE-2021-44228)',
      priority: 1,
      defaultIp: '185.220.101.5',
      desc: 'High severity RCE attack. Triggers AUTOMATED firewall block.',
      color: 'border-red-500/50 bg-red-950/20 text-red-400'
    },
    {
      id: 'sqli',
      name: 'SQL Injection UNION SELECT Attempt',
      priority: 1,
      defaultIp: '45.146.165.37',
      desc: 'Web application database compromise attempt. Triggers AUTOMATED block.',
      color: 'border-red-500/50 bg-red-950/20 text-red-400'
    },
    {
      id: 'ssh_brute',
      name: 'SSH Brute Force Dictionary Attack',
      priority: 2,
      defaultIp: '192.168.1.50',
      desc: 'Medium severity credential brute force against port 22.',
      color: 'border-amber-500/50 bg-amber-950/20 text-amber-400'
    },
    {
      id: 'dns_amp',
      name: 'DNS Amplification DDoS Reflection',
      priority: 2,
      defaultIp: '198.51.100.77',
      desc: 'Distributed denial of service attempt over UDP 53.',
      color: 'border-amber-500/50 bg-amber-950/20 text-amber-400'
    },
    {
      id: 'nmap',
      name: 'Nmap Scripting Engine Recon Scan',
      priority: 3,
      defaultIp: '192.0.2.77',
      desc: 'Low severity port reconnaissance scan.',
      color: 'border-sky-500/50 bg-sky-950/20 text-sky-400'
    }
  ];

  const handleInject = async () => {
    try {
      setLoading(true);
      let payload = {};

      if (mode === 'preset') {
        const p = presets.find((x) => x.id === selectedPreset);
        payload = {
          presetKey: selectedPreset,
          customSourceIp: customIp.trim() || p.defaultIp,
          customSeverity: p.priority
        };
      } else {
        payload = {
          rawLine: rawSnortLine.trim()
        };
      }

      const res = await onInject(payload);
      setLastInjected(res);
    } catch (err) {
      alert(`Error injecting log: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm animate-fade-in">
      <div className="w-full max-w-2xl bg-[#111726] border border-sky-500/30 rounded-xl shadow-2xl overflow-hidden glow-sky flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="p-4 sm:p-5 border-b border-slate-800 flex items-center justify-between bg-[#0e1422]">
          <div className="flex items-center space-x-2.5">
            <div className="p-2 rounded-lg bg-sky-500/10 text-sky-400 border border-sky-500/30">
              <Terminal className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono flex items-center gap-2">
                <span>Snort Sensor Attack Simulator</span>
                <span className="px-2 py-0.5 rounded text-[10px] bg-sky-500/20 text-sky-300 border border-sky-500/30">
                  REAL-TIME TEST
                </span>
              </h3>
              <p className="text-xs text-slate-400 font-sans">
                Appends formatted fast-alerts into <code className="text-sky-300 font-mono">mock_snort.log</code> to test logWatcher and firewall mitigation.
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Body */}
        <div className="p-5 space-y-4 overflow-y-auto">
          {/* Mode Tabs */}
          <div className="flex bg-[#0a0e17] p-1 rounded-lg border border-slate-700 text-xs font-mono">
            <button
              onClick={() => setMode('preset')}
              className={`flex-1 py-1.5 rounded-md font-semibold transition-all ${
                mode === 'preset' ? 'bg-sky-500/20 text-sky-300 border border-sky-500/30' : 'text-slate-400'
              }`}
            >
              Preset Attack Vectors
            </button>
            <button
              onClick={() => setMode('custom')}
              className={`flex-1 py-1.5 rounded-md font-semibold transition-all ${
                mode === 'custom' ? 'bg-sky-500/20 text-sky-300 border border-sky-500/30' : 'text-slate-400'
              }`}
            >
              Raw Snort Log Line
            </button>
          </div>

          {mode === 'preset' ? (
            <div className="space-y-3">
              <label className="block text-xs font-mono font-medium text-slate-300 uppercase tracking-wider">
                Select Intrusion Signature
              </label>
              <div className="space-y-2">
                {presets.map((p) => (
                  <div
                    key={p.id}
                    onClick={() => {
                      setSelectedPreset(p.id);
                      setCustomIp(p.defaultIp);
                    }}
                    className={`p-3 rounded-lg border transition-all cursor-pointer flex items-center justify-between ${
                      selectedPreset === p.id
                        ? `${p.color} border-current ring-1 ring-current`
                        : 'bg-[#0a0e17] border-slate-800 hover:border-slate-700 text-slate-300'
                    }`}
                  >
                    <div>
                      <div className="flex items-center space-x-2">
                        <span className="font-bold text-xs">{p.name}</span>
                        <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-black/40">
                          Priority {p.priority}
                        </span>
                      </div>
                      <p className="text-[11px] text-slate-400 mt-0.5">{p.desc}</p>
                    </div>

                    <div className="text-right font-mono text-[11px] text-slate-400 hidden sm:block">
                      Default IP: <span className="text-white">{p.defaultIp}</span>
                    </div>
                  </div>
                ))}
              </div>

              {/* Custom source IP override */}
              <div className="pt-2">
                <label className="block text-xs font-mono font-medium text-slate-300 uppercase tracking-wider mb-1">
                  Attacker Source IP (Optional Override)
                </label>
                <input
                  type="text"
                  placeholder="Enter custom attacker IP"
                  value={customIp}
                  onChange={(e) => setCustomIp(e.target.value)}
                  className="w-full px-3 py-1.5 rounded-lg bg-[#0a0e17] border border-slate-700 text-white font-mono text-xs focus:outline-none focus:border-sky-500"
                />
              </div>
            </div>
          ) : (
            <div className="space-y-2">
              <label className="block text-xs font-mono font-medium text-slate-300 uppercase tracking-wider">
                Raw Snort Fast-Alert Line
              </label>
              <textarea
                rows={4}
                value={rawSnortLine}
                onChange={(e) => setRawSnortLine(e.target.value)}
                placeholder="[**] [1:1000001:1] SSH Brute Force [**] [Classification: Attempted Login] [Priority: 2] {TCP} 192.168.1.50:54321 -> 10.0.0.5:22"
                className="w-full px-3 py-2 rounded-lg bg-[#0a0e17] border border-slate-700 text-sky-300 font-mono text-xs focus:outline-none focus:border-sky-500 leading-relaxed"
              />
              <p className="text-[11px] text-slate-400 font-mono">
                Supports standard Snort format with or without leading timestamps.
              </p>
            </div>
          )}

          {/* Last injected result banner */}
          {lastInjected && (
            <div className="p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-xs font-mono text-emerald-300 space-y-1">
              <div className="flex items-center gap-1.5 font-bold">
                <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                <span>Alert Line Written to mock_snort.log</span>
              </div>
              <div className="text-[11px] text-slate-300 break-all bg-black/40 p-2 rounded border border-emerald-500/20">
                {lastInjected.injectedLine}
              </div>
              <p className="text-[10px] text-slate-400">
                The Log Watcher will parse this alert and execute automated mitigation if Priority 1.
              </p>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-slate-800 bg-[#0e1422] flex items-center justify-between">
          <span className="text-xs text-slate-400 font-mono hidden sm:inline">
            Target: <code className="text-sky-300">mock_snort.log</code>
          </span>
          <div className="flex items-center space-x-2">
            <button
              onClick={onClose}
              className="px-3.5 py-1.5 rounded-lg text-xs font-medium text-slate-300 hover:bg-slate-800 transition-colors"
            >
              Close
            </button>
            <button
              onClick={handleInject}
              disabled={loading}
              className="flex items-center space-x-1.5 px-4 py-2 rounded-lg bg-sky-600 hover:bg-sky-500 text-white text-xs font-medium shadow-lg shadow-sky-600/30 transition-all disabled:opacity-50"
            >
              <Zap className="w-4 h-4" />
              <span>{loading ? 'Writing to Log...' : 'Inject Snort Alert'}</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
