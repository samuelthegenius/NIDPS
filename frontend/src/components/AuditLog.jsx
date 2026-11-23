import React from 'react';
import { ScrollText } from 'lucide-react';

const ACTION_STYLES = {
  block: 'bg-red-500/15 text-red-300 border-red-500/30',
  block_refused: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
  unblock: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
  login: 'bg-sky-500/15 text-sky-300 border-sky-500/30',
  login_failed: 'bg-red-500/15 text-red-300 border-red-500/30',
  logout: 'bg-slate-800 text-slate-300 border-slate-700',
  alert_status: 'bg-violet-500/15 text-violet-300 border-violet-500/30',
};

const LABELS = {
  block: 'Blocked',
  block_refused: 'Block refused (protected)',
  unblock: 'Unblocked',
  login: 'Signed in',
  login_failed: 'Failed sign-in',
  logout: 'Signed out',
  alert_status: 'Alert triaged',
};

export default function AuditLog({ entries = [], loading }) {
  return (
    <div className="bg-[#111726] border border-slate-800 rounded-xl overflow-hidden shadow-lg">
      <div className="p-4 sm:p-5 border-b border-slate-800 flex items-center space-x-2">
        <ScrollText className="w-5 h-5 text-sky-400" />
        <h2 className="text-base font-semibold text-white">Audit Log</h2>
        <span className="px-2 py-0.5 rounded text-xs font-mono bg-slate-800 text-slate-300 border border-slate-700">{entries.length} entries</span>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs">
          <thead>
            <tr className="bg-[#0b101c] border-b border-slate-800 text-slate-400 font-mono uppercase text-[11px] tracking-wider">
              <th className="py-3 px-4">When</th>
              <th className="py-3 px-4">Who</th>
              <th className="py-3 px-4">Action</th>
              <th className="py-3 px-4">Target</th>
              <th className="py-3 px-4">Details</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 font-mono">
            {loading && entries.length === 0 ? (
              <tr><td colSpan="5" className="py-10 text-center text-slate-500">Loading…</td></tr>
            ) : entries.length === 0 ? (
              <tr><td colSpan="5" className="py-10 text-center text-slate-500">No activity recorded yet.</td></tr>
            ) : (
              entries.map((e) => (
                <tr key={e.id} className="hover:bg-slate-800/30">
                  <td className="py-2.5 px-4 text-slate-400 whitespace-nowrap">{new Date(e.timestamp).toLocaleString()}</td>
                  <td className="py-2.5 px-4 text-slate-200">{e.actor}</td>
                  <td className="py-2.5 px-4">
                    <span className={`px-2 py-0.5 rounded border text-[11px] ${ACTION_STYLES[e.action] || 'bg-slate-800 text-slate-300 border-slate-700'}`}>
                      {LABELS[e.action] || e.action}
                    </span>
                  </td>
                  <td className="py-2.5 px-4 text-slate-200">{e.target || '—'}</td>
                  <td className="py-2.5 px-4 text-slate-400 font-sans max-w-md truncate" title={e.detail || ''}>{e.detail || '—'}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
