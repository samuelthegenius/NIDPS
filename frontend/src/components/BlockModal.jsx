import React, { useState, useEffect } from 'react';
import { X, Flame, ShieldAlert, AlertTriangle } from 'lucide-react';

export default function BlockModal({ isOpen, onClose, onSubmit, initialIp = '' }) {
  const [ip, setIp] = useState('');
  const [reason, setReason] = useState('Manual administrative mitigation: Suspicious activity');
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    if (initialIp) {
      setIp(initialIp);
    } else {
      setIp('');
    }
    setError('');
  }, [initialIp, isOpen]);

  if (!isOpen) return null;

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');

    const trimmedIp = ip.trim();
    if (!trimmedIp) {
      setError('Please provide an IP address.');
      return;
    }

    // IP validation regex
    const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    const ipv6Regex = /^[0-9a-fA-F:]+$/;
    if (!ipv4Regex.test(trimmedIp) && !ipv6Regex.test(trimmedIp)) {
      setError('Invalid IP address format. Enter a valid IPv4 or IPv6 address.');
      return;
    }

    try {
      setSubmitting(true);
      await onSubmit(trimmedIp, reason.trim() || 'Manual administrative mitigation');
      onClose();
    } catch (err) {
      setError(err.message || 'Failed to block IP.');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-fade-in">
      <div className="w-full max-w-md bg-[#111726] border border-red-500/30 rounded-xl shadow-2xl overflow-hidden glow-red">
        {/* Modal Header */}
        <div className="p-4 sm:p-5 border-b border-slate-800 flex items-center justify-between bg-[#0e1422]">
          <div className="flex items-center space-x-2.5">
            <div className="p-1.5 rounded-lg bg-red-500/10 text-red-400 border border-red-500/30">
              <Flame className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
                Manual Firewall Block
              </h3>
              <p className="text-xs text-slate-400 font-sans">
                Execute iptables DROP rule and store into blocked_ips
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

        {/* Modal Form */}
        <form onSubmit={handleSubmit} className="p-5 space-y-4">
          {error && (
            <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-xs flex items-center space-x-2 font-mono">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          <div>
            <label className="block text-xs font-mono font-medium text-slate-300 uppercase tracking-wider mb-1.5">
              Target IP Address *
            </label>
            <input
              type="text"
              placeholder="e.g. 198.51.100.23 or 203.0.113.50"
              value={ip}
              onChange={(e) => setIp(e.target.value)}
              required
              className="w-full px-3.5 py-2 rounded-lg bg-[#0a0e17] border border-slate-700 text-white font-mono text-sm placeholder-slate-500 focus:outline-none focus:border-red-500 focus:ring-1 focus:ring-red-500"
            />
          </div>

          <div>
            <label className="block text-xs font-mono font-medium text-slate-300 uppercase tracking-wider mb-1.5">
              Reason / Incident Reference
            </label>
            <textarea
              rows={3}
              placeholder="Specify justification for firewall blocking rule..."
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              className="w-full px-3.5 py-2 rounded-lg bg-[#0a0e17] border border-slate-700 text-white font-sans text-xs placeholder-slate-500 focus:outline-none focus:border-red-500 focus:ring-1 focus:ring-red-500"
            />
          </div>

          <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-800 text-[11px] text-slate-400 font-mono">
            Command to execute: <span className="text-red-400">iptables -A INPUT -s {ip || '<IP>'} -j DROP</span>
          </div>

          {/* Modal Actions */}
          <div className="pt-2 flex items-center justify-end space-x-2">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 rounded-lg text-xs font-medium text-slate-300 hover:bg-slate-800 transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={submitting}
              className="px-4 py-2 rounded-lg text-xs font-medium bg-red-600 hover:bg-red-500 text-white shadow-lg shadow-red-600/30 transition-all flex items-center space-x-1.5 disabled:opacity-50"
            >
              <Flame className="w-3.5 h-3.5" />
              <span>{submitting ? 'Executing Block...' : 'Enforce Block Rule'}</span>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
