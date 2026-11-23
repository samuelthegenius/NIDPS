import React, { useState } from 'react';
import { ShieldAlert, LogIn } from 'lucide-react';

export default function LoginScreen({ onLogin, notice }) {
  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const submit = async (e) => {
    e.preventDefault();
    setError('');
    setBusy(true);
    try {
      await onLogin(username.trim(), password);
    } catch (err) {
      setError(err.message || 'Login failed');
      setPassword('');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center p-4 bg-[#080c14]">
      <form onSubmit={submit} className="w-full max-w-sm bg-[#111726] border border-slate-800 rounded-xl shadow-2xl p-6 space-y-5">
        <div className="flex items-center space-x-3">
          <div className="w-11 h-11 rounded-lg bg-sky-500/10 border border-sky-500/30 flex items-center justify-center">
            <ShieldAlert className="w-6 h-6 text-sky-400" />
          </div>
          <div>
            <h1 className="text-lg font-bold text-white tracking-wide">NIDPS Console</h1>
            <p className="text-xs text-slate-400">Network Intrusion Detection and Prevention System</p>
          </div>
        </div>

        {notice && !error && (
          <p className="text-xs rounded-lg px-3 py-2 bg-amber-500/10 border border-amber-500/30 text-amber-300">{notice}</p>
        )}
        {error && (
          <p role="alert" className="text-xs rounded-lg px-3 py-2 bg-red-500/10 border border-red-500/30 text-red-300">
            {error}
          </p>
        )}

        <label className="block space-y-1">
          <span className="text-xs font-mono uppercase tracking-wider text-slate-400">Username</span>
          <input
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoComplete="username"
            required
            className="w-full px-3 py-2 rounded-lg bg-[#0a0e17] border border-slate-700 text-white text-sm focus:outline-none focus:border-sky-500"
          />
        </label>
        <label className="block space-y-1">
          <span className="text-xs font-mono uppercase tracking-wider text-slate-400">Password</span>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
            autoFocus
            required
            className="w-full px-3 py-2 rounded-lg bg-[#0a0e17] border border-slate-700 text-white text-sm focus:outline-none focus:border-sky-500"
          />
        </label>

        <button
          type="submit"
          disabled={busy}
          className="w-full flex items-center justify-center space-x-2 py-2 rounded-lg bg-sky-600 hover:bg-sky-500 text-white text-sm font-medium disabled:opacity-50"
        >
          <LogIn className="w-4 h-4" />
          <span>{busy ? 'Signing in…' : 'Sign in'}</span>
        </button>
        <p className="text-[11px] text-slate-500 text-center">Forgot the password? Run <code className="text-slate-300">npm run setup</code> in backend/.</p>
      </form>
    </div>
  );
}
