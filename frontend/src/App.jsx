import React, { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import Sidebar from './components/Sidebar';
import Navbar from './components/Navbar';
import MetricCards from './components/MetricCards';
import AlertsTable from './components/AlertsTable';
import FirewallTable from './components/FirewallTable';
import StatsCharts from './components/StatsCharts';
import BlockModal from './components/BlockModal';
import LogSimulatorModal from './components/LogSimulatorModal';
import LoginScreen from './components/LoginScreen';
import AuditLog from './components/AuditLog';
import SettingsPanel from './components/SettingsPanel';
import * as api from './services/api';
import { ShieldCheck, AlertCircle, Info, Zap } from 'lucide-react';

const PAGE_SIZE = 12;
const FALLBACK_POLL_MS = 15000;

export default function App() {
  // ---- Session -------------------------------------------------------------
  const [auth, setAuth] = useState({ state: 'checking', user: null, notice: '' });
  const authed = auth.state === 'in';

  useEffect(() => {
    api.onUnauthorized(() =>
      setAuth((prev) => (prev.state === 'in' ? { state: 'out', user: null, notice: 'Your session ended. Please sign in again.' } : prev))
    );
    api
      .me()
      .then((r) => setAuth({ state: 'in', user: r.user, notice: '' }))
      .catch(() => setAuth({ state: 'out', user: null, notice: '' }));
  }, []);

  const handleLogin = async (username, password) => {
    const r = await api.login(username, password);
    setAuth({ state: 'in', user: r.user, notice: '' });
  };
  const handleLogout = async () => {
    await api.logout().catch(() => {});
    setAuth({ state: 'out', user: null, notice: 'You have signed out.' });
  };

  // ---- View state ------------------------------------------------------------
  const [currentTab, setCurrentTab] = useState('dashboard');
  const [query, setQuery] = useState({ page: 1, severity: '', search: '' });
  const [searchInput, setSearchInput] = useState('');
  const [showActiveOnly, setShowActiveOnly] = useState(true);
  const [live, setLive] = useState(false);
  const [isRefreshing, setIsRefreshing] = useState(false);

  // ---- Data ------------------------------------------------------------------
  const [alerts, setAlerts] = useState([]);
  const [pagination, setPagination] = useState({ page: 1, limit: PAGE_SIZE, total: 0, totalPages: 1 });
  const [blockedIps, setBlockedIps] = useState([]);
  const [stats, setStats] = useState(null);
  const [settings, setSettings] = useState(null);
  const [audit, setAudit] = useState([]);
  const [loaded, setLoaded] = useState(false);

  // ---- Modals & toast ---------------------------------------------------------
  const [isBlockModalOpen, setIsBlockModalOpen] = useState(false);
  const [modalInitialIp, setModalInitialIp] = useState('');
  const [isSimulatorOpen, setIsSimulatorOpen] = useState(false);
  const [toast, setToast] = useState(null);
  const toastTimer = useRef(null);
  const showToast = useCallback((message, type = 'success') => {
    clearTimeout(toastTimer.current);
    setToast({ message, type });
    toastTimer.current = setTimeout(() => setToast(null), 4500);
  }, []);

  const blockedIpsSet = useMemo(() => new Set(blockedIps.filter((b) => b.is_active).map((b) => b.ip_address)), [blockedIps]);

  // One function loads everything the current view needs.
  const refresh = useCallback(async () => {
    const [a, b, s, st, au] = await Promise.allSettled([
      api.fetchAlerts({ page: query.page, limit: PAGE_SIZE, severity: query.severity, search: query.search }),
      api.fetchBlocked(showActiveOnly),
      api.fetchStats(),
      api.fetchSettings(),
      currentTab === 'audit' ? api.fetchAudit() : Promise.resolve(null),
    ]);
    if (a.status === 'fulfilled') {
      setAlerts(a.value.data || []);
      setPagination(a.value.pagination);
    }
    if (b.status === 'fulfilled') setBlockedIps(b.value.data || []);
    if (s.status === 'fulfilled') setStats(s.value);
    if (st.status === 'fulfilled') setSettings(st.value);
    if (au.status === 'fulfilled' && au.value) setAudit(au.value.data || []);
    setLoaded(true);
  }, [query, showActiveOnly, currentTab]);

  // Keep the latest refresh in a ref so timers and the event stream always call the current one.
  const refreshRef = useRef(refresh);
  refreshRef.current = refresh;

  useEffect(() => {
    if (authed) refresh();
  }, [authed, refresh]);

  // Debounce the search box into the query.
  useEffect(() => {
    const t = setTimeout(() => setQuery((q) => (q.search === searchInput ? q : { ...q, search: searchInput, page: 1 })), 350);
    return () => clearTimeout(t);
  }, [searchInput]);

  // Live updates: refresh shortly after a server event. Throttled, not debounced: during a
  // sustained attack (many events per second) the dashboard still refreshes every 250 ms
  // instead of waiting for the attack to stop.
  useEffect(() => {
    if (!authed) return undefined;
    let pending = null;
    const close = api.subscribeEvents(
      (type, payload) => {
        if (type === 'block' && payload?.created_by === 'system') showToast(`Auto-blocked ${payload.ip_address}`, 'error');
        if (pending) return;
        pending = setTimeout(() => {
          pending = null;
          refreshRef.current();
        }, 250);
      },
      setLive
    );
    return () => {
      clearTimeout(pending);
      close();
      setLive(false);
    };
  }, [authed, showToast]);

  // Fallback polling, in case the live stream is blocked by a proxy.
  useEffect(() => {
    if (!authed) return undefined;
    const t = setInterval(() => refreshRef.current(), FALLBACK_POLL_MS);
    return () => clearInterval(t);
  }, [authed]);

  const handleManualRefresh = async () => {
    setIsRefreshing(true);
    await refresh();
    setIsRefreshing(false);
  };

  // ---- Actions ------------------------------------------------------------------
  const handleBlockIp = async (ip, reason) => {
    try {
      const res = await api.blockIp(ip, reason);
      showToast(res.message || `Blocked ${ip}`, 'success');
      refresh();
    } catch (err) {
      showToast(err.message || `Failed to block ${ip}`, err.status === 409 ? 'info' : 'error');
      throw err;
    }
  };

  // Table buttons have no error UI of their own: the toast reports failures.
  const quickBlock = (ip, reason) => handleBlockIp(ip, reason).catch(() => {});

  const handleUnblockIp = async (ip) => {
    try {
      const res = await api.unblockIp(ip);
      showToast(res.message || `Unblocked ${ip}`, 'success');
      refresh();
    } catch (err) {
      showToast(err.message || `Failed to unblock ${ip}`, 'error');
      throw err;
    }
  };

  const handleTriage = async (id, status) => {
    try {
      await api.updateAlertStatus(id, status);
      refresh();
    } catch (err) {
      showToast(err.message, 'error');
    }
  };

  const handleInjectSimulated = async (payload) => {
    const res = await api.injectSimulatedAlert(payload);
    showToast('Simulated Snort alert written to the alert log', 'info');
    return res;
  };

  const openManualBlockModal = (initial = '') => {
    setModalInitialIp(typeof initial === 'string' ? initial : '');
    setIsBlockModalOpen(true);
  };

  // ---- Render ---------------------------------------------------------------------
  if (auth.state === 'checking') {
    return <div className="min-h-screen flex items-center justify-center text-slate-500 text-sm">Connecting to NIDPS…</div>;
  }
  if (!authed) return <LoginScreen onLogin={handleLogin} notice={auth.notice} />;

  const demoMode = Boolean(settings?.demoMode);
  const alertsTable = (
    <AlertsTable
      alerts={alerts}
      pagination={pagination}
      onPageChange={(page) => setQuery((q) => ({ ...q, page }))}
      severityFilter={query.severity}
      setSeverityFilter={(severity) => setQuery((q) => ({ ...q, severity, page: 1 }))}
      searchTerm={searchInput}
      setSearchTerm={setSearchInput}
      onBlockIp={quickBlock}
      onTriage={handleTriage}
      blockedIpsSet={blockedIpsSet}
      loading={!loaded}
    />
  );

  const header = (title, subtitle, action) => (
    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
      <div>
        <h2 className="text-xl font-bold text-white tracking-wide font-mono">{title}</h2>
        <p className="text-xs text-slate-400">{subtitle}</p>
      </div>
      {action}
    </div>
  );

  return (
    <div className="flex min-h-screen bg-[#080c14] text-slate-100 font-sans">
      <Sidebar
        currentTab={currentTab}
        setCurrentTab={setCurrentTab}
        settings={settings}
        onOpenSimulator={demoMode ? () => setIsSimulatorOpen(true) : null}
      />

      <div className="flex-1 flex flex-col min-w-0">
        <Navbar
          live={live}
          onRefresh={handleManualRefresh}
          isRefreshing={isRefreshing}
          onOpenSimulator={demoMode ? () => setIsSimulatorOpen(true) : null}
          stats={stats}
          settings={settings}
          user={auth.user}
          onLogout={handleLogout}
        />

        {toast && (
          <div className="fixed top-20 right-6 z-50" role="status" aria-live="polite">
            <div
              className={`flex items-center space-x-2.5 px-4 py-3 rounded-lg shadow-2xl border text-xs font-mono font-medium ${
                toast.type === 'error'
                  ? 'bg-red-950/90 text-red-200 border-red-500/50 glow-red'
                  : toast.type === 'info'
                    ? 'bg-sky-950/90 text-sky-200 border-sky-500/50 glow-sky'
                    : 'bg-emerald-950/90 text-emerald-200 border-emerald-500/50 glow-emerald'
              }`}
            >
              {toast.type === 'error' ? <AlertCircle className="w-4 h-4 text-red-400 shrink-0" /> : toast.type === 'info' ? <Info className="w-4 h-4 text-sky-400 shrink-0" /> : <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" />}
              <span>{toast.message}</span>
            </div>
          </div>
        )}

        <main className="flex-1 p-6 space-y-6 max-w-7xl w-full mx-auto">
          {currentTab === 'dashboard' && (
            <div className="space-y-6">
              <MetricCards stats={stats} settings={settings} onNavigate={setCurrentTab} />
              <StatsCharts stats={stats} onBlockIp={quickBlock} onNavigate={setCurrentTab} />
              <div>
                <div className="flex items-center justify-between mb-3">
                  <h3 className="text-sm font-semibold tracking-wide uppercase font-mono text-slate-300">Live Intrusion Activity Feed</h3>
                  <button onClick={() => setCurrentTab('alerts')} className="text-xs text-sky-400 hover:text-sky-300 font-mono">
                    View All Alerts →
                  </button>
                </div>
                {alertsTable}
              </div>
            </div>
          )}

          {currentTab === 'alerts' && (
            <div className="space-y-6">
              {header(
                'Snort Real-Time Alert Monitor',
                'Every alert Snort writes is parsed, stored and classified by priority. Triage alerts as resolved or false positives.',
                demoMode && (
                  <button onClick={() => setIsSimulatorOpen(true)} className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-sky-600 hover:bg-sky-500 text-white text-xs font-medium">
                    <Zap className="w-3.5 h-3.5" />
                    <span>Simulate Attack</span>
                  </button>
                )
              )}
              {alertsTable}
            </div>
          )}

          {currentTab === 'firewall' && (
            <div className="space-y-6">
              {header(
                'Firewall Rule Policy & Active Blocks',
                `Rules live in the dedicated NIDPS iptables chain (${settings?.mode === 'gateway' ? 'FORWARD — protecting the routed network' : 'INPUT — protecting this host'}). Blocks expire automatically.`
              )}
              <FirewallTable
                blockedIps={blockedIps}
                onUnblock={handleUnblockIp}
                onOpenBlockModal={openManualBlockModal}
                loading={!loaded}
                showActiveOnly={showActiveOnly}
                setShowActiveOnly={setShowActiveOnly}
              />
            </div>
          )}

          {currentTab === 'analytics' && (
            <div className="space-y-6">
              {header('Threat Analytics', 'Aggregated traffic analysis, protocol distribution, and top intrusion sources.')}
              <StatsCharts stats={stats} onBlockIp={quickBlock} onNavigate={setCurrentTab} />
              <div className="p-5 rounded-xl bg-[#111726] border border-slate-800 text-xs font-mono space-y-3">
                <h4 className="text-sm font-bold uppercase tracking-wider text-sky-400">NIDPS Response Policy</h4>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-slate-300">
                  <div className="p-3 rounded-lg bg-[#0a0e17] border border-slate-800">
                    <span className="text-red-400 font-bold block mb-1">Priority 1 (High)</span>
                    <span>Action: <strong>Automatic block</strong></span>
                    <p className="text-slate-500 mt-1">The source is dropped at once (unless it is on the protected list).</p>
                  </div>
                  <div className="p-3 rounded-lg bg-[#0a0e17] border border-slate-800">
                    <span className="text-amber-400 font-bold block mb-1">Priority 2 (Medium)</span>
                    <span>Action: <strong>Log, then escalate</strong></span>
                    <p className="text-slate-500 mt-1">
                      {settings?.escalateCount > 0
                        ? `Blocked automatically after ${settings.escalateCount} alerts within ${settings.escalateWindowMin} minutes.`
                        : 'Logged for review; one-click manual block.'}
                    </p>
                  </div>
                  <div className="p-3 rounded-lg bg-[#0a0e17] border border-slate-800">
                    <span className="text-sky-400 font-bold block mb-1">Priority 3 (Low / Recon)</span>
                    <span>Action: <strong>Log only</strong></span>
                    <p className="text-slate-500 mt-1">Kept for trend analysis and attacker profiling.</p>
                  </div>
                </div>
              </div>
            </div>
          )}

          {currentTab === 'audit' && (
            <div className="space-y-6">
              {header('Audit Log', 'Who blocked, unblocked, triaged or signed in — and when. Kept for the configured retention period.')}
              <AuditLog entries={audit} loading={!loaded} />
            </div>
          )}

          {currentTab === 'settings' && (
            <div className="space-y-6">
              {header('Settings', 'The configuration NIDPS is running with right now.')}
              <SettingsPanel settings={settings} />
            </div>
          )}
        </main>
      </div>

      <BlockModal isOpen={isBlockModalOpen} onClose={() => setIsBlockModalOpen(false)} onSubmit={handleBlockIp} initialIp={modalInitialIp} />
      {demoMode && <LogSimulatorModal isOpen={isSimulatorOpen} onClose={() => setIsSimulatorOpen(false)} onInject={handleInjectSimulated} />}
    </div>
  );
}
