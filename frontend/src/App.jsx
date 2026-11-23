import React, { useState, useEffect, useCallback, useMemo } from 'react';
import Sidebar from './components/Sidebar';
import Navbar from './components/Navbar';
import MetricCards from './components/MetricCards';
import AlertsTable from './components/AlertsTable';
import FirewallTable from './components/FirewallTable';
import StatsCharts from './components/StatsCharts';
import BlockModal from './components/BlockModal';
import LogSimulatorModal from './components/LogSimulatorModal';
import { 
  fetchAlerts, 
  fetchBlocked, 
  fetchStats, 
  fetchSystemStatus, 
  blockIp, 
  unblockIp, 
  injectSimulatedAlert 
} from './services/api';
import { ShieldCheck, AlertCircle, Info, Zap } from 'lucide-react';

export default function App() {
  const [currentTab, setCurrentTab] = useState('dashboard');
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);

  // Data states
  const [alerts, setAlerts] = useState([]);
  const [pagination, setPagination] = useState({ page: 1, limit: 12, total: 0, totalPages: 1 });
  const [severityFilter, setSeverityFilter] = useState('');
  const [searchTerm, setSearchTerm] = useState('');
  const [blockedIps, setBlockedIps] = useState([]);
  const [showActiveOnly, setShowActiveOnly] = useState(true);
  const [stats, setStats] = useState(null);
  const [systemStatus, setSystemStatus] = useState(null);
  const [loadingAlerts, setLoadingAlerts] = useState(false);
  const [loadingBlocked, setLoadingBlocked] = useState(false);

  // Modals & Notices
  const [isBlockModalOpen, setIsBlockModalOpen] = useState(false);
  const [modalInitialIp, setModalInitialIp] = useState('');
  const [isSimulatorOpen, setIsSimulatorOpen] = useState(false);
  const [toast, setToast] = useState(null);

  const showToast = (message, type = 'success') => {
    setToast({ message, type });
    setTimeout(() => {
      setToast(null);
    }, 4500);
  };

  // Set of actively blocked IPs for quick O(1) table lookups
  const blockedIpsSet = useMemo(() => {
    return new Set(blockedIps.filter((b) => b.is_active).map((b) => b.ip_address));
  }, [blockedIps]);

  // Load Alerts
  const loadAlerts = useCallback(async (page = pagination.page) => {
    try {
      setLoadingAlerts(true);
      const res = await fetchAlerts({
        page,
        limit: pagination.limit,
        severity: severityFilter,
        search: searchTerm,
      });
      setAlerts(res.data || []);
      setPagination(res.pagination || { page: 1, limit: 12, total: 0, totalPages: 1 });
    } catch (err) {
      console.error('Failed to load alerts:', err);
    } finally {
      setLoadingAlerts(false);
    }
  }, [pagination.page, pagination.limit, severityFilter, searchTerm]);

  // Load Blocked IPs
  const loadBlocked = useCallback(async () => {
    try {
      setLoadingBlocked(true);
      const res = await fetchBlocked(showActiveOnly);
      setBlockedIps(res.data || []);
    } catch (err) {
      console.error('Failed to load blocked IPs:', err);
    } finally {
      setLoadingBlocked(false);
    }
  }, [showActiveOnly]);

  // Load Stats & System Status
  const loadStatsAndStatus = useCallback(async () => {
    try {
      const [sData, statusData] = await Promise.all([
        fetchStats().catch(() => null),
        fetchSystemStatus().catch(() => null)
      ]);
      if (sData) setStats(sData);
      if (statusData) setSystemStatus(statusData);
    } catch (err) {
      console.error('Failed to load system stats:', err);
    }
  }, []);

  // Full Refresh Handler
  const handleFullRefresh = async () => {
    setIsRefreshing(true);
    await Promise.all([loadAlerts(), loadBlocked(), loadStatsAndStatus()]);
    setIsRefreshing(false);
  };

  // Initial Load
  useEffect(() => {
    handleFullRefresh();
  }, [showActiveOnly, severityFilter]);

  // Handle Search Debounce
  useEffect(() => {
    const timer = setTimeout(() => {
      loadAlerts(1);
    }, 350);
    return () => clearTimeout(timer);
  }, [searchTerm]);

  // Auto-Polling Interval (every 3 seconds)
  useEffect(() => {
    if (!autoRefresh) return;
    const interval = setInterval(() => {
      loadAlerts();
      loadBlocked();
      loadStatsAndStatus();
    }, 3000);
    return () => clearInterval(interval);
  }, [autoRefresh, loadAlerts, loadBlocked, loadStatsAndStatus]);

  // Action: Manual or Row IP Block
  const handleBlockIp = async (ip, reason) => {
    try {
      const res = await blockIp(ip, reason);
      showToast(res.message || `IP ${ip} blocked via iptables`, 'success');
      handleFullRefresh();
    } catch (err) {
      showToast(err.message || `Failed to block IP ${ip}`, 'error');
      throw err;
    }
  };

  // Action: Unblock IP
  const handleUnblockIp = async (ip) => {
    try {
      const res = await unblockIp(ip);
      showToast(res.message || `IP ${ip} unblocked and rule flushed`, 'success');
      handleFullRefresh();
    } catch (err) {
      showToast(err.message || `Failed to unblock IP ${ip}`, 'error');
      throw err;
    }
  };

  // Action: Inject Simulated Attack
  const handleInjectSimulated = async (payload) => {
    const res = await injectSimulatedAlert(payload);
    showToast('Snort alert injected into mock_snort.log', 'info');
    // Refresh shortly after to allow log watcher to parse
    setTimeout(() => {
      handleFullRefresh();
    }, 1200);
    return res;
  };

  const openManualBlockModal = (initial = '') => {
    setModalInitialIp(initial);
    setIsBlockModalOpen(true);
  };

  return (
    <div className="flex min-h-screen bg-[#080c14] text-slate-100 font-sans">
      {/* Sidebar Navigation */}
      <Sidebar
        currentTab={currentTab}
        setCurrentTab={setCurrentTab}
        systemStatus={systemStatus}
        onOpenSimulator={() => setIsSimulatorOpen(true)}
      />

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0">
        <Navbar
          autoRefresh={autoRefresh}
          setAutoRefresh={setAutoRefresh}
          onRefresh={handleFullRefresh}
          isRefreshing={isRefreshing}
          onOpenSimulator={() => setIsSimulatorOpen(true)}
          stats={stats}
        />

        {/* Global Toast Notification */}
        {toast && (
          <div className="fixed top-20 right-6 z-50 animate-bounce">
            <div
              className={`flex items-center space-x-2.5 px-4 py-3 rounded-lg shadow-2xl border text-xs font-mono font-medium ${
                toast.type === 'error'
                  ? 'bg-red-950/90 text-red-200 border-red-500/50 glow-red'
                  : toast.type === 'info'
                    ? 'bg-sky-950/90 text-sky-200 border-sky-500/50 glow-sky'
                    : 'bg-emerald-950/90 text-emerald-200 border-emerald-500/50 glow-emerald'
              }`}
            >
              {toast.type === 'error' ? (
                <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />
              ) : toast.type === 'info' ? (
                <Info className="w-4 h-4 text-sky-400 shrink-0" />
              ) : (
                <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" />
              )}
              <span>{toast.message}</span>
            </div>
          </div>
        )}

        <main className="flex-1 p-6 space-y-6 max-w-7xl w-full mx-auto">
          {/* DASHBOARD TAB */}
          {currentTab === 'dashboard' && (
            <div className="space-y-6">
              {/* Overview Metrics */}
              <MetricCards stats={stats} onNavigate={setCurrentTab} />

              {/* Charts & Threat Breakdown */}
              <StatsCharts stats={stats} onBlockIp={handleBlockIp} onNavigate={setCurrentTab} />

              {/* Recent Alerts Feed Preview */}
              <div>
                <div className="flex items-center justify-between mb-3">
                  <h3 className="text-sm font-semibold text-white tracking-wide uppercase font-mono text-slate-300">
                    Live Intrusion Activity Feed
                  </h3>
                  <button
                    onClick={() => setCurrentTab('alerts')}
                    className="text-xs text-sky-400 hover:text-sky-300 font-mono"
                  >
                    View All Alerts →
                  </button>
                </div>
                <AlertsTable
                  alerts={alerts}
                  pagination={pagination}
                  onPageChange={(page) => loadAlerts(page)}
                  severityFilter={severityFilter}
                  setSeverityFilter={setSeverityFilter}
                  searchTerm={searchTerm}
                  setSearchTerm={setSearchTerm}
                  onBlockIp={handleBlockIp}
                  blockedIpsSet={blockedIpsSet}
                  loading={loadingAlerts}
                />
              </div>
            </div>
          )}

          {/* ALERTS TAB */}
          {currentTab === 'alerts' && (
            <div className="space-y-6">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                <div>
                  <h2 className="text-xl font-bold text-white tracking-wide font-mono">
                    Snort Real-Time Alert Monitor
                  </h2>
                  <p className="text-xs text-slate-400">
                    Continuous line-by-line inspection of Snort fast-alert logs and rule priority classification.
                  </p>
                </div>
                <button
                  onClick={() => setIsSimulatorOpen(true)}
                  className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-sky-600 hover:bg-sky-500 text-white text-xs font-medium font-sans"
                >
                  <Zap className="w-3.5 h-3.5" />
                  <span>Simulate Snort Ingestion</span>
                </button>
              </div>

              <AlertsTable
                alerts={alerts}
                pagination={pagination}
                onPageChange={(page) => loadAlerts(page)}
                severityFilter={severityFilter}
                setSeverityFilter={setSeverityFilter}
                searchTerm={searchTerm}
                setSearchTerm={setSearchTerm}
                onBlockIp={handleBlockIp}
                blockedIpsSet={blockedIpsSet}
                loading={loadingAlerts}
              />
            </div>
          )}

          {/* FIREWALL TAB */}
          {currentTab === 'firewall' && (
            <div className="space-y-6">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                <div>
                  <h2 className="text-xl font-bold text-white tracking-wide font-mono">
                    Firewall Rule Policy & Active Blocks
                  </h2>
                  <p className="text-xs text-slate-400">
                    Host firewall state enforced by iptables DROP targets. High-severity threats are blocked automatically.
                  </p>
                </div>
              </div>

              <FirewallTable
                blockedIps={blockedIps}
                onUnblock={handleUnblockIp}
                onOpenBlockModal={openManualBlockModal}
                loading={loadingBlocked}
                showActiveOnly={showActiveOnly}
                setShowActiveOnly={setShowActiveOnly}
              />
            </div>
          )}

          {/* ANALYTICS TAB */}
          {currentTab === 'analytics' && (
            <div className="space-y-6">
              <div>
                <h2 className="text-xl font-bold text-white tracking-wide font-mono">
                  Threat Intelligence & Threat Aggregations
                </h2>
                <p className="text-xs text-slate-400">
                  Aggregated traffic analysis, protocol distribution, and top intrusion sources.
                </p>
              </div>

              <StatsCharts stats={stats} onBlockIp={handleBlockIp} onNavigate={setCurrentTab} />

              {/* Policy Architecture Card */}
              <div className="p-5 rounded-xl bg-[#111726] border border-slate-800 text-xs font-mono space-y-3">
                <h4 className="text-sm font-bold text-white uppercase tracking-wider text-sky-400">
                  NIDPS Operational Policy Summary
                </h4>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-slate-300">
                  <div className="p-3 rounded-lg bg-[#0a0e17] border border-slate-800">
                    <span className="text-red-400 font-bold block mb-1">Priority 1 (High)</span>
                    <span>Action: <strong>Automated Block</strong></span>
                    <p className="text-slate-500 mt-1">Triggers Prevention Engine immediately; executes simulated or kernel iptables DROP rule.</p>
                  </div>
                  <div className="p-3 rounded-lg bg-[#0a0e17] border border-slate-800">
                    <span className="text-amber-400 font-bold block mb-1">Priority 2 (Medium)</span>
                    <span>Action: <strong>Log & Flag</strong></span>
                    <p className="text-slate-500 mt-1">Logged into alerts table with status 'unresolved'. Administrative review and one-click manual block enabled.</p>
                  </div>
                  <div className="p-3 rounded-lg bg-[#0a0e17] border border-slate-800">
                    <span className="text-sky-400 font-bold block mb-1">Priority 3 (Low/Recon)</span>
                    <span>Action: <strong>Log Only</strong></span>
                    <p className="text-slate-500 mt-1">Stores port scans and ICMP anomalies for trend analytics and attacker profiling.</p>
                  </div>
                </div>
              </div>
            </div>
          )}
        </main>
      </div>

      {/* Manual Block IP Modal */}
      <BlockModal
        isOpen={isBlockModalOpen}
        onClose={() => setIsBlockModalOpen(false)}
        onSubmit={handleBlockIp}
        initialIp={modalInitialIp}
      />

      {/* Attack Simulator Modal */}
      <LogSimulatorModal
        isOpen={isSimulatorOpen}
        onClose={() => setIsSimulatorOpen(false)}
        onInject={handleInjectSimulated}
      />
    </div>
  );
}
