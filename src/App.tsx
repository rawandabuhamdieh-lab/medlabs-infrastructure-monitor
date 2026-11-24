import { useCallback, useEffect, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  BarChart3,
  Cpu,
  Database,
  Globe,
  HardDrive,
  LayoutDashboard,
  Lock,
  LogOut,
  Menu,
  Moon,
  Network,
  RefreshCw,
  Server,
  Shield,
  Sun,
  X,
} from 'lucide-react';
import { AlertsIncidentsModule } from './components/AlertsIncidentsModule';
import {
  AnalyticsModule,
  CollectorsArchitectureModule,
  UsersAuditModule,
} from './components/AnalyticsUsersArchitectureModules';
import { AuthModal } from './components/AuthModal';
import { ExecutiveDashboard } from './components/ExecutiveDashboard';
import {
  BackupsModule,
  IisModule,
  NetworkModule,
} from './components/IisNetworkBackupModules';
import { OracleModule } from './components/OracleModule';
import { ServersModule } from './components/ServersModule';
import { COPY } from './data/i18n';
import {
  HISTORICAL_REPORTS,
  INITIAL_ALERTS,
  INITIAL_API_ENDPOINTS,
  INITIAL_APP_POOLS,
  INITIAL_AUDIT_LOGS,
  INITIAL_BACKUP_JOBS,
  INITIAL_COLLECTORS,
  INITIAL_IIS_SITES,
  INITIAL_NETWORK_DEVICES,
  INITIAL_ORACLE_DATABASES,
  INITIAL_THRESHOLDS,
  INITIAL_USERS,
  INITIAL_WINDOWS_SERVERS,
} from './data/medlabsData';
import {
  AlertRecord,
  AlertThreshold,
  ApiEndpointCheck,
  AuditLogEntry,
  BackupJob,
  CollectorConfig,
  ConnectionTestResult,
  CredentialProfileSummary,
  DailyReportRow,
  IisAppPool,
  IisSite,
  Language,
  ModuleSection,
  NetworkDevice,
  OracleDatabaseMetric,
  ThemeMode,
  UserAccount,
  UserRole,
  WindowsProcessIdentity,
  WindowsServer,
} from './types/infrastructure';

interface AuthSessionUser {
  userId: string;
  username: string;
  fullName: string;
  role: UserRole;
}

export default function App() {
  const [lang, setLang] = useState<Language>('en');
  const [theme, setTheme] = useState<ThemeMode>('light');
  const [activeSection, setActiveSection] = useState<ModuleSection>('dashboard');
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  // Auth token kept strictly in JS/React memory (never localStorage/sessionStorage)
  const [authToken, setAuthToken] = useState<string | null>(null);
  const [sessionUser, setSessionUser] = useState<AuthSessionUser | null>(null);
  const [adminClaimed, setAdminClaimed] = useState(false);
  const [authModalOpen, setAuthModalOpen] = useState(false);
  const [polling, setPolling] = useState(false);

  // Infrastructure state
  const [servers, setServers] = useState<WindowsServer[]>(INITIAL_WINDOWS_SERVERS);
  const [oracleDatabases, setOracleDatabases] = useState<OracleDatabaseMetric[]>(INITIAL_ORACLE_DATABASES);
  const [iisSites, setIisSites] = useState<IisSite[]>(INITIAL_IIS_SITES);
  const [appPools, setAppPools] = useState<IisAppPool[]>(INITIAL_APP_POOLS);
  const [apiEndpoints, setApiEndpoints] = useState<ApiEndpointCheck[]>(INITIAL_API_ENDPOINTS);
  const [networkDevices, setNetworkDevices] = useState<NetworkDevice[]>(INITIAL_NETWORK_DEVICES);
  const [backups, setBackups] = useState<BackupJob[]>(INITIAL_BACKUP_JOBS);
  const [thresholds, setThresholds] = useState<AlertThreshold[]>(INITIAL_THRESHOLDS);
  const [alerts, setAlerts] = useState<AlertRecord[]>(INITIAL_ALERTS);
  const [collectors, setCollectors] = useState<CollectorConfig[]>(INITIAL_COLLECTORS);
  const [reports, setReports] = useState<DailyReportRow[]>(HISTORICAL_REPORTS);
  const [credentials, setCredentials] = useState<CredentialProfileSummary[]>([]);
  const [vaultPersistent, setVaultPersistent] = useState(false);
  const [processIdentity, setProcessIdentity] = useState<WindowsProcessIdentity | null>(null);
  const [users, setUsers] = useState<UserAccount[]>(INITIAL_USERS);
  const [auditLogs, setAuditLogs] = useState<AuditLogEntry[]>(INITIAL_AUDIT_LOGS);

  const copy = COPY[lang];

  useEffect(() => {
    document.documentElement.dir = lang === 'ar' ? 'rtl' : 'ltr';
    document.documentElement.lang = lang;
  }, [lang]);

  useEffect(() => {
    document.documentElement.classList.toggle('dark', theme === 'dark');
  }, [theme]);

  const fetchSnapshot = useCallback(async (token: string | null) => {
    setPolling(true);
    try {
      const headers: Record<string, string> = {};
      if (token) headers.Authorization = `Bearer ${token}`;

      const [authRes, snapRes] = await Promise.all([
        fetch('/api/auth/status', { headers }),
        fetch('/api/infrastructure/snapshot', { headers }),
      ]);

      if (authRes.ok) {
        const authData = await authRes.json();
        setAdminClaimed(Boolean(authData.adminClaimed));
      }

      if (snapRes.ok) {
        const d = await snapRes.json();
        setServers(d.servers);
        setOracleDatabases(d.oracleDatabases);
        setIisSites(d.iisSites);
        setAppPools(d.appPools);
        setApiEndpoints(d.apiEndpoints);
        setNetworkDevices(d.networkDevices);
        setBackups(d.backups);
        setThresholds(d.thresholds);
        setAlerts(d.alerts);
        setCollectors(d.collectors);
        setReports(d.reports);
        setCredentials(d.credentials ?? []);
        setVaultPersistent(Boolean(d.vaultPersistent));
        setProcessIdentity(d.processIdentity ?? null);
        setUsers(d.users);
        setAuditLogs(d.auditLogs);
      }
    } finally {
      setPolling(false);
    }
  }, []);

  useEffect(() => {
    fetchSnapshot(authToken);
    const id = setInterval(() => {
      fetchSnapshot(authToken);
    }, 30_000);
    return () => clearInterval(id);
  }, [authToken, fetchSnapshot]);

  const authedFetch = async (url: string, method: string, body?: unknown): Promise<string | null> => {
    try {
      const headers: Record<string, string> = {};
      if (method !== 'GET' && method !== 'DELETE') {
        headers['Content-Type'] = 'application/json';
      }
      if (authToken) headers.Authorization = `Bearer ${authToken}`;
      const res = await fetch(url, {
        method,
        headers,
        body: method !== 'GET' && method !== 'DELETE' ? JSON.stringify(body ?? {}) : undefined,
      });
      const raw = await res.text();
      let data: { error?: string } = {};
      try {
        data = raw ? (JSON.parse(raw) as { error?: string }) : {};
      } catch {
        data = {};
      }
      if (!res.ok) {
        return data.error || `Server error (${res.status}).`;
      }
      await fetchSnapshot(authToken);
      return null;
    } catch {
      return 'Network error communicating with backend API.';
    }
  };

  const authedTestFetch = async (
    url: string
  ): Promise<{ result?: ConnectionTestResult; error?: string }> => {
    try {
      const headers: Record<string, string> = { 'Content-Type': 'application/json' };
      if (authToken) headers.Authorization = `Bearer ${authToken}`;
      const res = await fetch(url, { method: 'POST', headers, body: '{}' });
      const raw = await res.text();
      let data: Record<string, unknown> = {};
      try {
        data = raw ? (JSON.parse(raw) as Record<string, unknown>) : {};
      } catch {
        data = {};
      }
      if (!res.ok) {
        return { error: typeof data.error === 'string' ? data.error : `Server error (${res.status}).` };
      }
      return { result: data as unknown as ConnectionTestResult };
    } catch {
      return { error: 'Network error communicating with backend API.' };
    }
  };

  const navItems: { id: ModuleSection; label: string; icon: typeof LayoutDashboard }[] = [
    { id: 'dashboard', label: copy.nav.dashboard, icon: LayoutDashboard },
    { id: 'servers', label: copy.nav.servers, icon: Server },
    { id: 'oracle', label: copy.nav.oracle, icon: Database },
    { id: 'iis', label: copy.nav.iis, icon: Activity },
    { id: 'network', label: copy.nav.network, icon: Network },
    { id: 'backups', label: copy.nav.backups, icon: HardDrive },
    { id: 'alerts', label: copy.nav.alerts, icon: AlertTriangle },
    { id: 'analytics', label: copy.nav.analytics, icon: BarChart3 },
    { id: 'users', label: copy.nav.users, icon: Shield },
    { id: 'architecture', label: copy.nav.architecture, icon: Cpu },
  ];

  const currentNavLabel = navItems.find((n) => n.id === activeSection)?.label ?? copy.nav.dashboard;

  const sidebarContent = (
    <div className="flex flex-col h-full bg-white dark:bg-slate-900 border-e border-slate-200 dark:border-slate-800">
      <div className="px-5 py-4 border-b border-slate-200 dark:border-slate-800">
        <div className="text-sm font-bold tracking-tight text-blue-700 dark:text-blue-400">
          {copy.brandTitle}
        </div>
        <div className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">
          {copy.brandSub}
        </div>
      </div>

      <nav className="flex-1 p-3 space-y-1 overflow-y-auto">
        {navItems.map((item) => {
          const Icon = item.icon;
          const active = activeSection === item.id;
          return (
            <button
              key={item.id}
              type="button"
              onClick={() => {
                setActiveSection(item.id);
                setMobileMenuOpen(false);
              }}
              className={`w-full flex items-center gap-3 px-3 py-2 text-xs font-medium rounded-md transition-colors cursor-pointer ${
                active
                  ? 'bg-blue-50 dark:bg-blue-950/60 text-blue-700 dark:text-blue-300'
                  : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800/70 hover:text-slate-900 dark:hover:text-slate-100'
              }`}
            >
              <Icon className="w-4 h-4 shrink-0" />
              <span className="truncate">{item.label}</span>
            </button>
          );
        })}
      </nav>

      {/* Session Role Card at Sidebar Footer */}
      <div className="p-4 border-t border-slate-200 dark:border-slate-800 text-xs">
        {sessionUser ? (
          <div className="space-y-2">
            <div>
              <div className="font-semibold text-slate-900 dark:text-slate-100 truncate">
                {sessionUser.fullName}
              </div>
              <div className="font-mono text-[11px] text-blue-700 dark:text-blue-400">
                {sessionUser.role}
              </div>
            </div>
            <button
              type="button"
              onClick={() => {
                setAuthToken(null);
                setSessionUser(null);
              }}
              className="w-full inline-flex items-center justify-center gap-1.5 px-3 py-1.5 rounded-md border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800 cursor-pointer"
            >
              <LogOut className="w-3.5 h-3.5" />
              <span>{copy.header.signOut}</span>
            </button>
          </div>
        ) : (
          <button
            type="button"
            onClick={() => setAuthModalOpen(true)}
            className="w-full inline-flex items-center justify-center gap-1.5 px-3 py-2 rounded-md bg-blue-600 hover:bg-blue-700 text-white font-medium cursor-pointer"
          >
            <Lock className="w-3.5 h-3.5" />
            <span>{adminClaimed ? copy.header.signIn : copy.header.claimAdmin}</span>
          </button>
        )}
      </div>
    </div>
  );

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100 flex">
      {/* Desktop Sidebar */}
      <aside className="hidden lg:block w-64 shrink-0 sticky top-0 h-screen">
        {sidebarContent}
      </aside>

      {/* Mobile Sidebar Drawer */}
      {mobileMenuOpen && (
        <div className="fixed inset-0 z-50 lg:hidden flex">
          <div
            className="fixed inset-0 bg-slate-950/60"
            onClick={() => setMobileMenuOpen(false)}
          />
          <div className="relative w-64 max-w-[80vw] h-full z-10">
            <button
              type="button"
              onClick={() => setMobileMenuOpen(false)}
              aria-label="Close navigation"
              className="absolute top-3 end-3 p-1.5 text-slate-500 hover:text-slate-900 dark:hover:text-slate-100 cursor-pointer"
            >
              <X className="w-4 h-4" />
            </button>
            {sidebarContent}
          </div>
        </div>
      )}

      {/* Main Column */}
      <div className="flex-1 min-w-0 flex flex-col">
        {/* Top Enterprise Header */}
        <header className="bg-white dark:bg-slate-900 border-b border-slate-200 dark:border-slate-800 px-5 py-3">
          <div className="flex items-center justify-between gap-4">
            <div className="flex items-center gap-3 min-w-0">
              <button
                type="button"
                onClick={() => setMobileMenuOpen(true)}
                aria-label="Open menu"
                className="lg:hidden p-1.5 rounded-md border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300 cursor-pointer"
              >
                <Menu className="w-4 h-4" />
              </button>
              <div className="text-xs text-slate-500 dark:text-slate-400 truncate">
                <span>{copy.header.orgCrumb}</span>
                <span className="mx-2" aria-hidden="true">/</span>
                <span className="font-semibold text-slate-900 dark:text-slate-100">
                  {currentNavLabel}
                </span>
              </div>
            </div>

            <div className="flex items-center gap-2 shrink-0">
              <button
                type="button"
                onClick={() => fetchSnapshot(authToken)}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-200 hover:bg-slate-200 dark:hover:bg-slate-700 rounded-md whitespace-nowrap cursor-pointer"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${polling ? 'animate-spin' : ''}`} />
                <span className="hidden sm:inline">{copy.common.refresh}</span>
              </button>

              <button
                type="button"
                onClick={() => setTheme((prev) => (prev === 'light' ? 'dark' : 'light'))}
                aria-label="Toggle theme"
                className="p-2 rounded-md border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800 cursor-pointer"
              >
                {theme === 'light' ? <Moon className="w-3.5 h-3.5" /> : <Sun className="w-3.5 h-3.5" />}
              </button>

              <button
                type="button"
                onClick={() => setLang((prev) => (prev === 'en' ? 'ar' : 'en'))}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800 rounded-md whitespace-nowrap cursor-pointer"
              >
                <Globe className="w-3.5 h-3.5" />
                <span>{lang === 'en' ? 'العربية' : 'English'}</span>
              </button>

              {!sessionUser && (
                <button
                  type="button"
                  onClick={() => setAuthModalOpen(true)}
                  className="px-3.5 py-1.5 text-xs font-medium bg-blue-600 hover:bg-blue-700 text-white rounded-md whitespace-nowrap cursor-pointer"
                >
                  {adminClaimed ? copy.header.signIn : copy.header.claimAdmin}
                </button>
              )}
            </div>
          </div>
        </header>

        {/* Read-Only Session Notice */}
        {!sessionUser && (
          <div className="bg-blue-50 dark:bg-blue-950/30 border-b border-blue-200 dark:border-blue-900 px-6 py-2 text-xs text-blue-900 dark:text-blue-200 flex items-center justify-between gap-3">
            <span>{copy.header.readOnlyBanner}</span>
            <button
              type="button"
              onClick={() => setAuthModalOpen(true)}
              className="font-semibold underline whitespace-nowrap shrink-0 cursor-pointer"
            >
              {adminClaimed ? copy.header.signIn : copy.header.claimAdmin}
            </button>
          </div>
        )}

        {/* Main Viewport */}
        <main className="flex-1 p-6 max-w-[1440px] w-full mx-auto">
          {activeSection === 'dashboard' && (
            <ExecutiveDashboard
              servers={servers}
              oracleDatabases={oracleDatabases}
              iisSites={iisSites}
              networkDevices={networkDevices}
              alerts={alerts}
              reports={reports}
              lang={lang}
              onNavigate={setActiveSection}
            />
          )}

          {activeSection === 'servers' && (
            <ServersModule
              servers={servers}
              credentials={credentials}
              processIdentity={processIdentity}
              currentRole={sessionUser?.role ?? null}
              lang={lang}
              onRegisterServer={(payload) => authedFetch('/api/servers', 'POST', payload)}
              onUpdateServer={(id, payload) => authedFetch(`/api/servers/${id}`, 'PATCH', payload)}
              onDeleteServer={(id) => authedFetch(`/api/servers/${id}`, 'DELETE')}
              onTestServer={(id) => authedTestFetch(`/api/servers/${id}/test`)}
              onPollHostNow={() => authedFetch('/api/servers/poll-host', 'POST', {})}
              onPollAllServers={() => authedFetch('/api/servers/poll-all', 'POST', {})}
            />
          )}

          {activeSection === 'oracle' && (
            <OracleModule
              databases={oracleDatabases}
              credentials={credentials}
              currentRole={sessionUser?.role ?? null}
              lang={lang}
              onRegisterOracle={(payload) => authedFetch('/api/oracle', 'POST', payload)}
              onUpdateOracle={(id, payload) => authedFetch(`/api/oracle/${id}`, 'PATCH', payload)}
              onDeleteOracle={(id) => authedFetch(`/api/oracle/${id}`, 'DELETE')}
              onTestOracle={(id) => authedTestFetch(`/api/oracle/${id}/test`)}
              onPollAllOracle={() => authedFetch('/api/oracle/poll-all', 'POST', {})}
              onDiscoverTns={async (customDir) => {
                try {
                  const headers: Record<string, string> = {};
                  if (authToken) headers.Authorization = `Bearer ${authToken}`;
                  const qs = customDir ? `?tnsAdminDir=${encodeURIComponent(customDir)}` : '';
                  const res = await fetch(`/api/oracle/tns-aliases${qs}`, { headers });
                  if (!res.ok) return { error: `Discovery failed (${res.status}).` };
                  return { data: await res.json() };
                } catch {
                  return { error: 'Network error communicating with backend API.' };
                }
              }}
            />
          )}

          {activeSection === 'iis' && (
            <IisModule
              sites={iisSites}
              appPools={appPools}
              apiEndpoints={apiEndpoints}
              credentials={credentials}
              currentRole={sessionUser?.role ?? null}
              lang={lang}
              onRegisterSite={(payload) => authedFetch('/api/iis/sites', 'POST', payload)}
              onDeleteSite={(id) => authedFetch(`/api/iis/sites/${id}`, 'DELETE')}
              onTestSite={(id) => authedTestFetch(`/api/iis/sites/${id}/test`)}
              onRegisterApi={(payload) => authedFetch('/api/iis/endpoints', 'POST', payload)}
              onDeleteApi={(id) => authedFetch(`/api/iis/endpoints/${id}`, 'DELETE')}
              onPollAllIis={() => authedFetch('/api/iis/poll-all', 'POST', {})}
            />
          )}

          {activeSection === 'network' && (
            <NetworkModule
              devices={networkDevices}
              credentials={credentials}
              currentRole={sessionUser?.role ?? null}
              lang={lang}
              onRegisterNetwork={(payload) => authedFetch('/api/network', 'POST', payload)}
              onDeleteNetwork={(id) => authedFetch(`/api/network/${id}`, 'DELETE')}
              onTestNetwork={(id) => authedTestFetch(`/api/network/${id}/test`)}
              onPollAllNetwork={() => authedFetch('/api/network/poll-all', 'POST', {})}
            />
          )}

          {activeSection === 'backups' && <BackupsModule jobs={backups} lang={lang} />}

          {activeSection === 'alerts' && (
            <AlertsIncidentsModule
              alerts={alerts}
              thresholds={thresholds}
              currentRole={sessionUser?.role ?? null}
              lang={lang}
              onCreateIncident={(payload) => authedFetch('/api/incidents', 'POST', payload)}
              onUpdateIncident={(id, patch) => authedFetch(`/api/incidents/${id}`, 'PATCH', patch)}
              onUpdateThreshold={(id, warningValue, criticalValue) =>
                authedFetch(`/api/thresholds/${id}`, 'PATCH', { warningValue, criticalValue })
              }
            />
          )}

          {activeSection === 'analytics' && (
            <AnalyticsModule
              servers={servers}
              oracleDatabases={oracleDatabases}
              alerts={alerts}
              reports={reports}
              lang={lang}
            />
          )}

          {activeSection === 'users' && (
            <UsersAuditModule
              users={users}
              auditLogs={auditLogs}
              currentRole={sessionUser?.role ?? null}
              lang={lang}
              onCreateUser={(payload) => authedFetch('/api/users', 'POST', payload)}
              onToggleUser={(id, active) => authedFetch(`/api/users/${id}`, 'PATCH', { active })}
              onChangeRole={(id, role) => authedFetch(`/api/users/${id}`, 'PATCH', { role })}
            />
          )}

          {activeSection === 'architecture' && (
            <CollectorsArchitectureModule
              collectors={collectors}
              credentials={credentials}
              vaultPersistent={vaultPersistent}
              currentRole={sessionUser?.role ?? null}
              lang={lang}
              onUpdateCollector={(id, patch) => authedFetch(`/api/collectors/${id}`, 'PATCH', patch)}
              onSaveCredential={(payload) => authedFetch('/api/credentials', 'POST', payload)}
              onDeleteCredential={(id) => authedFetch(`/api/credentials/${id}`, 'DELETE')}
            />
          )}
        </main>
      </div>

      <AuthModal
        open={authModalOpen}
        onClose={() => setAuthModalOpen(false)}
        adminClaimed={adminClaimed}
        lang={lang}
        onAuthenticated={(token, user) => {
          setAuthToken(token);
          setSessionUser(user);
        }}
      />
    </div>
  );
}
