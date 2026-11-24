import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { COPY } from '../data/i18n';
import {
  AlertRecord,
  DailyReportRow,
  IisSite,
  Language,
  ModuleSection,
  NetworkDevice,
  OracleDatabaseMetric,
  WindowsServer,
} from '../types/infrastructure';
import { AssetStatusBadge, IncidentStatusText, SeverityText } from './StatusGlyph';

interface ExecutiveDashboardProps {
  servers: WindowsServer[];
  oracleDatabases: OracleDatabaseMetric[];
  iisSites: IisSite[];
  networkDevices: NetworkDevice[];
  alerts: AlertRecord[];
  reports: DailyReportRow[];
  lang: Language;
  onNavigate: (section: ModuleSection) => void;
}

export function ExecutiveDashboard({
  servers,
  oracleDatabases,
  iisSites,
  networkDevices,
  alerts,
  reports,
  lang,
  onNavigate,
}: ExecutiveDashboardProps) {
  const copy = COPY[lang];

  const totalServers = servers.length;
  const onlineServers = servers.filter((s) => s.status === 'Online').length;
  const warningServers = servers.filter((s) => s.status === 'Warning').length;
  const criticalServers = servers.filter((s) => s.status === 'Critical').length;
  const offlineServers = servers.filter((s) => s.status === 'Offline').length;

  const activeAlerts = alerts.filter((a) => a.status !== 'Resolved');
  const openIncidents = alerts.filter((a) => a.status === 'Open' || a.status === 'In Progress');

  const healthyWeight =
    onlineServers * 1 + warningServers * 0.7 + criticalServers * 0.35 + offlineServers * 0;
  const overallHealthPct = totalServers > 0 ? Math.round((healthyWeight / totalServers) * 100) : null;

  const primaryOracle = oracleDatabases[0] ?? null;
  const iisOnlineCount = iisSites.filter((i) => i.status === 'Online' || i.status === 'Warning').length;
  const netOnlineCount = networkDevices.filter((n) => n.status !== 'Offline').length;
  const netAvailabilityAvg =
    networkDevices.length > 0
      ? `${(networkDevices.reduce((a, n) => a + n.uptimePct30d, 0) / networkDevices.length).toFixed(2)}%`
      : '—';

  const latestSync = servers[0]?.lastCheck ?? primaryOracle?.lastCheck ?? (lang === 'ar' ? 'بانتظار أول مجمّع' : 'Awaiting first collector');

  return (
    <div className="space-y-6">
      {/* Page Title */}
      <div className="flex flex-col sm:flex-row sm:items-end sm:justify-between gap-2 pb-4 border-b border-slate-200 dark:border-slate-800">
        <div>
          <h1 className="text-xl font-semibold text-slate-900 dark:text-slate-100">
            {lang === 'ar' ? 'لوحة قيادة البنية التحتية التنفيذية' : 'Executive Infrastructure Dashboard'}
          </h1>
          <p className="text-sm text-slate-600 dark:text-slate-400 mt-1">
            {lang === 'ar'
              ? 'مراقبة مركزية لحظية لخوادم Windows، قواعد Oracle، بوابات IIS، الشبكات، والتنبيهات في مجموعة ميدلابز.'
              : 'Centralized real-time monitoring across Windows Servers, Oracle Database, IIS, and Branch Networks.'}
          </p>
        </div>
        <div className="text-xs font-mono tabular-nums text-slate-500 dark:text-slate-400">
          {lang === 'ar' ? 'آخر تحديث للمجمّعات:' : 'Collector Sync:'} {latestSync}
        </div>
      </div>

      {/* Top Server & Health Summary Strip (6 Key Executive Figures) */}
      <section className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-4">
        <button
          type="button"
          onClick={() => onNavigate('servers')}
          className="text-start bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-4 hover:border-blue-500 dark:hover:border-blue-500 transition-colors cursor-pointer"
        >
          <div className="text-xs text-slate-500 dark:text-slate-400">
            {lang === 'ar' ? 'إجمالي الخوادم' : 'Total Servers'}
          </div>
          <div className="mt-2 text-2xl font-semibold font-mono tabular-nums text-slate-900 dark:text-slate-100">
            {totalServers}
          </div>
          <div className="mt-1 text-[11px] text-slate-500 dark:text-slate-400">
            {lang === 'ar' ? 'خوادم Windows مراقَبة' : 'Monitored Windows hosts'}
          </div>
        </button>

        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-4">
          <div className="text-xs text-slate-500 dark:text-slate-400">
            {lang === 'ar' ? 'خوادم متصلة' : 'Online Servers'}
          </div>
          <div className="mt-2 text-2xl font-semibold font-mono tabular-nums text-emerald-700 dark:text-emerald-400">
            {onlineServers}
          </div>
          <div className="mt-1 text-[11px] text-slate-500 dark:text-slate-400">
            {lang === 'ar' ? 'تعمل ضمن الحدود' : 'Nominal thresholds'}
          </div>
        </div>

        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-4">
          <div className="text-xs text-slate-500 dark:text-slate-400">
            {lang === 'ar' ? 'خوادم في تحذير' : 'Warning Servers'}
          </div>
          <div className="mt-2 text-2xl font-semibold font-mono tabular-nums text-amber-700 dark:text-amber-400">
            {warningServers}
          </div>
          <div className="mt-1 text-[11px] text-slate-500 dark:text-slate-400">
            {lang === 'ar' ? 'تتطلب متابعة' : 'Elevated load'}
          </div>
        </div>

        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-4">
          <div className="text-xs text-slate-500 dark:text-slate-400">
            {lang === 'ar' ? 'خوادم حرجة' : 'Critical Servers'}
          </div>
          <div className="mt-2 text-2xl font-semibold font-mono tabular-nums text-rose-700 dark:text-rose-400">
            {criticalServers}
          </div>
          <div className="mt-1 text-[11px] text-slate-500 dark:text-slate-400">
            {lang === 'ar' ? 'تجاوز الحد الحرج' : 'Threshold breach'}
          </div>
        </div>

        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-4">
          <div className="text-xs text-slate-500 dark:text-slate-400">
            {lang === 'ar' ? 'خوادم متوقفة' : 'Offline Servers'}
          </div>
          <div className="mt-2 text-2xl font-semibold font-mono tabular-nums text-slate-700 dark:text-slate-300">
            {offlineServers}
          </div>
          <div className="mt-1 text-[11px] text-slate-500 dark:text-slate-400">
            {lang === 'ar' ? 'غير قابلة للوصول' : 'Unreachable hosts'}
          </div>
        </div>

        <div className="bg-white dark:bg-slate-900 border border-blue-200 dark:border-blue-900 rounded-lg p-4">
          <div className="text-xs text-blue-700 dark:text-blue-400 font-medium">
            {lang === 'ar' ? 'صحة البنية التحتية' : 'Overall Health'}
          </div>
          <div className="mt-2 text-2xl font-semibold font-mono tabular-nums text-blue-700 dark:text-blue-400">
            {overallHealthPct !== null ? `${overallHealthPct}%` : '—'}
          </div>
          <div className="mt-1 text-[11px] text-slate-500 dark:text-slate-400">
            {activeAlerts.length} {lang === 'ar' ? 'تنبيه نشط' : 'active alerts'} · {openIncidents.length}{' '}
            {lang === 'ar' ? 'حوادث' : 'incidents'}
          </div>
        </div>
      </section>

      {/* Core Platform Subsystems Strip (Oracle, IIS, Network, Active Incidents) */}
      <section className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
        <button
          type="button"
          onClick={() => onNavigate('oracle')}
          className="text-start bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-4 hover:border-blue-500 transition-colors cursor-pointer"
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-500 dark:text-slate-400">
              {lang === 'ar' ? 'صحة قاعدة Oracle' : 'Oracle Database Health'}
            </span>
            {primaryOracle ? (
              <AssetStatusBadge
                status={primaryOracle.status}
                label={copy.status[primaryOracle.status]}
              />
            ) : (
              <span className="text-xs text-slate-400">{lang === 'ar' ? 'غير متصل' : 'Not Connected'}</span>
            )}
          </div>
          <div className="mt-2 text-lg font-semibold font-mono text-slate-900 dark:text-slate-100">
            {primaryOracle ? primaryOracle.serviceName : '—'}
          </div>
          <div className="mt-1.5 text-xs font-mono tabular-nums text-slate-600 dark:text-slate-400">
            {primaryOracle
              ? `${primaryOracle.responseTimeMs} ms · ${primaryOracle.activeSessions} sessions`
              : lang === 'ar'
                ? 'اضغط لإعداد مجمّع Oracle'
                : 'Click to configure Oracle collector'}
          </div>
        </button>

        <button
          type="button"
          onClick={() => onNavigate('iis')}
          className="text-start bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-4 hover:border-blue-500 transition-colors cursor-pointer"
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-500 dark:text-slate-400">
              {lang === 'ar' ? 'تطبيقات ومواقع IIS' : 'IIS Application Health'}
            </span>
            {iisSites.length > 0 ? (
              <AssetStatusBadge
                status={iisOnlineCount === iisSites.length ? 'Online' : 'Warning'}
                label={`${iisOnlineCount}/${iisSites.length}`}
              />
            ) : (
              <span className="text-xs text-slate-400">{lang === 'ar' ? 'لا بيانات' : 'No Data'}</span>
            )}
          </div>
          <div className="mt-2 text-lg font-semibold font-mono tabular-nums text-slate-900 dark:text-slate-100">
            {iisSites[0] ? `${iisSites[0].responseTimeMs} ms` : '0 / 0'}
          </div>
          <div className="mt-1.5 text-xs text-slate-600 dark:text-slate-400">
            {lang === 'ar' ? 'انقر لفحص مجموعات التطبيقات و APIs' : 'Inspect app pools & HTTP endpoints'}
          </div>
        </button>

        <button
          type="button"
          onClick={() => onNavigate('network')}
          className="text-start bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-4 hover:border-blue-500 transition-colors cursor-pointer"
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-500 dark:text-slate-400">
              {lang === 'ar' ? 'توفر الشبكة والفروع' : 'Network Availability'}
            </span>
            {networkDevices.length > 0 ? (
              <AssetStatusBadge
                status={netOnlineCount === networkDevices.length ? 'Online' : 'Critical'}
                label={`${netOnlineCount}/${networkDevices.length}`}
              />
            ) : (
              <span className="text-xs text-slate-400">{lang === 'ar' ? 'لا بيانات' : 'No Data'}</span>
            )}
          </div>
          <div className="mt-2 text-lg font-semibold font-mono tabular-nums text-slate-900 dark:text-slate-100">
            {netAvailabilityAvg}
          </div>
          <div className="mt-1.5 text-xs text-slate-600 dark:text-slate-400">
            {lang === 'ar' ? 'متوسط جاهزية الأجهزة المتصلة' : 'Monitored network device availability'}
          </div>
        </button>

        <button
          type="button"
          onClick={() => onNavigate('alerts')}
          className="text-start bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-4 hover:border-blue-500 transition-colors cursor-pointer"
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-500 dark:text-slate-400">
              {lang === 'ar' ? 'التنبيهات والحوادث الحالية' : 'Active Alerts & Incidents'}
            </span>
            <span className="text-xs font-mono tabular-nums font-semibold text-rose-700 dark:text-rose-400">
              {activeAlerts.filter((a) => a.severity === 'Critical').length}{' '}
              {lang === 'ar' ? 'حرج' : 'Critical'}
            </span>
          </div>
          <div className="mt-2 text-lg font-semibold font-mono tabular-nums text-slate-900 dark:text-slate-100">
            {activeAlerts.length} {lang === 'ar' ? 'مفتوحة / جارية' : 'Active'}
          </div>
          <div className="mt-1.5 text-xs text-slate-600 dark:text-slate-400">
            {lang === 'ar' ? 'إدارة الاستلام والتعيين والإغلاق' : 'Acknowledge, assign & resolve'}
          </div>
        </button>
      </section>

      {/* Historical Trends (Recharts) + Active Incident Table */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        <section className="lg:col-span-7 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-5">
          <div className="flex items-center justify-between pb-4 border-b border-slate-100 dark:border-slate-800">
            <div>
              <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                {lang === 'ar' ? 'اتجاهات الأداء التاريخية' : 'Historical Performance Trends'}
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                {lang === 'ar'
                  ? 'متوسط استهلاك المعالج (%) وزمن استجابة Oracle (ms)'
                  : 'Average Server CPU (%) vs Oracle Response Time (ms)'}
              </p>
            </div>
            <button
              type="button"
              onClick={() => onNavigate('analytics')}
              className="text-xs font-medium text-blue-600 dark:text-blue-400 hover:underline cursor-pointer whitespace-nowrap"
            >
              {lang === 'ar' ? 'التحليلات الكاملة' : 'Full Analytics'}
            </button>
          </div>

          {reports.length === 0 ? (
            <div className="h-64 flex flex-col items-center justify-center text-center text-xs text-slate-500 dark:text-slate-400 px-6">
              <p>
                {lang === 'ar'
                  ? 'لا توجد قراءات تاريخية بعد. ابدأ بربط خادم Windows من قسم "خوادم Windows" لجمع البيانات الحقيقية.'
                  : 'No historical telemetry recorded yet. Start by connecting a Windows Server in the Windows Servers tab.'}
              </p>
              <button
                type="button"
                onClick={() => onNavigate('servers')}
                className="mt-3 px-3.5 py-1.5 bg-blue-600 hover:bg-blue-700 text-white rounded-md font-medium cursor-pointer"
              >
                {lang === 'ar' ? 'ابدأ بربط السيرفرات' : 'Go to Windows Servers'}
              </button>
            </div>
          ) : (
            <div className="h-64 w-full mt-4" dir="ltr">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={reports} margin={{ top: 10, right: 16, left: -10, bottom: 0 }}>
                  <defs>
                    <linearGradient id="cpuGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#2563eb" stopOpacity={0.25} />
                      <stop offset="95%" stopColor="#2563eb" stopOpacity={0.02} />
                    </linearGradient>
                    <linearGradient id="oraGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#0ea5e9" stopOpacity={0.2} />
                      <stop offset="95%" stopColor="#0ea5e9" stopOpacity={0.02} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#cbd5e1" strokeOpacity={0.35} />
                  <XAxis dataKey="period" tick={{ fontSize: 11, fill: '#64748b' }} />
                  <YAxis tick={{ fontSize: 11, fill: '#64748b' }} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#0f172a',
                      border: '1px solid #1e293b',
                      borderRadius: '6px',
                      color: '#f8fafc',
                      fontSize: '12px',
                    }}
                  />
                  <Area
                    type="monotone"
                    dataKey="avgCpuPct"
                    name="Avg CPU (%)"
                    stroke="#2563eb"
                    strokeWidth={2}
                    fill="url(#cpuGrad)"
                  />
                  <Area
                    type="monotone"
                    dataKey="avgOracleMs"
                    name="Oracle RTT (ms)"
                    stroke="#0ea5e9"
                    strokeWidth={2}
                    fill="url(#oraGrad)"
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          )}
        </section>

        {/* Current Incidents List */}
        <section className="lg:col-span-5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg overflow-hidden">
          <div className="px-5 py-4 border-b border-slate-100 dark:border-slate-800 flex items-center justify-between">
            <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
              {lang === 'ar' ? 'الحوادث النشطة الحالية' : 'Current Active Incidents'}
            </h2>
            <button
              type="button"
              onClick={() => onNavigate('alerts')}
              className="text-xs font-medium text-blue-600 dark:text-blue-400 hover:underline cursor-pointer whitespace-nowrap"
            >
              {lang === 'ar' ? 'إدارة التنبيهات' : 'Manage Alerts'}
            </button>
          </div>

          {activeAlerts.length === 0 ? (
            <div className="p-8 text-center text-xs text-slate-500 dark:text-slate-400">
              {lang === 'ar'
                ? 'لا توجد تنبيهات أو حوادث مسجلة حتى الآن.'
                : 'No active alerts or incidents recorded.'}
            </div>
          ) : (
            <div className="divide-y divide-slate-100 dark:divide-slate-800">
              {activeAlerts.slice(0, 5).map((alert) => (
                <div
                  key={alert.id}
                  onClick={() => onNavigate('alerts')}
                  className="p-4 hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors cursor-pointer"
                >
                  <div className="flex items-center justify-between gap-2">
                    <SeverityText severity={alert.severity} label={copy.severity[alert.severity]} />
                    <IncidentStatusText status={alert.status} label={copy.incidentStatus[alert.status]} />
                  </div>
                  <div className="text-xs font-semibold text-slate-900 dark:text-slate-100 mt-1.5">
                    {lang === 'ar' ? alert.titleAr : alert.title}
                  </div>
                  <div className="text-[11px] font-mono text-slate-500 dark:text-slate-400 mt-1">
                    {alert.id} · {alert.assetName} · {alert.timestamp}
                  </div>
                </div>
              ))}
            </div>
          )}
        </section>
      </div>
    </div>
  );
}
