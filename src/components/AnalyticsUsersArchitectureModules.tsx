import { useState, type FormEvent } from 'react';
import { Check, Copy } from 'lucide-react';
import {
  Bar,
  BarChart,
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { ENTERPRISE_ARTIFACTS } from '../data/enterpriseKit';
import { COPY } from '../data/i18n';
import {
  AlertRecord,
  AuditLogEntry,
  CollectorConfig,
  CredentialKind,
  CredentialProfileSummary,
  DailyReportRow,
  Language,
  OracleDatabaseMetric,
  UserAccount,
  UserRole,
  WindowsServer,
} from '../types/infrastructure';
import {
  computeZScoreAnomalies,
  detectRecurringIncidents,
  forecastCapacity,
} from '../utils/intelligence';

/* =========================== MODULE H + SECTION 5: ANALYTICS & INTELLIGENT MONITORING =========================== */
export function AnalyticsModule({
  servers,
  oracleDatabases,
  alerts,
  reports,
  lang,
}: {
  servers: WindowsServer[];
  oracleDatabases: OracleDatabaseMetric[];
  alerts: AlertRecord[];
  reports: DailyReportRow[];
  lang: Language;
}) {
  const [reportPeriod, setReportPeriod] = useState<'daily' | 'weekly' | 'monthly'>('daily');

  const anomalies = computeZScoreAnomalies(servers);
  const forecasts = forecastCapacity(servers, oracleDatabases[0]?.tablespaces ?? []);
  const recurring = detectRecurringIncidents(alerts);

  const summaryMultiplier = reportPeriod === 'daily' ? 1 : reportPeriod === 'weekly' ? 7 : 30;

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 pb-4 border-b border-slate-200 dark:border-slate-800">
        <div>
          <h1 className="text-xl font-semibold text-slate-900 dark:text-slate-100">
            {lang === 'ar' ? 'التحليلات التاريخية والذكاء الإحصائي' : 'Historical Analytics & Statistical Intelligence'}
          </h1>
          <p className="text-sm text-slate-600 dark:text-slate-400 mt-1">
            {lang === 'ar'
              ? 'تقارير يومية/أسبوعية/شهرية، كشف الشذوذ عبر Z-Score، والتنبؤ الخطي بسعة الأقراص ومساحات Oracle.'
              : 'Daily/weekly/monthly reports plus real Z-score anomaly detection, OLS linear capacity forecasting, and recurring failure detection.'}
          </p>
        </div>

        <div className="inline-flex items-center p-1 bg-slate-100 dark:bg-slate-800 rounded-md">
          {(['daily', 'weekly', 'monthly'] as const).map((p) => (
            <button
              key={p}
              type="button"
              onClick={() => setReportPeriod(p)}
              className={`px-3 py-1 text-xs font-medium rounded transition-colors cursor-pointer ${
                reportPeriod === p
                  ? 'bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100 shadow-xs'
                  : 'text-slate-600 dark:text-slate-400'
              }`}
            >
              {p === 'daily'
                ? lang === 'ar'
                  ? 'يومي'
                  : 'Daily'
                : p === 'weekly'
                  ? lang === 'ar'
                    ? 'أسبوعي'
                    : 'Weekly'
                  : lang === 'ar'
                    ? 'شهري'
                    : 'Monthly'}
            </button>
          ))}
        </div>
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <section className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-5">
          <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100 mb-3">
            {lang === 'ar' ? 'نسبة التوفر وزمن استجابة Oracle' : 'Infrastructure Availability & Oracle RTT Trend'}
          </h2>
          {reports.length === 0 ? (
            <div className="h-56 flex items-center justify-center text-center px-4 text-xs text-slate-500 dark:text-slate-400 border border-dashed border-slate-200 dark:border-slate-800 rounded">
              {lang === 'ar'
                ? 'لا توجد تقارير تاريخية بعد — ستظهر البيانات الحقيقية هنا فور تجميع عينات القياس.'
                : 'No historical telemetry reports yet — trend charts populate once real metrics are collected.'}
            </div>
          ) : (
            <div className="h-56 w-full" dir="ltr">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={reports} margin={{ top: 5, right: 16, left: -10, bottom: 0 }}>
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
                  <Line type="monotone" dataKey="avgOracleMs" name="Oracle RTT (ms)" stroke="#2563eb" strokeWidth={2} />
                  <Line type="monotone" dataKey="avgCpuPct" name="Avg CPU (%)" stroke="#0ea5e9" strokeWidth={2} />
                </LineChart>
              </ResponsiveContainer>
            </div>
          )}
        </section>

        <section className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-5">
          <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100 mb-3">
            {lang === 'ar' ? 'تكرار الحوادث ووقت التوقف (دقائق)' : 'Incident Frequency & Downtime Minutes'}
          </h2>
          {reports.length === 0 ? (
            <div className="h-56 flex items-center justify-center text-center px-4 text-xs text-slate-500 dark:text-slate-400 border border-dashed border-slate-200 dark:border-slate-800 rounded">
              {lang === 'ar'
                ? 'لا توجد بيانات حوادث أو توقف مسجلة بعد.'
                : 'No incident or downtime report samples recorded yet.'}
            </div>
          ) : (
            <div className="h-56 w-full" dir="ltr">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={reports} margin={{ top: 5, right: 16, left: -10, bottom: 0 }}>
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
                  <Bar dataKey="totalDowntimeMin" name="Downtime (min)" fill="#e11d48" radius={[3, 3, 0, 0]} />
                  <Bar dataKey="incidentCount" name="Incidents" fill="#2563eb" radius={[3, 3, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </section>
      </div>

      {/* Period Summary Stats */}
      <section className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-4">
          <div className="text-slate-500 dark:text-slate-400">
            {lang === 'ar' ? 'متوسط التوفر للفترة' : 'Period Availability'}
          </div>
          <div className="text-xl font-mono tabular-nums font-semibold text-slate-900 dark:text-slate-100 mt-1">
            {reports.length > 0
              ? `${(reports.reduce((a, r) => a + r.availabilityPct, 0) / reports.length).toFixed(2)}%`
              : '—'}
          </div>
        </div>
        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-4">
          <div className="text-slate-500 dark:text-slate-400">
            {lang === 'ar' ? 'إجمالي الحوادث المقدّر' : 'Scaled Incident Count'}
          </div>
          <div className="text-xl font-mono tabular-nums font-semibold text-slate-900 dark:text-slate-100 mt-1">
            {reports.length > 0
              ? Math.round((reports.reduce((a, r) => a + r.incidentCount, 0) / reports.length) * summaryMultiplier)
              : alerts.length}
          </div>
        </div>
        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-4">
          <div className="text-slate-500 dark:text-slate-400">
            {lang === 'ar' ? 'إجمالي دقائق التوقف' : 'Period Downtime Minutes'}
          </div>
          <div className="text-xl font-mono tabular-nums font-semibold text-slate-900 dark:text-slate-100 mt-1">
            {reports.length > 0
              ? `${Math.round((reports.reduce((a, r) => a + r.totalDowntimeMin, 0) / reports.length) * summaryMultiplier)} min`
              : `${alerts.reduce((a, al) => a + al.downtimeMinutes, 0)} min`}
          </div>
        </div>
      </section>

      {/* Section 5: Real Statistical Intelligence (Anomalies, Capacity Forecast, Recurring Patterns) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Capacity Forecast */}
        <section className="lg:col-span-6 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg overflow-hidden">
          <div className="px-5 py-4 border-b border-slate-100 dark:border-slate-800">
            <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
              {lang === 'ar' ? 'توقعات السعة الخطية (OLS Regression)' : 'Capacity Exhaustion Forecast (Linear Trend)'}
            </h2>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
              {lang === 'ar'
                ? 'حساب الأيام المتبقية للوصول إلى عتبة 90% بناءً على معدل النمو اليومي.'
                : 'Projected days until 90% threshold based on observed daily storage growth.'}
            </p>
          </div>
          <div className="divide-y divide-slate-100 dark:divide-slate-800 text-xs">
            {forecasts.length === 0 ? (
              <div className="p-6 text-slate-500 dark:text-slate-400">
                {lang === 'ar'
                  ? 'لا توجد بيانات أقراص خوادم أو Oracle للتنبؤ بالسعة بعد.'
                  : 'No server disk or Oracle tablespace metrics ingested yet for capacity forecasting.'}
              </div>
            ) : (
              forecasts.slice(0, 6).map((f) => (
                <div key={f.target} className="px-5 py-3 flex items-center justify-between gap-3">
                  <div>
                    <div className="font-medium text-slate-900 dark:text-slate-100">{f.target}</div>
                    <div className="font-mono text-[11px] text-slate-500 dark:text-slate-400">
                      {f.category} · {f.currentPct}% used · +{f.dailyGrowthPct}%/day
                    </div>
                  </div>
                  <div className="text-end font-mono tabular-nums whitespace-nowrap">
                    <div
                      className={
                        f.status === 'Action Needed'
                          ? 'text-rose-700 dark:text-rose-400 font-semibold'
                          : f.status === 'Watch'
                            ? 'text-amber-700 dark:text-amber-400 font-semibold'
                            : 'text-emerald-700 dark:text-emerald-400 font-medium'
                      }
                    >
                      {f.daysTo90Pct === 0
                        ? 'Threshold Exceeded'
                        : f.daysTo90Pct !== null
                          ? `~${f.daysTo90Pct} days to 90%`
                          : 'Stable'}
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        </section>

        {/* Z-Score Anomalies & Recurring Incident Recommendations */}
        <section className="lg:col-span-6 space-y-6">
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg overflow-hidden">
            <div className="px-5 py-3.5 border-b border-slate-100 dark:border-slate-800">
              <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                {lang === 'ar' ? 'رصد الاستهلاك غير الطبيعي (Z-Score ≥ 1.75)' : 'Abnormal Consumption Detection (Z-Score ≥ 1.75)'}
              </h2>
            </div>
            <div className="divide-y divide-slate-100 dark:divide-slate-800 text-xs">
              {anomalies.length === 0 ? (
                <div className="p-6 text-slate-500 dark:text-slate-400">
                  {lang === 'ar'
                    ? 'لم يتم رصد شذوذ إحصائي حتى الآن (يتطلب عينة قراءات كافية).'
                    : 'No statistical anomalies detected yet (requires sufficient live telemetry samples).'}
                </div>
              ) : (
                anomalies.map((a, idx) => (
                  <div key={`${a.assetName}-${idx}`} className="px-5 py-3 flex items-center justify-between">
                    <div>
                      <div className="font-mono font-semibold text-slate-900 dark:text-slate-100">
                        {a.assetName} · {a.metric}
                      </div>
                      <div className="text-slate-500 dark:text-slate-400">
                        {a.timestamp} · Baseline μ = {a.baselineMean}
                        {a.unit}
                      </div>
                    </div>
                    <div className="text-end font-mono tabular-nums">
                      <span className="font-semibold text-amber-700 dark:text-amber-400">
                        {a.observedValue}
                        {a.unit} (z={a.zScore})
                      </span>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>

          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg overflow-hidden">
            <div className="px-5 py-3.5 border-b border-slate-100 dark:border-slate-800">
              <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                {lang === 'ar' ? 'الحوادث المتكررة والتوصيات التشغيلية' : 'Recurring Failure Patterns & Recommendations'}
              </h2>
            </div>
            <div className="divide-y divide-slate-100 dark:divide-slate-800 text-xs">
              {recurring.length === 0 ? (
                <div className="p-6 text-slate-500 dark:text-slate-400">
                  {lang === 'ar'
                    ? 'لا توجد أنماط حوادث متكررة مسجلة.'
                    : 'No recurring failure patterns detected.'}
                </div>
              ) : (
                recurring.map((r) => (
                  <div key={`${r.assetName}-${r.module}`} className="px-5 py-3 space-y-1">
                    <div className="flex items-center justify-between font-semibold text-slate-900 dark:text-slate-100">
                      <span className="font-mono">{r.assetName} ({r.module})</span>
                      <span className="font-mono tabular-nums text-rose-700 dark:text-rose-400">
                        {r.occurrences}x · {r.totalDowntimeMinutes}m downtime
                      </span>
                    </div>
                    <p className="text-slate-600 dark:text-slate-400">
                      {lang === 'ar' ? r.recommendationAr : r.recommendation}
                    </p>
                  </div>
                ))
              )}
            </div>
          </div>
        </section>
      </div>
    </div>
  );
}

/* =========================== MODULE I: USER MANAGEMENT & AUDIT LOGS =========================== */
export function UsersAuditModule({
  users,
  auditLogs,
  currentRole,
  lang,
  onCreateUser,
  onToggleUser,
  onChangeRole,
}: {
  users: UserAccount[];
  auditLogs: AuditLogEntry[];
  currentRole: UserRole | null;
  lang: Language;
  onCreateUser: (payload: {
    username: string;
    fullName: string;
    email: string;
    role: UserRole;
    password: string;
  }) => Promise<string | null>;
  onToggleUser: (id: string, active: boolean) => Promise<string | null>;
  onChangeRole: (id: string, role: UserRole) => Promise<string | null>;
}) {
  const isAdmin = currentRole === 'Administrator';
  const canViewAudit = currentRole !== null && ['Administrator', 'IT Manager'].includes(currentRole);

  const [username, setUsername] = useState('');
  const [fullName, setFullName] = useState('');
  const [email, setEmail] = useState('');
  const [role, setRole] = useState<UserRole>('IT Engineer');
  const [password, setPassword] = useState('');
  const [msg, setMsg] = useState<string | null>(null);

  const handleAddUser = async (e: FormEvent) => {
    e.preventDefault();
    const err = await onCreateUser({ username, fullName, email, role, password });
    if (err) {
      setMsg(err);
    } else {
      setUsername('');
      setFullName('');
      setEmail('');
      setPassword('');
      setMsg(lang === 'ar' ? 'تم إنشاء المستخدم بتشفير scrypt.' : 'User created with scrypt-hashed password.');
    }
  };

  return (
    <div className="space-y-6">
      <div className="pb-4 border-b border-slate-200 dark:border-slate-800">
        <h1 className="text-xl font-semibold text-slate-900 dark:text-slate-100">
          {lang === 'ar' ? 'إدارة المستخدمين والصلاحيات وسجل التدقيق' : 'User Management (RBAC) & Audit Logs'}
        </h1>
        <p className="text-sm text-slate-600 dark:text-slate-400 mt-1">
          {lang === 'ar'
            ? 'أدوار: Administrator، IT Manager، IT Engineer، Read-only Viewer مع سجل تدقيق للعمليات الحساسة.'
            : 'Roles: Administrator, IT Manager, IT Engineer, and Read-only Viewer with server-enforced audit trails.'}
        </p>
      </div>

      {msg && (
        <div className="p-3 bg-blue-50 dark:bg-blue-950/40 border border-blue-200 dark:border-blue-900 rounded-md text-xs text-blue-900 dark:text-blue-200">
          {msg}
        </div>
      )}

      {/* Create User Form (Administrator Only) */}
      {isAdmin && (
        <form
          onSubmit={handleAddUser}
          className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-5 space-y-4 text-xs"
        >
          <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
            {lang === 'ar' ? 'إضافة مستخدم جديد' : 'Provision New User Account'}
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-5 gap-3">
            <input
              type="text"
              placeholder="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
              className="px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md font-mono text-slate-900 dark:text-slate-100"
            />
            <input
              type="text"
              placeholder={lang === 'ar' ? 'الاسم الكامل' : 'Full Name'}
              value={fullName}
              onChange={(e) => setFullName(e.target.value)}
              required
              className="px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md text-slate-900 dark:text-slate-100"
            />
            <input
              type="email"
              placeholder="user@medlabs.jo"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              className="px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md text-slate-900 dark:text-slate-100"
            />
            <select
              value={role}
              onChange={(e) => setRole(e.target.value as UserRole)}
              className="px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md text-slate-900 dark:text-slate-100"
            >
              <option value="Administrator">Administrator</option>
              <option value="IT Manager">IT Manager</option>
              <option value="IT Engineer">IT Engineer</option>
              <option value="Read-only Viewer">Read-only Viewer</option>
            </select>
            <input
              type="password"
              placeholder={lang === 'ar' ? 'كلمة مرور (8+)' : 'Password (8+ chars)'}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              minLength={8}
              className="px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md text-slate-900 dark:text-slate-100"
            />
          </div>
          <div className="flex justify-end">
            <button
              type="submit"
              className="px-4 py-2 rounded-md bg-blue-600 text-white font-medium hover:bg-blue-700 cursor-pointer"
            >
              {lang === 'ar' ? 'إنشاء الحساب' : 'Create Account'}
            </button>
          </div>
        </form>
      )}

      {/* Users Table */}
      <section className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg overflow-hidden">
        <div className="px-5 py-3.5 border-b border-slate-100 dark:border-slate-800">
          <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
            {lang === 'ar' ? 'حسابات الفريق والأدوار' : 'Authorized Personnel & Roles'}
          </h2>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-start border-collapse">
            <thead>
              <tr className="border-b border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/50 text-[11px] font-semibold text-slate-500 dark:text-slate-400">
                <th className="py-2.5 px-4 text-start">{lang === 'ar' ? 'المستخدم' : 'User'}</th>
                <th className="py-2.5 px-3 text-start">{lang === 'ar' ? 'الدور' : 'Role'}</th>
                <th className="py-2.5 px-3 text-start">{lang === 'ar' ? 'الحالة' : 'Status'}</th>
                <th className="py-2.5 px-3 text-start">{lang === 'ar' ? 'آخر دخول' : 'Last Login'}</th>
                <th className="py-2.5 px-4 text-end">{lang === 'ar' ? 'إدارة' : 'Manage'}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800 text-xs">
              {users.map((u) => (
                <tr key={u.id} className="hover:bg-slate-50 dark:hover:bg-slate-800/40">
                  <td className="py-3 px-4">
                    <div className="font-medium text-slate-900 dark:text-slate-100">{u.fullName}</div>
                    <div className="font-mono text-[11px] text-slate-500 dark:text-slate-400">
                      {u.username} · {u.email}
                    </div>
                  </td>
                  <td className="py-3 px-3">
                    {isAdmin ? (
                      <select
                        value={u.role}
                        onChange={async (e) => {
                          const err = await onChangeRole(u.id, e.target.value as UserRole);
                          if (err) setMsg(err);
                        }}
                        className="px-2 py-1 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded text-xs"
                      >
                        <option value="Administrator">Administrator</option>
                        <option value="IT Manager">IT Manager</option>
                        <option value="IT Engineer">IT Engineer</option>
                        <option value="Read-only Viewer">Read-only Viewer</option>
                      </select>
                    ) : (
                      <span className="font-mono text-slate-800 dark:text-slate-200">{u.role}</span>
                    )}
                  </td>
                  <td className="py-3 px-3">
                    <span
                      className={
                        u.active
                          ? 'text-emerald-700 dark:text-emerald-400 font-medium'
                          : 'text-slate-500 font-medium'
                      }
                    >
                      {u.active ? '● Active' : '○ Disabled'}
                    </span>
                  </td>
                  <td className="py-3 px-3 font-mono tabular-nums text-slate-500 dark:text-slate-400">
                    {u.lastLogin}
                  </td>
                  <td className="py-3 px-4 text-end">
                    <button
                      type="button"
                      disabled={!isAdmin || u.username === 'admin.medlabs'}
                      onClick={async () => {
                        const err = await onToggleUser(u.id, !u.active);
                        if (err) setMsg(err);
                      }}
                      className="text-xs font-medium text-blue-600 dark:text-blue-400 hover:underline disabled:opacity-40 cursor-pointer"
                    >
                      {u.active ? (lang === 'ar' ? 'تعطيل' : 'Disable') : lang === 'ar' ? 'تفعيل' : 'Enable'}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {/* Audit Logs */}
      <section className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg overflow-hidden">
        <div className="px-5 py-3.5 border-b border-slate-100 dark:border-slate-800">
          <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
            {lang === 'ar' ? 'سجل التدقيق الأمني والعمليات' : 'Administrative & Security Audit Log'}
          </h2>
        </div>

        {!canViewAudit ? (
          <div className="p-6 text-xs text-slate-500 dark:text-slate-400">
            {lang === 'ar'
              ? 'سجل التدقيق متاح فقط لأدوار Administrator و IT Manager.'
              : 'Sign in as Administrator or IT Manager to inspect live security audit events.'}
          </div>
        ) : auditLogs.length === 0 ? (
          <div className="p-6 text-xs text-slate-500 dark:text-slate-400">
            {lang === 'ar'
              ? 'لا توجد أحداث تدقيق مسجلة بعد — يتم تسجيل عمليات الدخول وتغييرات الإعدادات تلقائياً.'
              : 'No security or administrative audit events recorded yet.'}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-start border-collapse">
              <thead>
                <tr className="border-b border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/50 text-[11px] font-semibold text-slate-500 dark:text-slate-400">
                  <th className="py-2.5 px-4 text-start">{lang === 'ar' ? 'الوقت' : 'Timestamp'}</th>
                  <th className="py-2.5 px-3 text-start">{lang === 'ar' ? 'المنفذ' : 'Actor'}</th>
                  <th className="py-2.5 px-3 text-start">{lang === 'ar' ? 'العملية' : 'Action'}</th>
                  <th className="py-2.5 px-3 text-start">{lang === 'ar' ? 'الهدف' : 'Target'}</th>
                  <th className="py-2.5 px-4 text-end">{lang === 'ar' ? 'النتيجة' : 'Outcome'}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800 text-xs">
                {auditLogs.map((log) => (
                  <tr key={log.id}>
                    <td className="py-2.5 px-4 font-mono tabular-nums text-slate-500 dark:text-slate-400 whitespace-nowrap">
                      {log.timestamp}
                    </td>
                    <td className="py-2.5 px-3 font-mono text-slate-900 dark:text-slate-100">
                      {log.actor} ({log.role})
                    </td>
                    <td className="py-2.5 px-3 font-mono text-blue-700 dark:text-blue-400">{log.action}</td>
                    <td className="py-2.5 px-3 text-slate-700 dark:text-slate-300">{log.target}</td>
                    <td className="py-2.5 px-4 text-end">
                      <span
                        className={
                          log.outcome === 'Success'
                            ? 'text-emerald-700 dark:text-emerald-400 font-medium'
                            : 'text-rose-700 dark:text-rose-400 font-medium'
                        }
                      >
                        {log.outcome}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}

/* =========================== SECTION 4: CENTRAL MONITORING ENGINE, ENCRYPTED VAULT & REFERENCE KIT =========================== */
export function CollectorsArchitectureModule({
  collectors,
  credentials,
  vaultPersistent,
  currentRole,
  lang,
  onUpdateCollector,
  onSaveCredential,
  onDeleteCredential,
}: {
  collectors: CollectorConfig[];
  credentials: CredentialProfileSummary[];
  vaultPersistent: boolean;
  currentRole: UserRole | null;
  lang: Language;
  onUpdateCollector: (
    id: string,
    patch: { enabled?: boolean; scheduleSeconds?: number; timeoutMs?: number; retryCount?: number; runNow?: boolean }
  ) => Promise<string | null>;
  onSaveCredential: (payload: {
    name: string;
    kind: CredentialKind;
    username?: string;
    password?: string;
    domain?: string;
    community?: string;
    useIntegratedAuth?: boolean;
    snmpSecurityLevel?: 'noAuthNoPriv' | 'authNoPriv' | 'authPriv';
    snmpAuthProtocol?: 'MD5' | 'SHA' | 'SHA256';
    snmpPrivProtocol?: 'DES' | 'AES';
    snmpPrivPassword?: string;
  }) => Promise<string | null>;
  onDeleteCredential: (id: string) => Promise<string | null>;
}) {
  const copy = COPY[lang];
  const [selectedArtifactId, setSelectedArtifactId] = useState(ENTERPRISE_ARTIFACTS[0].id);
  const [copied, setCopied] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);

  // Encrypted Vault form state
  const [credName, setCredName] = useState('');
  const [credKind, setCredKind] = useState<CredentialKind>('oracle');
  const [credUser, setCredUser] = useState('');
  const [credDomain, setCredDomain] = useState('');
  const [credPass, setCredPass] = useState('');
  const [credCommunity, setCredCommunity] = useState('');
  const [credIntegrated, setCredIntegrated] = useState(false);
  const [snmpSecLevel, setSnmpSecLevel] = useState<'noAuthNoPriv' | 'authNoPriv' | 'authPriv'>('authPriv');
  const [snmpAuthProto, setSnmpAuthProto] = useState<'MD5' | 'SHA' | 'SHA256'>('SHA');
  const [snmpPrivProto, setSnmpPrivProto] = useState<'DES' | 'AES'>('AES');
  const [snmpPrivPass, setSnmpPrivPass] = useState('');

  // Inline interval edit
  const [editingColId, setEditingColId] = useState<string | null>(null);
  const [editSec, setEditSec] = useState(60);
  const [editTimeout, setEditTimeout] = useState(8000);
  const [editRetries, setEditRetries] = useState(1);

  const canModify = currentRole !== null && ['Administrator', 'IT Manager', 'IT Engineer'].includes(currentRole);
  const artifact = ENTERPRISE_ARTIFACTS.find((a) => a.id === selectedArtifactId) ?? ENTERPRISE_ARTIFACTS[0];

  const handleCopy = () => {
    navigator.clipboard?.writeText(artifact.code);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  const handleAddCred = async (e: FormEvent) => {
    e.preventDefault();
    const err = await onSaveCredential({
      name: credName,
      kind: credKind,
      username: credUser || undefined,
      password: credPass || undefined,
      domain: credDomain || undefined,
      community: credCommunity || undefined,
      useIntegratedAuth: credIntegrated,
      snmpSecurityLevel: snmpSecLevel,
      snmpAuthProtocol: snmpAuthProto,
      snmpPrivProtocol: snmpPrivProto,
      snmpPrivPassword: snmpPrivPass || undefined,
    });
    if (err) {
      setMsg(err);
    } else {
      setCredName('');
      setCredUser('');
      setCredDomain('');
      setCredPass('');
      setCredCommunity('');
      setSnmpPrivPass('');
      setMsg(
        lang === 'ar'
          ? 'تم تشفير وحفظ بيانات الاعتماد للقراءة فقط داخل الخزنة (AES-256-GCM).'
          : 'Read-only credential encrypted (AES-256-GCM) and saved to central vault.'
      );
    }
  };

  return (
    <div className="space-y-6">
      <div className="pb-4 border-b border-slate-200 dark:border-slate-800">
        <h1 className="text-xl font-semibold text-slate-900 dark:text-slate-100">
          {lang === 'ar'
            ? 'محرك المراقبة المركزي، خزنة الاعتماد المشفرة، والمرجع الهندسي'
            : 'Central Monitoring Engine, Encrypted Vault & Reference Kit'}
        </h1>
        <p className="text-sm text-slate-600 dark:text-slate-400 mt-1">
          {lang === 'ar'
            ? 'تشغيل المجمّعات مركزياً بدون أي وكلاء على السيرفرات أو قواعد البيانات، مع تشفير بيانات الاعتماد عبر AES-256-GCM.'
            : 'All 5 agentless collectors run centrally with configurable intervals/timeouts/retries and AES-256-GCM encrypted read-only credentials.'}
        </p>
      </div>

      {msg && (
        <div className="p-3 bg-blue-50 dark:bg-blue-950/40 border border-blue-200 dark:border-blue-900 rounded-md text-xs text-blue-900 dark:text-blue-200">
          {msg}
        </div>
      )}

      {/* Encrypted Read-Only Credential Vault */}
      <section className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-5 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 pb-3 border-b border-slate-100 dark:border-slate-800">
          <div>
            <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
              {lang === 'ar' ? 'خزنة بيانات الاعتماد المشفرة (AES-256-GCM · قراءة فقط)' : 'Encrypted Read-Only Credential Vault (AES-256-GCM)'}
            </h2>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
              {lang === 'ar'
                ? 'لا يتم إرسال كلمات المرور إلى المتصفح أبداً. تُستخدم داخل الخادم المركزي فقط أثناء الفحص.'
                : 'Secrets are encrypted on the backend and never exposed to the browser or client code.'}
            </p>
          </div>
          <span
            className={`text-[11px] font-mono px-2.5 py-1 rounded border ${
              vaultPersistent
                ? 'bg-emerald-50 dark:bg-emerald-950/30 border-emerald-200 dark:border-emerald-900 text-emerald-700 dark:text-emerald-300'
                : 'bg-amber-50 dark:bg-amber-950/30 border-amber-200 dark:border-amber-900 text-amber-800 dark:text-amber-300'
            }`}
          >
            {vaultPersistent
              ? 'MEDLABS_VAULT_KEY Active'
              : 'Preview Ephemeral Key (Set MEDLABS_VAULT_KEY in .env for persistent reboot decryption)'}
          </span>
        </div>

        {canModify ? (
          <form onSubmit={handleAddCred} className="grid grid-cols-1 md:grid-cols-4 gap-3 text-xs">
            <input
              type="text"
              placeholder={lang === 'ar' ? 'اسم الملف (مثلاً Oracle-RO)' : 'Profile Name (e.g. Oracle-RO)'}
              value={credName}
              onChange={(e) => setCredName(e.target.value)}
              required
              className="px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md text-slate-900 dark:text-slate-100"
            />
            <select
              value={credKind}
              onChange={(e) => setCredKind(e.target.value as CredentialKind)}
              className="px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md text-slate-900 dark:text-slate-100"
            >
              <option value="oracle">Oracle Read-Only (SELECT)</option>
              <option value="windows">Windows WMI / WinRM Read-Only</option>
              <option value="snmpv2c">SNMPv2c Read-Only Community</option>
              <option value="snmpv3">SNMPv3 USM (Auth / Priv)</option>
            </select>

            {credKind === 'snmpv2c' ? (
              <input
                type="password"
                placeholder="SNMPv2c Community String"
                value={credCommunity}
                onChange={(e) => setCredCommunity(e.target.value)}
                required
                className="px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md font-mono text-slate-900 dark:text-slate-100"
              />
            ) : (
              <input
                type="text"
                placeholder={credKind === 'snmpv3' ? 'SNMPv3 Username' : 'Username (read-only)'}
                value={credUser}
                onChange={(e) => setCredUser(e.target.value)}
                required={!credIntegrated}
                className="px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md font-mono text-slate-900 dark:text-slate-100"
              />
            )}

            {credKind === 'windows' && (
              <input
                type="text"
                placeholder="AD Domain (optional, e.g. MEDLABS)"
                value={credDomain}
                onChange={(e) => setCredDomain(e.target.value)}
                className="px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md font-mono text-slate-900 dark:text-slate-100"
              />
            )}

            {credKind !== 'snmpv2c' && !(credKind === 'windows' && credIntegrated) && (
              <input
                type="password"
                placeholder={credKind === 'snmpv3' ? 'Auth Password (if authNoPriv/authPriv)' : 'Password (encrypted at rest)'}
                value={credPass}
                onChange={(e) => setCredPass(e.target.value)}
                required={credKind === 'oracle' || (credKind === 'windows' && !credIntegrated)}
                className="px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md text-slate-900 dark:text-slate-100"
              />
            )}

            {credKind === 'windows' && (
              <label className="inline-flex items-center gap-2 px-3 py-2 border border-slate-200 dark:border-slate-700 rounded-md text-slate-700 dark:text-slate-300">
                <input
                  type="checkbox"
                  checked={credIntegrated}
                  onChange={(e) => setCredIntegrated(e.target.checked)}
                />
                <span>{lang === 'ar' ? 'مصادقة Windows المتكاملة' : 'Windows Integrated Auth'}</span>
              </label>
            )}

            {credKind === 'snmpv3' && (
              <>
                <select
                  value={snmpSecLevel}
                  onChange={(e) => setSnmpSecLevel(e.target.value as 'noAuthNoPriv' | 'authNoPriv' | 'authPriv')}
                  className="px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md"
                >
                  <option value="authPriv">authPriv (Auth + AES)</option>
                  <option value="authNoPriv">authNoPriv (Auth Only)</option>
                  <option value="noAuthNoPriv">noAuthNoPriv</option>
                </select>
                <select
                  value={snmpAuthProto}
                  onChange={(e) => setSnmpAuthProto(e.target.value as 'MD5' | 'SHA' | 'SHA256')}
                  className="px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md"
                >
                  <option value="SHA">Auth: SHA-1</option>
                  <option value="SHA256">Auth: SHA-256</option>
                  <option value="MD5">Auth: MD5</option>
                </select>
                {snmpSecLevel === 'authPriv' && (
                  <>
                    <select
                      value={snmpPrivProto}
                      onChange={(e) => setSnmpPrivProto(e.target.value as 'DES' | 'AES')}
                      className="px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md"
                    >
                      <option value="AES">Priv: AES-128</option>
                    </select>
                    <input
                      type="password"
                      placeholder="SNMPv3 Privacy Password"
                      value={snmpPrivPass}
                      onChange={(e) => setSnmpPrivPass(e.target.value)}
                      required
                      className="px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md"
                    />
                  </>
                )}
              </>
            )}

            <button
              type="submit"
              className="px-4 py-2 rounded-md bg-blue-600 hover:bg-blue-700 text-white font-medium cursor-pointer"
            >
              {lang === 'ar' ? 'تشفير وحفظ بالخزنة' : 'Encrypt & Store'}
            </button>
          </form>
        ) : (
          <div className="text-xs text-slate-500 dark:text-slate-400">
            {lang === 'ar'
              ? 'سجّل الدخول بحساب Engineer أو Administrator لإدارة خزنة بيانات الاعتماد.'
              : 'Sign in as IT Engineer or Administrator to add encrypted credential profiles.'}
          </div>
        )}

        {credentials.length > 0 && (
          <div className="divide-y divide-slate-100 dark:divide-slate-800 border-t border-slate-100 dark:border-slate-800 pt-2 text-xs">
            {credentials.map((c) => (
              <div key={c.id} className="py-2.5 flex items-center justify-between gap-3">
                <div>
                  <span className="font-semibold text-slate-900 dark:text-slate-100">{c.name}</span>
                  <span className="ms-2 font-mono text-[11px] px-1.5 py-0.5 bg-slate-100 dark:bg-slate-800 rounded">
                    {c.kind}
                  </span>
                  <span className="ms-2 font-mono text-slate-500">
                    {c.useIntegratedAuth ? 'Windows Integrated' : c.username ? `${c.domain ? `${c.domain}\\` : ''}${c.username}` : 'Encrypted Secret'}
                  </span>
                </div>
                <div className="flex items-center gap-3">
                  <span className="font-mono text-[11px] text-slate-400">{c.encryptedAt}</span>
                  {canModify && (
                    <button
                      type="button"
                      onClick={() => onDeleteCredential(c.id)}
                      className="text-rose-600 hover:underline cursor-pointer"
                    >
                      {lang === 'ar' ? 'حذف' : 'Delete'}
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </section>

      {/* 5 Independent Collectors Table */}
      <section className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg overflow-hidden">
        <div className="px-5 py-3.5 border-b border-slate-100 dark:border-slate-800">
          <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
            {lang === 'ar' ? 'المجمّعات المركزية المستقلة (5 Agentless Collectors)' : 'Central Monitoring Engine — 5 Agentless Collectors'}
          </h2>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-start border-collapse">
            <thead>
              <tr className="border-b border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/50 text-[11px] font-semibold text-slate-500 dark:text-slate-400">
                <th className="py-2.5 px-4 text-start">{lang === 'ar' ? 'المجمّع' : 'Collector'}</th>
                <th className="py-2.5 px-3 text-start">{lang === 'ar' ? 'البروتوكول' : 'Protocol'}</th>
                <th className="py-2.5 px-3 text-start">{lang === 'ar' ? 'الحالة' : 'State'}</th>
                <th className="py-2.5 px-3 text-end">{lang === 'ar' ? 'الجدول / المهلة / المحاولات' : 'Interval / Timeout / Retries'}</th>
                <th className="py-2.5 px-3 text-end">{lang === 'ar' ? 'الأهداف' : 'Targets'}</th>
                <th className="py-2.5 px-4 text-end">{copy.common.actions}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800 text-xs">
              {collectors.map((c) => {
                const isEditing = editingColId === c.id;
                return (
                  <tr key={c.id} className="hover:bg-slate-50 dark:hover:bg-slate-800/40">
                    <td className="py-3 px-4">
                      <div className="font-medium text-slate-900 dark:text-slate-100">
                        {lang === 'ar' ? c.nameAr : c.name}
                      </div>
                      <div className="font-mono text-[11px] text-slate-500 dark:text-slate-400">
                        {c.endpoint} · {lang === 'ar' ? 'آخر دورة:' : 'Last:'} {c.lastRun} ({c.lastDurationMs}ms)
                      </div>
                      {c.lastError && (
                        <div className="text-[11px] text-amber-700 dark:text-amber-400 mt-0.5 truncate max-w-md">
                          {c.lastError}
                        </div>
                      )}
                    </td>
                    <td className="py-3 px-3 text-slate-600 dark:text-slate-300">{c.runtime}</td>
                    <td className="py-3 px-3">
                      <span
                        className={
                          c.status === 'Healthy'
                            ? 'text-emerald-700 dark:text-emerald-400 font-medium'
                            : c.status === 'Degraded'
                              ? 'text-amber-700 dark:text-amber-400 font-medium'
                              : 'text-slate-500 font-medium'
                        }
                      >
                        ● {c.status}
                      </span>
                    </td>
                    <td className="py-3 px-3 text-end font-mono tabular-nums text-slate-900 dark:text-slate-100">
                      {isEditing ? (
                        <div className="inline-flex items-center gap-1.5">
                          <input
                            type="number"
                            min={15}
                            max={86400}
                            value={editSec}
                            onChange={(e) => setEditSec(Number(e.target.value))}
                            className="w-14 px-1.5 py-0.5 border border-slate-300 dark:border-slate-700 rounded bg-white dark:bg-slate-950"
                          />
                          <span>s /</span>
                          <input
                            type="number"
                            min={1000}
                            max={30000}
                            step={500}
                            value={editTimeout}
                            onChange={(e) => setEditTimeout(Number(e.target.value))}
                            className="w-16 px-1.5 py-0.5 border border-slate-300 dark:border-slate-700 rounded bg-white dark:bg-slate-950"
                          />
                          <span>ms /</span>
                          <input
                            type="number"
                            min={0}
                            max={5}
                            value={editRetries}
                            onChange={(e) => setEditRetries(Number(e.target.value))}
                            className="w-10 px-1.5 py-0.5 border border-slate-300 dark:border-slate-700 rounded bg-white dark:bg-slate-950"
                          />
                        </div>
                      ) : (
                        <span>
                          {c.scheduleSeconds}s · {c.timeoutMs ?? 8000}ms · {c.retryCount ?? 1}x
                        </span>
                      )}
                    </td>
                    <td className="py-3 px-3 text-end font-mono tabular-nums text-slate-700 dark:text-slate-300">
                      {c.targetsHealthy ?? 0}/{c.targetsTotal ?? 0}
                    </td>
                    <td className="py-3 px-4 text-end space-x-2.5 whitespace-nowrap">
                      {isEditing ? (
                        <>
                          <button
                            type="button"
                            onClick={async () => {
                              const err = await onUpdateCollector(c.id, {
                                scheduleSeconds: editSec,
                                timeoutMs: editTimeout,
                                retryCount: editRetries,
                              });
                              setEditingColId(null);
                              if (err) setMsg(err);
                              else setMsg(`${c.name} schedule updated.`);
                            }}
                            className="text-emerald-600 font-medium hover:underline cursor-pointer"
                          >
                            {copy.common.save}
                          </button>
                          <button
                            type="button"
                            onClick={() => setEditingColId(null)}
                            className="text-slate-500 hover:underline cursor-pointer"
                          >
                            {copy.common.cancel}
                          </button>
                        </>
                      ) : (
                        <>
                          <button
                            type="button"
                            disabled={!canModify}
                            onClick={() => {
                              setEditingColId(c.id);
                              setEditSec(c.scheduleSeconds);
                              setEditTimeout(c.timeoutMs ?? 8000);
                              setEditRetries(c.retryCount ?? 1);
                            }}
                            className="text-slate-600 dark:text-slate-300 hover:underline disabled:opacity-40 cursor-pointer"
                          >
                            {lang === 'ar' ? 'تعديل' : 'Config'}
                          </button>
                          <button
                            type="button"
                            disabled={!canModify}
                            onClick={async () => {
                              const err = await onUpdateCollector(c.id, { runNow: true });
                              setMsg(err || `${c.name} live collection finished.`);
                            }}
                            className="text-blue-600 dark:text-blue-400 hover:underline disabled:opacity-40 cursor-pointer"
                          >
                            {lang === 'ar' ? 'فحص الآن' : 'Run Now'}
                          </button>
                          <button
                            type="button"
                            disabled={!canModify}
                            onClick={async () => {
                              const err = await onUpdateCollector(c.id, { enabled: !c.enabled });
                              if (err) setMsg(err);
                            }}
                            className="text-slate-600 dark:text-slate-400 hover:underline disabled:opacity-40 cursor-pointer"
                          >
                            {c.enabled ? (lang === 'ar' ? 'إيقاف' : 'Pause') : lang === 'ar' ? 'تشغيل' : 'Enable'}
                          </button>
                        </>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </section>

      {/* Enterprise SQL / Architecture Reference Kit */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        <div className="lg:col-span-4 space-y-2">
          {ENTERPRISE_ARTIFACTS.map((item) => {
            const active = item.id === artifact.id;
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => setSelectedArtifactId(item.id)}
                className={`w-full text-start p-3.5 rounded-lg border transition-colors cursor-pointer ${
                  active
                    ? 'bg-white dark:bg-slate-900 border-blue-600'
                    : 'bg-white dark:bg-slate-900 border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700'
                }`}
              >
                <div className="text-[11px] font-mono text-blue-700 dark:text-blue-400">{item.category}</div>
                <div className="text-xs font-semibold text-slate-900 dark:text-slate-100 mt-1">
                  {lang === 'ar' ? item.titleAr : item.title}
                </div>
                <div className="text-[11px] font-mono text-slate-500 dark:text-slate-400 mt-1">
                  {item.filename}
                </div>
              </button>
            );
          })}
        </div>

        <div className="lg:col-span-8 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-5 space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-3 pb-3 border-b border-slate-100 dark:border-slate-800">
            <div>
              <div className="text-xs font-mono text-slate-500 dark:text-slate-400">{artifact.filename}</div>
              <h3 className="text-base font-semibold text-slate-900 dark:text-slate-100 mt-0.5">
                {lang === 'ar' ? artifact.titleAr : artifact.title}
              </h3>
              <p className="text-xs text-slate-600 dark:text-slate-400 mt-1">
                {lang === 'ar' ? artifact.summaryAr : artifact.summary}
              </p>
            </div>
            <button
              type="button"
              onClick={handleCopy}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-slate-100 dark:bg-slate-800 text-slate-800 dark:text-slate-200 hover:bg-slate-200 dark:hover:bg-slate-700 rounded-md whitespace-nowrap shrink-0 cursor-pointer"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied ? copy.common.copied : copy.common.copy}</span>
            </button>
          </div>

          <pre
            dir="ltr"
            className="p-4 bg-slate-950 text-slate-100 rounded-md text-xs leading-relaxed overflow-x-auto font-mono"
          >
            {artifact.code}
          </pre>
        </div>
      </div>
    </div>
  );
}
