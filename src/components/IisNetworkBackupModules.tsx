import { useState, type FormEvent } from 'react';
import { Activity, Plus, PlugZap, Trash2 } from 'lucide-react';
import {
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { COPY } from '../data/i18n';
import {
  ApiEndpointCheck,
  BackupJob,
  ConnectionTestResult,
  CredentialProfileSummary,
  IisAppPool,
  IisSite,
  Language,
  NetworkDevice,
  UserRole,
} from '../types/infrastructure';
import { AssetStatusBadge, CollectionStatusBadge, IntegrityBanner } from './StatusGlyph';

/* =========================== MODULE D: IIS & APPLICATIONS =========================== */
export function IisModule({
  sites,
  appPools,
  apiEndpoints,
  credentials,
  currentRole,
  lang,
  onRegisterSite,
  onDeleteSite,
  onTestSite,
  onRegisterApi,
  onDeleteApi,
  onPollAllIis,
}: {
  sites: IisSite[];
  appPools: IisAppPool[];
  apiEndpoints: ApiEndpointCheck[];
  credentials: CredentialProfileSummary[];
  currentRole: UserRole | null;
  lang: Language;
  onRegisterSite: (payload: {
    name: string;
    url: string;
    serverHostname?: string;
    appPoolName?: string;
    credentialId?: string;
  }) => Promise<string | null>;
  onDeleteSite: (id: string) => Promise<string | null>;
  onTestSite: (id: string) => Promise<{ result?: ConnectionTestResult; error?: string }>;
  onRegisterApi: (payload: { name: string; method: 'GET' | 'POST'; url: string }) => Promise<string | null>;
  onDeleteApi: (id: string) => Promise<string | null>;
  onPollAllIis: () => Promise<string | null>;
}) {
  const copy = COPY[lang];
  const canModify =
    currentRole !== null && ['Administrator', 'IT Manager', 'IT Engineer'].includes(currentRole);
  const winCreds = credentials.filter((c) => c.kind === 'windows');

  const [showSiteForm, setShowSiteForm] = useState(false);
  const [siteName, setSiteName] = useState('');
  const [siteUrl, setSiteUrl] = useState('');
  const [siteHost, setSiteHost] = useState('');
  const [sitePool, setSitePool] = useState('DefaultAppPool');
  const [siteCredId, setSiteCredId] = useState('');

  const [showApiForm, setShowApiForm] = useState(false);
  const [apiName, setApiName] = useState('');
  const [apiMethod, setApiMethod] = useState<'GET' | 'POST'>('GET');
  const [apiUrl, setApiUrl] = useState('');

  const [feedback, setFeedback] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<ConnectionTestResult | null>(null);
  const [testingId, setTestingId] = useState<string | null>(null);
  const [polling, setPolling] = useState(false);

  const handleAddSite = async (e: FormEvent) => {
    e.preventDefault();
    const err = await onRegisterSite({
      name: siteName,
      url: siteUrl,
      serverHostname: siteHost || undefined,
      appPoolName: sitePool || undefined,
      credentialId: siteCredId || undefined,
    });
    if (err) setFeedback(err);
    else {
      setSiteName('');
      setSiteUrl('');
      setSiteHost('');
      setShowSiteForm(false);
      setFeedback(lang === 'ar' ? 'تم تسجيل الموقع وفحصه عن بُعد.' : 'Web site registered and probed.');
    }
  };

  const handleAddApi = async (e: FormEvent) => {
    e.preventDefault();
    const err = await onRegisterApi({ name: apiName, method: apiMethod, url: apiUrl });
    if (err) setFeedback(err);
    else {
      setApiName('');
      setApiUrl('');
      setShowApiForm(false);
      setFeedback(lang === 'ar' ? 'تم إضافة نقطة فحص API.' : 'API health endpoint registered.');
    }
  };

  const handleTest = async (id: string) => {
    setTestingId(id);
    setTestResult(null);
    const { result, error } = await onTestSite(id);
    setTestingId(null);
    if (error) setFeedback(error);
    else if (result) setTestResult(result);
  };

  const handlePollAll = async () => {
    setPolling(true);
    const err = await onPollAllIis();
    setPolling(false);
    setFeedback(err || (lang === 'ar' ? 'تم فحص جميع المواقع ونقاط API.' : 'Polled all IIS sites and API endpoints.'));
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col xl:flex-row xl:items-center xl:justify-between gap-4 pb-4 border-b border-slate-200 dark:border-slate-800">
        <div>
          <h1 className="text-xl font-semibold text-slate-900 dark:text-slate-100">
            {lang === 'ar' ? 'مراقبة خوادم الويب IIS والتطبيقات (بدون وكيل)' : 'IIS & Application Monitoring (Agentless)'}
          </h1>
          <p className="text-sm text-slate-600 dark:text-slate-400 mt-1">
            {lang === 'ar'
              ? 'فحص مركزي عن بُعد عبر HTTP/HTTPS وشهادات SSL ومجموعات App Pools عبر CIM بدون تثبيت برمجيات على خوادم الويب.'
              : 'Remote HTTP/HTTPS availability, TLS expiry, response latency, and optional native WebAdministration CIM checks.'}
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {(sites.length > 0 || apiEndpoints.length > 0) && (
            <button
              type="button"
              disabled={!canModify || polling}
              onClick={handlePollAll}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-slate-900 dark:bg-slate-700 hover:bg-slate-800 text-white rounded-md disabled:opacity-50 cursor-pointer"
            >
              <Activity className="w-3.5 h-3.5" />
              <span>{polling ? (lang === 'ar' ? 'جاري الفحص...' : 'Polling...') : lang === 'ar' ? 'فحص الكل' : 'Poll All'}</span>
            </button>
          )}
          <button
            type="button"
            onClick={() => setShowSiteForm((p) => !p)}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-blue-600 hover:bg-blue-700 text-white rounded-md cursor-pointer"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>{lang === 'ar' ? 'إضافة موقع IIS / Web' : 'Add Website'}</span>
          </button>
          <button
            type="button"
            onClick={() => setShowApiForm((p) => !p)}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-800 dark:text-slate-200 rounded-md cursor-pointer"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>{lang === 'ar' ? 'إضافة نقطة API' : 'Add API Check'}</span>
          </button>
        </div>
      </div>

      {feedback && (
        <div className="p-3 bg-blue-50 dark:bg-blue-950/40 border border-blue-200 dark:border-blue-900 rounded-md text-xs text-blue-900 dark:text-blue-200">
          {feedback}
        </div>
      )}

      {testResult && (
        <div
          className={`p-3.5 rounded-md border text-xs space-y-1 ${
            testResult.ok
              ? 'bg-emerald-50 dark:bg-emerald-950/30 border-emerald-200 dark:border-emerald-900'
              : 'bg-amber-50 dark:bg-amber-950/30 border-amber-200 dark:border-amber-900'
          }`}
        >
          <div className="flex items-center justify-between">
            <CollectionStatusBadge status={testResult.status} lang={lang} />
            <span className="font-mono text-[11px]">{testResult.measuredAt}</span>
          </div>
          <div className="font-mono text-[11px]">{testResult.details}</div>
        </div>
      )}

      {showSiteForm && (
        <form
          onSubmit={handleAddSite}
          className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-5 space-y-4 text-xs"
        >
          <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
            {lang === 'ar' ? 'إضافة موقع IIS أو تطبيق ويب للمراقبة' : 'Register Website / IIS Target'}
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-5 gap-3">
            <input
              type="text"
              placeholder={lang === 'ar' ? 'اسم الموقع' : 'Site Name'}
              value={siteName}
              onChange={(e) => setSiteName(e.target.value)}
              required
              className="px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md text-slate-900 dark:text-slate-100"
            />
            <input
              type="url"
              placeholder="https://portal.medlabs.jo"
              value={siteUrl}
              onChange={(e) => setSiteUrl(e.target.value)}
              required
              className="px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md font-mono text-slate-900 dark:text-slate-100"
            />
            <input
              type="text"
              placeholder={lang === 'ar' ? 'سيرفر IIS (اختياري لـ AppPool)' : 'IIS Host (optional for CIM)'}
              value={siteHost}
              onChange={(e) => setSiteHost(e.target.value)}
              className="px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md font-mono text-slate-900 dark:text-slate-100"
            />
            <input
              type="text"
              placeholder="App Pool"
              value={sitePool}
              onChange={(e) => setSitePool(e.target.value)}
              className="px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md font-mono text-slate-900 dark:text-slate-100"
            />
            <select
              value={siteCredId}
              onChange={(e) => setSiteCredId(e.target.value)}
              className="px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md text-slate-900 dark:text-slate-100"
            >
              <option value="">{lang === 'ar' ? 'HTTP/HTTPS فقط (بدون CIM)' : 'HTTP/HTTPS Only'}</option>
              {winCreds.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.name} (CIM AppPool)
                </option>
              ))}
            </select>
          </div>
          <div className="flex justify-end gap-2">
            <button
              type="button"
              onClick={() => setShowSiteForm(false)}
              className="px-3 py-1.5 rounded border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300 cursor-pointer"
            >
              {copy.common.cancel}
            </button>
            <button
              type="submit"
              disabled={!canModify}
              className="px-4 py-1.5 rounded bg-blue-600 text-white hover:bg-blue-700 disabled:opacity-50 cursor-pointer"
            >
              {copy.common.save}
            </button>
          </div>
        </form>
      )}

      {showApiForm && (
        <form
          onSubmit={handleAddApi}
          className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-5 space-y-4 text-xs"
        >
          <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
            {lang === 'ar' ? 'إضافة نقطة فحص API' : 'Register API Health Endpoint'}
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <input
              type="text"
              placeholder={lang === 'ar' ? 'اسم الخدمة' : 'Endpoint Name'}
              value={apiName}
              onChange={(e) => setApiName(e.target.value)}
              required
              className="px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md text-slate-900 dark:text-slate-100"
            />
            <select
              value={apiMethod}
              onChange={(e) => setApiMethod(e.target.value as 'GET' | 'POST')}
              className="px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md font-mono text-slate-900 dark:text-slate-100"
            >
              <option value="GET">GET</option>
              <option value="POST">POST</option>
            </select>
            <input
              type="url"
              placeholder="https://api.medlabs.jo/health"
              value={apiUrl}
              onChange={(e) => setApiUrl(e.target.value)}
              required
              className="px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md font-mono text-slate-900 dark:text-slate-100"
            />
          </div>
          <div className="flex justify-end gap-2">
            <button
              type="button"
              onClick={() => setShowApiForm(false)}
              className="px-3 py-1.5 rounded border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300 cursor-pointer"
            >
              {copy.common.cancel}
            </button>
            <button
              type="submit"
              disabled={!canModify}
              className="px-4 py-1.5 rounded bg-blue-600 text-white hover:bg-blue-700 disabled:opacity-50 cursor-pointer"
            >
              {copy.common.save}
            </button>
          </div>
        </form>
      )}

      {/* IIS Websites Table */}
      <section className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg overflow-hidden">
        <div className="px-5 py-3.5 border-b border-slate-100 dark:border-slate-800">
          <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
            {lang === 'ar' ? 'مواقع الويب على IIS' : 'IIS Websites & TLS Certificates'}
          </h2>
        </div>
        {sites.length === 0 ? (
          <div className="p-8 text-center text-xs text-slate-500 dark:text-slate-400">
            {lang === 'ar'
              ? 'لا توجد مواقع ويب مسجلة بعد — اضغط «إضافة موقع IIS / Web» لمراقبة الحالة، زمن الاستجابة، وصلاحية SSL من الخادم المركزي.'
              : 'No IIS websites configured yet — click "Add Website" to monitor HTTP status, response time, and SSL expiration centrally.'}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-start border-collapse">
              <thead>
                <tr className="border-b border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/50 text-[11px] font-semibold text-slate-500 dark:text-slate-400">
                  <th className="py-2.5 px-4 text-start">{lang === 'ar' ? 'الموقع' : 'Website'}</th>
                  <th className="py-2.5 px-3 text-start">{lang === 'ar' ? 'الخادم / Pool' : 'Host / App Pool'}</th>
                  <th className="py-2.5 px-3 text-start">HTTP</th>
                  <th className="py-2.5 px-3 text-start">{lang === 'ar' ? 'الحالة' : 'State'}</th>
                  <th className="py-2.5 px-3 text-end">{lang === 'ar' ? 'الاستجابة' : 'RTT'}</th>
                  <th className="py-2.5 px-3 text-end">SSL</th>
                  <th className="py-2.5 px-4 text-end">{copy.common.actions}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800 text-xs">
                {sites.map((site) => (
                  <tr key={site.id} className="hover:bg-slate-50 dark:hover:bg-slate-800/40">
                    <td className="py-3 px-4">
                      <div className="font-medium text-slate-900 dark:text-slate-100">{site.name}</div>
                      <div className="font-mono text-[11px] text-slate-500 dark:text-slate-400">{site.url}</div>
                      {site.integrity?.errorDetail && (
                        <div className="text-[11px] text-rose-600 dark:text-rose-400 mt-0.5">{site.integrity.errorDetail}</div>
                      )}
                    </td>
                    <td className="py-3 px-3 font-mono text-slate-700 dark:text-slate-300">
                      {site.serverHostname} · {site.appPoolName}
                    </td>
                    <td className="py-3 px-3 font-mono tabular-nums font-semibold text-slate-900 dark:text-slate-100">
                      {site.httpStatus > 0 ? site.httpStatus : '—'}
                    </td>
                    <td className="py-3 px-3">
                      <div className="flex flex-col gap-1 items-start">
                        <AssetStatusBadge status={site.status} label={copy.status[site.status]} />
                        {site.integrity && (
                          <CollectionStatusBadge status={site.integrity.collectionStatus} lang={lang} />
                        )}
                      </div>
                    </td>
                    <td className="py-3 px-3 text-end font-mono tabular-nums text-slate-900 dark:text-slate-100">
                      {site.responseTimeMs > 0 ? `${site.responseTimeMs} ms` : 'Timeout'}
                    </td>
                    <td className="py-3 px-3 text-end font-mono tabular-nums text-slate-700 dark:text-slate-300">
                      {typeof site.sslDaysRemaining === 'number' ? `${site.sslDaysRemaining}d` : '—'}
                    </td>
                    <td className="py-3 px-4 text-end whitespace-nowrap">
                      <div className="inline-flex items-center gap-1">
                        <button
                          type="button"
                          disabled={!canModify || testingId === site.id}
                          onClick={() => handleTest(site.id)}
                          title={lang === 'ar' ? 'اختبار الاتصال' : 'Test Connection'}
                          className="p-1.5 rounded text-slate-500 hover:text-emerald-600 disabled:opacity-40 cursor-pointer"
                        >
                          <PlugZap className="w-3.5 h-3.5" />
                        </button>
                        <button
                          type="button"
                          disabled={!canModify}
                          onClick={() => onDeleteSite(site.id)}
                          title={lang === 'ar' ? 'حذف' : 'Delete'}
                          className="p-1.5 rounded text-slate-500 hover:text-rose-600 disabled:opacity-40 cursor-pointer"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Application Pools */}
        <section className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg overflow-hidden">
          <div className="px-5 py-3.5 border-b border-slate-100 dark:border-slate-800">
            <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
              {lang === 'ar' ? 'مجموعات التطبيقات (Application Pools · CIM)' : 'IIS Application Pools (Remote CIM)'}
            </h2>
          </div>
          {appPools.length === 0 ? (
            <div className="p-6 text-xs text-slate-500 dark:text-slate-400">
              {lang === 'ar'
                ? 'لا توجد مجموعات App Pools مسجلة بعد — تُقرأ تلقائياً عبر root\\WebAdministration عند ربط خادم Windows وحساب معتمد للموقع.'
                : 'No IIS application pools queried yet — populates via native remote WebAdministration CIM when a Windows credential is attached to an IIS site.'}
            </div>
          ) : (
            <div className="divide-y divide-slate-100 dark:divide-slate-800">
              {appPools.map((pool) => (
                <div key={`${pool.serverHostname || 'iis'}-${pool.name}`} className="px-5 py-3 flex items-center justify-between text-xs">
                  <div>
                    <div className="font-mono font-semibold text-slate-900 dark:text-slate-100">{pool.name}</div>
                    <div className="text-slate-500 dark:text-slate-400 mt-0.5">
                      {pool.serverHostname ? `${pool.serverHostname} · ` : ''}
                      {pool.runtime}
                    </div>
                  </div>
                  <div className="text-end font-mono tabular-nums">
                    <div
                      className={
                        pool.state === 'Started'
                          ? 'text-emerald-700 dark:text-emerald-400 font-medium'
                          : 'text-rose-700 dark:text-rose-400 font-medium'
                      }
                    >
                      {pool.state === 'Started' ? '● Started' : '✖ Stopped'}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </section>

        {/* API Endpoints */}
        <section className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg overflow-hidden">
          <div className="px-5 py-3.5 border-b border-slate-100 dark:border-slate-800">
            <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
              {lang === 'ar' ? 'نقاط فحص صحة الـ API' : 'API Health Check Endpoints'}
            </h2>
          </div>
          {apiEndpoints.length === 0 ? (
            <div className="p-6 text-xs text-slate-500 dark:text-slate-400">
              {lang === 'ar' ? 'لا توجد نقاط فحص API مسجلة بعد.' : 'No API health check endpoints registered yet.'}
            </div>
          ) : (
            <div className="divide-y divide-slate-100 dark:divide-slate-800">
              {apiEndpoints.map((api) => (
                <div key={api.id} className="px-5 py-3 flex items-center justify-between gap-2 text-xs">
                  <div className="min-w-0">
                    <div className="font-medium text-slate-900 dark:text-slate-100">{api.name}</div>
                    <div className="font-mono text-[11px] text-slate-500 dark:text-slate-400 mt-0.5 truncate">
                      {api.method} {api.url}
                    </div>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <AssetStatusBadge
                      status={api.status}
                      label={api.httpStatus > 0 ? `${api.httpStatus} · ${api.responseTimeMs} ms` : 'Timeout'}
                    />
                    <button
                      type="button"
                      disabled={!canModify}
                      onClick={() => onDeleteApi(api.id)}
                      className="p-1 text-slate-400 hover:text-rose-600 disabled:opacity-40 cursor-pointer"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
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

/* =========================== MODULE E: NETWORK MONITORING =========================== */
export function NetworkModule({
  devices,
  credentials,
  currentRole,
  lang,
  onRegisterNetwork,
  onDeleteNetwork,
  onTestNetwork,
  onPollAllNetwork,
}: {
  devices: NetworkDevice[];
  credentials: CredentialProfileSummary[];
  currentRole: UserRole | null;
  lang: Language;
  onRegisterNetwork: (payload: {
    name: string;
    type: NetworkDevice['type'];
    site: string;
    ipAddress: string;
    credentialId?: string;
    tcpPorts?: number[];
  }) => Promise<string | null>;
  onDeleteNetwork: (id: string) => Promise<string | null>;
  onTestNetwork: (id: string) => Promise<{ result?: ConnectionTestResult; error?: string }>;
  onPollAllNetwork: () => Promise<string | null>;
}) {
  const copy = COPY[lang];
  const [selectedId, setSelectedId] = useState(devices[0]?.id ?? '');
  const selected = devices.find((d) => d.id === selectedId) ?? devices[0];

  const canModify =
    currentRole !== null && ['Administrator', 'IT Manager', 'IT Engineer'].includes(currentRole);
  const snmpCreds = credentials.filter((c) => c.kind === 'snmpv2c' || c.kind === 'snmpv3');

  const [showAdd, setShowAdd] = useState(false);
  const [name, setName] = useState('');
  const [type, setType] = useState<NetworkDevice['type']>('L3 Switch');
  const [site, setSite] = useState('Abdali Central');
  const [ipAddress, setIpAddress] = useState('');
  const [credentialId, setCredentialId] = useState('');
  const [portsInput, setPortsInput] = useState('22,80,443');

  const [feedback, setFeedback] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<ConnectionTestResult | null>(null);
  const [testingId, setTestingId] = useState<string | null>(null);
  const [polling, setPolling] = useState(false);

  const handleAdd = async (e: FormEvent) => {
    e.preventDefault();
    const parsedPorts = portsInput
      .split(',')
      .map((s) => Number(s.trim()))
      .filter((n) => Number.isInteger(n) && n >= 1 && n <= 65535);
    const err = await onRegisterNetwork({
      name,
      type,
      site,
      ipAddress,
      credentialId: credentialId || undefined,
      tcpPorts: parsedPorts,
    });
    if (err) setFeedback(err);
    else {
      setName('');
      setIpAddress('');
      setCredentialId('');
      setShowAdd(false);
      setFeedback(lang === 'ar' ? 'تم تسجيل جهاز الشبكة وفحصه.' : 'Network device registered and probed.');
    }
  };

  const handleTest = async (id: string) => {
    setTestingId(id);
    setTestResult(null);
    const { result, error } = await onTestNetwork(id);
    setTestingId(null);
    if (error) setFeedback(error);
    else if (result) setTestResult(result);
  };

  const handlePollAll = async () => {
    setPolling(true);
    setTestResult(null);
    const err = await onPollAllNetwork();
    setPolling(false);
    setFeedback(err || (lang === 'ar' ? 'تم تنفيذ فحص ICMP/TCP/SNMP لكل أجهزة الشبكة.' : 'Network ICMP, TCP, and SNMP sweep completed.'));
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col xl:flex-row xl:items-center xl:justify-between gap-4 pb-4 border-b border-slate-200 dark:border-slate-800">
        <div>
          <h1 className="text-xl font-semibold text-slate-900 dark:text-slate-100">
            {lang === 'ar' ? 'مراقبة الشبكة والربط بين الفروع (بدون وكيل)' : 'Network & Branch Connectivity Monitoring (Agentless)'}
          </h1>
          <p className="text-sm text-slate-600 dark:text-slate-400 mt-1">
            {lang === 'ar'
              ? 'فحص Ping متعدد الحزم، زمن الاستجابة، فقدان الحزم، منافذ TCP، وإحصائيات واجهات السويتش والراوتر عبر SNMPv2c / SNMPv3.'
              : 'Multi-packet ICMP latency & packet loss, TCP port availability, and SNMPv2c/SNMPv3 switch/router interface traffic & errors.'}
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {devices.length > 0 && (
            <button
              type="button"
              disabled={!canModify || polling}
              onClick={handlePollAll}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-slate-900 dark:bg-slate-700 hover:bg-slate-800 text-white rounded-md disabled:opacity-50 cursor-pointer"
            >
              <Activity className="w-3.5 h-3.5" />
              <span>{polling ? (lang === 'ar' ? 'جاري الفحص...' : 'Polling...') : lang === 'ar' ? 'فحص كل الأجهزة' : 'Poll All Devices'}</span>
            </button>
          )}
          <button
            type="button"
            onClick={() => setShowAdd((p) => !p)}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-blue-600 hover:bg-blue-700 text-white rounded-md cursor-pointer"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>{lang === 'ar' ? 'إضافة جهاز شبكة' : 'Add Network Device'}</span>
          </button>
        </div>
      </div>

      {feedback && (
        <div className="p-3 bg-blue-50 dark:bg-blue-950/40 border border-blue-200 dark:border-blue-900 rounded-md text-xs text-blue-900 dark:text-blue-200">
          {feedback}
        </div>
      )}

      {testResult && (
        <div
          className={`p-3.5 rounded-md border text-xs space-y-1 ${
            testResult.ok
              ? 'bg-emerald-50 dark:bg-emerald-950/30 border-emerald-200 dark:border-emerald-900'
              : 'bg-amber-50 dark:bg-amber-950/30 border-amber-200 dark:border-amber-900'
          }`}
        >
          <div className="flex items-center justify-between">
            <CollectionStatusBadge status={testResult.status} lang={lang} />
            <span className="font-mono text-[11px]">{testResult.measuredAt}</span>
          </div>
          <div className="font-mono text-[11px]">{testResult.details}</div>
          {testResult.prerequisiteHint && (
            <div className="text-[11px]">
              <strong>{lang === 'ar' ? 'المتطلب: ' : 'Prerequisite: '}</strong>
              {testResult.prerequisiteHint}
            </div>
          )}
        </div>
      )}

      {showAdd && (
        <form
          onSubmit={handleAdd}
          className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-5 space-y-4 text-xs"
        >
          <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
            {lang === 'ar' ? 'إضافة جهاز شبكة أو نقطة مراقبة ICMP/SNMP' : 'Register Network Target (ICMP / TCP / SNMPv2c / SNMPv3)'}
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <input
              type="text"
              placeholder={lang === 'ar' ? 'اسم الجهاز (مثلاً Core-SW-01)' : 'Device Name (e.g. Core-SW-01)'}
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
              className="px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md text-slate-900 dark:text-slate-100"
            />
            <input
              type="text"
              placeholder="IP / Host (e.g. 192.168.127.33)"
              value={ipAddress}
              onChange={(e) => setIpAddress(e.target.value)}
              required
              className="px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md font-mono text-slate-900 dark:text-slate-100"
            />
            <select
              value={type}
              onChange={(e) => setType(e.target.value as NetworkDevice['type'])}
              className="px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md text-slate-900 dark:text-slate-100"
            >
              <option value="Core Firewall">Core Firewall</option>
              <option value="L3 Switch">L3 Switch</option>
              <option value="SD-WAN Gateway">SD-WAN Gateway</option>
              <option value="Branch Router">Branch Router</option>
            </select>
            <input
              type="text"
              placeholder={lang === 'ar' ? 'الموقع' : 'Site'}
              value={site}
              onChange={(e) => setSite(e.target.value)}
              required
              className="px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md text-slate-900 dark:text-slate-100"
            />
            <select
              value={credentialId}
              onChange={(e) => setCredentialId(e.target.value)}
              className="px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md text-slate-900 dark:text-slate-100"
            >
              <option value="">{lang === 'ar' ? 'ICMP + TCP فقط (بدون SNMP)' : 'ICMP + TCP Only (No SNMP)'}</option>
              {snmpCreds.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.name} ({c.kind})
                </option>
              ))}
            </select>
            <input
              type="text"
              placeholder="TCP Ports (e.g. 22,80,443,1521)"
              value={portsInput}
              onChange={(e) => setPortsInput(e.target.value)}
              className="px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md font-mono text-slate-900 dark:text-slate-100"
            />
          </div>
          <div className="flex justify-end gap-2">
            <button
              type="button"
              onClick={() => setShowAdd(false)}
              className="px-3 py-1.5 rounded border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300 cursor-pointer"
            >
              {copy.common.cancel}
            </button>
            <button
              type="submit"
              disabled={!canModify}
              className="px-4 py-1.5 rounded bg-blue-600 text-white hover:bg-blue-700 disabled:opacity-50 cursor-pointer"
            >
              {copy.common.save}
            </button>
          </div>
        </form>
      )}

      {devices.length === 0 ? (
        <section className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-8 text-center text-xs text-slate-500 dark:text-slate-400">
          {lang === 'ar'
            ? 'لا توجد أجهزة شبكة مسجلة بعد — اضغط «إضافة جهاز شبكة» لمراقبة Ping، فقدان الحزم، منافذ TCP، وحركة واجهات SNMP بدون أي وكيل.'
            : 'No network devices configured yet — click "Add Network Device" to start ICMP, TCP, and SNMPv2c/v3 interface polling centrally.'}
        </section>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
          <section className="lg:col-span-7 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-start border-collapse">
                <thead>
                  <tr className="border-b border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/50 text-[11px] font-semibold text-slate-500 dark:text-slate-400">
                    <th className="py-2.5 px-4 text-start">{lang === 'ar' ? 'الجهاز' : 'Device'}</th>
                    <th className="py-2.5 px-3 text-start">IP</th>
                    <th className="py-2.5 px-3 text-start">{lang === 'ar' ? 'الحالة' : 'State'}</th>
                    <th className="py-2.5 px-3 text-end">{lang === 'ar' ? 'الزمن' : 'Latency'}</th>
                    <th className="py-2.5 px-3 text-end">{lang === 'ar' ? 'الفقد' : 'Loss'}</th>
                    <th className="py-2.5 px-4 text-end">{copy.common.actions}</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 dark:divide-slate-800 text-xs">
                  {devices.map((dev) => (
                    <tr
                      key={dev.id}
                      onClick={() => setSelectedId(dev.id)}
                      className={`cursor-pointer transition-colors ${
                        dev.id === selected?.id
                          ? 'bg-blue-50/70 dark:bg-blue-950/30'
                          : 'hover:bg-slate-50 dark:hover:bg-slate-800/40'
                      }`}
                    >
                      <td className="py-3 px-4">
                        <div className="font-medium text-slate-900 dark:text-slate-100">{dev.name}</div>
                        <div className="text-[11px] text-slate-500 dark:text-slate-400">
                          {dev.type} · {dev.site}
                        </div>
                      </td>
                      <td className="py-3 px-3 font-mono tabular-nums text-slate-700 dark:text-slate-300">
                        {dev.ipAddress}
                      </td>
                      <td className="py-3 px-3">
                        <div className="flex flex-col gap-1 items-start">
                          <AssetStatusBadge status={dev.status} label={copy.status[dev.status]} />
                          {dev.integrity && (
                            <CollectionStatusBadge status={dev.integrity.collectionStatus} lang={lang} />
                          )}
                        </div>
                      </td>
                      <td className="py-3 px-3 text-end font-mono tabular-nums text-slate-900 dark:text-slate-100">
                        {dev.status === 'Offline' ? 'Timeout' : `${dev.latencyMs} ms`}
                      </td>
                      <td className="py-3 px-3 text-end font-mono tabular-nums text-slate-900 dark:text-slate-100">
                        {dev.packetLossPct}%
                      </td>
                      <td
                        className="py-3 px-4 text-end whitespace-nowrap"
                        onClick={(e) => e.stopPropagation()}
                      >
                        <div className="inline-flex items-center gap-1">
                          <button
                            type="button"
                            disabled={!canModify || testingId === dev.id}
                            onClick={() => handleTest(dev.id)}
                            title={lang === 'ar' ? 'اختبار الاتصال' : 'Test Connection'}
                            className="p-1.5 rounded text-slate-500 hover:text-emerald-600 disabled:opacity-40 cursor-pointer"
                          >
                            <PlugZap className="w-3.5 h-3.5" />
                          </button>
                          <button
                            type="button"
                            disabled={!canModify}
                            onClick={() => onDeleteNetwork(dev.id)}
                            title={lang === 'ar' ? 'حذف' : 'Delete'}
                            className="p-1.5 rounded text-slate-500 hover:text-rose-600 disabled:opacity-40 cursor-pointer"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>

          {selected && (
            <section className="lg:col-span-5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-5 space-y-4">
              <div className="flex items-start justify-between pb-3 border-b border-slate-100 dark:border-slate-800">
                <div>
                  <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">{selected.name}</h2>
                  <p className="text-xs font-mono text-slate-500 dark:text-slate-400 mt-0.5">
                    {selected.ipAddress} · Uptime {selected.uptimePct30d}% · Open TCP: [
                    {(selected.openPorts || []).join(', ') || 'none'}]
                  </p>
                </div>
                <AssetStatusBadge status={selected.status} label={copy.status[selected.status]} />
              </div>

              <IntegrityBanner integrity={selected.integrity} lang={lang} />

              <div className="h-52 w-full" dir="ltr">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={selected.latencyHistory} margin={{ top: 8, right: 12, left: -16, bottom: 0 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#cbd5e1" strokeOpacity={0.35} />
                    <XAxis dataKey="time" tick={{ fontSize: 11, fill: '#64748b' }} />
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
                    <Bar dataKey="latencyMs" name="Latency (ms)" fill="#2563eb" radius={[3, 3, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>

              {selected.interfaces && selected.interfaces.length > 0 && (
                <div className="pt-3 border-t border-slate-100 dark:border-slate-800">
                  <div className="text-xs font-semibold text-slate-700 dark:text-slate-300 mb-2">
                    {lang === 'ar' ? 'إحصائيات واجهات الشبكة (SNMP IF-MIB)' : 'Switch / Router Interfaces (SNMP IF-MIB)'}
                  </div>
                  <div className="max-h-56 overflow-y-auto divide-y divide-slate-100 dark:divide-slate-800 text-[11px]">
                    {selected.interfaces.map((iface) => (
                      <div key={iface.index} className="py-1.5 flex items-center justify-between gap-2">
                        <div className="min-w-0">
                          <span className="font-mono font-semibold text-slate-800 dark:text-slate-200">
                            {iface.name}
                          </span>
                          <span
                            className={`ms-2 ${
                              iface.operStatus === 'up' ? 'text-emerald-600' : 'text-slate-400'
                            }`}
                          >
                            ● {iface.operStatus}
                          </span>
                        </div>
                        <div className="font-mono tabular-nums text-slate-600 dark:text-slate-300 whitespace-nowrap">
                          {iface.rxKbps}/{iface.txKbps} kbps · Err {iface.inErrors}/{iface.outErrors}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </section>
          )}
        </div>
      )}
    </div>
  );
}

/* =========================== MODULE F: BACKUP MONITORING =========================== */
export function BackupsModule({ jobs, lang }: { jobs: BackupJob[]; lang: Language }) {
  return (
    <div className="space-y-6">
      <div className="pb-4 border-b border-slate-200 dark:border-slate-800">
        <h1 className="text-xl font-semibold text-slate-900 dark:text-slate-100">
          {lang === 'ar' ? 'مراقبة النسخ الاحتياطي (بدون وكيل)' : 'Backup Monitoring (Agentless)'}
        </h1>
        <p className="text-sm text-slate-600 dark:text-slate-400 mt-1">
          {lang === 'ar'
            ? 'قراءة تلقائية لحالة نسخ Oracle RMAN مباشرة من V$RMAN_BACKUP_JOB_DETAILS (SELECT فقط) بدون تثبيت وكلاء نسخ احتياطي.'
            : 'Agentless read-only tracking from Oracle V$RMAN_BACKUP_JOB_DETAILS (last run, duration, size, and failure counts).'}
        </p>
      </div>

      <section className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg overflow-hidden">
        {jobs.length === 0 ? (
          <div className="p-8 text-center text-xs text-slate-500 dark:text-slate-400">
            {lang === 'ar'
              ? 'لا توجد مهام نسخ احتياطي مسجلة بعد — تظهر مهام RMAN هنا تلقائياً فور ربط قاعدة بيانات Oracle في تبويب Oracle Database.'
              : 'No backup jobs collected yet — Oracle RMAN job history populates automatically when an Oracle Database target is connected.'}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-start border-collapse">
              <thead>
                <tr className="border-b border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/50 text-[11px] font-semibold text-slate-500 dark:text-slate-400">
                  <th className="py-2.5 px-4 text-start">{lang === 'ar' ? 'مهمة النسخ' : 'Backup Job'}</th>
                  <th className="py-2.5 px-3 text-start">{lang === 'ar' ? 'المصدر' : 'Source'}</th>
                  <th className="py-2.5 px-3 text-start">{lang === 'ar' ? 'الحالة' : 'Status'}</th>
                  <th className="py-2.5 px-3 text-start">{lang === 'ar' ? 'آخر تنفيذ' : 'Last Run'}</th>
                  <th className="py-2.5 px-3 text-end">{lang === 'ar' ? 'المدة' : 'Duration'}</th>
                  <th className="py-2.5 px-3 text-end">{lang === 'ar' ? 'الحجم' : 'Size'}</th>
                  <th className="py-2.5 px-3 text-end">{lang === 'ar' ? 'العمر' : 'Age'}</th>
                  <th className="py-2.5 px-4 text-end">{lang === 'ar' ? 'إخفاقات' : 'Failures'}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800 text-xs">
                {jobs.map((job) => {
                  const statusBadge =
                    job.status === 'Succeeded' ? (
                      <span className="text-emerald-700 dark:text-emerald-400 font-medium">● Succeeded</span>
                    ) : job.status === 'Warning' ? (
                      <span className="text-amber-700 dark:text-amber-400 font-medium">▲ Warning</span>
                    ) : (
                      <span className="text-rose-700 dark:text-rose-400 font-medium">✖ Failed</span>
                    );

                  return (
                    <tr key={job.id} className="hover:bg-slate-50 dark:hover:bg-slate-800/40">
                      <td className="py-3 px-4">
                        <div className="font-medium text-slate-900 dark:text-slate-100">{job.jobName}</div>
                        <div className="font-mono text-[11px] text-slate-500 dark:text-slate-400">{job.targetSystem}</div>
                      </td>
                      <td className="py-3 px-3 text-slate-600 dark:text-slate-300">{job.backupSource}</td>
                      <td className="py-3 px-3 whitespace-nowrap">{statusBadge}</td>
                      <td className="py-3 px-3 font-mono tabular-nums text-slate-700 dark:text-slate-300">
                        {job.lastSuccessfulRun}
                      </td>
                      <td className="py-3 px-3 text-end font-mono tabular-nums text-slate-900 dark:text-slate-100">
                        {job.durationMinutes} min
                      </td>
                      <td className="py-3 px-3 text-end font-mono tabular-nums text-slate-900 dark:text-slate-100">
                        {job.sizeGb.toLocaleString()} GB
                      </td>
                      <td className="py-3 px-3 text-end font-mono tabular-nums text-slate-900 dark:text-slate-100">
                        {job.ageHours}h
                      </td>
                      <td className="py-3 px-4 text-end font-mono tabular-nums font-semibold text-slate-900 dark:text-slate-100">
                        {job.failures7d}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
