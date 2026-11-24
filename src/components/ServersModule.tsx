import { useState, type FormEvent } from 'react';
import { Activity, Pencil, Plus, PlugZap, Search, Trash2 } from 'lucide-react';
import {
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { COPY } from '../data/i18n';
import {
  AssetStatus,
  CloudProviderId,
  ConnectionTestResult,
  CredentialProfileSummary,
  Language,
  MonitoringCapabilityMatrix,
  MonitoringMethod,
  MonitoringPolicy,
  ServerEnvironment,
  ServerPlatform,
  UserRole,
  WindowsProcessIdentity,
  WindowsServer,
} from '../types/infrastructure';
import {
  AssetStatusBadge,
  CollectionStatusBadge,
  getEnvironmentLabel,
  getPlatformLabel,
  HealthClassificationBadge,
  IntegrityBanner,
} from './StatusGlyph';

export interface ServerUpsertPayload {
  hostname: string;
  ipAddress: string;
  site: string;
  role: string;
  platform?: ServerPlatform;
  environment?: ServerEnvironment;
  osVersion?: string;
  monitoringPolicy?: MonitoringPolicy;
  allowedMethods?: MonitoringMethod[];
  authMode?: 'integrated' | 'credential' | 'snmp-only';
  credentialId?: string;
  snmpCommunity?: string;
  sshPort?: number;
  httpUrl?: string;
  tcpPorts?: number[];
  parentHypervHost?: string;
  cloudProvider?: CloudProviderId;
  cloudInstanceId?: string;
  ociRegion?: string;
  ociCompartment?: string;
  ociInstanceOcid?: string;
  oracleTnsAlias?: string;
  oracleServiceName?: string;
  notes?: string;
}

interface ServersModuleProps {
  servers: WindowsServer[];
  credentials: CredentialProfileSummary[];
  processIdentity?: WindowsProcessIdentity | null;
  currentRole: UserRole | null;
  lang: Language;
  onRegisterServer: (payload: ServerUpsertPayload) => Promise<string | null>;
  onUpdateServer: (id: string, payload: ServerUpsertPayload) => Promise<string | null>;
  onDeleteServer: (id: string) => Promise<string | null>;
  onTestServer: (id: string) => Promise<{ result?: ConnectionTestResult; error?: string }>;
  onPollHostNow: () => Promise<string | null>;
  onPollAllServers: () => Promise<string | null>;
}

const PLATFORMS: ServerPlatform[] = [
  'windows',
  'linux',
  'oracle-linux',
  'cloud-vps',
  'oci-compute',
  'oracle-db',
  'hyperv-host',
  'hyperv-vm',
  'network-device',
  'restricted',
];

const ENVIRONMENTS: ServerEnvironment[] = ['Production', 'Testing', 'Development'];

const POLICIES: { id: MonitoringPolicy; labelEn: string; labelAr: string }[] = [
  { id: 'standard', labelEn: 'Standard Agentless', labelAr: 'قياسي بدون وكيل' },
  { id: 'least-privilege', labelEn: 'Least Privilege (HTTPS/CIM)', labelAr: 'أقل صلاحية (HTTPS/CIM)' },
  { id: 'restricted-passive', labelEn: 'Restricted Passive Only', labelAr: 'خادم مقيد (سلبي فقط)' },
  { id: 'hyperv-host-only', labelEn: 'Hyper-V Host-Level Only', labelAr: 'عبر مضيف Hyper-V فقط' },
  { id: 'cloud-api', labelEn: 'Cloud Provider API + Passive', labelAr: 'واجهة السحابة + سلبي' },
];

const ALL_METHODS: { id: MonitoringMethod; label: string }[] = [
  { id: 'icmp', label: 'ICMP' },
  { id: 'tcp', label: 'TCP' },
  { id: 'winrm-https', label: 'WinRM 5986' },
  { id: 'winrm-http', label: 'WinRM 5985' },
  { id: 'wmi-dcom', label: 'WMI/DCOM' },
  { id: 'ssh', label: 'SSH (RO)' },
  { id: 'snmp', label: 'SNMP' },
  { id: 'http-https', label: 'HTTP/HTTPS' },
  { id: 'cloud-api', label: 'Cloud API' },
  { id: 'oci-api', label: 'OCI API' },
  { id: 'oracle-tns', label: 'Oracle TNS' },
  { id: 'hyperv-host', label: 'Hyper-V Host' },
];

const CLOUD_PROVIDERS: { id: CloudProviderId; label: string }[] = [
  { id: 'oci', label: 'Oracle Cloud Infrastructure (OCI)' },
  { id: 'hetzner', label: 'Hetzner Cloud' },
  { id: 'digitalocean', label: 'DigitalOcean' },
  { id: 'vultr', label: 'Vultr' },
  { id: 'aws-cloudwatch', label: 'AWS CloudWatch Proxy' },
  { id: 'azure-monitor', label: 'Azure Monitor Proxy' },
  { id: 'generic-rest', label: 'Generic REST Telemetry' },
];

function defaultPolicyForPlatform(platform: ServerPlatform): MonitoringPolicy {
  if (platform === 'restricted') return 'restricted-passive';
  if (platform === 'hyperv-vm') return 'hyperv-host-only';
  if (platform === 'cloud-vps' || platform === 'oci-compute') return 'cloud-api';
  return 'standard';
}

function defaultMethodsForPlatform(platform: ServerPlatform): MonitoringMethod[] {
  switch (platform) {
    case 'windows':
      return ['icmp', 'tcp', 'winrm-https', 'wmi-dcom', 'snmp', 'http-https'];
    case 'linux':
      return ['icmp', 'tcp', 'ssh', 'snmp', 'http-https'];
    case 'oracle-linux':
      return ['ssh', 'oci-api', 'icmp', 'tcp', 'snmp'];
    case 'cloud-vps':
      return ['cloud-api', 'icmp', 'tcp', 'http-https', 'ssh', 'snmp'];
    case 'oci-compute':
      return ['oci-api', 'ssh', 'oracle-tns', 'icmp', 'tcp'];
    case 'oracle-db':
      return ['oracle-tns', 'oci-api', 'ssh', 'tcp', 'icmp'];
    case 'hyperv-host':
      return ['icmp', 'tcp', 'winrm-https', 'wmi-dcom', 'hyperv-host'];
    case 'hyperv-vm':
      return ['hyperv-host', 'icmp', 'tcp', 'http-https'];
    case 'network-device':
      return ['icmp', 'tcp', 'snmp', 'http-https'];
    case 'restricted':
      return ['icmp', 'tcp', 'http-https', 'hyperv-host'];
  }
}

interface ServerFormState {
  hostname: string;
  ipAddress: string;
  site: string;
  role: string;
  platform: ServerPlatform;
  environment: ServerEnvironment;
  osVersion: string;
  monitoringPolicy: MonitoringPolicy;
  allowedMethods: MonitoringMethod[];
  authMode: 'integrated' | 'credential' | 'snmp-only';
  credentialId: string;
  snmpCommunity: string;
  sshPort: string;
  httpUrl: string;
  tcpPortsText: string;
  parentHypervHost: string;
  cloudProvider: CloudProviderId | '';
  cloudInstanceId: string;
  ociRegion: string;
  ociCompartment: string;
  ociInstanceOcid: string;
  oracleTnsAlias: string;
  oracleServiceName: string;
  notes: string;
}

function makeInitialFormState(): ServerFormState {
  return {
    hostname: '',
    ipAddress: '',
    site: 'Abdali Central Lab',
    role: 'LIS Application Server',
    platform: 'windows',
    environment: 'Production',
    osVersion: '',
    monitoringPolicy: 'standard',
    allowedMethods: defaultMethodsForPlatform('windows'),
    authMode: 'integrated',
    credentialId: '',
    snmpCommunity: '',
    sshPort: '22',
    httpUrl: '',
    tcpPortsText: '',
    parentHypervHost: '',
    cloudProvider: '',
    cloudInstanceId: '',
    ociRegion: '',
    ociCompartment: '',
    ociInstanceOcid: '',
    oracleTnsAlias: '',
    oracleServiceName: '',
    notes: '',
  };
}

function parseTcpPortsInput(raw: string): number[] | undefined {
  const nums = raw
    .split(/[\s,;]+/)
    .map((s) => Number(s.trim()))
    .filter((n) => Number.isInteger(n) && n >= 1 && n <= 65535);
  return nums.length > 0 ? Array.from(new Set(nums)).slice(0, 12) : undefined;
}

function CapabilityMatrixPanel({
  matrix,
  lang,
}: {
  matrix: MonitoringCapabilityMatrix;
  lang: Language;
}) {
  const protocols: { label: string; state: boolean | null }[] = [
    { label: 'ICMP', state: matrix.icmpAvailable },
    { label: 'TCP', state: matrix.tcpAvailable },
    { label: 'WinRM', state: matrix.winrmAvailable },
    { label: 'WMI/DCOM', state: matrix.wmiAvailable },
    { label: 'SSH', state: matrix.sshAvailable },
    { label: 'SNMP', state: matrix.snmpAvailable },
    { label: 'OCI API', state: matrix.ociApiAvailable ?? null },
    { label: 'Oracle TNS', state: matrix.oracleTnsAvailable ?? null },
    { label: 'Cloud API', state: matrix.cloudApiAvailable },
    { label: 'Hyper-V Host', state: matrix.hypervHostAccess },
  ];

  const renderFlag = (val: boolean | null) => {
    if (val === true) {
      return <span className="text-emerald-700 dark:text-emerald-400 font-semibold">✓ {lang === 'ar' ? 'متاح' : 'Available'}</span>;
    }
    if (val === false) {
      return <span className="text-rose-700 dark:text-rose-400 font-semibold">✖ {lang === 'ar' ? 'محجوب/فشل' : 'Blocked'}</span>;
    }
    return <span className="text-slate-400 dark:text-slate-500">— {lang === 'ar' ? 'غير مختبر' : 'N/A'}</span>;
  };

  return (
    <div className="pt-3 border-t border-slate-100 dark:border-slate-800 space-y-3 text-xs">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="font-semibold text-slate-800 dark:text-slate-200">
          {lang === 'ar' ? 'مصفوفة قدرات المراقبة (بدون وكيل)' : 'Monitoring Capability Matrix (Agentless)'}
        </span>
        <span className="font-mono text-[11px] text-slate-500 dark:text-slate-400">
          {matrix.platformDetected}
          {matrix.activeMethod ? ` · ${matrix.activeMethod}` : ''}
        </span>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
        {protocols.map((p) => (
          <div
            key={p.label}
            className="px-2.5 py-1.5 rounded border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/50 flex items-center justify-between gap-2"
          >
            <span className="font-mono text-[11px] text-slate-600 dark:text-slate-400">{p.label}</span>
            <span className="text-[11px]">{renderFlag(p.state)}</span>
          </div>
        ))}
      </div>

      {matrix.availableMetrics.length > 0 && (
        <div className="text-[11px] text-slate-700 dark:text-slate-300">
          <span className="font-semibold text-emerald-700 dark:text-emerald-400">
            {lang === 'ar' ? 'المؤشرات المقاسة فعلياً: ' : 'Verified Metrics: '}
          </span>
          <span className="font-mono">{matrix.availableMetrics.join(', ')}</span>
        </div>
      )}

      {matrix.unavailableMetrics.length > 0 && (
        <div className="space-y-1">
          <div className="text-[11px] font-semibold text-amber-700 dark:text-amber-400">
            {lang === 'ar' ? 'المؤشرات غير المتاحة والسبب:' : 'Unavailable Metrics & Exact Reason:'}
          </div>
          <div className="divide-y divide-slate-100 dark:divide-slate-800 border border-slate-200 dark:border-slate-800 rounded">
            {matrix.unavailableMetrics.map((u, idx) => (
              <div key={`${u.metric}-${idx}`} className="px-2.5 py-1.5 flex flex-col sm:flex-row sm:justify-between gap-1 text-[11px]">
                <span className="font-mono font-semibold text-slate-800 dark:text-slate-200 shrink-0">
                  {u.metric}
                </span>
                <span className="text-slate-600 dark:text-slate-400 break-words">{u.reason}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {matrix.accessRestrictions.length > 0 && (
        <div className="text-[11px] text-slate-600 dark:text-slate-400">
          <span className="font-semibold text-slate-800 dark:text-slate-200">
            {lang === 'ar' ? 'قيود الوصول / السياسة: ' : 'Policy & Access Notes: '}
          </span>
          {matrix.accessRestrictions.join(' | ')}
        </div>
      )}
    </div>
  );
}

export function ServersModule({
  servers,
  credentials,
  processIdentity,
  currentRole,
  lang,
  onRegisterServer,
  onUpdateServer,
  onDeleteServer,
  onTestServer,
  onPollHostNow,
  onPollAllServers,
}: ServersModuleProps) {
  const copy = COPY[lang];
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState<'all' | AssetStatus>('all');
  const [platformFilter, setPlatformFilter] = useState<'all' | ServerPlatform>('all');
  const [selectedId, setSelectedId] = useState(servers[0]?.id ?? '');

  const [showAddForm, setShowAddForm] = useState(false);
  const [feedback, setFeedback] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<ConnectionTestResult | null>(null);
  const [testingId, setTestingId] = useState<string | null>(null);
  const [pollingHost, setPollingHost] = useState(false);
  const [pollingAll, setPollingAll] = useState(false);

  const [newForm, setNewForm] = useState<ServerFormState>(makeInitialFormState);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editForm, setEditForm] = useState<ServerFormState>(makeInitialFormState);
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null);

  const canModify =
    currentRole !== null && ['Administrator', 'IT Manager', 'IT Engineer'].includes(currentRole);

  const serverCredentials = credentials.filter((c) =>
    ['windows', 'hyperv', 'linux-ssh', 'cloud-api', 'oci-api', 'oracle', 'snmpv2c', 'snmpv3', 'http'].includes(c.kind)
  );
  const hypervHostCandidates = servers.filter((s) => (s.platform ?? 'windows') === 'hyperv-host');

  const filtered = servers.filter((s) => {
    const plat = s.platform ?? 'windows';
    const matchesSearch =
      s.hostname.toLowerCase().includes(search.toLowerCase()) ||
      s.ipAddress.includes(search) ||
      s.site.toLowerCase().includes(search.toLowerCase()) ||
      s.role.toLowerCase().includes(search.toLowerCase()) ||
      (s.osVersion || '').toLowerCase().includes(search.toLowerCase());
    const matchesStatus = statusFilter === 'all' || s.status === statusFilter;
    const matchesPlatform = platformFilter === 'all' || plat === platformFilter;
    return matchesSearch && matchesStatus && matchesPlatform;
  });

  const selected = filtered.find((s) => s.id === selectedId) ?? filtered[0] ?? servers[0];

  const requireSignInNotice = () => {
    setFeedback(
      lang === 'ar'
        ? 'يجب تسجيل الدخول بحساب مهندس أو مسؤول (admin.medlabs) من القائمة الجانبية أولاً لتتمكن من التعديل أو الاختبار.'
        : 'Please sign in as Administrator or IT Engineer from the sidebar first.'
    );
  };

  const toUpsertPayload = (form: ServerFormState): ServerUpsertPayload => {
    const sshNum = Number(form.sshPort);
    return {
      hostname: form.hostname.trim(),
      ipAddress: form.ipAddress.trim(),
      site: form.site.trim(),
      role: form.role.trim(),
      platform: form.platform,
      environment: form.environment,
      osVersion: form.osVersion.trim() || undefined,
      monitoringPolicy: form.monitoringPolicy,
      allowedMethods: form.allowedMethods.length > 0 ? form.allowedMethods : undefined,
      authMode: form.authMode,
      credentialId: form.credentialId || undefined,
      snmpCommunity: form.snmpCommunity.trim() || undefined,
      sshPort: Number.isInteger(sshNum) && sshNum >= 1 && sshNum <= 65535 ? sshNum : undefined,
      httpUrl: form.httpUrl.trim() || undefined,
      tcpPorts: parseTcpPortsInput(form.tcpPortsText),
      parentHypervHost: form.parentHypervHost.trim() || undefined,
      cloudProvider: form.cloudProvider || undefined,
      cloudInstanceId: form.cloudInstanceId.trim() || undefined,
      ociRegion: form.ociRegion.trim() || undefined,
      ociCompartment: form.ociCompartment.trim() || undefined,
      ociInstanceOcid: form.ociInstanceOcid.trim() || undefined,
      oracleTnsAlias: form.oracleTnsAlias.trim() || undefined,
      oracleServiceName: form.oracleServiceName.trim() || undefined,
      notes: form.notes.trim() || undefined,
    };
  };

  const handleRegister = async (e: FormEvent) => {
    e.preventDefault();
    setTestResult(null);
    const err = await onRegisterServer(toUpsertPayload(newForm));
    if (err) {
      setFeedback(err);
    } else {
      setFeedback(
        lang === 'ar'
          ? `تم تسجيل الخادم ${newForm.hostname} (${getPlatformLabel(newForm.platform, lang)}) وفحصه مركزياً بدون وكيل.`
          : `Registered ${newForm.hostname} (${getPlatformLabel(newForm.platform, lang)}) and ran initial agentless check.`
      );
      setNewForm(makeInitialFormState());
      setShowAddForm(false);
    }
  };

  const handlePollHost = async () => {
    setPollingHost(true);
    setFeedback(null);
    setTestResult(null);
    const err = await onPollHostNow();
    setPollingHost(false);
    if (err) {
      setFeedback(err);
    } else {
      setFeedback(
        lang === 'ar'
          ? 'تم سحب القراءات الفعلية للخادم المركزي وتحديث اللوحة.'
          : 'Live OS CPU, RAM, Disk, and uptime metrics polled from central hosting server.'
      );
    }
  };

  const handlePollAll = async () => {
    if (!canModify) {
      requireSignInNotice();
      return;
    }
    setPollingAll(true);
    setFeedback(null);
    setTestResult(null);
    const err = await onPollAllServers();
    setPollingAll(false);
    if (err) {
      setFeedback(err);
    } else {
      setFeedback(
        lang === 'ar'
          ? 'تم تنفيذ جولة الفحص المركزية متعددة المنصات (WinRM/WMI و SSH و Cloud API و Hyper-V و SNMP و ICMP/TCP) لجميع الأهداف.'
          : 'Centralized multi-platform agentless sweep completed across all registered servers.'
      );
    }
  };

  const handleTestConnection = async (srvId: string) => {
    if (!canModify) {
      requireSignInNotice();
      return;
    }
    setTestingId(srvId);
    setTestResult(null);
    const { result, error } = await onTestServer(srvId);
    setTestingId(null);
    if (error) {
      setFeedback(error);
    } else if (result) {
      setTestResult(result);
    }
  };

  const startEdit = (srv: WindowsServer) => {
    if (!canModify) {
      requireSignInNotice();
      return;
    }
    const platform = srv.platform ?? 'windows';
    setShowAddForm(false);
    setConfirmDeleteId(null);
    setEditingId(srv.id);
    setEditForm({
      hostname: srv.hostname,
      ipAddress: srv.ipAddress,
      site: srv.site,
      role: srv.role,
      platform,
      environment: srv.environment ?? 'Production',
      osVersion: srv.osVersion || '',
      monitoringPolicy: srv.monitoringPolicy ?? defaultPolicyForPlatform(platform),
      allowedMethods: srv.allowedMethods ?? defaultMethodsForPlatform(platform),
      authMode: srv.authMode || 'integrated',
      credentialId: srv.credentialId || '',
      snmpCommunity: srv.snmpCommunity || '',
      sshPort: srv.sshPort ? String(srv.sshPort) : '22',
      httpUrl: srv.httpUrl || '',
      tcpPortsText: srv.tcpPorts ? srv.tcpPorts.join(', ') : '',
      parentHypervHost: srv.parentHypervHost || '',
      cloudProvider: srv.cloudProvider || '',
      cloudInstanceId: srv.cloudInstanceId || '',
      ociRegion: srv.ociRegion || '',
      ociCompartment: srv.ociCompartment || '',
      ociInstanceOcid: srv.ociInstanceOcid || '',
      oracleTnsAlias: srv.oracleTnsAlias || '',
      oracleServiceName: srv.oracleServiceName || '',
      notes: srv.notes || '',
    });
  };

  const handleSaveEdit = async (e: FormEvent) => {
    e.preventDefault();
    if (!editingId) return;
    if (!canModify) {
      requireSignInNotice();
      return;
    }
    const err = await onUpdateServer(editingId, {
      ...toUpsertPayload(editForm),
      credentialId: editForm.credentialId || '',
      snmpCommunity: editForm.snmpCommunity.trim(),
    });
    if (err) {
      setFeedback(err);
    } else {
      setFeedback(
        lang === 'ar'
          ? `تم تحديث بيانات الخادم ${editForm.hostname} وإعادة فحصه مركزياً.`
          : `Updated server ${editForm.hostname} and re-polled centrally.`
      );
      setEditingId(null);
    }
  };

  const requestDelete = (srvId: string) => {
    if (!canModify) {
      requireSignInNotice();
      return;
    }
    setConfirmDeleteId(srvId);
  };

  const handleDelete = async (srv: WindowsServer) => {
    if (!canModify) {
      requireSignInNotice();
      return;
    }
    const err = await onDeleteServer(srv.id);
    setConfirmDeleteId(null);
    if (err) {
      setFeedback(err);
    } else {
      if (editingId === srv.id) setEditingId(null);
      setFeedback(
        lang === 'ar'
          ? `تم حذف الخادم ${srv.hostname} من قائمة المراقبة.`
          : `Removed server ${srv.hostname} from inventory.`
      );
    }
  };

  const fmtMetric = (val: number, available?: boolean, suffix = '%') =>
    available === false ? (lang === 'ar' ? 'غير متاح' : 'Unavailable') : `${val}${suffix}`;

  const renderServerFormFields = (
    form: ServerFormState,
    setForm: (updater: (prev: ServerFormState) => ServerFormState) => void,
    isEdit: boolean
  ) => {
    const toggleMethod = (m: MonitoringMethod) => {
      setForm((prev) => {
        const exists = prev.allowedMethods.includes(m);
        return {
          ...prev,
          allowedMethods: exists
            ? prev.allowedMethods.filter((x) => x !== m)
            : [...prev.allowedMethods, m],
        };
      });
    };

    const handlePlatformChange = (p: ServerPlatform) => {
      setForm((prev) => ({
        ...prev,
        platform: p,
        monitoringPolicy: isEdit ? prev.monitoringPolicy : defaultPolicyForPlatform(p),
        allowedMethods: isEdit ? prev.allowedMethods : defaultMethodsForPlatform(p),
        authMode:
          !isEdit && (p === 'linux' || p === 'oracle-linux' || p === 'cloud-vps' || p === 'oci-compute' || p === 'oracle-db')
            ? 'credential'
            : !isEdit && p === 'network-device'
              ? 'snmp-only'
              : prev.authMode,
        cloudProvider: !isEdit && p === 'oci-compute' ? 'oci' : prev.cloudProvider,
      }));
    };

    return (
      <div className="space-y-4">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <input
            type="text"
            placeholder={lang === 'ar' ? 'اسم الخادم (Hostname)' : 'Hostname (e.g. MLJ-LIS-02)'}
            value={form.hostname}
            onChange={(e) => setForm((p) => ({ ...p, hostname: e.target.value }))}
            required
            className="px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md font-mono text-slate-900 dark:text-slate-100"
          />
          <input
            type="text"
            placeholder={
              form.platform === 'hyperv-vm' || form.platform === 'cloud-vps' || form.platform === 'oci-compute'
                ? 'IP / FQDN (optional if via Host/API)'
                : 'IP / FQDN (e.g. 192.168.127.33)'
            }
            value={form.ipAddress}
            onChange={(e) => setForm((p) => ({ ...p, ipAddress: e.target.value }))}
            required={form.platform !== 'hyperv-vm' && form.platform !== 'cloud-vps' && form.platform !== 'oci-compute'}
            className="px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md font-mono text-slate-900 dark:text-slate-100"
          />
          <select
            value={form.platform}
            onChange={(e) => handlePlatformChange(e.target.value as ServerPlatform)}
            className="px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md text-slate-900 dark:text-slate-100"
          >
            {PLATFORMS.map((p) => (
              <option key={p} value={p}>
                {getPlatformLabel(p, lang)}
              </option>
            ))}
          </select>

          <select
            value={form.environment}
            onChange={(e) => setForm((p) => ({ ...p, environment: e.target.value as ServerEnvironment }))}
            className="px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md text-slate-900 dark:text-slate-100"
          >
            {ENVIRONMENTS.map((env) => (
              <option key={env} value={env}>
                {getEnvironmentLabel(env, lang)}
              </option>
            ))}
          </select>
          <input
            type="text"
            placeholder={lang === 'ar' ? 'الموقع / الفرع' : 'Site / Branch'}
            value={form.site}
            onChange={(e) => setForm((p) => ({ ...p, site: e.target.value }))}
            required
            className="px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md text-slate-900 dark:text-slate-100"
          />
          <input
            type="text"
            placeholder={lang === 'ar' ? 'الدور الوظيفي' : 'Server Role'}
            value={form.role}
            onChange={(e) => setForm((p) => ({ ...p, role: e.target.value }))}
            required
            className="px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md text-slate-900 dark:text-slate-100"
          />

          <select
            value={form.monitoringPolicy}
            onChange={(e) => setForm((p) => ({ ...p, monitoringPolicy: e.target.value as MonitoringPolicy }))}
            className="px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md text-slate-900 dark:text-slate-100"
          >
            {POLICIES.map((pol) => (
              <option key={pol.id} value={pol.id}>
                {lang === 'ar' ? pol.labelAr : pol.labelEn}
              </option>
            ))}
          </select>

          <select
            value={form.authMode}
            onChange={(e) =>
              setForm((p) => ({
                ...p,
                authMode: e.target.value as 'integrated' | 'credential' | 'snmp-only',
              }))
            }
            className="px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md text-slate-900 dark:text-slate-100"
          >
            <option value="integrated">
              {lang === 'ar' ? 'مصادقة Windows المتكاملة (AD/Integrated)' : 'Windows Integrated Auth (Kerberos/NTLM)'}
            </option>
            <option value="credential">
              {lang === 'ar' ? 'حساب مشفّر من الخزنة (WinRM/SSH/Cloud/Hyper-V)' : 'Encrypted Read-Only Vault Profile'}
            </option>
            <option value="snmp-only">
              {lang === 'ar' ? 'SNMP / سلبي Read-Only فقط' : 'SNMP / Passive Read-Only Only'}
            </option>
          </select>

          <select
            value={form.credentialId}
            onChange={(e) => setForm((p) => ({ ...p, credentialId: e.target.value }))}
            className="px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md text-slate-900 dark:text-slate-100"
          >
            <option value="">{lang === 'ar' ? '— ملف اعتماد الخزنة (اختياري) —' : '— Encrypted Vault Profile (optional) —'}</option>
            {serverCredentials.map((c) => (
              <option key={c.id} value={c.id}>
                {c.name} ({c.kind})
              </option>
            ))}
          </select>

          <input
            type="text"
            placeholder={lang === 'ar' ? 'إصدار نظام التشغيل (اختياري)' : 'OS Version (optional, auto-detected when reachable)'}
            value={form.osVersion}
            onChange={(e) => setForm((p) => ({ ...p, osVersion: e.target.value }))}
            className="px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md text-slate-900 dark:text-slate-100"
          />

          <input
            type="text"
            placeholder={lang === 'ar' ? 'SNMPv2c Community (اختياري)' : 'SNMPv2c Community (optional)'}
            value={form.snmpCommunity}
            onChange={(e) => setForm((p) => ({ ...p, snmpCommunity: e.target.value }))}
            className="px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md font-mono text-slate-900 dark:text-slate-100"
          />

          <input
            type="text"
            placeholder={lang === 'ar' ? 'منافذ TCP للفحص (مثل 80, 443, 1521)' : 'TCP Ports (optional, e.g. 80, 443, 1521)'}
            value={form.tcpPortsText}
            onChange={(e) => setForm((p) => ({ ...p, tcpPortsText: e.target.value }))}
            className="px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md font-mono text-slate-900 dark:text-slate-100"
          />

          <input
            type="url"
            placeholder={lang === 'ar' ? 'رابط فحص HTTP/HTTPS (اختياري)' : 'HTTP/HTTPS Health URL (optional)'}
            value={form.httpUrl}
            onChange={(e) => setForm((p) => ({ ...p, httpUrl: e.target.value }))}
            className="px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md font-mono text-slate-900 dark:text-slate-100"
          />

          {(form.platform === 'linux' || form.platform === 'oracle-linux' || form.platform === 'cloud-vps' || form.platform === 'oci-compute' || form.platform === 'oracle-db') && (
            <input
              type="number"
              min={1}
              max={65535}
              placeholder="SSH Port (default 22)"
              value={form.sshPort}
              onChange={(e) => setForm((p) => ({ ...p, sshPort: e.target.value }))}
              className="px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md font-mono text-slate-900 dark:text-slate-100"
            />
          )}

          {(form.platform === 'oci-compute' || form.platform === 'oracle-linux' || form.platform === 'oracle-db') && (
            <>
              <input
                type="text"
                placeholder="OCI Region (e.g. me-jeddah-1)"
                value={form.ociRegion}
                onChange={(e) => setForm((p) => ({ ...p, ociRegion: e.target.value }))}
                className="px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md font-mono text-slate-900 dark:text-slate-100"
              />
              <input
                type="text"
                placeholder="OCI Instance OCID (ocid1.instance.oc1..)"
                value={form.ociInstanceOcid}
                onChange={(e) => setForm((p) => ({ ...p, ociInstanceOcid: e.target.value }))}
                className="px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md font-mono text-slate-900 dark:text-slate-100"
              />
              <input
                type="text"
                placeholder="OCI Compartment OCID (optional)"
                value={form.ociCompartment}
                onChange={(e) => setForm((p) => ({ ...p, ociCompartment: e.target.value }))}
                className="px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md font-mono text-slate-900 dark:text-slate-100"
              />
            </>
          )}

          {(form.platform === 'oracle-db' || form.platform === 'oci-compute') && (
            <>
              <input
                type="text"
                placeholder="Oracle TNS Alias (optional, e.g. MEDLABS_PROD)"
                value={form.oracleTnsAlias}
                onChange={(e) => setForm((p) => ({ ...p, oracleTnsAlias: e.target.value }))}
                className="px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md font-mono text-slate-900 dark:text-slate-100"
              />
              <input
                type="text"
                placeholder="Oracle Service Name (optional)"
                value={form.oracleServiceName}
                onChange={(e) => setForm((p) => ({ ...p, oracleServiceName: e.target.value }))}
                className="px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md font-mono text-slate-900 dark:text-slate-100"
              />
            </>
          )}

          {(form.platform === 'hyperv-vm' || form.platform === 'restricted') && (
            <div>
              <input
                type="text"
                list="hyperv-host-candidates"
                placeholder={lang === 'ar' ? 'مضيف Hyper-V الأب (اختياري)' : 'Parent Hyper-V Host (optional)'}
                value={form.parentHypervHost}
                onChange={(e) => setForm((p) => ({ ...p, parentHypervHost: e.target.value }))}
                className="w-full px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md font-mono text-slate-900 dark:text-slate-100"
              />
              <datalist id="hyperv-host-candidates">
                {hypervHostCandidates.map((h) => (
                  <option key={h.id} value={h.hostname} />
                ))}
              </datalist>
            </div>
          )}

          {form.platform === 'cloud-vps' && (
            <>
              <select
                value={form.cloudProvider}
                onChange={(e) =>
                  setForm((p) => ({ ...p, cloudProvider: e.target.value as CloudProviderId | '' }))
                }
                className="px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md text-slate-900 dark:text-slate-100"
              >
                <option value="">{lang === 'ar' ? '— مزوّد السحابة —' : '— Cloud Provider —'}</option>
                {CLOUD_PROVIDERS.map((cp) => (
                  <option key={cp.id} value={cp.id}>
                    {cp.label}
                  </option>
                ))}
              </select>
              <input
                type="text"
                placeholder={lang === 'ar' ? 'معرّف الخادم السحابي (Instance ID)' : 'Cloud Instance ID (for Cloud API)'}
                value={form.cloudInstanceId}
                onChange={(e) => setForm((p) => ({ ...p, cloudInstanceId: e.target.value }))}
                className="px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md font-mono text-slate-900 dark:text-slate-100"
              />
            </>
          )}

          <input
            type="text"
            placeholder={lang === 'ar' ? 'ملاحظات تشغيلية / قيود أمان (اختياري)' : 'Security / Policy Notes (optional)'}
            value={form.notes}
            onChange={(e) => setForm((p) => ({ ...p, notes: e.target.value }))}
            className="md:col-span-2 px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md text-slate-900 dark:text-slate-100"
          />
        </div>

        <div className="pt-2 border-t border-slate-100 dark:border-slate-800">
          <div className="text-[11px] font-semibold text-slate-600 dark:text-slate-400 mb-2">
            {lang === 'ar'
              ? 'طرق الفحص المسموحة لهذا الهدف (قراءة فقط وبدون وكيل):'
              : 'Permitted Read-Only Monitoring Methods:'}
          </div>
          <div className="flex flex-wrap gap-2">
            {ALL_METHODS.map((m) => {
              const checked = form.allowedMethods.includes(m.id);
              return (
                <label
                  key={m.id}
                  className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded border text-[11px] font-mono cursor-pointer transition-colors ${
                    checked
                      ? 'bg-blue-50 dark:bg-blue-950/40 border-blue-300 dark:border-blue-800 text-blue-800 dark:text-blue-200'
                      : 'bg-white dark:bg-slate-950 border-slate-200 dark:border-slate-800 text-slate-600 dark:text-slate-400'
                  }`}
                >
                  <input
                    type="checkbox"
                    checked={checked}
                    onChange={() => toggleMethod(m.id)}
                  />
                  <span>{m.label}</span>
                </label>
              );
            })}
          </div>
        </div>
      </div>
    );
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col xl:flex-row xl:items-center xl:justify-between gap-4 pb-4 border-b border-slate-200 dark:border-slate-800">
        <div>
          <h1 className="text-xl font-semibold text-slate-900 dark:text-slate-100">
            {lang === 'ar'
              ? 'مراقبة الخوادم والمنصات المتعددة (بدون وكيل)'
              : 'Multi-Platform Server Monitoring (Agentless)'}
          </h1>
          <p className="text-sm text-slate-600 dark:text-slate-400 mt-1">
            {lang === 'ar'
              ? 'فحص مركزي للقراءة فقط عبر WMI/CIM/WinRM و SSH و Cloud API و Hyper-V و SNMP و HTTP/TCP/ICMP لخوادم Windows و Linux والسحابة والمقيدة.'
              : 'Centralized read-only polling across Windows, Linux, Cloud VPS, Hyper-V Hosts & VMs, Network Devices, and Restricted Servers.'}
          </p>
          {processIdentity && (
            <div className="mt-2 flex flex-wrap items-center gap-2 text-[11px] font-mono">
              <span
                className={`px-2 py-0.5 rounded border ${
                  processIdentity.isDomainUser && !processIdentity.doubleHopRisk
                    ? 'bg-emerald-50 dark:bg-emerald-950/30 border-emerald-200 dark:border-emerald-900 text-emerald-800 dark:text-emerald-300'
                    : 'bg-amber-50 dark:bg-amber-950/30 border-amber-200 dark:border-amber-900 text-amber-800 dark:text-amber-300'
                }`}
              >
                {lang === 'ar' ? 'سياق الخادم المركزي: ' : 'Process Context: '}
                {processIdentity.identityName} ({processIdentity.authenticationType}
                {processIdentity.partOfDomain ? ` · ${processIdentity.domain}` : ' · Non-Domain'}
                {processIdentity.kerberosTgtAvailable ? ' · Kerberos TGT' : ''})
              </span>
              {processIdentity.doubleHopRisk && (
                <span className="px-2 py-0.5 rounded border bg-red-50 dark:bg-red-950/30 border-red-200 dark:border-red-900 text-red-700 dark:text-red-300">
                  {lang === 'ar' ? 'تحذير Double-Hop / التفويض' : 'Double-Hop / Delegation Warning'}
                </span>
              )}
            </div>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          <button
            type="button"
            disabled={!canModify || pollingHost}
            onClick={handlePollHost}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-emerald-600 hover:bg-emerald-700 text-white rounded-md disabled:opacity-50 whitespace-nowrap shrink-0 cursor-pointer"
          >
            <Activity className="w-3.5 h-3.5" />
            <span>
              {pollingHost
                ? lang === 'ar'
                  ? 'جاري الفحص...'
                  : 'Polling Host...'
                : lang === 'ar'
                  ? 'فحص السيرفر المركزي الآن'
                  : 'Poll Central Server Live'}
            </span>
          </button>

          <button
            type="button"
            disabled={pollingAll || servers.length === 0}
            onClick={handlePollAll}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-slate-900 dark:bg-slate-700 hover:bg-slate-800 dark:hover:bg-slate-600 text-white rounded-md disabled:opacity-50 whitespace-nowrap shrink-0 cursor-pointer"
          >
            <Activity className="w-3.5 h-3.5" />
            <span>
              {pollingAll
                ? lang === 'ar'
                  ? 'جاري فحص الكل...'
                  : 'Polling All...'
                : lang === 'ar'
                  ? 'فحص كل الخوادم الآن'
                  : 'Poll All Servers'}
            </span>
          </button>

          <button
            type="button"
            onClick={() => {
              setEditingId(null);
              setShowAddForm((p) => !p);
            }}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-blue-600 hover:bg-blue-700 text-white rounded-md whitespace-nowrap shrink-0 cursor-pointer"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>{lang === 'ar' ? 'إضافة خادم' : 'Register Server'}</span>
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
          className={`p-3.5 rounded-md border text-xs space-y-2 ${
            testResult.ok
              ? 'bg-emerald-50 dark:bg-emerald-950/30 border-emerald-200 dark:border-emerald-900 text-emerald-900 dark:text-emerald-200'
              : 'bg-amber-50 dark:bg-amber-950/30 border-amber-200 dark:border-amber-900 text-amber-950 dark:text-amber-200'
          }`}
        >
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2 font-semibold">
              <CollectionStatusBadge status={testResult.status} lang={lang} />
              <span>{testResult.dataSource}</span>
            </div>
            <span className="font-mono tabular-nums text-[11px]">
              {testResult.latencyMs !== null ? `${testResult.latencyMs}ms · ` : ''}
              {testResult.measuredAt}
            </span>
          </div>
          <div className="font-mono text-[11px]">{testResult.details}</div>
          {testResult.doubleHopWarning && (
            <div className="p-2 rounded border border-red-300 dark:border-red-800 bg-red-50 dark:bg-red-950/40 text-red-800 dark:text-red-200 text-[11px]">
              <strong>{lang === 'ar' ? 'تنبيه Double-Hop / التفويض: ' : 'Double-Hop / Delegation Alert: '}</strong>
              {testResult.doubleHopWarning}
            </div>
          )}
          {testResult.checks && testResult.checks.length > 0 && (
            <div className="pt-2 border-t border-slate-200/70 dark:border-slate-700/70 space-y-1.5">
              {testResult.checks.map((chk) => (
                <div
                  key={chk.key}
                  className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-1.5 p-2 rounded bg-white/70 dark:bg-slate-900/60 border border-slate-200/60 dark:border-slate-800"
                >
                  <div className="space-y-0.5">
                    <div className="flex items-center gap-2 font-semibold">
                      <CollectionStatusBadge status={chk.status} lang={lang} />
                      <span>{chk.label}</span>
                    </div>
                    <div className="font-mono text-[11px] text-slate-700 dark:text-slate-300">{chk.details}</div>
                    {chk.prerequisiteHint && (
                      <div className="text-[11px] text-slate-600 dark:text-slate-400">
                        {chk.prerequisiteHint}
                      </div>
                    )}
                  </div>
                  {chk.latencyMs !== null && (
                    <span className="font-mono tabular-nums text-[11px] text-slate-500 shrink-0">{chk.latencyMs}ms</span>
                  )}
                </div>
              ))}
            </div>
          )}
          {testResult.capabilityMatrix && (
            <CapabilityMatrixPanel matrix={testResult.capabilityMatrix} lang={lang} />
          )}
          {testResult.prerequisiteHint && (
            <div className="text-[11px]">
              <strong>{lang === 'ar' ? 'المتطلب: ' : 'Prerequisite: '}</strong>
              {testResult.prerequisiteHint}
            </div>
          )}
        </div>
      )}

      {/* Register Server Form */}
      {showAddForm && (
        <form
          onSubmit={handleRegister}
          className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-5 space-y-4 text-xs"
        >
          <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
            {lang === 'ar'
              ? 'تسجيل خادم أو منصة للمراقبة المركزية (بدون وكيل)'
              : 'Register Server / Platform (Agentless Central Polling)'}
          </h2>
          {renderServerFormFields(newForm, setNewForm, false)}
          <div className="flex justify-end gap-2">
            <button
              type="button"
              onClick={() => setShowAddForm(false)}
              className="px-3 py-1.5 rounded border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300 cursor-pointer"
            >
              {copy.common.cancel}
            </button>
            <button
              type="submit"
              disabled={!canModify}
              className="px-4 py-1.5 rounded bg-blue-600 text-white hover:bg-blue-700 disabled:opacity-50 cursor-pointer"
            >
              {canModify
                ? copy.common.save
                : lang === 'ar'
                  ? 'يتطلب تسجيل الدخول'
                  : 'Sign in as Engineer+'}
            </button>
          </div>
        </form>
      )}

      {/* Edit Server Form */}
      {editingId && (
        <form
          onSubmit={handleSaveEdit}
          className="bg-white dark:bg-slate-900 border border-blue-200 dark:border-blue-900 rounded-lg p-5 space-y-4 text-xs"
        >
          <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
            {lang === 'ar' ? `تعديل بيانات الخادم: ${editForm.hostname}` : `Edit Server: ${editForm.hostname}`}
          </h2>
          {renderServerFormFields(editForm, setEditForm, true)}
          <div className="flex justify-end gap-2">
            <button
              type="button"
              onClick={() => setEditingId(null)}
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

      {/* Search & Filter Row */}
      <div className="space-y-2.5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="relative">
            <Search className="w-4 h-4 text-slate-400 absolute start-3 top-1/2 -translate-y-1/2 pointer-events-none" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder={copy.common.search}
              className="ps-9 pe-3 py-1.5 text-xs bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-md text-slate-900 dark:text-slate-100 placeholder:text-slate-400 focus:outline-none focus:border-blue-600 w-60"
            />
          </div>

          <div className="inline-flex items-center p-1 bg-slate-100 dark:bg-slate-800 rounded-md">
            {(['all', 'Online', 'Warning', 'Critical', 'Offline'] as const).map((st) => (
              <button
                key={st}
                type="button"
                onClick={() => setStatusFilter(st)}
                className={`px-2.5 py-1 text-xs font-medium rounded transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                  statusFilter === st
                    ? 'bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100 shadow-xs'
                    : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
                }`}
              >
                {st === 'all' ? copy.common.all : copy.status[st]}
              </button>
            ))}
          </div>
        </div>

        {/* Platform Segmented Filter */}
        <div className="flex flex-wrap items-center gap-1 p-1 bg-slate-100 dark:bg-slate-800 rounded-md w-fit">
          <button
            type="button"
            onClick={() => setPlatformFilter('all')}
            className={`px-2.5 py-1 text-[11px] font-medium rounded whitespace-nowrap cursor-pointer transition-colors ${
              platformFilter === 'all'
                ? 'bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100 shadow-xs'
                : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
            }`}
          >
            {copy.common.all} ({servers.length})
          </button>
          {PLATFORMS.map((p) => {
            const count = servers.filter((s) => (s.platform ?? 'windows') === p).length;
            return (
              <button
                key={p}
                type="button"
                onClick={() => setPlatformFilter(p)}
                className={`px-2.5 py-1 text-[11px] font-medium rounded whitespace-nowrap cursor-pointer transition-colors ${
                  platformFilter === p
                    ? 'bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100 shadow-xs'
                    : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
                }`}
              >
                {getPlatformLabel(p, lang)} ({count})
              </button>
            );
          })}
        </div>
      </div>

      {/* Servers Inventory Table */}
      <section className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg overflow-hidden">
        {servers.length === 0 ? (
          <div className="p-8 text-center space-y-2 text-xs text-slate-600 dark:text-slate-400">
            <div className="text-sm font-semibold text-slate-900 dark:text-slate-100">
              {lang === 'ar' ? 'لا توجد خوادم مسجلة بعد' : 'No Servers Registered Yet'}
            </div>
            <p className="max-w-lg mx-auto">
              {lang === 'ar'
                ? 'اضغط «فحص السيرفر المركزي الآن» أو «إضافة خادم» لمراقبة خوادم Windows أو Linux أو Cloud VPS أو Hyper-V أو الخوادم المقيدة بدون أي وكيل.'
                : 'Click "Poll Central Server Live" or Register Server to begin centralized agentless monitoring across Windows, Linux, Cloud VPS, Hyper-V, Network, and Restricted servers.'}
            </p>
          </div>
        ) : filtered.length === 0 ? (
          <div className="p-8 text-center text-xs text-slate-500 dark:text-slate-400">
            {copy.common.noResults}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-start border-collapse">
              <thead>
                <tr className="border-b border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/50 text-[11px] font-semibold text-slate-500 dark:text-slate-400">
                  <th className="py-2.5 px-4 text-start">{lang === 'ar' ? 'الخادم والمنصة' : 'Host & Platform'}</th>
                  <th className="py-2.5 px-3 text-start">{lang === 'ar' ? 'التصنيف وحالة الجمع' : 'Classification & Collection'}</th>
                  <th className="py-2.5 px-3 text-end">CPU</th>
                  <th className="py-2.5 px-3 text-end">RAM</th>
                  <th className="py-2.5 px-3 text-end">{lang === 'ar' ? 'القرص' : 'Disk'}</th>
                  <th className="py-2.5 px-3 text-end">{lang === 'ar' ? 'التشغيل' : 'Uptime'}</th>
                  <th className="py-2.5 px-3 text-end">{copy.common.lastCheck}</th>
                  <th className="py-2.5 px-4 text-end">{lang === 'ar' ? 'إجراءات' : 'Actions'}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800 text-xs">
                {filtered.map((srv) => {
                  const isSel = srv.id === selected?.id;
                  const isConfirmingDel = confirmDeleteId === srv.id;
                  const avail = srv.metricsAvailable;
                  return (
                    <tr
                      key={srv.id}
                      onClick={() => setSelectedId(srv.id)}
                      className={`cursor-pointer transition-colors ${
                        isSel
                          ? 'bg-blue-50/70 dark:bg-blue-950/30'
                          : 'hover:bg-slate-50 dark:hover:bg-slate-800/40'
                      }`}
                    >
                      <td className="py-3 px-4">
                        <div className="font-mono font-semibold text-slate-900 dark:text-slate-100">
                          {srv.hostname}
                        </div>
                        <div className="text-[11px] text-slate-500 dark:text-slate-400">
                          {srv.ipAddress} · {srv.site} · {getPlatformLabel(srv.platform, lang)} · {getEnvironmentLabel(srv.environment, lang)}
                        </div>
                      </td>
                      <td className="py-3 px-3">
                        <div className="flex flex-col gap-1 items-start">
                          <HealthClassificationBadge
                            classification={srv.healthClassification}
                            lang={lang}
                          />
                          <div className="flex flex-wrap items-center gap-1.5">
                            <AssetStatusBadge status={srv.status} label={copy.status[srv.status]} />
                            {srv.integrity && (
                              <CollectionStatusBadge status={srv.integrity.collectionStatus} lang={lang} />
                            )}
                          </div>
                        </div>
                      </td>
                      <td className="py-3 px-3 text-end font-mono tabular-nums text-slate-900 dark:text-slate-100">
                        <div>{fmtMetric(srv.cpuPct, avail?.cpu)}</div>
                        {srv.loadAverage && (
                          <div className="text-[10px] text-slate-500 dark:text-slate-400">
                            load {srv.loadAverage}
                          </div>
                        )}
                      </td>
                      <td className="py-3 px-3 text-end font-mono tabular-nums text-slate-900 dark:text-slate-100">
                        {fmtMetric(srv.ramPct, avail?.ram)}
                      </td>
                      <td className="py-3 px-3 text-end font-mono tabular-nums text-slate-900 dark:text-slate-100">
                        {avail?.disk === false
                          ? lang === 'ar'
                            ? 'غير متاح'
                            : 'Unavailable'
                          : srv.diskTotalGb > 0
                            ? `${srv.diskPct}% (${srv.diskAvailableGb} GB)`
                            : '—'}
                      </td>
                      <td className="py-3 px-3 text-end font-mono tabular-nums text-slate-700 dark:text-slate-300">
                        {avail?.uptime === false ? '—' : `${srv.uptimeHours}h`}
                      </td>
                      <td className="py-3 px-3 text-end font-mono tabular-nums text-slate-500 dark:text-slate-400">
                        <div>{srv.lastCheck.length > 11 ? srv.lastCheck.slice(11) : srv.lastCheck}</div>
                        {srv.lastSuccessfulCheck && (
                          <div className="text-[10px] text-emerald-700 dark:text-emerald-400">
                            ok {srv.lastSuccessfulCheck.length > 11 ? srv.lastSuccessfulCheck.slice(11) : srv.lastSuccessfulCheck}
                          </div>
                        )}
                      </td>
                      <td
                        className="py-3 px-4 text-end whitespace-nowrap"
                        onClick={(e) => e.stopPropagation()}
                      >
                        {isConfirmingDel ? (
                          <div className="inline-flex items-center gap-1.5">
                            <button
                              type="button"
                              disabled={!canModify}
                              onClick={() => handleDelete(srv)}
                              className="px-2 py-1 text-[11px] font-medium rounded bg-rose-600 hover:bg-rose-700 text-white disabled:opacity-50 cursor-pointer"
                            >
                              {lang === 'ar' ? 'تأكيد الحذف' : 'Confirm'}
                            </button>
                            <button
                              type="button"
                              onClick={() => setConfirmDeleteId(null)}
                              className="px-2 py-1 text-[11px] rounded border border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-300 cursor-pointer"
                            >
                              {copy.common.cancel}
                            </button>
                          </div>
                        ) : (
                          <div className="inline-flex items-center gap-1">
                            <button
                              type="button"
                              disabled={testingId === srv.id}
                              onClick={() => handleTestConnection(srv.id)}
                              title={lang === 'ar' ? 'اختبار الاتصال' : 'Test Connection'}
                              className="p-1.5 rounded text-slate-500 hover:text-emerald-600 hover:bg-emerald-50 dark:hover:bg-emerald-950/40 cursor-pointer"
                            >
                              <PlugZap className="w-3.5 h-3.5" />
                            </button>
                            <button
                              type="button"
                              onClick={() => startEdit(srv)}
                              title={lang === 'ar' ? 'تعديل' : 'Edit'}
                              className="p-1.5 rounded text-slate-500 hover:text-blue-600 hover:bg-blue-50 dark:hover:bg-blue-950/40 cursor-pointer"
                            >
                              <Pencil className="w-3.5 h-3.5" />
                            </button>
                            <button
                              type="button"
                              onClick={() => requestDelete(srv.id)}
                              title={lang === 'ar' ? 'حذف' : 'Delete'}
                              className="p-1.5 rounded text-slate-500 hover:text-rose-600 hover:bg-rose-50 dark:hover:bg-rose-950/40 cursor-pointer"
                            >
                              <Trash2 className="w-3.5 h-3.5" />
                            </button>
                          </div>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* Individual Server Detail & Historical Recharts Chart */}
      {selected && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
          <section className="lg:col-span-7 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-5 space-y-4">
            <div className="flex flex-wrap items-start justify-between gap-3 pb-4 border-b border-slate-100 dark:border-slate-800">
              <div className="space-y-1">
                <div className="flex flex-wrap items-center gap-2.5">
                  <h2 className="text-base font-semibold font-mono text-slate-900 dark:text-slate-100">
                    {selected.hostname}
                  </h2>
                  <HealthClassificationBadge
                    classification={selected.healthClassification}
                    lang={lang}
                  />
                </div>
                <p className="text-xs text-slate-500 dark:text-slate-400">
                  {selected.osVersion} · {selected.ipAddress} · {selected.site} ·{' '}
                  {getPlatformLabel(selected.platform, lang)} ·{' '}
                  {getEnvironmentLabel(selected.environment, lang)}
                  {selected.domainMembership ? ` · ${selected.domainMembership}` : ''}
                  {selected.parentHypervHost ? ` · Hyper-V: ${selected.parentHypervHost}` : ''}
                  {selected.cloudProvider ? ` · Cloud: ${selected.cloudProvider}` : ''}
                </p>
                {selected.notes && (
                  <p className="text-[11px] text-slate-500 dark:text-slate-400">{selected.notes}</p>
                )}
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <button
                  type="button"
                  disabled={testingId === selected.id}
                  onClick={() => handleTestConnection(selected.id)}
                  className="inline-flex items-center gap-1 px-2.5 py-1 text-xs rounded border border-emerald-200 dark:border-emerald-900 text-emerald-700 dark:text-emerald-300 hover:bg-emerald-50 dark:hover:bg-emerald-950/40 whitespace-nowrap cursor-pointer"
                >
                  <PlugZap className="w-3 h-3" />
                  <span>
                    {testingId === selected.id
                      ? lang === 'ar'
                        ? 'جاري الاختبار...'
                        : 'Testing...'
                      : lang === 'ar'
                        ? 'اختبار الاتصال'
                        : 'Test Connection'}
                  </span>
                </button>
                <button
                  type="button"
                  onClick={() => startEdit(selected)}
                  className="inline-flex items-center gap-1 px-2.5 py-1 text-xs rounded border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800 whitespace-nowrap cursor-pointer"
                >
                  <Pencil className="w-3 h-3" />
                  <span>{lang === 'ar' ? 'تعديل' : 'Edit'}</span>
                </button>
                {confirmDeleteId === selected.id ? (
                  <button
                    type="button"
                    onClick={() => handleDelete(selected)}
                    className="inline-flex items-center gap-1 px-2.5 py-1 text-xs font-medium rounded bg-rose-600 hover:bg-rose-700 text-white whitespace-nowrap cursor-pointer"
                  >
                    <span>{lang === 'ar' ? 'تأكيد الحذف' : 'Confirm Delete'}</span>
                  </button>
                ) : (
                  <button
                    type="button"
                    onClick={() => requestDelete(selected.id)}
                    className="inline-flex items-center gap-1 px-2.5 py-1 text-xs rounded border border-rose-200 dark:border-rose-900 text-rose-600 dark:text-rose-400 hover:bg-rose-50 dark:hover:bg-rose-950/40 whitespace-nowrap cursor-pointer"
                  >
                    <Trash2 className="w-3 h-3" />
                    <span>{lang === 'ar' ? 'حذف' : 'Delete'}</span>
                  </button>
                )}
                <AssetStatusBadge status={selected.status} label={copy.status[selected.status]} />
              </div>
            </div>

            <IntegrityBanner integrity={selected.integrity} lang={lang} />

            <div className="grid grid-cols-3 gap-4 py-3 border-b border-slate-100 dark:border-slate-800 text-xs">
              <div>
                <div className="text-slate-500 dark:text-slate-400">CPU</div>
                <div className="text-lg font-mono tabular-nums font-semibold text-slate-900 dark:text-slate-100 mt-0.5">
                  {fmtMetric(selected.cpuPct, selected.metricsAvailable?.cpu)}
                </div>
                {selected.loadAverage && (
                  <div className="text-[11px] font-mono text-slate-500 dark:text-slate-400">
                    Load: {selected.loadAverage}
                  </div>
                )}
              </div>
              <div>
                <div className="text-slate-500 dark:text-slate-400">
                  RAM {selected.ramTotalGb > 0 ? `(${selected.ramTotalGb} GB)` : ''}
                </div>
                <div className="text-lg font-mono tabular-nums font-semibold text-slate-900 dark:text-slate-100 mt-0.5">
                  {fmtMetric(selected.ramPct, selected.metricsAvailable?.ram)}
                </div>
              </div>
              <div>
                <div className="text-slate-500 dark:text-slate-400">
                  {lang === 'ar' ? 'المساحة المتاحة' : 'Disk Free / Total'}
                </div>
                <div className="text-lg font-mono tabular-nums font-semibold text-slate-900 dark:text-slate-100 mt-0.5">
                  {selected.metricsAvailable?.disk === false
                    ? lang === 'ar'
                      ? 'غير متاح'
                      : 'Unavailable'
                    : selected.diskTotalGb > 0
                      ? `${selected.diskAvailableGb} / ${selected.diskTotalGb} GB`
                      : '—'}
                </div>
              </div>
            </div>

            {/* Extended OS / Hyper-V VM / Policy Metadata */}
            {(selected.hypervVmState ||
              selected.hypervGuestOsHealth ||
              selected.runningProcessesCount !== undefined ||
              selected.eventErrors24h !== undefined ||
              (selected.iisDetectedSites && selected.iisDetectedSites.length > 0) ||
              selected.lastSuccessfulCheck) && (
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 text-xs pb-3 border-b border-slate-100 dark:border-slate-800">
                {selected.lastSuccessfulCheck && (
                  <div>
                    <div className="text-[11px] text-slate-500 dark:text-slate-400">
                      {lang === 'ar' ? 'آخر فحص ناجح' : 'Last Successful Check'}
                    </div>
                    <div className="font-mono tabular-nums text-slate-800 dark:text-slate-200 mt-0.5">
                      {selected.lastSuccessfulCheck}
                    </div>
                  </div>
                )}
                {selected.hypervVmState && (
                  <div>
                    <div className="text-[11px] text-slate-500 dark:text-slate-400">
                      {lang === 'ar' ? 'حالة VM التشغيلية (Hyper-V)' : 'VM Operational State'}
                    </div>
                    <div className="font-mono font-semibold text-slate-900 dark:text-slate-100 mt-0.5">
                      {selected.hypervVmState}
                    </div>
                  </div>
                )}
                {selected.hypervGuestOsHealth && (
                  <div>
                    <div className="text-[11px] text-slate-500 dark:text-slate-400">
                      {lang === 'ar' ? 'صحة نظام الضيف (Guest OS)' : 'Guest OS Health'}
                    </div>
                    <div className="font-mono text-slate-800 dark:text-slate-200 mt-0.5">
                      {selected.hypervGuestOsHealth}
                    </div>
                  </div>
                )}
                {selected.runningProcessesCount !== undefined && (
                  <div>
                    <div className="text-[11px] text-slate-500 dark:text-slate-400">
                      {lang === 'ar' ? 'العمليات النشطة' : 'Running Processes'}
                    </div>
                    <div className="font-mono tabular-nums text-slate-800 dark:text-slate-200 mt-0.5">
                      {selected.runningProcessesCount}
                    </div>
                  </div>
                )}
                {selected.eventErrors24h !== undefined && (
                  <div>
                    <div className="text-[11px] text-slate-500 dark:text-slate-400">
                      {lang === 'ar' ? 'أخطاء النظام (24 ساعة)' : 'System Event Errors (24h)'}
                    </div>
                    <div className="font-mono tabular-nums text-slate-800 dark:text-slate-200 mt-0.5">
                      {selected.eventErrors24h}
                    </div>
                  </div>
                )}
                {selected.iisDetectedSites && selected.iisDetectedSites.length > 0 && (
                  <div className="sm:col-span-3">
                    <div className="text-[11px] text-slate-500 dark:text-slate-400">
                      {lang === 'ar' ? 'مواقع IIS المكتشفة' : 'Detected IIS Sites'}
                    </div>
                    <div className="font-mono text-slate-800 dark:text-slate-200 mt-0.5">
                      {selected.iisDetectedSites.join(', ')}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Monitoring Capability Matrix */}
            {selected.capabilityMatrix && (
              <CapabilityMatrixPanel matrix={selected.capabilityMatrix} lang={lang} />
            )}

            {/* Hyper-V Host VM & Virtual Switch Inventory */}
            {selected.hypervDetails && (
              <div className="pt-3 border-t border-slate-100 dark:border-slate-800 space-y-3 text-xs">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-slate-800 dark:text-slate-200">
                    {lang === 'ar'
                      ? `مخزون مضيف Hyper-V (${selected.hypervDetails.vms.length} آلة افتراضية)`
                      : `Hyper-V Host Inventory (${selected.hypervDetails.vms.length} VMs)`}
                  </span>
                  <span className="font-mono text-[11px] text-slate-500 dark:text-slate-400">
                    {selected.hypervDetails.virtualSwitches.length}{' '}
                    {lang === 'ar' ? 'محول شبكة' : 'vSwitches'}
                  </span>
                </div>

                {selected.hypervDetails.virtualSwitches.length > 0 && (
                  <div className="text-[11px] font-mono text-slate-600 dark:text-slate-400">
                    {selected.hypervDetails.virtualSwitches
                      .map((sw) => `${sw.name} (${sw.switchType}${sw.netAdapter ? ` · ${sw.netAdapter}` : ''})`)
                      .join(' | ')}
                  </div>
                )}

                {selected.hypervDetails.vms.length > 0 && (
                  <div className="overflow-x-auto border border-slate-200 dark:border-slate-800 rounded">
                    <table className="w-full text-start border-collapse">
                      <thead>
                        <tr className="bg-slate-50 dark:bg-slate-800/50 border-b border-slate-200 dark:border-slate-800 text-[11px] text-slate-500 dark:text-slate-400">
                          <th className="py-1.5 px-2.5 text-start">VM</th>
                          <th className="py-1.5 px-2.5 text-start">{lang === 'ar' ? 'الحالة' : 'State'}</th>
                          <th className="py-1.5 px-2.5 text-end">CPU</th>
                          <th className="py-1.5 px-2.5 text-end">{lang === 'ar' ? 'الذاكرة' : 'RAM (MB)'}</th>
                          <th className="py-1.5 px-2.5 text-start">{lang === 'ar' ? 'المحول' : 'vSwitch'}</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-100 dark:divide-slate-800 text-[11px] font-mono">
                        {selected.hypervDetails.vms.map((vm) => (
                          <tr key={vm.name}>
                            <td className="py-1.5 px-2.5 font-semibold text-slate-900 dark:text-slate-100">
                              {vm.name}
                            </td>
                            <td className="py-1.5 px-2.5">
                              <span
                                className={
                                  vm.state === 'Running'
                                    ? 'text-emerald-700 dark:text-emerald-400'
                                    : 'text-slate-500 dark:text-slate-400'
                                }
                              >
                                {vm.state}
                              </span>
                            </td>
                            <td className="py-1.5 px-2.5 text-end tabular-nums">
                              {vm.cpuUsagePct !== null && vm.cpuUsagePct !== undefined ? `${vm.cpuUsagePct}%` : '—'}
                            </td>
                            <td className="py-1.5 px-2.5 text-end tabular-nums">
                              {vm.memoryAssignedMb ?? '—'}
                            </td>
                            <td className="py-1.5 px-2.5 text-slate-600 dark:text-slate-400">
                              {vm.switchNames?.join(', ') || '—'}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            )}

            <div className="pt-2">
              <div className="text-xs font-semibold text-slate-700 dark:text-slate-300 mb-3">
                {lang === 'ar' ? 'الأداء التاريخي الفعلي (CPU / RAM / القرص %)' : 'Actual Historical Telemetry (CPU / RAM / Disk %)'}
              </div>
              {selected.history.length === 0 ? (
                <div className="h-52 px-6 flex items-center justify-center text-center text-xs text-slate-500 dark:text-slate-400 border border-dashed border-slate-200 dark:border-slate-800 rounded leading-relaxed">
                  {lang === 'ar'
                    ? 'لا توجد قراءات أداء مسحوبة بعد. يتم تسجيل النقاط فقط عند توفر قياس فعلي بدون أي بيانات وهمية.'
                    : 'No telemetry points collected yet. Points are plotted exclusively from verified agentless measurements.'}
                </div>
              ) : (
                <div className="h-56 w-full" dir="ltr">
                  <ResponsiveContainer width="100%" height="100%">
                    <LineChart data={selected.history} margin={{ top: 5, right: 16, left: -14, bottom: 0 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#cbd5e1" strokeOpacity={0.35} />
                      <XAxis dataKey="time" tick={{ fontSize: 11, fill: '#64748b' }} />
                      <YAxis domain={[0, 100]} tick={{ fontSize: 11, fill: '#64748b' }} />
                      <Tooltip
                        contentStyle={{
                          backgroundColor: '#0f172a',
                          border: '1px solid #1e293b',
                          borderRadius: '6px',
                          color: '#f8fafc',
                          fontSize: '12px',
                        }}
                      />
                      <Line type="monotone" dataKey="cpuPct" name="CPU %" stroke="#2563eb" strokeWidth={2} dot={selected.history.length < 3 ? { r: 3 } : false} />
                      <Line type="monotone" dataKey="ramPct" name="RAM %" stroke="#0ea5e9" strokeWidth={2} dot={selected.history.length < 3 ? { r: 3 } : false} />
                      <Line type="monotone" dataKey="diskPct" name="Disk %" stroke="#f59e0b" strokeWidth={1.5} strokeDasharray="4 4" dot={selected.history.length < 3 ? { r: 3 } : false} />
                    </LineChart>
                  </ResponsiveContainer>
                </div>
              )}
            </div>

            {selected.networkInterfaces && selected.networkInterfaces.length > 0 && (
              <div className="pt-3 border-t border-slate-100 dark:border-slate-800">
                <div className="text-xs font-semibold text-slate-700 dark:text-slate-300 mb-2">
                  {lang === 'ar' ? 'حركة بطاقات الشبكة' : 'Network Interface Throughput'}
                </div>
                <div className="divide-y divide-slate-100 dark:divide-slate-800 text-xs">
                  {selected.networkInterfaces.map((nic) => (
                    <div key={nic.name} className="py-1.5 flex items-center justify-between gap-2">
                      <span className="font-mono text-slate-700 dark:text-slate-300 truncate">{nic.name}</span>
                      <span className="font-mono tabular-nums text-slate-900 dark:text-slate-100 whitespace-nowrap">
                        RX {nic.rxKbps} kbps · TX {nic.txKbps} kbps
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </section>

          {/* Services / Probed Ports */}
          <section className="lg:col-span-5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg overflow-hidden">
            <div className="px-5 py-4 border-b border-slate-100 dark:border-slate-800">
              <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                {selected.metricsAvailable?.services
                  ? lang === 'ar'
                    ? 'الخدمات والعمليات المراقَبة (قراءة فقط)'
                    : 'Monitored Services (Read-Only)'
                  : lang === 'ar'
                    ? 'منافذ الإدارة والخدمات المفحوصة (TCP / HTTP)'
                    : 'Probed Service & Management Endpoints'}
              </h3>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                {lang === 'ar'
                  ? 'مراقبة قراءة فقط (لا يتم إعادة التشغيل التلقائي لحماية التشغيل).'
                  : 'Read-only status tracking (automated restarts or target modifications disabled by policy).'}
              </p>
            </div>
            {selected.services.length === 0 ? (
              <div className="p-6 text-xs text-slate-500 dark:text-slate-400">
                {lang === 'ar' ? 'لا توجد خدمات أو منافذ مسجلة بعد.' : 'No services or ports probed yet.'}
              </div>
            ) : (
              <div className="divide-y divide-slate-100 dark:divide-slate-800">
                {selected.services.map((svc) => (
                  <div key={svc.name} className="px-5 py-3 flex items-center justify-between gap-3 text-xs">
                    <div>
                      <div className="font-mono font-semibold text-slate-900 dark:text-slate-100">
                        {svc.name}
                      </div>
                      <div className="text-slate-500 dark:text-slate-400 mt-0.5">{svc.displayName}</div>
                    </div>
                    <div className="text-end">
                      <span
                        className={`font-medium ${
                          svc.status === 'Running'
                            ? 'text-emerald-700 dark:text-emerald-400'
                            : 'text-rose-700 dark:text-rose-400'
                        }`}
                      >
                        {svc.status === 'Running' ? '● Running' : `✖ ${svc.status}`}
                      </span>
                      <div className="text-[11px] text-slate-400 mt-0.5">{svc.startupType}</div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </section>
        </div>
      )}
    </div>
  );
}
