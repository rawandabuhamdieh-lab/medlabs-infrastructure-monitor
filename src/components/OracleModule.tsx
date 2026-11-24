import { useState, type FormEvent } from 'react';
import { Activity, Cloud, FolderSearch, Pencil, Plus, PlugZap, Server, ShieldCheck, Trash2 } from 'lucide-react';
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
import type { TnsDiscoverySnapshot } from '../engine/oracle/oracleTypes';
import {
  ConnectionTestResult,
  CredentialProfileSummary,
  Language,
  OracleConnectorHealth,
  OracleDatabaseMetric,
  OracleScheduleConfig,
  UserRole,
} from '../types/infrastructure';
import {
  AssetStatusBadge,
  CollectionStatusBadge,
  ConnectorHealthCard,
  IntegrityBanner,
  MetricSourceChip,
} from './StatusGlyph';

export interface OracleTargetPayload {
  connectionType: 'tns' | 'direct';
  tnsAlias?: string;
  tnsAdminDir?: string;
  host: string;
  port: number;
  serviceName: string;
  protocol: 'TCP' | 'TCPS';
  walletDir?: string;
  role: 'Primary' | 'Read-Only Standby';
  credentialId?: string;
  connectTimeoutMs?: number;
  queryTimeoutMs?: number;
  collectRmanBackups?: boolean;
  ociConfig?: {
    enabled: boolean;
    region?: string;
    tenancyOcid?: string;
    compartmentOcid?: string;
    instanceOcid?: string;
    authMethod?: 'api-key' | 'instance-principal' | 'resource-principal' | 'proxy-url';
    credentialId?: string;
    collectIntervalSeconds?: number;
  };
  linuxConfig?: {
    enabled: boolean;
    host?: string;
    port?: number;
    credentialId?: string;
    collectIntervalSeconds?: number;
  };
  schedules?: OracleScheduleConfig;
}

interface OracleTestWithConnectors extends ConnectionTestResult {
  ociTest?: OracleConnectorHealth;
  linuxTest?: OracleConnectorHealth;
  dbTest?: OracleConnectorHealth;
}

interface OracleModuleProps {
  databases: OracleDatabaseMetric[];
  credentials: CredentialProfileSummary[];
  currentRole: UserRole | null;
  lang: Language;
  onRegisterOracle: (payload: OracleTargetPayload) => Promise<string | null>;
  onUpdateOracle: (id: string, payload: OracleTargetPayload) => Promise<string | null>;
  onDeleteOracle: (id: string) => Promise<string | null>;
  onTestOracle: (id: string) => Promise<{ result?: OracleTestWithConnectors; error?: string }>;
  onPollAllOracle: () => Promise<string | null>;
  onDiscoverTns: (customDir?: string) => Promise<{ data?: TnsDiscoverySnapshot; error?: string }>;
}

interface OracleFormState {
  connectionType: 'tns' | 'direct';
  tnsAlias: string;
  tnsAdminDir: string;
  host: string;
  port: string;
  serviceName: string;
  protocol: 'TCP' | 'TCPS';
  walletDir: string;
  role: 'Primary' | 'Read-Only Standby';
  credentialId: string;
  connectTimeoutMs: string;
  queryTimeoutMs: string;
  collectRmanBackups: boolean;
  ociEnabled: boolean;
  ociRegion: string;
  ociTenancyOcid: string;
  ociCompartmentOcid: string;
  ociInstanceOcid: string;
  ociAuthMethod: 'api-key' | 'instance-principal' | 'resource-principal' | 'proxy-url';
  ociCredentialId: string;
  linuxEnabled: boolean;
  linuxHost: string;
  linuxPort: string;
  linuxCredentialId: string;
  availabilitySec: string;
  sessionsPerfSec: string;
  memorySec: string;
  tablespaceSec: string;
  ociSec: string;
  linuxSec: string;
}

function makeInitialFormState(): OracleFormState {
  return {
    connectionType: 'tns',
    tnsAlias: '',
    tnsAdminDir: '',
    host: '',
    port: '1521',
    serviceName: '',
    protocol: 'TCP',
    walletDir: '',
    role: 'Primary',
    credentialId: '',
    connectTimeoutMs: '8000',
    queryTimeoutMs: '8000',
    collectRmanBackups: true,
    ociEnabled: true,
    ociRegion: 'me-jeddah-1',
    ociTenancyOcid: '',
    ociCompartmentOcid: '',
    ociInstanceOcid: '',
    ociAuthMethod: 'api-key',
    ociCredentialId: '',
    linuxEnabled: false,
    linuxHost: '',
    linuxPort: '22',
    linuxCredentialId: '',
    availabilitySec: '60',
    sessionsPerfSec: '60',
    memorySec: '120',
    tablespaceSec: '300',
    ociSec: '120',
    linuxSec: '60',
  };
}

function formStateFromTarget(db: OracleDatabaseMetric): OracleFormState {
  return {
    connectionType: db.connectionType ?? (db.tnsAlias ? 'tns' : 'direct'),
    tnsAlias: db.tnsAlias || '',
    tnsAdminDir: db.tnsAdminDir || '',
    host: db.host || '',
    port: String(db.port || 1521),
    serviceName: db.serviceName || '',
    protocol: db.protocol || 'TCP',
    walletDir: db.walletDir || '',
    role: db.role || 'Primary',
    credentialId: db.credentialId || '',
    connectTimeoutMs: String(db.connectTimeoutMs || 8000),
    queryTimeoutMs: String(db.queryTimeoutMs || 8000),
    collectRmanBackups: db.collectRmanBackups ?? true,
    ociEnabled: db.ociConfig?.enabled ?? false,
    ociRegion: db.ociConfig?.region || 'me-jeddah-1',
    ociTenancyOcid: db.ociConfig?.tenancyOcid || '',
    ociCompartmentOcid: db.ociConfig?.compartmentOcid || '',
    ociInstanceOcid: db.ociConfig?.instanceOcid || '',
    ociAuthMethod: db.ociConfig?.authMethod || 'api-key',
    ociCredentialId: db.ociConfig?.credentialId || '',
    linuxEnabled: db.linuxConfig?.enabled ?? false,
    linuxHost: db.linuxConfig?.host || db.host || '',
    linuxPort: String(db.linuxConfig?.port || 22),
    linuxCredentialId: db.linuxConfig?.credentialId || '',
    availabilitySec: String(db.schedules?.availabilitySec ?? 60),
    sessionsPerfSec: String(db.schedules?.sessionsPerfSec ?? 60),
    memorySec: String(db.schedules?.memorySec ?? 120),
    tablespaceSec: String(db.schedules?.tablespaceSec ?? 300),
    ociSec: String(db.schedules?.ociSec ?? db.ociConfig?.collectIntervalSeconds ?? 120),
    linuxSec: String(db.schedules?.linuxSec ?? db.linuxConfig?.collectIntervalSeconds ?? 60),
  };
}

function formatBytesUi(bytes: number | null | undefined): string {
  if (bytes === null || bytes === undefined || !Number.isFinite(bytes)) return 'Unavailable';
  if (bytes >= 1024 ** 3) return `${(bytes / 1024 ** 3).toFixed(2)} GB`;
  if (bytes >= 1024 ** 2) return `${(bytes / 1024 ** 2).toFixed(2)} MB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${Math.round(bytes)} B`;
}

export function OracleModule({
  databases,
  credentials,
  currentRole,
  lang,
  onRegisterOracle,
  onUpdateOracle,
  onDeleteOracle,
  onTestOracle,
  onPollAllOracle,
  onDiscoverTns,
}: OracleModuleProps) {
  const copy = COPY[lang];
  const [selectedId, setSelectedId] = useState<string>(databases[0]?.id ?? '');
  const primary = databases.find((d) => d.id === selectedId) ?? databases[0] ?? null;

  const [showAdd, setShowAdd] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [savingEdit, setSavingEdit] = useState(false);
  const [newForm, setNewForm] = useState<OracleFormState>(makeInitialFormState);
  const [editForm, setEditForm] = useState<OracleFormState>(makeInitialFormState);

  const [tnsDiscovery, setTnsDiscovery] = useState<TnsDiscoverySnapshot | null>(null);
  const [scanningTns, setScanningTns] = useState(false);
  const [feedback, setFeedback] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<OracleTestWithConnectors | null>(null);
  const [testingId, setTestingId] = useState<string | null>(null);
  const [polling, setPolling] = useState(false);

  const canModify =
    currentRole !== null && ['Administrator', 'IT Manager', 'IT Engineer'].includes(currentRole);
  const oracleCreds = credentials.filter((c) => c.kind === 'oracle');
  const ociCreds = credentials.filter((c) => c.kind === 'oci-api');
  const sshCreds = credentials.filter((c) => c.kind === 'linux-ssh');

  const toPayload = (f: OracleFormState): OracleTargetPayload => ({
    connectionType: f.connectionType,
    tnsAlias: f.tnsAlias.trim() || undefined,
    tnsAdminDir: f.tnsAdminDir.trim() || undefined,
    host: f.host.trim() || f.tnsAlias.trim(),
    port: Number(f.port) || 1521,
    serviceName: f.serviceName.trim() || f.tnsAlias.trim(),
    protocol: f.protocol,
    walletDir: f.walletDir.trim() || undefined,
    role: f.role,
    credentialId: f.credentialId || undefined,
    connectTimeoutMs: Number(f.connectTimeoutMs) || 8000,
    queryTimeoutMs: Number(f.queryTimeoutMs) || 8000,
    collectRmanBackups: f.collectRmanBackups,
    ociConfig: {
      enabled: f.ociEnabled,
      region: f.ociRegion.trim() || undefined,
      tenancyOcid: f.ociTenancyOcid.trim() || undefined,
      compartmentOcid: f.ociCompartmentOcid.trim() || undefined,
      instanceOcid: f.ociInstanceOcid.trim() || undefined,
      authMethod: f.ociAuthMethod,
      credentialId: f.ociCredentialId || undefined,
      collectIntervalSeconds: Number(f.ociSec) || 120,
    },
    linuxConfig: {
      enabled: f.linuxEnabled,
      host: f.linuxHost.trim() || f.host.trim() || undefined,
      port: Number(f.linuxPort) || 22,
      credentialId: f.linuxCredentialId || undefined,
      collectIntervalSeconds: Number(f.linuxSec) || 60,
    },
    schedules: {
      availabilitySec: Number(f.availabilitySec) || 60,
      sessionsPerfSec: Number(f.sessionsPerfSec) || 60,
      memorySec: Number(f.memorySec) || 120,
      tablespaceSec: Number(f.tablespaceSec) || 300,
      ociSec: Number(f.ociSec) || 120,
      linuxSec: Number(f.linuxSec) || 60,
    },
  });

  const handleScanTns = async (customDir?: string) => {
    setScanningTns(true);
    const { data, error } = await onDiscoverTns(customDir);
    setScanningTns(false);
    if (error) setFeedback(error);
    else if (data) setTnsDiscovery(data);
  };

  const handleRegister = async (e: FormEvent) => {
    e.preventDefault();
    setTestResult(null);
    const payload = toPayload(newForm);
    const err = await onRegisterOracle(payload);
    if (err) {
      setFeedback(err);
    } else {
      setFeedback(
        lang === 'ar'
          ? `تم تسجيل هدف Oracle (${payload.tnsAlias || `${payload.host}:${payload.port}/${payload.serviceName}`}) وفحص الموصّلات الثلاثة.`
          : `Registered Oracle target (${payload.tnsAlias || `${payload.host}:${payload.port}/${payload.serviceName}`}) and probed all enabled connectors.`
      );
      setNewForm(makeInitialFormState());
      setShowAdd(false);
    }
  };

  const handleSaveEdit = async (e: FormEvent) => {
    e.preventDefault();
    if (!editingId || savingEdit) return;
    setSavingEdit(true);
    setFeedback(null);
    setTestResult(null);
    const payload = toPayload(editForm);
    const err = await onUpdateOracle(editingId, payload);
    setSavingEdit(false);
    if (err) {
      setFeedback(err);
    } else {
      setFeedback(
        lang === 'ar'
          ? 'تم تحديث إعدادات هدف Oracle و OCI و Oracle Linux وإعادة الفحص.'
          : 'Updated Oracle / OCI / Oracle Linux configuration and re-polled.'
      );
      setEditingId(null);
    }
  };

  const handleTest = async (id: string) => {
    setTestingId(id);
    setTestResult(null);
    const { result, error } = await onTestOracle(id);
    setTestingId(null);
    if (error) setFeedback(error);
    else if (result) setTestResult(result);
  };

  const handlePollAll = async () => {
    setPolling(true);
    setTestResult(null);
    const err = await onPollAllOracle();
    setPolling(false);
    setFeedback(
      err ||
        (lang === 'ar'
          ? 'تم تحديث موصّلات OCI و Oracle Linux و Oracle SQL (قراءة فقط).'
          : 'Refreshed OCI Infrastructure, Oracle Linux OS, and Oracle SQL connectors.')
    );
  };

  const renderFormFields = (
    form: OracleFormState,
    setForm: (updater: (prev: OracleFormState) => OracleFormState) => void
  ) => (
    <div className="space-y-4">
      {/* TNS Discovery Strip */}
      <div className="p-3 rounded-md bg-slate-50 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800 space-y-2">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="text-[11px] text-slate-600 dark:text-slate-300">
            <span className="font-semibold">
              {lang === 'ar' ? 'اكتشاف TNS_ADMIN و Oracle Wallet (قراءة فقط): ' : 'Read-Only TNS_ADMIN & Wallet Discovery: '}
            </span>
            {lang === 'ar'
              ? 'لا يكتب أو يعدّل ملف tnsnames.ora أبداً.'
              : 'Never writes or modifies existing tnsnames.ora files.'}
          </div>
          <button
            type="button"
            disabled={scanningTns}
            onClick={() => handleScanTns(form.tnsAdminDir || undefined)}
            className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 text-[11px] font-medium hover:bg-slate-100 dark:hover:bg-slate-800 cursor-pointer"
          >
            <FolderSearch className="w-3.5 h-3.5" />
            <span>{scanningTns ? (lang === 'ar' ? 'جاري المسح...' : 'Scanning...') : lang === 'ar' ? 'مسح TNS_ADMIN' : 'Scan TNS_ADMIN'}</span>
          </button>
        </div>
        {tnsDiscovery && (
          <div className="space-y-1.5 text-[11px] font-mono">
            <div className="text-slate-500 dark:text-slate-400">
              Driver: Thin={String(tnsDiscovery.oracledbThinSupported)} · Thick={String(tnsDiscovery.oracledbThickInitialized)} · TNS_ADMIN={tnsDiscovery.tnsAdminEnv || 'unset'} · Dirs found: {tnsDiscovery.existingDirectories.length}
            </div>
            {tnsDiscovery.aliases.length > 0 ? (
              <div className="flex flex-wrap gap-1.5">
                {tnsDiscovery.aliases.map((a) => (
                  <button
                    key={a.alias}
                    type="button"
                    onClick={() =>
                      setForm((p) => ({
                        ...p,
                        connectionType: 'tns',
                        tnsAlias: a.alias,
                        host: a.host || p.host,
                        port: a.port ? String(a.port) : p.port,
                        serviceName: a.serviceName || p.serviceName,
                        protocol: a.protocol || p.protocol,
                      }))
                    }
                    className="px-2 py-0.5 rounded bg-blue-50 dark:bg-blue-950/50 border border-blue-200 dark:border-blue-800 text-blue-800 dark:text-blue-200 hover:bg-blue-100 cursor-pointer"
                  >
                    {a.alias} ({a.protocol || 'TCP'} {a.host || ''}:{a.port || 1521}/{a.serviceName || ''})
                  </button>
                ))}
              </div>
            ) : (
              <div className="text-amber-700 dark:text-amber-400">
                No tnsnames.ora aliases detected on central server; specify TNS_ADMIN directory or use Direct Host/Port.
              </div>
            )}
          </div>
        )}
      </div>

      {/* Section A: Oracle Database Connection */}
      <div className="space-y-2">
        <div className="text-[11px] font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">
          {lang === 'ar' ? '1. موصل Oracle Database (TNS أو Direct)' : '1. Oracle Database Connector (Existing TNS or Direct)'}
        </div>
        <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
          <select
            value={form.connectionType}
            onChange={(e) => setForm((p) => ({ ...p, connectionType: e.target.value as 'tns' | 'direct' }))}
            className="px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md"
          >
            <option value="tns">Existing Oracle TNS Alias</option>
            <option value="direct">Direct Host / Port / Service Name</option>
          </select>

          {form.connectionType === 'tns' ? (
            <>
              <input
                type="text"
                placeholder="TNS Alias (e.g. MEDLABS_OCI_PROD)"
                value={form.tnsAlias}
                onChange={(e) => setForm((p) => ({ ...p, tnsAlias: e.target.value }))}
                required
                className="px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md font-mono"
              />
              <input
                type="text"
                placeholder="TNS_ADMIN Directory (optional)"
                value={form.tnsAdminDir}
                onChange={(e) => setForm((p) => ({ ...p, tnsAdminDir: e.target.value }))}
                className="px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md font-mono"
              />
              <input
                type="text"
                placeholder="Service Name (display/override)"
                value={form.serviceName}
                onChange={(e) => setForm((p) => ({ ...p, serviceName: e.target.value }))}
                className="px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md font-mono"
              />
            </>
          ) : (
            <>
              <input
                type="text"
                placeholder="Host / IP (e.g. 10.0.10.25)"
                value={form.host}
                onChange={(e) => setForm((p) => ({ ...p, host: e.target.value }))}
                required
                className="px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md font-mono"
              />
              <input
                type="number"
                placeholder="Port (1521 or 2484)"
                value={form.port}
                onChange={(e) => setForm((p) => ({ ...p, port: e.target.value }))}
                required
                className="px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md font-mono"
              />
              <input
                type="text"
                placeholder="Service Name (e.g. ORCLPDB1)"
                value={form.serviceName}
                onChange={(e) => setForm((p) => ({ ...p, serviceName: e.target.value }))}
                required
                className="px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md font-mono"
              />
            </>
          )}

          <select
            value={form.protocol}
            onChange={(e) => setForm((p) => ({ ...p, protocol: e.target.value as 'TCP' | 'TCPS' }))}
            className="px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md"
          >
            <option value="TCP">TCP (Standard / Private VCN)</option>
            <option value="TCPS">TCPS (TLS + Oracle Wallet)</option>
          </select>

          <input
            type="text"
            placeholder="Oracle Wallet Dir (optional, e.g. /opt/oracle/wallet)"
            value={form.walletDir}
            onChange={(e) => setForm((p) => ({ ...p, walletDir: e.target.value }))}
            className="px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md font-mono"
          />

          <select
            value={form.role}
            onChange={(e) => setForm((p) => ({ ...p, role: e.target.value as 'Primary' | 'Read-Only Standby' }))}
            className="px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md"
          >
            <option value="Primary">Primary</option>
            <option value="Read-Only Standby">Read-Only Standby</option>
          </select>

          <select
            value={form.credentialId}
            onChange={(e) => setForm((p) => ({ ...p, credentialId: e.target.value }))}
            className="px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md"
          >
            <option value="">{lang === 'ar' ? '— حساب Oracle RO من الخزنة —' : '— Oracle RO Vault Credential —'}</option>
            {oracleCreds.map((c) => (
              <option key={c.id} value={c.id}>
                {c.name} ({c.username})
              </option>
            ))}
          </select>

          <input
            type="number"
            min={2000}
            max={30000}
            placeholder="Connect Timeout ms (8000)"
            value={form.connectTimeoutMs}
            onChange={(e) => setForm((p) => ({ ...p, connectTimeoutMs: e.target.value }))}
            className="px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md font-mono"
          />
          <input
            type="number"
            min={2000}
            max={30000}
            placeholder="Query Timeout ms (8000)"
            value={form.queryTimeoutMs}
            onChange={(e) => setForm((p) => ({ ...p, queryTimeoutMs: e.target.value }))}
            className="px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md font-mono"
          />
          <label className="md:col-span-2 inline-flex items-center gap-2 px-3 py-2 border border-slate-200 dark:border-slate-700 rounded-md">
            <input
              type="checkbox"
              checked={form.collectRmanBackups}
              onChange={(e) => setForm((p) => ({ ...p, collectRmanBackups: e.target.checked }))}
            />
            <span>{lang === 'ar' ? 'قراءة سجل نسخ RMAN (V$RMAN_BACKUP_JOB_DETAILS)' : 'Read RMAN backup jobs (V$RMAN_BACKUP_JOB_DETAILS)'}</span>
          </label>
        </div>
      </div>

      {/* Section B: OCI Infrastructure Connector */}
      <div className="pt-3 border-t border-slate-100 dark:border-slate-800 space-y-2">
        <label className="inline-flex items-center gap-2 text-[11px] font-semibold uppercase tracking-wide text-slate-600 dark:text-slate-300">
          <input
            type="checkbox"
            checked={form.ociEnabled}
            onChange={(e) => setForm((p) => ({ ...p, ociEnabled: e.target.checked }))}
          />
          <span>{lang === 'ar' ? '2. موصل Oracle Cloud Infrastructure (OCI API)' : '2. OCI Infrastructure Connector (Compute & Monitoring API)'}</span>
        </label>
        {form.ociEnabled && (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <input
              type="text"
              placeholder="OCI Region (e.g. me-jeddah-1)"
              value={form.ociRegion}
              onChange={(e) => setForm((p) => ({ ...p, ociRegion: e.target.value }))}
              className="px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md font-mono"
            />
            <input
              type="text"
              placeholder="Instance OCID (ocid1.instance.oc1..)"
              value={form.ociInstanceOcid}
              onChange={(e) => setForm((p) => ({ ...p, ociInstanceOcid: e.target.value }))}
              className="md:col-span-2 px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md font-mono"
            />
            <input
              type="text"
              placeholder="Compartment OCID (ocid1.compartment.oc1..)"
              value={form.ociCompartmentOcid}
              onChange={(e) => setForm((p) => ({ ...p, ociCompartmentOcid: e.target.value }))}
              className="px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md font-mono"
            />
            <input
              type="text"
              placeholder="Tenancy OCID (optional override)"
              value={form.ociTenancyOcid}
              onChange={(e) => setForm((p) => ({ ...p, ociTenancyOcid: e.target.value }))}
              className="px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md font-mono"
            />
            <select
              value={form.ociCredentialId}
              onChange={(e) => setForm((p) => ({ ...p, ociCredentialId: e.target.value }))}
              className="px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md"
            >
              <option value="">{lang === 'ar' ? '— ملف اعتماد OCI من الخزنة —' : '— OCI API Vault Profile —'}</option>
              {ociCreds.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.name} ({c.ociRegion || c.ociAuthType || 'oci-api'})
                </option>
              ))}
            </select>
          </div>
        )}
      </div>

      {/* Section C: Oracle Linux OS SSH Connector */}
      <div className="pt-3 border-t border-slate-100 dark:border-slate-800 space-y-2">
        <label className="inline-flex items-center gap-2 text-[11px] font-semibold uppercase tracking-wide text-slate-600 dark:text-slate-300">
          <input
            type="checkbox"
            checked={form.linuxEnabled}
            onChange={(e) => setForm((p) => ({ ...p, linuxEnabled: e.target.checked }))}
          />
          <span>{lang === 'ar' ? '3. موصل Oracle Linux OS (SSH للقراءة فقط عند التصريح)' : '3. Oracle Linux OS Connector (Read-Only SSH if Authorized)'}</span>
        </label>
        {form.linuxEnabled && (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <input
              type="text"
              placeholder="SSH Host / IP (defaults to DB host)"
              value={form.linuxHost}
              onChange={(e) => setForm((p) => ({ ...p, linuxHost: e.target.value }))}
              className="px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md font-mono"
            />
            <input
              type="number"
              min={1}
              max={65535}
              placeholder="SSH Port (22)"
              value={form.linuxPort}
              onChange={(e) => setForm((p) => ({ ...p, linuxPort: e.target.value }))}
              className="px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md font-mono"
            />
            <select
              value={form.linuxCredentialId}
              onChange={(e) => setForm((p) => ({ ...p, linuxCredentialId: e.target.value }))}
              className="px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md"
            >
              <option value="">{lang === 'ar' ? '— حساب SSH للقراءة فقط —' : '— SSH Read-Only Credential —'}</option>
              {sshCreds.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.name} ({c.username})
                </option>
              ))}
            </select>
          </div>
        )}
      </div>

      {/* Section D: Cadence Schedule Intervals */}
      <div className="pt-3 border-t border-slate-100 dark:border-slate-800 grid grid-cols-2 sm:grid-cols-6 gap-2 text-[11px]">
        <label className="space-y-1">
          <span className="text-slate-500">DB Avail (s)</span>
          <input type="number" min={15} max={3600} value={form.availabilitySec} onChange={(e) => setForm((p) => ({ ...p, availabilitySec: e.target.value }))} className="w-full px-2 py-1 border border-slate-200 dark:border-slate-700 rounded bg-white dark:bg-slate-950 font-mono" />
        </label>
        <label className="space-y-1">
          <span className="text-slate-500">Sessions/Wait (s)</span>
          <input type="number" min={15} max={3600} value={form.sessionsPerfSec} onChange={(e) => setForm((p) => ({ ...p, sessionsPerfSec: e.target.value }))} className="w-full px-2 py-1 border border-slate-200 dark:border-slate-700 rounded bg-white dark:bg-slate-950 font-mono" />
        </label>
        <label className="space-y-1">
          <span className="text-slate-500">SGA/PGA (s)</span>
          <input type="number" min={30} max={3600} value={form.memorySec} onChange={(e) => setForm((p) => ({ ...p, memorySec: e.target.value }))} className="w-full px-2 py-1 border border-slate-200 dark:border-slate-700 rounded bg-white dark:bg-slate-950 font-mono" />
        </label>
        <label className="space-y-1">
          <span className="text-slate-500">Tablespaces (s)</span>
          <input type="number" min={60} max={86400} value={form.tablespaceSec} onChange={(e) => setForm((p) => ({ ...p, tablespaceSec: e.target.value }))} className="w-full px-2 py-1 border border-slate-200 dark:border-slate-700 rounded bg-white dark:bg-slate-950 font-mono" />
        </label>
        <label className="space-y-1">
          <span className="text-slate-500">OCI API (s)</span>
          <input type="number" min={30} max={3600} value={form.ociSec} onChange={(e) => setForm((p) => ({ ...p, ociSec: e.target.value }))} className="w-full px-2 py-1 border border-slate-200 dark:border-slate-700 rounded bg-white dark:bg-slate-950 font-mono" />
        </label>
        <label className="space-y-1">
          <span className="text-slate-500">Linux SSH (s)</span>
          <input type="number" min={15} max={3600} value={form.linuxSec} onChange={(e) => setForm((p) => ({ ...p, linuxSec: e.target.value }))} className="w-full px-2 py-1 border border-slate-200 dark:border-slate-700 rounded bg-white dark:bg-slate-950 font-mono" />
        </label>
      </div>
    </div>
  );

  return (
    <div className="space-y-6">
      <div className="flex flex-col xl:flex-row xl:items-center xl:justify-between gap-4 pb-4 border-b border-slate-200 dark:border-slate-800">
        <div>
          <h1 className="text-xl font-semibold text-slate-900 dark:text-slate-100">
            {lang === 'ar'
              ? 'منصة مراقبة سحابة أوراكل (OCI + Oracle Linux + Oracle DB)'
              : 'Oracle Cloud Infrastructure, Oracle Linux & Database Dashboard'}
          </h1>
          <p className="text-sm text-slate-600 dark:text-slate-400 mt-1">
            {lang === 'ar'
              ? 'ثلاثة موصّلات مستقلة بدون وكلاء: OCI Cloud API، و Oracle Linux SSH، و Oracle SQL (SELECT فقط عبر TNS أو Direct/TCPS).'
              : 'Three independent agentless connectors: OCI Monitoring API, Oracle Linux SSH, and SELECT-only Oracle SQL via existing TNS or TCPS/Direct.'}
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          <div className="inline-flex items-center gap-2 px-3 py-1.5 bg-blue-50 dark:bg-blue-950/40 border border-blue-200 dark:border-blue-900 rounded-md text-xs text-blue-900 dark:text-blue-200">
            <ShieldCheck className="w-4 h-4 shrink-0" />
            <span>{lang === 'ar' ? 'SELECT فقط · بدون تعديل TNS' : 'SELECT-Only · Read-Only TNS'}</span>
          </div>
          {databases.length > 0 && (
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
            onClick={() => {
              setEditingId(null);
              setShowAdd((p) => !p);
            }}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-blue-600 hover:bg-blue-700 text-white rounded-md cursor-pointer"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>{lang === 'ar' ? 'ربط هدف Oracle / OCI' : 'Register Oracle / OCI Target'}</span>
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
          className={`p-3.5 rounded-md border text-xs space-y-2.5 ${
            testResult.ok
              ? 'bg-emerald-50 dark:bg-emerald-950/30 border-emerald-200 dark:border-emerald-900 text-emerald-900 dark:text-emerald-200'
              : 'bg-amber-50 dark:bg-amber-950/30 border-amber-200 dark:border-amber-900 text-amber-950 dark:text-amber-200'
          }`}
        >
          <div className="flex items-center justify-between">
            <CollectionStatusBadge status={testResult.status} lang={lang} />
            <span className="font-mono text-[11px]">
              {testResult.latencyMs !== null ? `${testResult.latencyMs}ms · ` : ''}
              {testResult.measuredAt}
            </span>
          </div>
          <div className="font-mono text-[11px]">{testResult.details}</div>
          {(testResult.ociTest || testResult.linuxTest || testResult.dbTest) && (
            <div className="grid grid-cols-1 md:grid-cols-3 gap-2.5 pt-1">
              {testResult.ociTest && <ConnectorHealthCard connector={testResult.ociTest} lang={lang} />}
              {testResult.linuxTest && <ConnectorHealthCard connector={testResult.linuxTest} lang={lang} />}
              {testResult.dbTest && <ConnectorHealthCard connector={testResult.dbTest} lang={lang} />}
            </div>
          )}
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
          onSubmit={handleRegister}
          className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-5 space-y-4 text-xs"
        >
          <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
            {lang === 'ar'
              ? 'تسجيل هدف Oracle Cloud VM (OCI + Oracle Linux + Oracle DB)'
              : 'Register Oracle Cloud VM / Database Target'}
          </h2>
          {renderFormFields(newForm, setNewForm)}
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
              disabled={!canModify || savingEdit}
              className="px-4 py-1.5 rounded bg-blue-600 text-white hover:bg-blue-700 disabled:opacity-50 cursor-pointer"
            >
              {canModify ? copy.common.save : lang === 'ar' ? 'يتطلب تسجيل الدخول' : 'Sign in as Engineer+'}
            </button>
          </div>
        </form>
      )}

      {editingId && (
        <form
          onSubmit={handleSaveEdit}
          className="bg-white dark:bg-slate-900 border border-blue-200 dark:border-blue-900 rounded-lg p-5 space-y-4 text-xs"
        >
          <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
            {lang === 'ar' ? 'تعديل إعدادات هدف Oracle / OCI' : 'Edit Oracle / OCI Target Configuration'}
          </h2>
          {renderFormFields(editForm, setEditForm)}
          <div className="flex justify-end gap-2">
            <button
              type="button"
              onClick={() => { setEditingId(null); setFeedback(null); }}
              className="px-3 py-1.5 rounded border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300 cursor-pointer"
            >
              {copy.common.cancel}
            </button>
            <button
              type="submit"
              disabled={!canModify || savingEdit}
              className="px-4 py-1.5 rounded bg-blue-600 text-white hover:bg-blue-700 disabled:opacity-50 cursor-pointer"
            >
              {copy.common.save}
            </button>
          </div>
        </form>
      )}

      {!primary ? (
        <section className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-8 text-center space-y-2">
          <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
            {lang === 'ar' ? 'لا توجد قاعدة بيانات Oracle مسجلة بعد' : 'No Oracle / OCI Targets Configured Yet'}
          </h2>
          <p className="text-xs text-slate-600 dark:text-slate-400 max-w-xl mx-auto leading-relaxed">
            {lang === 'ar'
              ? 'أضف حساب Oracle RO (SELECT فقط) أو ملف OCI API في «خزنة بيانات الاعتماد»، ثم اضغط «ربط هدف Oracle / OCI» للاتصال عبر TNS الموجود أو Host/TCPS.'
              : 'Save an encrypted Oracle RO / OCI API / SSH profile in Collectors & Vault, then register your existing TNS Alias or Direct host here.'}
          </p>
        </section>
      ) : (
        <>
          {/* Target Selector Cards */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {databases.map((db) => (
              <section
                key={db.id}
                onClick={() => setSelectedId(db.id)}
                className={`bg-white dark:bg-slate-900 border rounded-lg p-5 cursor-pointer transition-colors ${
                  db.id === primary.id
                    ? 'border-blue-500'
                    : 'border-slate-200 dark:border-slate-800 hover:border-slate-300'
                }`}
              >
                <div className="flex items-start justify-between gap-3 pb-3 border-b border-slate-100 dark:border-slate-800">
                  <div>
                    <div className="flex flex-wrap items-center gap-1.5 text-xs font-mono text-slate-500 dark:text-slate-400">
                      <span>{db.role}</span>
                      <span>·</span>
                      <span>{db.tnsAlias ? `TNS:${db.tnsAlias}` : `${db.host}:${db.port || 1521}`}</span>
                      {db.protocol === 'TCPS' && <MetricSourceChip source="TCPS" />}
                      {db.dbVersion && <MetricSourceChip source={`v${db.dbVersion}`} />}
                    </div>
                    <h2 className="text-base font-semibold font-mono text-slate-900 dark:text-slate-100 mt-0.5">
                      {db.serviceName}
                      {db.instanceName && db.instanceName !== db.serviceName ? ` (${db.instanceName})` : ''}
                    </h2>
                  </div>
                  <div className="flex items-center gap-1.5" onClick={(e) => e.stopPropagation()}>
                    <button
                      type="button"
                      disabled={!canModify || testingId === db.id}
                      onClick={() => handleTest(db.id)}
                      title={lang === 'ar' ? 'اختبار الموصّلات الثلاثة' : 'Test All 3 Connectors'}
                      className="p-1.5 rounded border border-slate-200 dark:border-slate-700 text-emerald-600 hover:bg-emerald-50 dark:hover:bg-emerald-950/30 disabled:opacity-40 cursor-pointer"
                    >
                      <PlugZap className="w-3.5 h-3.5" />
                    </button>
                    <button
                      type="button"
                      disabled={!canModify}
                      onClick={() => {
                        setShowAdd(false);
                        setEditingId(db.id);
                        setEditForm(formStateFromTarget(db));
                      }}
                      title={lang === 'ar' ? 'تعديل' : 'Edit'}
                      className="p-1.5 rounded border border-slate-200 dark:border-slate-700 text-blue-600 hover:bg-blue-50 dark:hover:bg-blue-950/30 disabled:opacity-40 cursor-pointer"
                    >
                      <Pencil className="w-3.5 h-3.5" />
                    </button>
                    <button
                      type="button"
                      disabled={!canModify}
                      onClick={() => onDeleteOracle(db.id)}
                      title={lang === 'ar' ? 'حذف' : 'Delete'}
                      className="p-1.5 rounded border border-slate-200 dark:border-slate-700 text-rose-600 hover:bg-rose-50 dark:hover:bg-rose-950/30 disabled:opacity-40 cursor-pointer"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                    <AssetStatusBadge status={db.status} label={copy.status[db.status]} />
                  </div>
                </div>

                <div className="mt-3">
                  <IntegrityBanner integrity={db.integrity} lang={lang} />
                </div>

                <div className="grid grid-cols-3 sm:grid-cols-6 gap-3 mt-4 text-xs">
                  <div>
                    <div className="text-slate-500 dark:text-slate-400">{lang === 'ar' ? 'التوفر' : 'Avail.'}</div>
                    <div className="font-mono tabular-nums font-semibold text-slate-900 dark:text-slate-100 mt-0.5">
                      {db.availabilityPct}%
                    </div>
                  </div>
                  <div>
                    <div className="text-slate-500 dark:text-slate-400">{lang === 'ar' ? 'الاستجابة' : 'RTT'}</div>
                    <div className="font-mono tabular-nums font-semibold text-slate-900 dark:text-slate-100 mt-0.5">
                      {db.responseTimeMs > 0 ? `${db.responseTimeMs} ms` : '—'}
                    </div>
                  </div>
                  <div>
                    <div className="text-slate-500 dark:text-slate-400">{lang === 'ar' ? 'نشطة' : 'Active'}</div>
                    <div className="font-mono tabular-nums font-semibold text-slate-900 dark:text-slate-100 mt-0.5">
                      {db.activeSessions}
                    </div>
                  </div>
                  <div>
                    <div className="text-slate-500 dark:text-slate-400">{lang === 'ar' ? 'الإجمالي' : 'Total'}</div>
                    <div className="font-mono tabular-nums font-semibold text-slate-900 dark:text-slate-100 mt-0.5">
                      {db.totalSessions ?? db.activeSessions}
                    </div>
                  </div>
                  <div>
                    <div className="text-slate-500 dark:text-slate-400">{lang === 'ar' ? 'حاجبة' : 'Blocking'}</div>
                    <div
                      className={`font-mono tabular-nums font-semibold mt-0.5 ${
                        db.blockingSessions > 0
                          ? 'text-rose-700 dark:text-rose-400'
                          : 'text-emerald-700 dark:text-emerald-400'
                      }`}
                    >
                      {db.blockingSessions}
                    </div>
                  </div>
                  <div>
                    <div className="text-slate-500 dark:text-slate-400">{lang === 'ar' ? 'الحجم' : 'DB Size'}</div>
                    <div className="font-mono tabular-nums font-semibold text-slate-900 dark:text-slate-100 mt-0.5">
                      {db.dbSizeGb ? `${db.dbSizeGb} GB` : '—'}
                    </div>
                  </div>
                </div>

                <div className="mt-4 pt-3 border-t border-slate-100 dark:border-slate-800 flex flex-wrap gap-3 text-xs font-mono tabular-nums text-slate-500 dark:text-slate-400">
                  <span>Open: {db.openMode || '—'}</span>
                  <span>SGA: {db.sgaUsedPct}%</span>
                  <span>PGA: {db.pgaUsedMb.toLocaleString()} MB</span>
                  <span>{copy.common.lastCheck}: {db.lastCheck}</span>
                </div>
              </section>
            ))}
          </div>

          {/* 3 Independent Connector Health Cards */}
          {(primary.ociConnector || primary.linuxConnector || primary.dbConnector) && (
            <section className="space-y-2">
              <div className="text-xs font-semibold text-slate-700 dark:text-slate-300">
                {lang === 'ar'
                  ? 'حالة الموصّلات الثلاثة المستقلة (فشل أحدها لا يعطّل الآخرين)'
                  : 'Three Independent Connectors Health Status (Isolated Fault Domains)'}
              </div>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {primary.ociConnector && <ConnectorHealthCard connector={primary.ociConnector} lang={lang} />}
                {primary.linuxConnector && <ConnectorHealthCard connector={primary.linuxConnector} lang={lang} />}
                {primary.dbConnector && <ConnectorHealthCard connector={primary.dbConnector} lang={lang} />}
              </div>
            </section>
          )}

          {/* Panel A & Panel B: OCI Cloud Telemetry + Oracle Linux OS Telemetry */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
            {/* Panel A: OCI Cloud Metrics */}
            <section className="lg:col-span-5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-5 space-y-4">
              <div className="flex items-center justify-between gap-2 pb-3 border-b border-slate-100 dark:border-slate-800">
                <div className="flex items-center gap-2">
                  <Cloud className="w-4 h-4 text-blue-600" />
                  <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                    {lang === 'ar' ? 'مؤشرات السحابة (OCI Compute & Monitoring)' : 'OCI Cloud VM Metrics'}
                  </h2>
                </div>
                <MetricSourceChip source="OCI API" />
              </div>

              {!primary.ociMetrics ? (
                <div className="text-xs text-slate-500 dark:text-slate-400">
                  {primary.ociConnector?.errorDetail ||
                    (lang === 'ar'
                      ? 'موصل OCI غير مُفعّل أو بانتظار أول قراءة ناجحة.'
                      : 'OCI connector not configured or awaiting first telemetry sweep.')}
                </div>
              ) : (
                <div className="space-y-3 text-xs">
                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <div className="text-slate-500">Lifecycle State</div>
                      <div className="font-mono font-semibold text-slate-900 dark:text-slate-100 mt-0.5">
                        {primary.ociMetrics.lifecycleState || 'Unavailable'}
                      </div>
                    </div>
                    <div>
                      <div className="text-slate-500">Shape / AD</div>
                      <div className="font-mono text-slate-900 dark:text-slate-100 mt-0.5 truncate" title={`${primary.ociMetrics.shape || ''} · ${primary.ociMetrics.availabilityDomain || ''}`}>
                        {primary.ociMetrics.shape || '—'}
                      </div>
                    </div>
                    <div>
                      <div className="text-slate-500">CPU Utilization</div>
                      <div className="font-mono tabular-nums font-semibold text-slate-900 dark:text-slate-100 mt-0.5">
                        {primary.ociMetrics.cpuUtilizationPct !== null && primary.ociMetrics.cpuUtilizationPct !== undefined
                          ? `${primary.ociMetrics.cpuUtilizationPct}%`
                          : 'Unavailable'}
                      </div>
                    </div>
                    <div>
                      <div className="text-slate-500">Memory Utilization</div>
                      <div className="font-mono tabular-nums text-slate-900 dark:text-slate-100 mt-0.5">
                        {primary.ociMetrics.memoryUtilizationPct !== null && primary.ociMetrics.memoryUtilizationPct !== undefined
                          ? `${primary.ociMetrics.memoryUtilizationPct}%`
                          : 'Unavailable (No Agent)'}
                      </div>
                    </div>
                    <div>
                      <div className="text-slate-500">Disk Read / Write</div>
                      <div className="font-mono tabular-nums text-slate-900 dark:text-slate-100 mt-0.5">
                        {formatBytesUi(primary.ociMetrics.diskBytesRead)} / {formatBytesUi(primary.ociMetrics.diskBytesWritten)}
                      </div>
                    </div>
                    <div>
                      <div className="text-slate-500">Disk IOPS (R / W)</div>
                      <div className="font-mono tabular-nums text-slate-900 dark:text-slate-100 mt-0.5">
                        {primary.ociMetrics.diskIopsRead ?? '—'} / {primary.ociMetrics.diskIopsWrite ?? '—'}
                      </div>
                    </div>
                    <div>
                      <div className="text-slate-500">Network In / Out</div>
                      <div className="font-mono tabular-nums text-slate-900 dark:text-slate-100 mt-0.5">
                        {formatBytesUi(primary.ociMetrics.networkBytesIn)} / {formatBytesUi(primary.ociMetrics.networkBytesOut)}
                      </div>
                    </div>
                    <div>
                      <div className="text-slate-500">OCI Load Avg</div>
                      <div className="font-mono tabular-nums text-slate-900 dark:text-slate-100 mt-0.5">
                        {primary.ociMetrics.loadAverage ?? 'Unavailable'}
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </section>

            {/* Panel B: Oracle Linux OS Metrics */}
            <section className="lg:col-span-7 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-5 space-y-4">
              <div className="flex items-center justify-between gap-2 pb-3 border-b border-slate-100 dark:border-slate-800">
                <div className="flex items-center gap-2">
                  <Server className="w-4 h-4 text-emerald-600" />
                  <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                    {lang === 'ar' ? 'نظام التشغيل Oracle Linux' : 'Oracle Linux OS Telemetry'}
                  </h2>
                </div>
                <MetricSourceChip source={primary.linuxMetrics?.source || primary.linuxConnector?.source || 'SSH'} />
              </div>

              {!primary.linuxMetrics ? (
                <div className="text-xs text-slate-500 dark:text-slate-400">
                  {primary.linuxConnector?.errorDetail ||
                    (lang === 'ar'
                      ? 'موصل SSH غير مُفعّل لهذا الخادم — يتم الاعتماد على مؤشرات OCI و Oracle SQL.'
                      : 'SSH OS connector is disabled or unreachable; using OCI / Oracle SQL telemetry.')}
                </div>
              ) : (
                <div className="space-y-4 text-xs">
                  {primary.linuxMetrics.fallbackFromOci && (
                    <div className="p-2 rounded bg-amber-50 dark:bg-amber-950/30 border border-amber-200 dark:border-amber-900 text-[11px] text-amber-900 dark:text-amber-200">
                      {lang === 'ar'
                        ? 'ملاحظة: تعذّر SSH؛ القراءات أدناه مأخوذة كبديل من موصّل OCI API.'
                        : 'Notice: SSH unavailable — CPU/Load values shown below are labeled fallback from OCI API.'}
                    </div>
                  )}

                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                    <div>
                      <div className="text-slate-500">OS / Kernel</div>
                      <div className="font-mono text-slate-900 dark:text-slate-100 mt-0.5 truncate" title={`${primary.linuxMetrics.osVersion || ''} ${primary.linuxMetrics.kernelVersion || ''}`}>
                        {primary.linuxMetrics.osVersion || 'Oracle Linux'}
                      </div>
                      {primary.linuxMetrics.kernelVersion && (
                        <div className="font-mono text-[10px] text-slate-500 truncate">{primary.linuxMetrics.kernelVersion}</div>
                      )}
                    </div>
                    <div>
                      <div className="text-slate-500">CPU / Load</div>
                      <div className="font-mono tabular-nums font-semibold text-slate-900 dark:text-slate-100 mt-0.5">
                        {primary.linuxMetrics.cpuPct !== null && primary.linuxMetrics.cpuPct !== undefined
                          ? `${primary.linuxMetrics.cpuPct}%`
                          : 'Unavailable'}
                        {primary.linuxMetrics.cpuCores ? ` (${primary.linuxMetrics.cpuCores}c)` : ''}
                      </div>
                      <div className="font-mono text-[10px] text-slate-500">{primary.linuxMetrics.loadAverage || '—'}</div>
                    </div>
                    <div>
                      <div className="text-slate-500">Memory / Swap</div>
                      <div className="font-mono tabular-nums font-semibold text-slate-900 dark:text-slate-100 mt-0.5">
                        {primary.linuxMetrics.ramPct !== null && primary.linuxMetrics.ramPct !== undefined
                          ? `${primary.linuxMetrics.ramPct}% (${primary.linuxMetrics.ramUsedGb}/${primary.linuxMetrics.ramTotalGb} GB)`
                          : 'Unavailable'}
                      </div>
                      {primary.linuxMetrics.swapTotalGb !== null && primary.linuxMetrics.swapTotalGb !== undefined && (
                        <div className="font-mono text-[10px] text-slate-500">
                          Swap: {primary.linuxMetrics.swapUsedGb ?? 0}/{primary.linuxMetrics.swapTotalGb} GB
                        </div>
                      )}
                    </div>
                    <div>
                      <div className="text-slate-500">Uptime / Procs</div>
                      <div className="font-mono tabular-nums text-slate-900 dark:text-slate-100 mt-0.5">
                        {primary.linuxMetrics.uptimeHours !== null && primary.linuxMetrics.uptimeHours !== undefined
                          ? `${primary.linuxMetrics.uptimeHours}h`
                          : 'Unavailable'}
                        {primary.linuxMetrics.processCount ? ` · ${primary.linuxMetrics.processCount} procs` : ''}
                      </div>
                    </div>
                  </div>

                  {primary.linuxMetrics.filesystems.length > 0 && (
                    <div className="overflow-x-auto border border-slate-200 dark:border-slate-800 rounded">
                      <table className="w-full text-start border-collapse text-[11px] font-mono">
                        <thead>
                          <tr className="bg-slate-50 dark:bg-slate-800/50 border-b border-slate-200 dark:border-slate-800 text-slate-500">
                            <th className="py-1.5 px-2.5 text-start">Mount</th>
                            <th className="py-1.5 px-2.5 text-end">Used / Total</th>
                            <th className="py-1.5 px-2.5 text-end">Avail</th>
                            <th className="py-1.5 px-2.5 text-end">Use %</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                          {primary.linuxMetrics.filesystems.slice(0, 6).map((fs) => (
                            <tr key={fs.mountPoint}>
                              <td className="py-1.5 px-2.5 font-semibold text-slate-800 dark:text-slate-200">{fs.mountPoint}</td>
                              <td className="py-1.5 px-2.5 text-end tabular-nums">{fs.usedGb} / {fs.totalGb} GB</td>
                              <td className="py-1.5 px-2.5 text-end tabular-nums">{fs.availableGb} GB</td>
                              <td className={`py-1.5 px-2.5 text-end tabular-nums font-semibold ${fs.usedPct >= 85 ? 'text-rose-600' : ''}`}>
                                {fs.usedPct}%
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}

                  {primary.linuxMetrics.networkInterfaces.length > 0 && (
                    <div className="flex flex-wrap gap-2 text-[11px] font-mono">
                      {primary.linuxMetrics.networkInterfaces.map((nic) => (
                        <div key={nic.name} className="px-2.5 py-1 rounded border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/40">
                          <span className="font-semibold">{nic.name}</span> ({nic.state || 'up'}) · RX {nic.rxKbps} / TX {nic.txKbps} kbps
                          {nic.rxErrors || nic.txErrors ? ` · err:${(nic.rxErrors || 0) + (nic.txErrors || 0)}` : ''}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </section>
          </div>

          {/* Panel C: Oracle Database Deep Telemetry (Tablespaces, FRA, Sessions, Response Chart) */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
            <section className="lg:col-span-6 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-5 space-y-4">
              <div className="flex items-center justify-between">
                <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                  {lang === 'ar' ? 'مساحات الجداول، FRA والملفات' : 'Tablespaces, Datafiles, Temp & FRA'}
                </h2>
                <MetricSourceChip source="Oracle SQL" />
              </div>

              {primary.missingPermissions && primary.missingPermissions.length > 0 && (
                <div className="p-2.5 rounded border border-amber-200 dark:border-amber-900 bg-amber-50/60 dark:bg-amber-950/20 text-[11px] text-amber-900 dark:text-amber-200">
                  <div className="font-semibold">
                    {lang === 'ar' ? 'صلاحيات Dictionary غير متاحة جزئياً (لا توقف بقية المراقبة):' : 'Missing Optional Dictionary SELECT Grants:'}
                  </div>
                  <div className="font-mono mt-0.5">{primary.missingPermissions.join(' | ')}</div>
                </div>
              )}

              {primary.tablespaces.length === 0 ? (
                <div className="text-xs text-slate-500 dark:text-slate-400">
                  {lang === 'ar' ? 'لا توجد بيانات Tablespaces متاحة بعد.' : 'No tablespace utilization data collected yet.'}
                </div>
              ) : (
                <div className="space-y-3.5">
                  {primary.tablespaces.map((ts) => {
                    const barColor =
                      ts.usedPct >= 90
                        ? 'bg-rose-600'
                        : ts.usedPct >= 80
                          ? 'bg-amber-600'
                          : 'bg-blue-600';
                    return (
                      <div key={ts.name}>
                        <div className="flex items-center justify-between text-xs mb-1">
                          <span className="font-mono font-medium text-slate-900 dark:text-slate-100">
                            {ts.name}
                          </span>
                          <span className="font-mono tabular-nums text-slate-600 dark:text-slate-400">
                            {ts.usedGb} / {ts.maxGb} GB ({ts.usedPct}%)
                          </span>
                        </div>
                        <div className="h-2 w-full bg-slate-100 dark:bg-slate-800 rounded-full overflow-hidden">
                          <div className={`h-full ${barColor}`} style={{ width: `${Math.min(100, ts.usedPct)}%` }} />
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}

              {(primary.datafilesSummary || primary.fraUsage || (primary.tempTablespaces && primary.tempTablespaces.length > 0)) && (
                <div className="pt-3 border-t border-slate-100 dark:border-slate-800 grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs font-mono">
                  {primary.datafilesSummary && (
                    <div className="p-2.5 rounded border border-slate-200 dark:border-slate-800">
                      <div className="text-[11px] text-slate-500">Datafiles (DBA_DATA_FILES)</div>
                      <div className="mt-0.5 text-slate-900 dark:text-slate-100">
                        {primary.datafilesSummary.fileCount} files · {primary.datafilesSummary.totalGb} GB / {primary.datafilesSummary.maxGb} GB max ({primary.datafilesSummary.autoextensibleCount} autoext)
                      </div>
                    </div>
                  )}
                  {primary.fraUsage && (
                    <div className="p-2.5 rounded border border-slate-200 dark:border-slate-800">
                      <div className="text-[11px] text-slate-500">FRA (V$RECOVERY_FILE_DEST)</div>
                      <div className="mt-0.5 text-slate-900 dark:text-slate-100">
                        {primary.fraUsage.spaceUsedGb} / {primary.fraUsage.spaceLimitGb} GB ({primary.fraUsage.usedPct}%)
                      </div>
                    </div>
                  )}
                  {primary.tempTablespaces && primary.tempTablespaces.length > 0 && (
                    <div className="sm:col-span-2 p-2.5 rounded border border-slate-200 dark:border-slate-800">
                      <div className="text-[11px] text-slate-500">Temp Tablespaces (DBA_TEMP_FREE_SPACE)</div>
                      <div className="mt-0.5 text-slate-900 dark:text-slate-100">
                        {primary.tempTablespaces
                          .map((t) => `${t.name}: ${t.usedGb}/${t.allocatedGb} GB (free ${t.freeGb} GB)`)
                          .join(' | ')}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </section>

            <section className="lg:col-span-6 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-5 space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                    {lang === 'ar' ? 'زمن استجابة Oracle والجلسات النشطة' : 'Oracle Response Time & Active Sessions'}
                  </h2>
                  <p className="text-xs text-slate-500 dark:text-slate-400">
                    {lang === 'ar' ? 'سلسلة زمنية (ms مقابل الجلسات)' : 'Response latency (ms) vs active sessions'}
                  </p>
                </div>
                <MetricSourceChip source="Oracle SQL" />
              </div>

              {primary.sqlAreaAggregate && (
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs font-mono p-2.5 rounded border border-slate-200 dark:border-slate-800 bg-slate-50/60 dark:bg-slate-950/40">
                  <div>
                    <div className="text-[10px] text-slate-500">Executions</div>
                    <div className="font-semibold">{primary.sqlAreaAggregate.totalExecutions.toLocaleString()}</div>
                  </div>
                  <div>
                    <div className="text-[10px] text-slate-500">Disk Reads</div>
                    <div className="font-semibold">{primary.sqlAreaAggregate.diskReads.toLocaleString()}</div>
                  </div>
                  <div>
                    <div className="text-[10px] text-slate-500">Buffer Gets</div>
                    <div className="font-semibold">{primary.sqlAreaAggregate.bufferGets.toLocaleString()}</div>
                  </div>
                  <div>
                    <div className="text-[10px] text-slate-500">Avg Elapsed</div>
                    <div className="font-semibold">{primary.sqlAreaAggregate.avgElapsedMs} ms</div>
                  </div>
                </div>
              )}

              {primary.responseHistory.length === 0 ? (
                <div className="h-56 flex items-center justify-center text-xs text-slate-500 border border-dashed border-slate-200 dark:border-slate-800 rounded">
                  {lang === 'ar' ? 'بانتظار أول قراءة ناجحة من Oracle.' : 'Awaiting first verified Oracle measurement.'}
                </div>
              ) : (
                <div className="h-56 w-full" dir="ltr">
                  <ResponsiveContainer width="100%" height="100%">
                    <LineChart data={primary.responseHistory} margin={{ top: 5, right: 16, left: -10, bottom: 0 }}>
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
                      <Line type="monotone" dataKey="responseMs" name="Response (ms)" stroke="#2563eb" strokeWidth={2} dot={primary.responseHistory.length < 3 ? { r: 3 } : false} />
                      <Line type="monotone" dataKey="activeSessions" name="Active Sessions" stroke="#0ea5e9" strokeWidth={2} dot={primary.responseHistory.length < 3 ? { r: 3 } : false} />
                    </LineChart>
                  </ResponsiveContainer>
                </div>
              )}

              {primary.resourceLimits && primary.resourceLimits.length > 0 && (
                <div className="flex flex-wrap gap-2 text-[11px] font-mono">
                  {primary.resourceLimits.map((rl) => (
                    <div key={rl.resourceName} className="px-2 py-1 rounded border border-slate-200 dark:border-slate-800">
                      {rl.resourceName}: {rl.currentUtilization}/{rl.limitValue} (peak {rl.maxUtilization})
                    </div>
                  ))}
                </div>
              )}
            </section>
          </div>

          {/* Wait Events & Long-Running Queries (SQL_ID only, no SQL_TEXT) */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
            <section className="lg:col-span-5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg overflow-hidden">
              <div className="px-5 py-4 border-b border-slate-100 dark:border-slate-800 flex items-center justify-between">
                <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                  {lang === 'ar' ? 'أبرز أحداث الانتظار (V$SYSTEM_EVENT)' : 'Top Non-Idle Wait Events (V$SYSTEM_EVENT)'}
                </h2>
                <MetricSourceChip source="Oracle SQL" />
              </div>
              {!primary.topWaitEvents || primary.topWaitEvents.length === 0 ? (
                <div className="p-6 text-xs text-slate-500 dark:text-slate-400">
                  {lang === 'ar' ? 'لا توجد بيانات أحداث انتظار.' : 'No wait event statistics recorded yet.'}
                </div>
              ) : (
                <div className="divide-y divide-slate-100 dark:divide-slate-800 text-xs">
                  {primary.topWaitEvents.map((we) => (
                    <div key={we.event} className="px-5 py-3 flex items-center justify-between gap-2">
                      <span className="font-mono text-slate-800 dark:text-slate-200 truncate">{we.event}</span>
                      <span className="font-mono tabular-nums text-slate-600 dark:text-slate-400 whitespace-nowrap">
                        {we.totalWaits.toLocaleString()} waits · {we.timeWaitedMs.toLocaleString()} ms
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </section>

            <section className="lg:col-span-7 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg overflow-hidden">
              <div className="px-5 py-4 border-b border-slate-100 dark:border-slate-800 flex items-center justify-between">
                <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                  {lang === 'ar' ? 'الاستعلامات طويلة التنفيذ (> 30 ثانية)' : 'Long-Running Queries (> 30s · V$SESSION)'}
                </h2>
                <MetricSourceChip source="Oracle SQL" />
              </div>
              {primary.longRunningQueries.length === 0 ? (
                <div className="p-6 text-xs text-slate-500 dark:text-slate-400">
                  {lang === 'ar' ? 'لا توجد استعلامات طويلة حالياً.' : 'No long-running queries detected.'}
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-start border-collapse">
                    <thead>
                      <tr className="border-b border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/50 text-[11px] font-semibold text-slate-500 dark:text-slate-400">
                        <th className="py-2.5 px-4 text-start">SQL_ID</th>
                        <th className="py-2.5 px-3 text-start">{lang === 'ar' ? 'المستخدم' : 'Username'}</th>
                        <th className="py-2.5 px-3 text-start">{lang === 'ar' ? 'الوحدة' : 'Module'}</th>
                        <th className="py-2.5 px-3 text-start">{lang === 'ar' ? 'حدث الانتظار' : 'Wait Event'}</th>
                        <th className="py-2.5 px-4 text-end">{lang === 'ar' ? 'المدة' : 'Elapsed'}</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100 dark:divide-slate-800 text-xs">
                      {primary.longRunningQueries.map((q) => (
                        <tr key={q.sqlId} className="hover:bg-slate-50 dark:hover:bg-slate-800/40">
                          <td className="py-3 px-4 font-mono font-semibold text-blue-700 dark:text-blue-400">
                            {q.sqlId}
                          </td>
                          <td className="py-3 px-3 font-mono text-slate-900 dark:text-slate-100">{q.username}</td>
                          <td className="py-3 px-3 font-mono text-slate-700 dark:text-slate-300">{q.module}</td>
                          <td className="py-3 px-3 text-slate-600 dark:text-slate-400">{q.waitEvent}</td>
                          <td className="py-3 px-4 text-end font-mono tabular-nums font-semibold text-amber-700 dark:text-amber-400">
                            {q.elapsedSec}s
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </section>
          </div>
        </>
      )}
    </div>
  );
}
