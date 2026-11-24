import {
  AlertRecord,
  AlertThreshold,
  ApiEndpointCheck,
  AuditLogEntry,
  BackupJob,
  CollectorConfig,
  DailyReportRow,
  IisAppPool,
  IisSite,
  NetworkDevice,
  OracleDatabaseMetric,
  UserAccount,
  WindowsServer,
} from '../types/infrastructure';

// Clean production initialization — zero mock/demo telemetry.
// All monitoring arrays populate exclusively from real collectors and API ingestion.
export const INITIAL_WINDOWS_SERVERS: WindowsServer[] = [];
export const INITIAL_ORACLE_DATABASES: OracleDatabaseMetric[] = [];
export const INITIAL_IIS_SITES: IisSite[] = [];
export const INITIAL_APP_POOLS: IisAppPool[] = [];
export const INITIAL_API_ENDPOINTS: ApiEndpointCheck[] = [];
export const INITIAL_NETWORK_DEVICES: NetworkDevice[] = [];
export const INITIAL_BACKUP_JOBS: BackupJob[] = [];
export const INITIAL_ALERTS: AlertRecord[] = [];
export const HISTORICAL_REPORTS: DailyReportRow[] = [];
export const INITIAL_AUDIT_LOGS: AuditLogEntry[] = [];

// Default configurable alert threshold rules (editable by Administrator / IT Manager)
export const INITIAL_THRESHOLDS: AlertThreshold[] = [
  {
    id: 'THR-CPU',
    metricKey: 'server.cpu_pct',
    label: 'Windows Server CPU Utilization',
    labelAr: 'استهلاك المعالج في خوادم Windows',
    unit: '%',
    warningValue: 75,
    criticalValue: 90,
    updatedBy: 'Default Policy',
    updatedAt: 'Not modified',
  },
  {
    id: 'THR-RAM',
    metricKey: 'server.ram_pct',
    label: 'Windows Server RAM Utilization',
    labelAr: 'استهلاك الذاكرة في خوادم Windows',
    unit: '%',
    warningValue: 80,
    criticalValue: 92,
    updatedBy: 'Default Policy',
    updatedAt: 'Not modified',
  },
  {
    id: 'THR-DISK',
    metricKey: 'server.disk_pct',
    label: 'Windows Server Disk Utilization',
    labelAr: 'امتلاء القرص في خوادم Windows',
    unit: '%',
    warningValue: 80,
    criticalValue: 90,
    updatedBy: 'Default Policy',
    updatedAt: 'Not modified',
  },
  {
    id: 'THR-ORA-RESP',
    metricKey: 'oracle.response_ms',
    label: 'Oracle DB Query Response Time',
    labelAr: 'زمن استجابة قاعدة بيانات Oracle',
    unit: 'ms',
    warningValue: 35,
    criticalValue: 75,
    updatedBy: 'Default Policy',
    updatedAt: 'Not modified',
  },
  {
    id: 'THR-NET-LOSS',
    metricKey: 'network.packet_loss_pct',
    label: 'Branch WAN Packet Loss',
    labelAr: 'فقدان الحزم في شبكة الفروع',
    unit: '%',
    warningValue: 0.5,
    criticalValue: 2.0,
    updatedBy: 'Default Policy',
    updatedAt: 'Not modified',
  },
];

// Central Agentless Collector definitions — all execution runs centrally on monitoring host
export const INITIAL_COLLECTORS: CollectorConfig[] = [
  {
    id: 'COL-WIN',
    name: 'Windows Server Collector (Agentless WMI/CIM)',
    nameAr: 'جامع خوادم Windows (بدون وكيل عبر WMI/CIM و SNMP)',
    runtime: 'Native WMI / CIM / WinRM + SNMPv2c/v3',
    scheduleSeconds: 60,
    timeoutMs: 8000,
    retryCount: 1,
    enabled: true,
    lastRun: 'Never',
    lastDurationMs: 0,
    errorCount24h: 0,
    status: 'Healthy',
    endpoint: 'Central Scheduler -> WMI/CIM/SNMP',
  },
  {
    id: 'COL-ORA',
    name: 'Oracle Database Collector (Read-Only Thin)',
    nameAr: 'جامع قواعد بيانات Oracle (قراءة فقط عن بُعد)',
    runtime: 'Oracle Thin Mode (SELECT-only V$/DBA_ Views)',
    scheduleSeconds: 120,
    timeoutMs: 8000,
    retryCount: 1,
    enabled: true,
    lastRun: 'Never',
    lastDurationMs: 0,
    errorCount24h: 0,
    status: 'Healthy',
    endpoint: 'Central Scheduler -> TCP/1521 SELECT',
  },
  {
    id: 'COL-IIS',
    name: 'IIS & Web/API Collector (HTTP/HTTPS + CIM)',
    nameAr: 'جامع خوادم الويب IIS والـ APIs (بدون وكيل)',
    runtime: 'Remote HTTP/HTTPS/TLS + Native WebAdministration CIM',
    scheduleSeconds: 60,
    timeoutMs: 6000,
    retryCount: 1,
    enabled: true,
    lastRun: 'Never',
    lastDurationMs: 0,
    errorCount24h: 0,
    status: 'Healthy',
    endpoint: 'Central Scheduler -> HTTP/TLS/CIM',
  },
  {
    id: 'COL-NET',
    name: 'Network Collector (ICMP / TCP / SNMPv2c / SNMPv3)',
    nameAr: 'جامع الشبكة والفروع (Ping / TCP / SNMPv2c-v3)',
    runtime: 'ICMP Multi-Ping + TCP Probe + SNMPv2c/v3 IF-MIB',
    scheduleSeconds: 60,
    timeoutMs: 3000,
    retryCount: 1,
    enabled: true,
    lastRun: 'Never',
    lastDurationMs: 0,
    errorCount24h: 0,
    status: 'Healthy',
    endpoint: 'Central Scheduler -> ICMP/TCP/UDP:161',
  },
  {
    id: 'COL-BKP',
    name: 'Oracle RMAN Backup Reader (Read-Only)',
    nameAr: 'قارئ حالة النسخ الاحتياطي Oracle RMAN (قراءة فقط)',
    runtime: 'Oracle V$RMAN_BACKUP_JOB_DETAILS (Agentless)',
    scheduleSeconds: 900,
    timeoutMs: 8000,
    retryCount: 1,
    enabled: true,
    lastRun: 'Never',
    lastDurationMs: 0,
    errorCount24h: 0,
    status: 'Healthy',
    endpoint: 'Central Scheduler -> V$RMAN_BACKUP_JOB_DETAILS',
  },
];

// Bootstrap Administrator account only (additional users created by Administrator via RBAC)
export const INITIAL_USERS: UserAccount[] = [
  {
    id: 'USR-01',
    username: 'admin.medlabs',
    fullName: 'MedLabs IT Administrator',
    email: 'it-admin@medlabs.jo',
    role: 'Administrator',
    active: true,
    lastLogin: 'Never',
  },
];
