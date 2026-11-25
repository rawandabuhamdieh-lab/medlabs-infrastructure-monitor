export type Language = 'en' | 'ar';
export type ThemeMode = 'light' | 'dark';

export type ModuleSection =
  | 'dashboard'
  | 'servers'
  | 'oracle'
  | 'iis'
  | 'network'
  | 'backups'
  | 'alerts'
  | 'analytics'
  | 'users'
  | 'architecture';

export type UserRole =
  | 'Administrator'
  | 'IT Manager'
  | 'IT Engineer'
  | 'Read-only Viewer';

export type AlertSeverity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Information';

export type IncidentStatus = 'Open' | 'Acknowledged' | 'In Progress' | 'Resolved';

export type AssetStatus = 'Online' | 'Warning' | 'Critical' | 'Offline';

export type CollectionStatus =
  | 'Healthy'
  | 'Warning'
  | 'Critical'
  | 'Unreachable'
  | 'Authentication Failed'
  | 'Permission Denied'
  | 'Unsupported Metric'
  | 'Not Configured';

export interface MetricIntegrity {
  collectionStatus: CollectionStatus;
  dataSource: string;
  measuredAt: string;
  targetIdentifier: string;
  errorDetail?: string;
  prerequisiteHint?: string;
}

export type CredentialKind =
  | 'windows'
  | 'oracle'
  | 'snmpv2c'
  | 'snmpv3'
  | 'http'
  | 'linux-ssh'
  | 'cloud-api'
  | 'oci-api'
  | 'hyperv';

export type ServerPlatform =
  | 'windows'
  | 'linux'
  | 'oracle-linux'
  | 'cloud-vps'
  | 'oci-compute'
  | 'oracle-db'
  | 'hyperv-host'
  | 'hyperv-vm'
  | 'network-device'
  | 'restricted';

export type ServerEnvironment = 'Production' | 'Testing' | 'Development';

export type MonitoringPolicy =
  | 'standard'
  | 'least-privilege'
  | 'restricted-passive'
  | 'hyperv-host-only'
  | 'cloud-api';

export type MonitoringMethod =
  | 'icmp'
  | 'tcp'
  | 'winrm-https'
  | 'winrm-http'
  | 'wmi-dcom'
  | 'ssh'
  | 'snmp'
  | 'http-https'
  | 'cloud-api'
  | 'oci-api'
  | 'oracle-tns'
  | 'hyperv-host';

export type ServerHealthClassification =
  | 'Monitoring Healthy'
  | 'Partial Monitoring'
  | 'Monitoring Access Denied'
  | 'Connection Blocked'
  | 'Authentication Failed'
  | 'Unsupported Monitoring Method'
  | 'Server Offline';

export type CloudProviderId =
  | 'hetzner'
  | 'digitalocean'
  | 'vultr'
  | 'aws-cloudwatch'
  | 'azure-monitor'
  | 'oci'
  | 'generic-rest';

export type MetricSourceTag = 'OCI API' | 'SSH' | 'Oracle SQL' | 'SNMP' | 'ICMP/TCP' | 'WinRM/WMI' | 'Hyper-V' | 'Mixed';

export type ConnectorStatusState =
  | 'Healthy'
  | 'Warning'
  | 'Critical'
  | 'Access Restricted'
  | 'Authentication Failed'
  | 'Not Configured'
  | 'Unreachable';

export type CapabilityProtocolStatus =
  | 'Available'
  | 'Blocked'
  | 'Not Configured'
  | 'Not Supported'
  | 'Authentication Failed'
  | 'Restricted by Policy';

export interface CredentialProfileSummary {
  id: string;
  name: string;
  kind: CredentialKind;
  username?: string;
  domain?: string;
  useIntegratedAuth?: boolean;
  hasPrivateKey?: boolean;
  cloudProvider?: CloudProviderId;
  cloudBaseUrl?: string;
  ociUserOcid?: string;
  ociTenancyOcid?: string;
  ociFingerprint?: string;
  ociRegion?: string;
  ociProxyUrl?: string;
  ociAuthType?: 'api-key' | 'instance-principal' | 'resource-principal' | 'proxy-url';
  snmpSecurityLevel?: 'noAuthNoPriv' | 'authNoPriv' | 'authPriv';
  snmpAuthProtocol?: 'MD5' | 'SHA' | 'SHA256';
  snmpPrivProtocol?: 'DES' | 'AES';
  encryptedAt: string;
}

export interface MonitoringCapabilityMatrix {
  platformDetected: string;
  icmpAvailable: boolean | null;
  tcpAvailable: boolean | null;
  winrmAvailable: boolean | null;
  wmiAvailable: boolean | null;
  sshAvailable: boolean | null;
  snmpAvailable: boolean | null;
  cloudApiAvailable: boolean | null;
  ociApiAvailable?: boolean | null;
  oracleTnsAvailable?: boolean | null;
  hypervHostAccess: boolean | null;
  protocolDetails?: Record<string, CapabilityProtocolStatus>;
  availableMetrics: string[];
  unavailableMetrics: { metric: string; reason: string }[];
  accessRestrictions: string[];
  activeMethod?: string;
  evaluatedAt: string;
}

export interface HyperVGuestSummary {
  name: string;
  state: 'Running' | 'Off' | 'Paused' | 'Saved' | 'Other';
  cpuUsagePct?: number | null;
  cpuAllocated?: number;
  memoryAssignedMb?: number;
  memoryDemandMb?: number;
  uptimeSeconds?: number;
  integrationServicesVersion?: string;
  statusText?: string;
  diskPaths?: string[];
  switchNames?: string[];
}

export interface HyperVHostDetails {
  hostStatus: AssetStatus;
  virtualSwitches: { name: string; switchType: string; netAdapter?: string }[];
  vms: HyperVGuestSummary[];
  collectedAt: string;
}

export interface WindowsServiceItem {
  name: string;
  displayName: string;
  status: 'Running' | 'Stopped' | 'Paused';
  startupType: 'Automatic' | 'Manual';
}

export interface ServerNetworkInterface {
  name: string;
  rxKbps: number;
  txKbps: number;
}

export interface ServerHistoryPoint {
  time: string;
  cpuPct: number;
  ramPct: number;
  diskPct: number;
}

export interface WindowsServer {
  id: string;
  hostname: string;
  platform?: ServerPlatform;
  environment?: ServerEnvironment;
  monitoringPolicy?: MonitoringPolicy;
  allowedMethods?: MonitoringMethod[];
  role: string;
  roleAr: string;
  site: string;
  ipAddress: string;
  osVersion: string;
  domainMembership?: string;
  status: AssetStatus;
  healthClassification?: ServerHealthClassification;
  cpuPct: number;
  ramPct: number;
  ramTotalGb: number;
  diskTotalGb: number;
  diskAvailableGb: number;
  diskPct: number;
  uptimeHours: number;
  loadAverage?: string;
  lastCheck: string;
  lastSuccessfulCheck?: string;
  snmpCommunity?: string;
  credentialId?: string;
  authMode?: 'integrated' | 'credential' | 'snmp-only';
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
  linkedOracleTargetId?: string;
  notes?: string;
  iisDetectedSites?: string[];
  eventErrors24h?: number;
  runningProcessesCount?: number;
  hypervVmState?: 'Running' | 'Off' | 'Paused' | 'Saved' | 'Other';
  hypervGuestOsHealth?: 'Verified' | 'Host-Only (Guest OS Restricted)' | 'Offline';
  hypervDetails?: HyperVHostDetails;
  capabilityMatrix?: MonitoringCapabilityMatrix;
  metricsAvailable?: {
    cpu: boolean;
    ram: boolean;
    disk: boolean;
    uptime: boolean;
    services: boolean;
    networkTraffic: boolean;
  };
  networkInterfaces?: ServerNetworkInterface[];
  integrity?: MetricIntegrity;
  services: WindowsServiceItem[];
  history: ServerHistoryPoint[];
}

export interface OracleTablespace {
  name: string;
  usedGb: number;
  maxGb: number;
  usedPct: number;
  dailyGrowthGb: number;
}

export interface OracleLongQuery {
  sqlId: string;
  username: string;
  elapsedSec: number;
  waitEvent: string;
  module: string;
}

export interface OracleWaitEvent {
  event: string;
  totalWaits: number;
  timeWaitedMs: number;
}

export interface OracleConnectorHealth {
  connector: 'OCI Infrastructure' | 'Oracle Linux OS' | 'Oracle Database';
  status: ConnectorStatusState;
  collectionStatus: CollectionStatus;
  source: MetricSourceTag;
  lastAttemptAt: string;
  lastSuccessAt?: string;
  latencyMs?: number | null;
  availableMetrics: string[];
  unavailableMetrics: { metric: string; reason: string }[];
  errorDetail?: string;
  prerequisiteHint?: string;
}

export interface OciCloudConfig {
  enabled: boolean;
  region?: string;
  tenancyOcid?: string;
  compartmentOcid?: string;
  instanceOcid?: string;
  authMethod?: 'api-key' | 'instance-principal' | 'resource-principal' | 'proxy-url';
  credentialId?: string;
  collectIntervalSeconds?: number;
}

export interface OciInstanceMetrics {
  lifecycleState?: string;
  shape?: string;
  availabilityDomain?: string;
  cpuUtilizationPct?: number | null;
  memoryUtilizationPct?: number | null;
  diskBytesRead?: number | null;
  diskBytesWritten?: number | null;
  diskIopsRead?: number | null;
  diskIopsWrite?: number | null;
  networkBytesIn?: number | null;
  networkBytesOut?: number | null;
  loadAverage?: number | null;
  bootVolumeReadBytes?: number | null;
  bootVolumeWriteBytes?: number | null;
  source: 'OCI API';
  collectedAt: string;
}

export interface OracleLinuxOsConfig {
  enabled: boolean;
  host?: string;
  port?: number;
  credentialId?: string;
  collectIntervalSeconds?: number;
}

export interface OracleLinuxFilesystem {
  filesystem: string;
  mountPoint: string;
  totalGb: number;
  usedGb: number;
  availableGb: number;
  usedPct: number;
}

export interface OracleLinuxOsMetrics {
  osVersion?: string;
  kernelVersion?: string;
  hostname?: string;
  cpuPct?: number | null;
  cpuCores?: number | null;
  ramTotalGb?: number | null;
  ramUsedGb?: number | null;
  ramAvailableGb?: number | null;
  ramPct?: number | null;
  swapTotalGb?: number | null;
  swapUsedGb?: number | null;
  swapPct?: number | null;
  diskTotalGb?: number | null;
  diskUsedGb?: number | null;
  diskAvailableGb?: number | null;
  diskPct?: number | null;
  filesystems: OracleLinuxFilesystem[];
  loadAverage?: string;
  uptimeHours?: number | null;
  networkInterfaces: (ServerNetworkInterface & { rxErrors?: number; txErrors?: number; state?: string })[];
  processCount?: number | null;
  services: WindowsServiceItem[];
  fallbackFromOci?: boolean;
  source: 'SSH' | 'OCI API';
  collectedAt: string;
}

export interface OracleScheduleConfig {
  availabilitySec: number;
  sessionsPerfSec: number;
  memorySec: number;
  tablespaceSec: number;
  ociSec: number;
  linuxSec: number;
}

export interface OracleHistoryRecord {
  serverId: string;
  platform: string;
  metricName: string;
  metricValue: number | string;
  metricUnit: string;
  metricSource: MetricSourceTag;
  collectionTime: string;
  collectionStatus: string;
  errorDetails?: string;
}

export interface TnsAliasInfo {
  alias: string;
  host?: string;
  port?: number;
  serviceName?: string;
  protocol?: 'TCP' | 'TCPS';
  sourceFile: string;
}

export interface OracleDatabaseMetric {
  id: string;
  serviceName: string;
  dbName?: string;
  dbVersion?: string;
  instanceName?: string;
  openMode?: string;
  startupTime?: string;
  uptimeHours?: number | null;
  host: string;
  port?: number;
  connectionType?: 'tns' | 'direct';
  tnsAlias?: string;
  tnsAdminDir?: string;
  protocol?: 'TCP' | 'TCPS';
  walletDir?: string;
  connectTimeoutMs?: number;
  queryTimeoutMs?: number;
  collectRmanBackups?: boolean;
  credentialId?: string;
  role: 'Primary' | 'Read-Only Standby';
  status: AssetStatus;
  availabilityPct: number;
  responseTimeMs: number;
  activeSessions: number;
  inactiveSessions?: number | null;
  totalSessions?: number;
  blockingSessions: number;
  connectionFailures24h: number;
  cpuUsagePct: number;
  sgaUsedPct: number;
  pgaUsedMb: number;
  dbSizeGb?: number;
  lastCheck: string;
  tablespaces: OracleTablespace[];
  datafilesSummary?: {
    fileCount: number;
    totalGb: number;
    maxGb: number;
    autoextensibleCount: number;
  };
  tempTablespaces?: {
    name: string;
    allocatedGb: number;
    usedGb: number;
    freeGb: number;
  }[];
  fraUsage?: {
    name: string;
    spaceLimitGb: number;
    spaceUsedGb: number;
    spaceReclaimableGb: number;
    usedPct: number;
  } | null;
  resourceLimits?: {
    resourceName: string;
    currentUtilization: number;
    maxUtilization: number;
    limitValue: string;
  }[];
  sysstatSummary?: { name: string; value: number }[];
  sqlAreaAggregate?: {
    totalExecutions: number;
    diskReads: number;
    bufferGets: number;
    avgElapsedMs: number;
  };
  missingPermissions?: string[];
  longRunningQueries: OracleLongQuery[];
  topWaitEvents?: OracleWaitEvent[];
  responseHistory: { time: string; responseMs: number; activeSessions: number }[];
  integrity?: MetricIntegrity;
  ociConfig?: OciCloudConfig;
  linuxConfig?: OracleLinuxOsConfig;
  schedules?: OracleScheduleConfig;
  ociConnector?: OracleConnectorHealth;
  linuxConnector?: OracleConnectorHealth;
  dbConnector?: OracleConnectorHealth;
  ociMetrics?: OciInstanceMetrics;
  linuxMetrics?: OracleLinuxOsMetrics;
  metricHistory?: OracleHistoryRecord[];
  linkedServerId?: string;
}

export interface IisAppPool {
  name: string;
  serverHostname?: string;
  runtime: string;
  state: 'Started' | 'Stopped';
  workerMemoryMb: number;
  cpuPct: number;
}

export interface IisSite {
  id: string;
  name: string;
  serverHostname: string;
  url: string;
  appPoolName: string;
  credentialId?: string;
  httpStatus: number;
  responseTimeMs: number;
  availabilityPct: number;
  httpErrors1h: number;
  sslDaysRemaining?: number | null;
  status: AssetStatus;
  lastCheck: string;
  integrity?: MetricIntegrity;
}

export interface ApiEndpointCheck {
  id: string;
  name: string;
  method: 'GET' | 'POST';
  url: string;
  httpStatus: number;
  responseTimeMs: number;
  status: AssetStatus;
  lastCheck: string;
  integrity?: MetricIntegrity;
}

export interface NetworkInterfaceStat {
  index: number;
  name: string;
  operStatus: 'up' | 'down';
  speedMbps: number;
  rxKbps: number;
  txKbps: number;
  inErrors: number;
  outErrors: number;
}

export interface NetworkDevice {
  id: string;
  name: string;
  type: 'Core Firewall' | 'L3 Switch' | 'SD-WAN Gateway' | 'Branch Router';
  site: string;
  ipAddress: string;
  snmpEnabled: boolean;
  snmpVersion?: 'none' | 'v2c' | 'v3';
  credentialId?: string;
  tcpPorts?: number[];
  openPorts?: number[];
  status: AssetStatus;
  latencyMs: number;
  packetLossPct: number;
  uptimePct30d: number;
  lastCheck: string;
  interfaces?: NetworkInterfaceStat[];
  latencyHistory: { time: string; latencyMs: number; packetLossPct: number }[];
  integrity?: MetricIntegrity;
}

export interface BackupJob {
  id: string;
  jobName: string;
  targetSystem: string;
  backupSource: string;
  status: 'Succeeded' | 'Warning' | 'Failed';
  lastSuccessfulRun: string;
  durationMinutes: number;
  sizeGb: number;
  ageHours: number;
  failures7d: number;
}

export interface AlertRecord {
  id: string;
  timestamp: string;
  severity: AlertSeverity;
  status: IncidentStatus;
  module: 'Windows Server' | 'Oracle DB' | 'IIS & App' | 'Network' | 'Backup';
  assetId: string;
  assetName: string;
  title: string;
  titleAr: string;
  description: string;
  descriptionAr: string;
  acknowledgedBy: string | null;
  assignedTo: string | null;
  resolutionNotes: string;
  downtimeMinutes: number;
  notifiedChannels: string[];
}

export interface AlertThreshold {
  id: string;
  metricKey: string;
  label: string;
  labelAr: string;
  unit: string;
  warningValue: number;
  criticalValue: number;
  updatedBy: string;
  updatedAt: string;
}

export interface CollectorConfig {
  id: string;
  name: string;
  nameAr: string;
  runtime: string;
  scheduleSeconds: number;
  timeoutMs?: number;
  retryCount?: number;
  enabled: boolean;
  lastRun: string;
  lastDurationMs: number;
  errorCount24h: number;
  lastError?: string;
  targetsTotal?: number;
  targetsHealthy?: number;
  status: 'Healthy' | 'Degraded' | 'Paused';
  endpoint: string;
}

export interface UserAccount {
  id: string;
  username: string;
  fullName: string;
  email: string;
  role: UserRole;
  active: boolean;
  lastLogin: string;
}

export interface AuditLogEntry {
  id: string;
  timestamp: string;
  actor: string;
  role: string;
  action: string;
  target: string;
  outcome: 'Success' | 'Denied';
  details: string;
}

export interface DailyReportRow {
  period: string;
  availabilityPct: number;
  avgCpuPct: number;
  avgOracleMs: number;
  incidentCount: number;
  totalDowntimeMin: number;
}

export interface TimelineSample {
  timestamp: string; // YYYY-MM-DD HH:MM:SS
  date: string;      // YYYY-MM-DD
  time: string;      // HH:MM:SS
  minuteLabel: string; // HH:MM
  dbCpuMs: number;
  dbIoMs: number;
  dbLockMs: number;
  appResponseMs: number;
  networkLatencyMs: number;
  serverLoadScore: number;
  serverCpuPct: number;
  serverRamPct: number;
  oracleResponseMs: number;
  activeSessions: number;
  blockingSessions: number;
  appErrors1h: number;
  packetLossPct: number;
  activeAlerts: number;
  criticalAlerts: number;
  hasIssue: boolean;
  issueSummary?: string;
  issueSummaryAr?: string;
  topWaitEvent?: string;
  topObject?: string;
  affectedTarget?: string;
}

export interface WindowsProcessIdentity {
  platform: string;
  hostname: string;
  identityName: string;
  domain?: string;
  partOfDomain: boolean;
  isDomainUser: boolean;
  isSystemAccount: boolean;
  authenticationType: string;
  impersonationLevel?: string;
  logonType?: string;
  kerberosTgtAvailable: boolean;
  doubleHopRisk: boolean;
  doubleHopReason?: string;
  detectedAt: string;
}

export interface DiagnosticCheckItem {
  key: 'domain_auth' | 'kerberos' | 'wmi_dcom' | 'winrm_https' | 'metrics_collection';
  label: string;
  ok: boolean;
  status: CollectionStatus;
  latencyMs: number | null;
  details: string;
  prerequisiteHint?: string;
}

export interface ConnectionTestResult {
  ok: boolean;
  status: CollectionStatus;
  dataSource: string;
  latencyMs: number | null;
  measuredAt: string;
  details: string;
  prerequisiteHint?: string;
  processIdentity?: WindowsProcessIdentity;
  checks?: DiagnosticCheckItem[];
  doubleHopWarning?: string;
  capabilityMatrix?: MonitoringCapabilityMatrix;
}
