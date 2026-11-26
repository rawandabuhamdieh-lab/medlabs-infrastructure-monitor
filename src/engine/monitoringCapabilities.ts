import { formatMedLabsTimestamp } from './time.ts';
import type { CredentialVault } from './credentialVault.ts';
import type {
  ConnectionTestResult,
  MetricIntegrity,
  MonitoringCapabilityMatrix,
  MonitoringMethod,
  MonitoringPolicy,
  ServerHealthClassification,
  ServerPlatform,
  WindowsServer,
} from '../types/infrastructure.ts';

export interface CollectorContext {
  vault: CredentialVault;
  timeoutMs: number;
  allServers: WindowsServer[];
  backoff: MethodBackoffTracker;
  bypassBackoff?: boolean;
}

export interface UnifiedCollectionResult {
  ok: boolean;
  integrity: MetricIntegrity;
  healthClassification: ServerHealthClassification;
  capabilityMatrix: MonitoringCapabilityMatrix;
}

export interface ServerCollectorAdapter {
  readonly platform: ServerPlatform;
  collect(target: WindowsServer, ctx: CollectorContext): Promise<UnifiedCollectionResult>;
  testConnection(target: WindowsServer, ctx: CollectorContext): Promise<ConnectionTestResult>;
}

const DEFAULT_METHODS_BY_PLATFORM: Record<ServerPlatform, MonitoringMethod[]> = {
  windows: ['icmp', 'tcp', 'winrm-https', 'winrm-http', 'wmi-dcom', 'snmp', 'http-https'],
  linux: ['icmp', 'tcp', 'ssh', 'snmp', 'http-https'],
  'oracle-linux': ['ssh', 'oci-api', 'icmp', 'tcp', 'snmp', 'http-https'],
  'cloud-vps': ['cloud-api', 'ssh', 'http-https', 'icmp', 'tcp', 'snmp'],
  'oci-compute': ['oci-api', 'ssh', 'oracle-tns', 'icmp', 'tcp', 'http-https'],
  'oracle-db': ['oracle-tns', 'oci-api', 'ssh', 'icmp', 'tcp'],
  'hyperv-host': ['icmp', 'tcp', 'winrm-https', 'winrm-http', 'wmi-dcom', 'hyperv-host', 'snmp'],
  'hyperv-vm': ['hyperv-host', 'icmp', 'tcp', 'winrm-https', 'ssh', 'http-https', 'snmp'],
  'network-device': ['icmp', 'tcp', 'snmp', 'http-https'],
  restricted: ['icmp', 'tcp', 'http-https', 'snmp'],
};

const POLICY_PROHIBITED_METHODS: Record<MonitoringPolicy, MonitoringMethod[]> = {
  standard: [],
  'least-privilege': ['winrm-http'],
  'restricted-passive': ['winrm-https', 'winrm-http', 'wmi-dcom', 'ssh'],
  'hyperv-host-only': ['winrm-https', 'winrm-http', 'wmi-dcom', 'ssh'],
  'cloud-api': [],
};

export function resolveServerPlatform(srv: Pick<WindowsServer, 'platform' | 'osVersion' | 'monitoringPolicy'>): ServerPlatform {
  if (srv.monitoringPolicy === 'restricted-passive' && (!srv.platform || srv.platform === 'restricted')) {
    return 'restricted';
  }
  if (srv.platform) return srv.platform;
  const osLower = (srv.osVersion || '').toLowerCase();
  if (/oracle linux/i.test(osLower)) return 'oracle-linux';
  if (/ubuntu|debian|red hat|rhel|rocky|almalinux|centos|cloudlinux|linux/i.test(osLower)) {
    return 'linux';
  }
  if (/hyper-v/i.test(osLower)) return 'hyperv-host';
  return 'windows';
}

export function getPermittedMethods(srv: WindowsServer): {
  permitted: MonitoringMethod[];
  prohibitedReasons: string[];
} {
  const platform = resolveServerPlatform(srv);
  const policy: MonitoringPolicy =
    srv.monitoringPolicy || (platform === 'restricted' ? 'restricted-passive' : 'standard');

  const base =
    Array.isArray(srv.allowedMethods) && srv.allowedMethods.length > 0
      ? srv.allowedMethods
      : DEFAULT_METHODS_BY_PLATFORM[platform];

  const policyBlocked = new Set(POLICY_PROHIBITED_METHODS[policy] || []);
  const prohibitedReasons: string[] = [];

  if (platform === 'restricted' || policy === 'restricted-passive') {
    policyBlocked.add('winrm-https');
    policyBlocked.add('winrm-http');
    policyBlocked.add('wmi-dcom');
    policyBlocked.add('ssh');
    prohibitedReasons.push(
      'Restricted Server policy: WinRM, WMI/DCOM, and SSH active remote execution are strictly prohibited.'
    );
  }
  if (policy === 'hyperv-host-only') {
    prohibitedReasons.push(
      'Hyper-V Host-Only policy: Direct guest OS access (WinRM/WMI/SSH) is disabled; telemetry comes from authorized Hyper-V host + passive checks.'
    );
  }
  if (policy === 'least-privilege') {
    prohibitedReasons.push('Least-Privilege policy: Unencrypted WinRM HTTP (5985) is disabled.');
  }

  const permitted = base.filter((m) => !policyBlocked.has(m));
  return { permitted, prohibitedReasons };
}

export function isMethodPermitted(srv: WindowsServer, method: MonitoringMethod): boolean {
  const { permitted } = getPermittedMethods(srv);
  return permitted.includes(method);
}

export class MethodBackoffTracker {
  private readonly blockedUntil = new Map<string, { until: number; failures: number; reason: string }>();

  private key(serverId: string, method: MonitoringMethod): string {
    return `${serverId}::${method}`;
  }

  isBackedOff(serverId: string, method: MonitoringMethod): { active: boolean; reason?: string; retryAt?: string } {
    const entry = this.blockedUntil.get(this.key(serverId, method));
    if (!entry) return { active: false };
    if (Date.now() >= entry.until) {
      return { active: false };
    }
    return {
      active: true,
      reason: entry.reason,
      retryAt: formatMedLabsTimestamp(entry.until),
    };
  }

  recordBlockedOrDenied(serverId: string, method: MonitoringMethod, reason: string): void {
    const k = this.key(serverId, method);
    const prev = this.blockedUntil.get(k);
    const failures = (prev?.failures ?? 0) + 1;
    // Exponential cooldown: 2m -> 4m -> 8m -> max 15m so blocked protocols aren't repeatedly hammered
    const delayMs = Math.min(15 * 60_000, 120_000 * 2 ** (failures - 1));
    this.blockedUntil.set(k, {
      until: Date.now() + delayMs,
      failures,
      reason,
    });
  }

  clearMethod(serverId: string, method: MonitoringMethod): void {
    this.blockedUntil.delete(this.key(serverId, method));
  }

  clearServer(serverId: string): void {
    for (const k of this.blockedUntil.keys()) {
      if (k.startsWith(`${serverId}::`)) {
        this.blockedUntil.delete(k);
      }
    }
  }
}

export function mapCollectionToHealthClassification(params: {
  reachable: boolean;
  hasOsOrPrimaryMetrics: boolean;
  hasAnyPassiveMetric: boolean;
  collectionStatus: MetricIntegrity['collectionStatus'];
  connectionBlocked?: boolean;
}): ServerHealthClassification {
  const { reachable, hasOsOrPrimaryMetrics, hasAnyPassiveMetric, collectionStatus, connectionBlocked } = params;

  if (!reachable && !hasAnyPassiveMetric) {
    if (connectionBlocked) return 'Connection Blocked';
    return 'Server Offline';
  }

  if (collectionStatus === 'Authentication Failed') {
    return 'Authentication Failed';
  }
  if (collectionStatus === 'Permission Denied') {
    return 'Monitoring Access Denied';
  }
  if (collectionStatus === 'Unsupported Metric') {
    return hasAnyPassiveMetric ? 'Partial Monitoring' : 'Unsupported Monitoring Method';
  }
  if (connectionBlocked && !hasOsOrPrimaryMetrics) {
    return hasAnyPassiveMetric ? 'Partial Monitoring' : 'Connection Blocked';
  }
  if (hasOsOrPrimaryMetrics) {
    return 'Monitoring Healthy';
  }
  if (hasAnyPassiveMetric) {
    return 'Partial Monitoring';
  }
  return 'Unsupported Monitoring Method';
}

export function buildDefaultUnavailableMetrics(
  srv: WindowsServer,
  reason: string
): { metric: string; reason: string }[] {
  const out: { metric: string; reason: string }[] = [];
  if (!srv.metricsAvailable?.cpu) out.push({ metric: 'CPU Utilization', reason });
  if (!srv.metricsAvailable?.ram) out.push({ metric: 'RAM Usage', reason });
  if (!srv.metricsAvailable?.disk) out.push({ metric: 'Disk Usage', reason });
  if (!srv.metricsAvailable?.uptime) out.push({ metric: 'Uptime', reason });
  if (!srv.metricsAvailable?.services) out.push({ metric: 'Services / Processes', reason });
  if (!srv.metricsAvailable?.networkTraffic) out.push({ metric: 'Network Interface Traffic', reason });
  return out;
}
