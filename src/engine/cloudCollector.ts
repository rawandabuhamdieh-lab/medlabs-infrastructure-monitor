import { formatMedLabsTimestamp } from './time.ts';
import { runReadOnlySshTelemetry } from './linuxCollector.ts';
import {
  buildDefaultUnavailableMetrics,
  getPermittedMethods,
  isMethodPermitted,
  mapCollectionToHealthClassification,
  type CollectorContext,
  type ServerCollectorAdapter,
  type UnifiedCollectionResult,
} from './monitoringCapabilities.ts';
import { checkTcpPort, isValidTargetHost, pingHostStats } from './networkHelpers.ts';
import { pollSnmpServerMetrics } from '../snmpPoller.ts';
import type {
  CloudProviderId,
  ConnectionTestResult,
  MetricIntegrity,
  MonitoringCapabilityMatrix,
  WindowsServer,
} from '../types/infrastructure.ts';

export interface CloudTelemetryResult {
  ok: boolean;
  status: MetricIntegrity['collectionStatus'];
  instanceState?: 'Running' | 'Stopped' | 'Degraded';
  cpuPct?: number;
  ramPct?: number;
  ramTotalGb?: number;
  diskPct?: number;
  diskTotalGb?: number;
  rxKbps?: number;
  txKbps?: number;
  osHint?: string;
  errorDetail?: string;
  prerequisiteHint?: string;
}

export interface CloudProviderAdapter {
  readonly id: CloudProviderId;
  readonly displayName: string;
  readonly supportedMetrics: string[];
  fetchTelemetry(params: {
    instanceId: string;
    apiToken?: string;
    baseUrl?: string;
    timeoutMs: number;
  }): Promise<CloudTelemetryResult>;
}

const providerRegistry = new Map<CloudProviderId, CloudProviderAdapter>();

export function registerCloudProviderAdapter(adapter: CloudProviderAdapter): void {
  providerRegistry.set(adapter.id, adapter);
}

export function listCloudProviders(): { id: CloudProviderId; displayName: string; supportedMetrics: string[] }[] {
  return Array.from(providerRegistry.values()).map((a) => ({
    id: a.id,
    displayName: a.displayName,
    supportedMetrics: a.supportedMetrics,
  }));
}

// 1. Hetzner Cloud Adapter (read-only Bearer token)
registerCloudProviderAdapter({
  id: 'hetzner',
  displayName: 'Hetzner Cloud API',
  supportedMetrics: ['Instance Status', 'CPU %', 'Network RX/TX kbps', 'Disk IOPS/Size'],
  async fetchTelemetry({ instanceId, apiToken, timeoutMs }) {
    if (!apiToken) {
      return {
        ok: false,
        status: 'Not Configured',
        errorDetail: 'Hetzner Cloud Read-Only API token is missing.',
        prerequisiteHint: 'Create a Read-Only API token in Hetzner Cloud Console and save it in Credential Vault.',
      };
    }
    try {
      const headers = { Authorization: `Bearer ${apiToken}` };
      const srvResp = await fetch(`https://api.hetzner.cloud/v1/servers/${encodeURIComponent(instanceId)}`, {
        headers,
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (srvResp.status === 401 || srvResp.status === 403) {
        return { ok: false, status: 'Authentication Failed', errorDetail: `Hetzner API returned HTTP ${srvResp.status}.` };
      }
      if (!srvResp.ok) {
        return { ok: false, status: 'Unreachable', errorDetail: `Hetzner API HTTP ${srvResp.status}.` };
      }
      const srvJson = (await srvResp.json()) as {
        server?: { status?: string; server_type?: { memory?: number; disk?: number }; image?: { description?: string } };
      };
      const endIso = new Date().toISOString();
      const startIso = new Date(Date.now() - 10 * 60_000).toISOString();
      const mResp = await fetch(
        `https://api.hetzner.cloud/v1/servers/${encodeURIComponent(instanceId)}/metrics?type=cpu,network&start=${encodeURIComponent(startIso)}&end=${encodeURIComponent(endIso)}`,
        { headers, signal: AbortSignal.timeout(timeoutMs) }
      );
      let cpuPct: number | undefined;
      if (mResp.ok) {
        const mJson = (await mResp.json()) as {
          metrics?: { time_series?: { cpu?: { values?: [number, string][] } } };
        };
        const vals = mJson.metrics?.time_series?.cpu?.values;
        if (Array.isArray(vals) && vals.length > 0) {
          cpuPct = Number(parseFloat(vals[vals.length - 1][1]).toFixed(1));
        }
      }
      return {
        ok: true,
        status: 'Healthy',
        instanceState: srvJson.server?.status === 'running' ? 'Running' : 'Stopped',
        cpuPct,
        ramTotalGb: srvJson.server?.server_type?.memory,
        diskTotalGb: srvJson.server?.server_type?.disk,
        osHint: srvJson.server?.image?.description,
      };
    } catch (err) {
      return { ok: false, status: 'Unreachable', errorDetail: err instanceof Error ? err.message : String(err) };
    }
  },
});

// 2. DigitalOcean Adapter
registerCloudProviderAdapter({
  id: 'digitalocean',
  displayName: 'DigitalOcean API v2',
  supportedMetrics: ['Droplet Status', 'Allocated Memory/Disk', 'CPU/Memory (when DO Monitoring enabled)'],
  async fetchTelemetry({ instanceId, apiToken, timeoutMs }) {
    if (!apiToken) {
      return {
        ok: false,
        status: 'Not Configured',
        errorDetail: 'DigitalOcean Read-Only Personal Access Token is missing.',
      };
    }
    try {
      const resp = await fetch(`https://api.digitalocean.com/v2/droplets/${encodeURIComponent(instanceId)}`, {
        headers: { Authorization: `Bearer ${apiToken}` },
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (resp.status === 401 || resp.status === 403) {
        return { ok: false, status: 'Authentication Failed', errorDetail: `DigitalOcean API returned HTTP ${resp.status}.` };
      }
      if (!resp.ok) {
        return { ok: false, status: 'Unreachable', errorDetail: `DigitalOcean API HTTP ${resp.status}.` };
      }
      const data = (await resp.json()) as {
        droplet?: { status?: string; memory?: number; disk?: number; image?: { distribution?: string; name?: string } };
      };
      return {
        ok: true,
        status: 'Healthy',
        instanceState: data.droplet?.status === 'active' ? 'Running' : 'Stopped',
        ramTotalGb: data.droplet?.memory ? Number((data.droplet.memory / 1024).toFixed(1)) : undefined,
        diskTotalGb: data.droplet?.disk,
        osHint: data.droplet?.image ? `${data.droplet.image.distribution || ''} ${data.droplet.image.name || ''}`.trim() : undefined,
      };
    } catch (err) {
      return { ok: false, status: 'Unreachable', errorDetail: err instanceof Error ? err.message : String(err) };
    }
  },
});

// 3. Vultr Adapter
registerCloudProviderAdapter({
  id: 'vultr',
  displayName: 'Vultr API v2',
  supportedMetrics: ['Instance Status', 'Allocated RAM/Disk', 'Bandwidth'],
  async fetchTelemetry({ instanceId, apiToken, timeoutMs }) {
    if (!apiToken) {
      return { ok: false, status: 'Not Configured', errorDetail: 'Vultr Read-Only API key is missing.' };
    }
    try {
      const resp = await fetch(`https://api.vultr.com/v2/instances/${encodeURIComponent(instanceId)}`, {
        headers: { Authorization: `Bearer ${apiToken}` },
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (resp.status === 401 || resp.status === 403) {
        return { ok: false, status: 'Authentication Failed', errorDetail: `Vultr API returned HTTP ${resp.status}.` };
      }
      if (!resp.ok) {
        return { ok: false, status: 'Unreachable', errorDetail: `Vultr API HTTP ${resp.status}.` };
      }
      const data = (await resp.json()) as {
        instance?: { power_status?: string; ram?: number; disk?: number; os?: string };
      };
      return {
        ok: true,
        status: 'Healthy',
        instanceState: data.instance?.power_status === 'running' ? 'Running' : 'Stopped',
        ramTotalGb: data.instance?.ram ? Number((data.instance.ram / 1024).toFixed(1)) : undefined,
        diskTotalGb: data.instance?.disk,
        osHint: data.instance?.os,
      };
    } catch (err) {
      return { ok: false, status: 'Unreachable', errorDetail: err instanceof Error ? err.message : String(err) };
    }
  },
});

// 4. Generic Read-Only Provider REST Adapter (extensible without touching core engine)
registerCloudProviderAdapter({
  id: 'generic-rest',
  displayName: 'Generic Provider Read-Only Metrics API',
  supportedMetrics: ['Instance Status', 'CPU %', 'RAM %', 'Disk %', 'Network RX/TX'],
  async fetchTelemetry({ instanceId, apiToken, baseUrl, timeoutMs }) {
    if (!baseUrl) {
      return {
        ok: false,
        status: 'Not Configured',
        errorDetail: 'Provider API Base URL is required for Generic Cloud REST adapter.',
      };
    }
    let parsed: URL;
    try {
      parsed = new URL(baseUrl);
      if (!['http:', 'https:'].includes(parsed.protocol)) {
        return { ok: false, status: 'Not Configured', errorDetail: 'Provider API Base URL must use http:// or https://.' };
      }
    } catch {
      return { ok: false, status: 'Not Configured', errorDetail: 'Invalid Provider API Base URL.' };
    }

    try {
      const targetUrl = new URL(parsed.toString());
      if (!targetUrl.pathname.endsWith('/')) targetUrl.pathname += '/';
      const fullUrl = new URL(encodeURIComponent(instanceId), targetUrl).toString();
      const headers: Record<string, string> = {};
      if (apiToken) headers.Authorization = `Bearer ${apiToken}`;
      const resp = await fetch(fullUrl, { headers, signal: AbortSignal.timeout(timeoutMs) });
      if (resp.status === 401 || resp.status === 403) {
        return { ok: false, status: 'Authentication Failed', errorDetail: `Provider API HTTP ${resp.status}.` };
      }
      if (!resp.ok) {
        return { ok: false, status: 'Unreachable', errorDetail: `Provider API HTTP ${resp.status}.` };
      }
      const d = (await resp.json()) as Record<string, unknown>;
      return {
        ok: true,
        status: 'Healthy',
        instanceState: d.status === 'stopped' || d.status === 'offline' ? 'Stopped' : 'Running',
        cpuPct: typeof d.cpuPct === 'number' ? d.cpuPct : undefined,
        ramPct: typeof d.ramPct === 'number' ? d.ramPct : undefined,
        diskPct: typeof d.diskPct === 'number' ? d.diskPct : undefined,
        rxKbps: typeof d.rxKbps === 'number' ? d.rxKbps : undefined,
        txKbps: typeof d.txKbps === 'number' ? d.txKbps : undefined,
      };
    } catch (err) {
      return { ok: false, status: 'Unreachable', errorDetail: err instanceof Error ? err.message : String(err) };
    }
  },
});

// 5 & 6. AWS CloudWatch & Azure Monitor Descriptors
registerCloudProviderAdapter({
  id: 'aws-cloudwatch',
  displayName: 'AWS EC2 / CloudWatch (Read-Only)',
  supportedMetrics: ['EC2 Instance Status', 'CloudWatch CPUUtilization', 'NetworkIn/Out'],
  async fetchTelemetry({ baseUrl, apiToken, instanceId, timeoutMs }) {
    if (!baseUrl) {
      return {
        ok: false,
        status: 'Not Configured',
        errorDetail: 'AWS CloudWatch requires an authenticated CloudWatch proxy/IAM SigV4 endpoint URL configured in Credential Vault.',
        prerequisiteHint: 'Configure a Read-Only CloudWatch REST proxy Base URL or enable authorized SSH Read-Only monitoring on the EC2 instance.',
      };
    }
    return providerRegistry.get('generic-rest')!.fetchTelemetry({ instanceId, apiToken, baseUrl, timeoutMs });
  },
});

registerCloudProviderAdapter({
  id: 'azure-monitor',
  displayName: 'Microsoft Azure Monitor (Read-Only)',
  supportedMetrics: ['VM PowerState', 'Percentage CPU', 'Available Memory Bytes', 'Network In/Out'],
  async fetchTelemetry({ instanceId, apiToken, baseUrl, timeoutMs }) {
    if (!apiToken || !baseUrl) {
      return {
        ok: false,
        status: 'Not Configured',
        errorDetail: 'Azure Monitor requires a Read-Only Bearer Token and Resource Metrics REST URL.',
        prerequisiteHint: 'Assign Monitoring Reader RBAC role in Azure and provide the Resource Metrics URL + OAuth2 Bearer token.',
      };
    }
    return providerRegistry.get('generic-rest')!.fetchTelemetry({ instanceId, apiToken, baseUrl, timeoutMs });
  },
});

export class CloudVpsCollector implements ServerCollectorAdapter {
  readonly platform = 'cloud-vps' as const;

  async collect(srv: WindowsServer, ctx: CollectorContext): Promise<UnifiedCollectionResult> {
    const stamp = formatMedLabsTimestamp();
    const target =
      srv.ipAddress && srv.ipAddress !== '—' && srv.ipAddress !== '-' ? srv.ipAddress : srv.hostname;
    const { prohibitedReasons } = getPermittedMethods(srv);
    const restrictions = [...prohibitedReasons];

    const allowCloudApi = isMethodPermitted(srv, 'cloud-api');
    const allowSsh = isMethodPermitted(srv, 'ssh');
    const allowHttp = isMethodPermitted(srv, 'http-https') && Boolean(srv.httpUrl);
    const allowIcmp = isMethodPermitted(srv, 'icmp');
    const allowTcp = isMethodPermitted(srv, 'tcp');

    let cloudCred: { provider?: CloudProviderId; token?: string; baseUrl?: string } | null = null;
    let sshCred: { username: string; password?: string; privateKey?: string; passphrase?: string } | null = null;
    let snmpCommunity = srv.snmpCommunity?.trim() || '';
    let credError: string | null = null;

    if (srv.credentialId) {
      const dec = ctx.vault.getDecrypted(srv.credentialId);
      if (!dec.ok) {
        credError = dec.error;
      } else if (dec.payload.kind === 'cloud-api') {
        cloudCred = {
          provider: dec.payload.cloudProvider || srv.cloudProvider,
          token: dec.payload.cloudApiToken,
          baseUrl: dec.payload.cloudBaseUrl,
        };
      } else if (dec.payload.kind === 'linux-ssh' && dec.payload.username) {
        sshCred = {
          username: dec.payload.username,
          password: dec.payload.password,
          privateKey: dec.payload.privateKey,
          passphrase: dec.payload.passphrase,
        };
      } else if (dec.payload.kind === 'snmpv2c' && dec.payload.community) {
        snmpCommunity = dec.payload.community;
      }
    }

    const providerId: CloudProviderId = cloudCred?.provider || srv.cloudProvider || 'generic-rest';
    const adapter = providerRegistry.get(providerId);
    const instanceId = srv.cloudInstanceId || srv.hostname;

    let cloudOk = false;
    let cloudRes: CloudTelemetryResult | null = null;
    if (allowCloudApi && adapter && (cloudCred || srv.cloudProvider)) {
      cloudRes = await adapter.fetchTelemetry({
        instanceId,
        apiToken: cloudCred?.token,
        baseUrl: cloudCred?.baseUrl,
        timeoutMs: Math.min(6000, ctx.timeoutMs),
      });
      if (cloudRes.ok) {
        cloudOk = true;
        if (typeof cloudRes.cpuPct === 'number') srv.cpuPct = cloudRes.cpuPct;
        if (typeof cloudRes.ramPct === 'number') srv.ramPct = cloudRes.ramPct;
        if (typeof cloudRes.ramTotalGb === 'number') srv.ramTotalGb = cloudRes.ramTotalGb;
        if (typeof cloudRes.diskPct === 'number') srv.diskPct = cloudRes.diskPct;
        if (typeof cloudRes.diskTotalGb === 'number') srv.diskTotalGb = cloudRes.diskTotalGb;
        if (cloudRes.osHint) srv.osVersion = cloudRes.osHint;
        if (typeof cloudRes.rxKbps === 'number' || typeof cloudRes.txKbps === 'number') {
          srv.networkInterfaces = [{ name: 'cloud-wan0', rxKbps: cloudRes.rxKbps || 0, txKbps: cloudRes.txKbps || 0 }];
        }
      }
    }

    // Augment with authorized Read-Only SSH if guest metrics (like RAM/Disk) aren't exposed by Cloud API
    let sshOk = false;
    if (allowSsh && sshCred && isValidTargetHost(target)) {
      const sshRes = await runReadOnlySshTelemetry({
        host: target,
        port: srv.sshPort || 22,
        username: sshCred.username,
        password: sshCred.password,
        privateKey: sshCred.privateKey,
        passphrase: sshCred.passphrase,
        timeoutMs: Math.min(7000, ctx.timeoutMs),
      });
      if (sshRes.ok && sshRes.metrics) {
        sshOk = true;
        const m = sshRes.metrics;
        srv.cpuPct = m.cpuPct;
        srv.ramPct = m.ramPct;
        srv.ramTotalGb = m.ramTotalGb;
        srv.diskTotalGb = m.diskTotalGb;
        srv.diskAvailableGb = m.diskAvailableGb;
        srv.diskPct = m.diskPct;
        srv.uptimeHours = m.uptimeHours;
        srv.loadAverage = m.loadAverage;
        if (m.distro) srv.osVersion = m.distro;
        if (m.interfaces.length > 0) srv.networkInterfaces = m.interfaces;
        if (m.services.length > 0) srv.services = m.services;
      }
    }

    // Passive HTTP / ICMP / TCP / SNMP checks
    const validTarget = isValidTargetHost(target);
    const [pingRes, portResults] = validTarget
      ? await Promise.all([
          allowIcmp
            ? pingHostStats(target, 2, 1200)
            : Promise.resolve({ alive: false, avgLatencyMs: null, minLatencyMs: null, maxLatencyMs: null, packetLossPct: 100 }),
          allowTcp
            ? Promise.all(
                (srv.tcpPorts?.length ? srv.tcpPorts : [22, 80, 443]).slice(0, 6).map(async (p) => ({
                  port: p,
                  open: (await checkTcpPort(target, p, 900)).open,
                }))
              )
            : Promise.resolve([]),
        ])
      : [{ alive: false, avgLatencyMs: null, minLatencyMs: null, maxLatencyMs: null, packetLossPct: 100 }, []];

    let httpOk = false;
    if (allowHttp && srv.httpUrl) {
      try {
        const u = new URL(srv.httpUrl);
        if (u.protocol === 'http:' || u.protocol === 'https:') {
          const resp = await fetch(u.toString(), { method: 'GET', redirect: 'manual', signal: AbortSignal.timeout(4000) });
          httpOk = resp.status < 500;
        }
      } catch {
        httpOk = false;
      }
    }

    let snmpOk = false;
    if (!sshOk && !cloudOk && snmpCommunity && validTarget) {
      const snmpRes = await pollSnmpServerMetrics(target, { version: 'v2c', community: snmpCommunity }, 161, 2500);
      if (snmpRes) {
        snmpOk = true;
        srv.cpuPct = snmpRes.cpuPct;
        srv.ramPct = snmpRes.ramPct;
        srv.ramTotalGb = snmpRes.ramTotalGb;
        srv.diskTotalGb = snmpRes.diskTotalGb;
        srv.diskAvailableGb = snmpRes.diskAvailableGb;
        srv.diskPct = snmpRes.diskPct;
        if (typeof snmpRes.uptimeHours === 'number') srv.uptimeHours = snmpRes.uptimeHours;
      }
    }

    const hasCpu = sshOk || snmpOk || (cloudOk && typeof cloudRes?.cpuPct === 'number');
    const hasRam = sshOk || snmpOk || (cloudOk && typeof cloudRes?.ramPct === 'number');
    const hasDisk = sshOk || snmpOk || (cloudOk && typeof cloudRes?.diskPct === 'number');

    srv.metricsAvailable = {
      cpu: hasCpu,
      ram: hasRam,
      disk: hasDisk,
      uptime: sshOk || snmpOk,
      services: sshOk && srv.services.length > 0,
      networkTraffic: Boolean(srv.networkInterfaces && srv.networkInterfaces.length > 0),
    };

    if (!sshOk) {
      srv.services = portResults.map((p) => ({
        name: `TCP:${p.port}`,
        displayName: `Cloud Port ${p.port}`,
        status: p.open ? 'Running' : 'Stopped',
        startupType: 'Automatic',
      }));
    }

    if (hasCpu || hasRam || hasDisk) {
      srv.history.push({
        time: stamp.slice(11, 16),
        cpuPct: srv.cpuPct,
        ramPct: srv.ramPct,
        diskPct: srv.diskPct,
      });
      if (srv.history.length > 24) srv.history.shift();
    }

    const openPorts = portResults.filter((p) => p.open);
    const reachable = pingRes.alive || openPorts.length > 0 || httpOk || cloudRes?.instanceState === 'Running' || sshOk || snmpOk;

    srv.lastCheck = pingRes.avgLatencyMs !== null ? `${stamp} (${pingRes.avgLatencyMs}ms)` : stamp;
    if (reachable) srv.lastSuccessfulCheck = stamp;

    const availableMetrics: string[] = [];
    if (cloudOk && cloudRes?.instanceState) availableMetrics.push(`Cloud State (${cloudRes.instanceState})`);
    if (hasCpu) availableMetrics.push('CPU %');
    if (hasRam) availableMetrics.push('RAM %');
    if (hasDisk) availableMetrics.push('Disk %');
    if (pingRes.alive) availableMetrics.push(`ICMP (${pingRes.avgLatencyMs ?? 0}ms)`);
    if (openPorts.length > 0) availableMetrics.push(`TCP (${openPorts.map((p) => p.port).join(', ')})`);
    if (httpOk) availableMetrics.push('HTTP/HTTPS OK');

    const failReason =
      credError ||
      cloudRes?.errorDetail ||
      'Provider API did not expose this guest metric and SSH Read-Only is not attached.';

    const collectionStatus: MetricIntegrity['collectionStatus'] =
      hasCpu || (cloudOk && !cloudRes?.errorDetail)
        ? 'Healthy'
        : cloudRes?.status || (credError ? 'Authentication Failed' : reachable ? 'Warning' : 'Unreachable');

    const healthClassification = mapCollectionToHealthClassification({
      reachable,
      hasOsOrPrimaryMetrics: sshOk || (cloudOk && hasCpu),
      hasAnyPassiveMetric: reachable,
      collectionStatus,
    });

    srv.status = cloudRes?.instanceState === 'Stopped' || !reachable ? 'Offline' : 'Online';
    srv.healthClassification = healthClassification;

    const integrity: MetricIntegrity = {
      collectionStatus,
      dataSource: [cloudOk ? adapter?.displayName : '', sshOk ? 'SSH Read-Only' : '', httpOk ? 'HTTP' : '']
        .filter(Boolean)
        .join(' + ') || 'Cloud VPS Probe',
      measuredAt: stamp,
      targetIdentifier: `${providerId}:${instanceId}`,
      errorDetail: !sshOk && !cloudOk ? failReason : undefined,
      prerequisiteHint: cloudRes?.prerequisiteHint || (!sshOk && !cloudOk ? 'Attach a Read-Only Cloud API token or Linux SSH key/credential in Credential Vault.' : undefined),
    };
    srv.integrity = integrity;

    const capabilityMatrix: MonitoringCapabilityMatrix = {
      platformDetected: `Cloud VPS (${adapter?.displayName || providerId})`,
      icmpAvailable: allowIcmp ? pingRes.alive : false,
      tcpAvailable: allowTcp ? openPorts.length > 0 : false,
      winrmAvailable: false,
      wmiAvailable: false,
      sshAvailable: allowSsh ? sshOk : false,
      snmpAvailable: snmpCommunity ? snmpOk : false,
      cloudApiAvailable: allowCloudApi ? cloudOk : false,
      hypervHostAccess: false,
      availableMetrics,
      unavailableMetrics: buildDefaultUnavailableMetrics(srv, failReason),
      accessRestrictions: restrictions,
      activeMethod: integrity.dataSource,
      evaluatedAt: stamp,
    };
    srv.capabilityMatrix = capabilityMatrix;

    return { ok: reachable, integrity, healthClassification, capabilityMatrix };
  }

  async testConnection(srv: WindowsServer, ctx: CollectorContext): Promise<ConnectionTestResult> {
    const started = Date.now();
    const clone: WindowsServer = structuredClone(srv);
    const res = await this.collect(clone, ctx);
    return {
      ok: res.ok,
      status: res.integrity.collectionStatus,
      dataSource: res.integrity.dataSource,
      latencyMs: Date.now() - started,
      measuredAt: res.integrity.measuredAt,
      details: `${res.healthClassification}: ${res.capabilityMatrix.availableMetrics.join(', ') || res.integrity.errorDetail || 'No Cloud API/SSH/ICMP telemetry.'}`,
      prerequisiteHint: res.integrity.prerequisiteHint,
    };
  }
}
