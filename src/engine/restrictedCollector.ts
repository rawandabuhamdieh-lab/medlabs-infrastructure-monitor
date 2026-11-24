import { pollSnmpServerMetrics, type SnmpTargetAuth } from '../snmpPoller.ts';
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
import type {
  ConnectionTestResult,
  MetricIntegrity,
  MonitoringCapabilityMatrix,
  WindowsServer,
} from '../types/infrastructure.ts';

function resolveSnmpAuth(srv: WindowsServer, ctx: CollectorContext): SnmpTargetAuth | null {
  if (srv.credentialId) {
    const dec = ctx.vault.getDecrypted(srv.credentialId);
    if (dec.ok) {
      if (dec.payload.kind === 'snmpv2c' && dec.payload.community) {
        return { version: 'v2c', community: dec.payload.community };
      }
      if (dec.payload.kind === 'snmpv3' && dec.payload.username) {
        return {
          version: 'v3',
          username: dec.payload.username,
          securityLevel: dec.payload.snmpSecurityLevel || 'authPriv',
          authProtocol: dec.payload.snmpAuthProtocol || 'SHA',
          authPassword: dec.payload.password,
          privProtocol: dec.payload.snmpPrivProtocol || 'AES',
          privPassword: dec.payload.snmpPrivPassword,
        };
      }
    }
  }
  if (srv.snmpCommunity?.trim()) {
    return { version: 'v2c', community: srv.snmpCommunity.trim() };
  }
  return null;
}

export class RestrictedServerCollector implements ServerCollectorAdapter {
  readonly platform = 'restricted' as const;

  async collect(srv: WindowsServer, ctx: CollectorContext): Promise<UnifiedCollectionResult> {
    const stamp = new Date().toISOString().replace('T', ' ').slice(0, 19);
    const target =
      srv.ipAddress && srv.ipAddress !== '—' && srv.ipAddress !== '-' ? srv.ipAddress : srv.hostname;
    const { prohibitedReasons } = getPermittedMethods(srv);
    const restrictions = [
      ...prohibitedReasons,
      'Strictly passive mode: WinRM, WMI/DCOM, SSH, and administrative commands are never attempted.',
    ];

    if (!isValidTargetHost(target)) {
      const integrity: MetricIntegrity = {
        collectionStatus: 'Not Configured',
        dataSource: 'Restricted Passive Policy',
        measuredAt: stamp,
        targetIdentifier: srv.hostname,
        errorDetail: 'Target hostname or IP address is invalid.',
      };
      const capabilityMatrix: MonitoringCapabilityMatrix = {
        platformDetected: 'Restricted Server',
        icmpAvailable: null,
        tcpAvailable: null,
        winrmAvailable: false,
        wmiAvailable: false,
        sshAvailable: false,
        snmpAvailable: null,
        cloudApiAvailable: false,
        hypervHostAccess: false,
        availableMetrics: [],
        unavailableMetrics: buildDefaultUnavailableMetrics(srv, 'Invalid target host/IP.'),
        accessRestrictions: restrictions,
        evaluatedAt: stamp,
      };
      srv.integrity = integrity;
      srv.capabilityMatrix = capabilityMatrix;
      srv.healthClassification = 'Unsupported Monitoring Method';
      return { ok: false, integrity, healthClassification: srv.healthClassification, capabilityMatrix };
    }

    const allowIcmp = isMethodPermitted(srv, 'icmp');
    const allowTcp = isMethodPermitted(srv, 'tcp');
    const allowHttp = isMethodPermitted(srv, 'http-https') && Boolean(srv.httpUrl);
    const allowSnmp = isMethodPermitted(srv, 'snmp');
    const snmpAuth = allowSnmp ? resolveSnmpAuth(srv, ctx) : null;

    const ports =
      Array.isArray(srv.tcpPorts) && srv.tcpPorts.length > 0 ? srv.tcpPorts.slice(0, 8) : [443, 80, 1433, 1521, 3389];

    const [pingRes, portResults] = await Promise.all([
      allowIcmp
        ? pingHostStats(target, 2, Math.min(1500, ctx.timeoutMs))
        : Promise.resolve({ alive: false, avgLatencyMs: null, minLatencyMs: null, maxLatencyMs: null, packetLossPct: 100, errorDetail: 'ICMP disabled by policy' }),
      allowTcp
        ? Promise.all(
            ports.map(async (p) => ({
              port: p,
              open: (await checkTcpPort(target, p, 900)).open,
            }))
          )
        : Promise.resolve([]),
    ]);

    let httpOk = false;
    let httpStatus = 0;
    let httpLatencyMs = 0;
    let httpErr: string | undefined;
    if (allowHttp && srv.httpUrl) {
      try {
        const parsed = new URL(srv.httpUrl);
        if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
          const started = Date.now();
          const resp = await fetch(parsed.toString(), {
            method: 'GET',
            redirect: 'manual',
            signal: AbortSignal.timeout(Math.min(4000, ctx.timeoutMs)),
          });
          httpStatus = resp.status;
          httpLatencyMs = Math.max(1, Date.now() - started);
          httpOk = resp.status < 500;
        }
      } catch (err) {
        httpErr = err instanceof Error ? err.message : String(err);
      }
    }

    let snmpOk = false;
    if (snmpAuth && (pingRes.alive || portResults.some((p) => p.open) || !allowIcmp)) {
      const snmpRes = await pollSnmpServerMetrics(target, snmpAuth, 161, Math.min(2500, ctx.timeoutMs));
      if (snmpRes) {
        snmpOk = true;
        srv.cpuPct = snmpRes.cpuPct;
        srv.ramPct = snmpRes.ramPct;
        if (snmpRes.ramTotalGb > 0) srv.ramTotalGb = snmpRes.ramTotalGb;
        if (snmpRes.diskTotalGb > 0) {
          srv.diskTotalGb = snmpRes.diskTotalGb;
          srv.diskAvailableGb = snmpRes.diskAvailableGb;
          srv.diskPct = snmpRes.diskPct;
        }
        if (typeof snmpRes.uptimeHours === 'number') srv.uptimeHours = snmpRes.uptimeHours;
        if (snmpRes.osVersion) srv.osVersion = snmpRes.osVersion;
        srv.metricsAvailable = {
          cpu: true,
          ram: snmpRes.ramTotalGb > 0,
          disk: snmpRes.diskTotalGb > 0,
          uptime: typeof snmpRes.uptimeHours === 'number',
          services: false,
          networkTraffic: false,
        };
        srv.history.push({
          time: stamp.slice(11, 16),
          cpuPct: srv.cpuPct,
          ramPct: srv.ramPct,
          diskPct: srv.diskPct,
        });
        if (srv.history.length > 24) srv.history.shift();
      }
    }

    if (!snmpOk) {
      srv.metricsAvailable = {
        cpu: false,
        ram: false,
        disk: false,
        uptime: false,
        services: false,
        networkTraffic: false,
      };
    }

    srv.services = [
      ...portResults.map((p) => ({
        name: `TCP:${p.port}`,
        displayName: `Passive TCP Port ${p.port}`,
        status: (p.open ? 'Running' : 'Stopped') as 'Running' | 'Stopped',
        startupType: 'Automatic' as const,
      })),
      ...(allowHttp && srv.httpUrl
        ? [
            {
              name: 'HTTP-PROBE',
              displayName: `${srv.httpUrl} (${httpStatus || 'Unreachable'})`,
              status: (httpOk ? 'Running' : 'Stopped') as 'Running' | 'Stopped',
              startupType: 'Automatic' as const,
            },
          ]
        : []),
    ];

    const openPorts = portResults.filter((p) => p.open);
    const anyPassiveSuccess = pingRes.alive || openPorts.length > 0 || httpOk || snmpOk;
    const availableMetrics: string[] = [];
    if (pingRes.alive) availableMetrics.push(`ICMP Ping (${pingRes.avgLatencyMs ?? 0}ms)`);
    if (openPorts.length > 0) availableMetrics.push(`TCP Ports (${openPorts.map((p) => p.port).join(', ')})`);
    if (httpOk) availableMetrics.push(`HTTP/HTTPS ${httpStatus} (${httpLatencyMs}ms)`);
    if (snmpOk) availableMetrics.push('SNMP Read-Only OS Metrics');

    // Check if Hyper-V host already populated VM state on this target
    const hasHypervParent = Boolean(srv.parentHypervHost);
    if (hasHypervParent && srv.hypervVmState) {
      availableMetrics.push(`Hyper-V Host State (${srv.hypervVmState})`);
    }

    srv.lastCheck = pingRes.avgLatencyMs !== null ? `${stamp} (${pingRes.avgLatencyMs}ms)` : stamp;
    if (anyPassiveSuccess || snmpOk) {
      srv.lastSuccessfulCheck = stamp;
    }

    const restrictionReason =
      'Prohibited by Restricted Server policy (WinRM, WMI/DCOM, SSH disabled; no agents permitted).';
    const unavailableMetrics = buildDefaultUnavailableMetrics(srv, restrictionReason);

    const collectionStatus: MetricIntegrity['collectionStatus'] = snmpOk
      ? 'Healthy'
      : anyPassiveSuccess
        ? 'Warning'
        : !allowIcmp && !allowTcp && !allowHttp && !snmpAuth
          ? 'Not Configured'
          : 'Unreachable';

    // Never falsely claim a server is Offline if only restricted probes are blocked or partial passive checks pass
    const healthClassification = mapCollectionToHealthClassification({
      reachable: anyPassiveSuccess,
      hasOsOrPrimaryMetrics: snmpOk,
      hasAnyPassiveMetric: anyPassiveSuccess || Boolean(hasHypervParent && srv.hypervVmState),
      collectionStatus,
      connectionBlocked: !anyPassiveSuccess && (Boolean(httpErr) || (!pingRes.alive && allowTcp && openPorts.length === 0)),
    });

    srv.status = snmpOk ? 'Online' : anyPassiveSuccess ? 'Online' : 'Offline';
    srv.healthClassification = healthClassification;

    const integrity: MetricIntegrity = {
      collectionStatus,
      dataSource: snmpOk ? 'Restricted Passive + SNMP Read-Only' : 'Restricted Passive (ICMP/TCP/HTTP)',
      measuredAt: stamp,
      targetIdentifier: target,
      errorDetail: !snmpOk
        ? httpErr ||
          (anyPassiveSuccess
            ? `Passive checks active (${availableMetrics.join(', ')}). OS internals unavailable due to security policy.`
            : 'All permitted passive checks (ICMP/TCP/HTTP) failed or returned no response.')
        : undefined,
      prerequisiteHint: !snmpOk
        ? 'To expand metrics without violating restricted policy: assign an authorized Parent Hyper-V Host or permit read-only SNMPv3/HTTP health endpoint.'
        : undefined,
    };
    srv.integrity = integrity;

    const capabilityMatrix: MonitoringCapabilityMatrix = {
      platformDetected: 'Restricted / Hardened Server',
      icmpAvailable: allowIcmp ? pingRes.alive : false,
      tcpAvailable: allowTcp ? openPorts.length > 0 : false,
      winrmAvailable: false,
      wmiAvailable: false,
      sshAvailable: false,
      snmpAvailable: snmpAuth ? snmpOk : false,
      cloudApiAvailable: false,
      hypervHostAccess: hasHypervParent ? Boolean(srv.hypervVmState) : false,
      availableMetrics,
      unavailableMetrics,
      accessRestrictions: restrictions,
      activeMethod: snmpOk ? 'SNMP Read-Only' : anyPassiveSuccess ? 'Passive ICMP/TCP/HTTP' : 'None Responding',
      evaluatedAt: stamp,
    };
    srv.capabilityMatrix = capabilityMatrix;

    return {
      ok: anyPassiveSuccess || snmpOk,
      integrity,
      healthClassification,
      capabilityMatrix,
    };
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
      details: `${res.healthClassification}: ${res.capabilityMatrix.availableMetrics.join(', ') || 'No passive signals responded.'}`,
      prerequisiteHint: res.integrity.prerequisiteHint,
    };
  }
}
