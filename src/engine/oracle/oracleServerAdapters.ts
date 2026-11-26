import { formatMedLabsTimestamp } from '../time.ts';
import type {
  ConnectionTestResult,
  MetricIntegrity,
  MonitoringCapabilityMatrix,
  OracleDatabaseMetric,
  WindowsServer,
} from '../../types/infrastructure.ts';
import {
  buildDefaultUnavailableMetrics,
  getPermittedMethods,
  isMethodPermitted,
  mapCollectionToHealthClassification,
  type CollectorContext,
  type ServerCollectorAdapter,
  type UnifiedCollectionResult,
} from '../monitoringCapabilities.ts';
import { checkTcpPort, isValidTargetHost, pingHostStats } from '../networkHelpers.ts';
import { collectOciInfrastructure } from './ociCollector.ts';
import { collectOracleLinuxOs } from './oracleLinuxCollector.ts';
import { collectOracleDatabaseOnly } from './oracleDatabaseCollector.ts';

export class OracleLinuxServerAdapter implements ServerCollectorAdapter {
  readonly platform = 'oracle-linux' as const;

  async collect(srv: WindowsServer, ctx: CollectorContext): Promise<UnifiedCollectionResult> {
    const stamp = formatMedLabsTimestamp();
    const target =
      srv.ipAddress && srv.ipAddress !== '—' && srv.ipAddress !== '-' ? srv.ipAddress : srv.hostname;
    const sshPort = srv.sshPort || 22;
    const { prohibitedReasons } = getPermittedMethods(srv);
    const restrictions = [...prohibitedReasons];

    if (!isValidTargetHost(target)) {
      const integrity: MetricIntegrity = {
        collectionStatus: 'Not Configured',
        dataSource: 'Oracle Linux Agentless Collector',
        measuredAt: stamp,
        targetIdentifier: srv.hostname,
        errorDetail: 'Target Oracle Linux IP/hostname is invalid.',
      };
      const capabilityMatrix: MonitoringCapabilityMatrix = {
        platformDetected: srv.osVersion || 'Oracle Linux',
        icmpAvailable: null,
        tcpAvailable: null,
        winrmAvailable: false,
        wmiAvailable: false,
        sshAvailable: null,
        snmpAvailable: null,
        cloudApiAvailable: false,
        ociApiAvailable: null,
        oracleTnsAvailable: null,
        hypervHostAccess: false,
        availableMetrics: [],
        unavailableMetrics: buildDefaultUnavailableMetrics(srv, 'Invalid target IP/hostname.'),
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
    const allowSsh = isMethodPermitted(srv, 'ssh');
    const ports = Array.isArray(srv.tcpPorts) && srv.tcpPorts.length > 0 ? srv.tcpPorts : [sshPort, 1521, 443];

    const [pingRes, portResults] = await Promise.all([
      allowIcmp
        ? pingHostStats(target, 2, 1200)
        : Promise.resolve({ alive: false, avgLatencyMs: null, minLatencyMs: null, maxLatencyMs: null, packetLossPct: 100 }),
      allowTcp
        ? Promise.all(ports.slice(0, 6).map(async (p) => ({ port: p, open: (await checkTcpPort(target, p, 900)).open })))
        : Promise.resolve([]),
    ]);

    const openPorts = portResults.filter((p) => p.open);
    const linuxRes = allowSsh
      ? await collectOracleLinuxOs({
          targetId: srv.id,
          fallbackHost: target,
          config: { enabled: true, host: target, port: sshPort, credentialId: srv.credentialId },
          vault: ctx.vault,
          timeoutMs: ctx.timeoutMs,
        })
      : {
          ok: false,
          connector: {
            connector: 'Oracle Linux OS' as const,
            status: 'Access Restricted' as const,
            collectionStatus: 'Permission Denied' as const,
            source: 'SSH' as const,
            lastAttemptAt: stamp,
            availableMetrics: [],
            unavailableMetrics: [{ metric: 'SSH', reason: 'SSH disabled by monitoring policy.' }],
            errorDetail: 'SSH disabled by monitoring policy.',
          },
          historyRecords: [],
        };

    const m = linuxRes.metrics;
    const osOk = Boolean(linuxRes.ok && m);

    if (osOk && m) {
      if (m.osVersion) srv.osVersion = m.kernelVersion ? `${m.osVersion} (${m.kernelVersion})` : m.osVersion;
      if (m.cpuPct !== null && m.cpuPct !== undefined) srv.cpuPct = m.cpuPct;
      if (m.ramPct !== null && m.ramPct !== undefined) srv.ramPct = m.ramPct;
      if (m.ramTotalGb !== null && m.ramTotalGb !== undefined) srv.ramTotalGb = m.ramTotalGb;
      if (m.diskTotalGb !== null && m.diskTotalGb !== undefined) srv.diskTotalGb = m.diskTotalGb;
      if (m.diskAvailableGb !== null && m.diskAvailableGb !== undefined) srv.diskAvailableGb = m.diskAvailableGb;
      if (m.diskPct !== null && m.diskPct !== undefined) srv.diskPct = m.diskPct;
      if (m.uptimeHours !== null && m.uptimeHours !== undefined) srv.uptimeHours = m.uptimeHours;
      if (m.loadAverage) srv.loadAverage = m.loadAverage;
      if (m.processCount !== null && m.processCount !== undefined) srv.runningProcessesCount = m.processCount;
      if (m.networkInterfaces.length > 0) {
        srv.networkInterfaces = m.networkInterfaces.map((n) => ({
          name: n.name,
          rxKbps: n.rxKbps,
          txKbps: n.txKbps,
        }));
      }
      if (m.services.length > 0) srv.services = m.services;
      srv.metricsAvailable = {
        cpu: m.cpuPct !== null && m.cpuPct !== undefined,
        ram: m.ramPct !== null && m.ramPct !== undefined,
        disk: m.diskPct !== null && m.diskPct !== undefined,
        uptime: m.uptimeHours !== null && m.uptimeHours !== undefined,
        services: m.services.length > 0,
        networkTraffic: m.networkInterfaces.length > 0,
      };
      srv.history.push({
        time: stamp.slice(11, 16),
        cpuPct: srv.cpuPct,
        ramPct: srv.ramPct,
        diskPct: srv.diskPct,
      });
      if (srv.history.length > 24) srv.history.shift();
    } else {
      srv.metricsAvailable = {
        cpu: false,
        ram: false,
        disk: false,
        uptime: false,
        services: false,
        networkTraffic: false,
      };
      srv.services = portResults.map((p) => ({
        name: `TCP:${p.port}`,
        displayName: p.port === sshPort ? `SSH Daemon (${sshPort})` : p.port === 1521 ? 'Oracle Listener (1521)' : `TCP Port (${p.port})`,
        status: p.open ? 'Running' : 'Stopped',
        startupType: 'Automatic',
      }));
    }

    const reachable = pingRes.alive || openPorts.length > 0 || osOk;
    srv.lastCheck = pingRes.avgLatencyMs !== null ? `${stamp} (${pingRes.avgLatencyMs}ms)` : stamp;
    if (reachable || osOk) srv.lastSuccessfulCheck = stamp;
    srv.status = osOk || reachable ? 'Online' : 'Offline';

    const availableMetrics = [
      ...(pingRes.alive ? [`ICMP (${pingRes.avgLatencyMs ?? 0}ms)`] : []),
      ...(openPorts.length > 0 ? [`TCP (${openPorts.map((p) => p.port).join(', ')})`] : []),
      ...linuxRes.connector.availableMetrics,
    ];

    const healthClassification = mapCollectionToHealthClassification({
      reachable,
      hasOsOrPrimaryMetrics: osOk,
      hasAnyPassiveMetric: pingRes.alive || openPorts.length > 0,
      collectionStatus: linuxRes.connector.collectionStatus,
      connectionBlocked: allowSsh && !openPorts.some((p) => p.port === sshPort) && (pingRes.alive || openPorts.length > 0),
    });
    srv.healthClassification = healthClassification;

    const integrity: MetricIntegrity = {
      collectionStatus: osOk ? linuxRes.connector.collectionStatus : reachable ? 'Warning' : linuxRes.connector.collectionStatus,
      dataSource: osOk ? `Oracle Linux SSH (TCP/${sshPort})` : reachable ? 'Oracle Linux Passive (ICMP/TCP)' : 'Oracle Linux Probe',
      measuredAt: stamp,
      targetIdentifier: target,
      errorDetail: osOk ? undefined : linuxRes.connector.errorDetail,
      prerequisiteHint: osOk ? undefined : linuxRes.connector.prerequisiteHint,
    };
    srv.integrity = integrity;

    const capabilityMatrix: MonitoringCapabilityMatrix = {
      platformDetected: srv.osVersion || 'Oracle Linux',
      icmpAvailable: allowIcmp ? pingRes.alive : false,
      tcpAvailable: allowTcp ? openPorts.length > 0 : false,
      winrmAvailable: false,
      wmiAvailable: false,
      sshAvailable: allowSsh ? osOk : false,
      snmpAvailable: null,
      cloudApiAvailable: Boolean(srv.ociInstanceOcid),
      ociApiAvailable: srv.ociInstanceOcid ? null : false,
      oracleTnsAvailable: openPorts.some((p) => p.port === 1521 || p.port === 2484) || Boolean(srv.oracleTnsAlias),
      hypervHostAccess: false,
      availableMetrics,
      unavailableMetrics: osOk
        ? linuxRes.connector.unavailableMetrics
        : buildDefaultUnavailableMetrics(srv, linuxRes.connector.errorDetail || 'Oracle Linux SSH metrics unavailable.'),
      accessRestrictions: restrictions,
      activeMethod: osOk ? `SSH Read-Only (TCP/${sshPort})` : reachable ? 'ICMP/TCP Passive' : 'None',
      evaluatedAt: stamp,
    };
    srv.capabilityMatrix = capabilityMatrix;

    return { ok: osOk || reachable, integrity, healthClassification, capabilityMatrix };
  }

  async testConnection(srv: WindowsServer, ctx: CollectorContext): Promise<ConnectionTestResult> {
    const started = Date.now();
    const clone = structuredClone(srv);
    const res = await this.collect(clone, { ...ctx, bypassBackoff: true });
    return {
      ok: res.ok,
      status: res.integrity.collectionStatus,
      dataSource: res.integrity.dataSource,
      latencyMs: Date.now() - started,
      measuredAt: res.integrity.measuredAt,
      details: `${res.healthClassification}: ${res.capabilityMatrix.availableMetrics.join(', ') || res.integrity.errorDetail || 'Unreachable'}`,
      prerequisiteHint: res.integrity.prerequisiteHint,
    };
  }
}

export class OciComputeServerAdapter implements ServerCollectorAdapter {
  readonly platform = 'oci-compute' as const;

  async collect(srv: WindowsServer, ctx: CollectorContext): Promise<UnifiedCollectionResult> {
    const stamp = formatMedLabsTimestamp();
    const target =
      srv.ipAddress && srv.ipAddress !== '—' && srv.ipAddress !== '-' ? srv.ipAddress : srv.hostname;
    const { prohibitedReasons } = getPermittedMethods(srv);
    const restrictions = [...prohibitedReasons];
    const allowIcmp = isMethodPermitted(srv, 'icmp');
    const allowTcp = isMethodPermitted(srv, 'tcp');
    const ports = Array.isArray(srv.tcpPorts) && srv.tcpPorts.length > 0 ? srv.tcpPorts : [22, 1521, 443];

    const [pingRes, portResults, ociRes] = await Promise.all([
      allowIcmp && isValidTargetHost(target)
        ? pingHostStats(target, 2, 1200)
        : Promise.resolve({ alive: false, avgLatencyMs: null, minLatencyMs: null, maxLatencyMs: null, packetLossPct: 100 }),
      allowTcp && isValidTargetHost(target)
        ? Promise.all(ports.slice(0, 6).map(async (p) => ({ port: p, open: (await checkTcpPort(target, p, 900)).open })))
        : Promise.resolve([]),
      collectOciInfrastructure({
        targetId: srv.id,
        config: {
          enabled: Boolean(srv.ociInstanceOcid && (srv.ociRegion || srv.credentialId)),
          region: srv.ociRegion,
          compartmentOcid: srv.ociCompartment,
          instanceOcid: srv.ociInstanceOcid || srv.cloudInstanceId,
          credentialId: srv.credentialId,
        },
        vault: ctx.vault,
        timeoutMs: ctx.timeoutMs,
      }),
    ]);

    const openPorts = portResults.filter((p) => p.open);
    const ociOk = ociRes.ok && Boolean(ociRes.metrics);
    const m = ociRes.metrics;

    if (ociOk && m) {
      if (m.shape) srv.osVersion = `OCI Compute (${m.shape}${m.lifecycleState ? ` · ${m.lifecycleState}` : ''})`;
      if (m.cpuUtilizationPct !== null && m.cpuUtilizationPct !== undefined) srv.cpuPct = m.cpuUtilizationPct;
      if (m.memoryUtilizationPct !== null && m.memoryUtilizationPct !== undefined) srv.ramPct = m.memoryUtilizationPct;
      if (m.loadAverage !== null && m.loadAverage !== undefined) srv.loadAverage = String(m.loadAverage);
      srv.metricsAvailable = {
        cpu: m.cpuUtilizationPct !== null && m.cpuUtilizationPct !== undefined,
        ram: m.memoryUtilizationPct !== null && m.memoryUtilizationPct !== undefined,
        disk: m.diskBytesRead !== null && m.diskBytesRead !== undefined,
        uptime: Boolean(m.lifecycleState),
        services: false,
        networkTraffic: m.networkBytesIn !== null && m.networkBytesIn !== undefined,
      };
      if (srv.metricsAvailable.cpu) {
        srv.history.push({
          time: stamp.slice(11, 16),
          cpuPct: srv.cpuPct,
          ramPct: srv.ramPct,
          diskPct: srv.diskPct,
        });
        if (srv.history.length > 24) srv.history.shift();
      }
    } else {
      srv.metricsAvailable = {
        cpu: false,
        ram: false,
        disk: false,
        uptime: false,
        services: false,
        networkTraffic: false,
      };
    }

    const reachable = ociOk || pingRes.alive || openPorts.length > 0;
    srv.lastCheck = pingRes.avgLatencyMs !== null ? `${stamp} (${pingRes.avgLatencyMs}ms)` : stamp;
    if (reachable) srv.lastSuccessfulCheck = stamp;
    srv.status =
      m?.lifecycleState && m.lifecycleState !== 'RUNNING'
        ? 'Offline'
        : ociOk || reachable
          ? 'Online'
          : 'Offline';

    const healthClassification = mapCollectionToHealthClassification({
      reachable,
      hasOsOrPrimaryMetrics: ociOk,
      hasAnyPassiveMetric: pingRes.alive || openPorts.length > 0,
      collectionStatus: ociRes.connector.collectionStatus,
      connectionBlocked: !ociOk && (pingRes.alive || openPorts.length > 0),
    });
    srv.healthClassification = healthClassification;

    const integrity: MetricIntegrity = {
      collectionStatus: ociOk ? ociRes.connector.collectionStatus : reachable ? 'Warning' : ociRes.connector.collectionStatus,
      dataSource: ociOk ? 'OCI Monitoring & Compute API' : reachable ? 'OCI Passive (ICMP/TCP)' : 'OCI API Probe',
      measuredAt: stamp,
      targetIdentifier: srv.ociInstanceOcid || target,
      errorDetail: ociOk ? undefined : ociRes.connector.errorDetail,
      prerequisiteHint: ociOk ? undefined : ociRes.connector.prerequisiteHint,
    };
    srv.integrity = integrity;

    const availableMetrics = [
      ...(pingRes.alive ? [`ICMP (${pingRes.avgLatencyMs ?? 0}ms)`] : []),
      ...(openPorts.length > 0 ? [`TCP (${openPorts.map((p) => p.port).join(', ')})`] : []),
      ...ociRes.connector.availableMetrics,
    ];

    const capabilityMatrix: MonitoringCapabilityMatrix = {
      platformDetected: srv.osVersion || 'OCI Compute VM',
      icmpAvailable: allowIcmp ? pingRes.alive : false,
      tcpAvailable: allowTcp ? openPorts.length > 0 : false,
      winrmAvailable: false,
      wmiAvailable: false,
      sshAvailable: openPorts.some((p) => p.port === 22) ? null : false,
      snmpAvailable: null,
      cloudApiAvailable: ociOk,
      ociApiAvailable: ociOk,
      oracleTnsAvailable: openPorts.some((p) => p.port === 1521 || p.port === 2484) || Boolean(srv.oracleTnsAlias),
      hypervHostAccess: false,
      availableMetrics,
      unavailableMetrics: ociOk ? ociRes.connector.unavailableMetrics : buildDefaultUnavailableMetrics(srv, ociRes.connector.errorDetail || 'OCI telemetry unavailable.'),
      accessRestrictions: restrictions,
      activeMethod: ociOk ? 'OCI API (HTTPS Signature v1)' : reachable ? 'ICMP/TCP Passive' : 'None',
      evaluatedAt: stamp,
    };
    srv.capabilityMatrix = capabilityMatrix;

    return { ok: reachable, integrity, healthClassification, capabilityMatrix };
  }

  async testConnection(srv: WindowsServer, ctx: CollectorContext): Promise<ConnectionTestResult> {
    const started = Date.now();
    const clone = structuredClone(srv);
    const res = await this.collect(clone, { ...ctx, bypassBackoff: true });
    return {
      ok: res.ok,
      status: res.integrity.collectionStatus,
      dataSource: res.integrity.dataSource,
      latencyMs: Date.now() - started,
      measuredAt: res.integrity.measuredAt,
      details: `${res.healthClassification}: ${res.capabilityMatrix.availableMetrics.join(', ') || res.integrity.errorDetail || 'Unreachable'}`,
      prerequisiteHint: res.integrity.prerequisiteHint,
    };
  }
}

export class OracleDbServerAdapter implements ServerCollectorAdapter {
  readonly platform = 'oracle-db' as const;

  async collect(srv: WindowsServer, ctx: CollectorContext): Promise<UnifiedCollectionResult> {
    const stamp = formatMedLabsTimestamp();
    const target =
      srv.ipAddress && srv.ipAddress !== '—' && srv.ipAddress !== '-' ? srv.ipAddress : srv.hostname;
    const { prohibitedReasons } = getPermittedMethods(srv);
    const ports = Array.isArray(srv.tcpPorts) && srv.tcpPorts.length > 0 ? srv.tcpPorts : [1521, 2484];

    const [pingRes, portResults] = await Promise.all([
      isValidTargetHost(target)
        ? pingHostStats(target, 2, 1200)
        : Promise.resolve({ alive: false, avgLatencyMs: null, minLatencyMs: null, maxLatencyMs: null, packetLossPct: 100 }),
      isValidTargetHost(target)
        ? Promise.all(ports.slice(0, 4).map(async (p) => ({ port: p, open: (await checkTcpPort(target, p, 900)).open })))
        : Promise.resolve([]),
    ]);

    const openPorts = portResults.filter((p) => p.open);
    let oracleOk = false;
    let oracleStatus: MetricIntegrity['collectionStatus'] = 'Not Configured';
    let oracleErr: string | undefined;
    let oracleHint: string | undefined;
    const availableMetrics: string[] = [
      ...(pingRes.alive ? [`ICMP (${pingRes.avgLatencyMs ?? 0}ms)`] : []),
      ...(openPorts.length > 0 ? [`TCP (${openPorts.map((p) => p.port).join(', ')})`] : []),
    ];

    if (srv.credentialId && (srv.oracleServiceName || srv.oracleTnsAlias)) {
      const tempDb: OracleDatabaseMetric = {
        id: `${srv.id}-ORA-PROBE`,
        serviceName: srv.oracleServiceName || srv.oracleTnsAlias || 'ORCL',
        host: target,
        port: ports[0] || 1521,
        connectionType: srv.oracleTnsAlias ? 'tns' : 'direct',
        tnsAlias: srv.oracleTnsAlias,
        credentialId: srv.credentialId,
        role: 'Primary',
        status: 'Offline',
        availabilityPct: 0,
        responseTimeMs: 0,
        activeSessions: 0,
        blockingSessions: 0,
        connectionFailures24h: 0,
        cpuUsagePct: 0,
        sgaUsedPct: 0,
        pgaUsedMb: 0,
        lastCheck: stamp,
        tablespaces: [],
        longRunningQueries: [],
        responseHistory: [],
      };
      const dbRes = await collectOracleDatabaseOnly(tempDb, ctx.vault, { timeoutMs: ctx.timeoutMs, forceAllCadences: true });
      oracleOk = dbRes.ok;
      oracleStatus = dbRes.connector.collectionStatus;
      oracleErr = dbRes.connector.errorDetail;
      oracleHint = dbRes.connector.prerequisiteHint;
      if (oracleOk) {
        availableMetrics.push(...dbRes.connector.availableMetrics);
        srv.cpuPct = tempDb.cpuUsagePct;
        srv.ramPct = tempDb.sgaUsedPct;
        if (tempDb.dbVersion) srv.osVersion = `Oracle Database ${tempDb.dbVersion}`;
      }
    }

    const reachable = oracleOk || pingRes.alive || openPorts.length > 0;
    srv.lastCheck = pingRes.avgLatencyMs !== null ? `${stamp} (${pingRes.avgLatencyMs}ms)` : stamp;
    if (reachable) srv.lastSuccessfulCheck = stamp;
    srv.status = reachable ? 'Online' : 'Offline';
    srv.metricsAvailable = {
      cpu: oracleOk,
      ram: oracleOk,
      disk: false,
      uptime: oracleOk,
      services: openPorts.length > 0,
      networkTraffic: false,
    };

    const healthClassification = mapCollectionToHealthClassification({
      reachable,
      hasOsOrPrimaryMetrics: oracleOk,
      hasAnyPassiveMetric: pingRes.alive || openPorts.length > 0,
      collectionStatus: oracleStatus,
      connectionBlocked: !oracleOk && !openPorts.some((p) => p.port === 1521 || p.port === 2484),
    });
    srv.healthClassification = healthClassification;

    const integrity: MetricIntegrity = {
      collectionStatus: oracleOk ? oracleStatus : reachable ? 'Warning' : oracleStatus,
      dataSource: oracleOk ? 'Oracle SQL SELECT-only (TNS/Direct)' : 'Oracle Listener Probe (TCP/ICMP)',
      measuredAt: stamp,
      targetIdentifier: srv.oracleTnsAlias || `${target}:${ports[0] || 1521}/${srv.oracleServiceName || ''}`,
      errorDetail: oracleOk ? undefined : oracleErr,
      prerequisiteHint: oracleOk ? undefined : oracleHint,
    };
    srv.integrity = integrity;

    const capabilityMatrix: MonitoringCapabilityMatrix = {
      platformDetected: srv.osVersion || 'Oracle Database Host',
      icmpAvailable: pingRes.alive,
      tcpAvailable: openPorts.length > 0,
      winrmAvailable: false,
      wmiAvailable: false,
      sshAvailable: null,
      snmpAvailable: null,
      cloudApiAvailable: Boolean(srv.ociInstanceOcid),
      ociApiAvailable: srv.ociInstanceOcid ? null : false,
      oracleTnsAvailable: oracleOk || openPorts.some((p) => p.port === 1521 || p.port === 2484),
      hypervHostAccess: false,
      availableMetrics,
      unavailableMetrics: oracleOk ? [] : buildDefaultUnavailableMetrics(srv, oracleErr || 'Oracle DB telemetry not attached or blocked.'),
      accessRestrictions: prohibitedReasons,
      activeMethod: oracleOk ? 'Oracle TNS / SQL SELECT-only' : reachable ? 'ICMP/TCP Listener Probe' : 'None',
      evaluatedAt: stamp,
    };
    srv.capabilityMatrix = capabilityMatrix;

    return { ok: reachable, integrity, healthClassification, capabilityMatrix };
  }

  async testConnection(srv: WindowsServer, ctx: CollectorContext): Promise<ConnectionTestResult> {
    const started = Date.now();
    const clone = structuredClone(srv);
    const res = await this.collect(clone, { ...ctx, bypassBackoff: true });
    return {
      ok: res.ok,
      status: res.integrity.collectionStatus,
      dataSource: res.integrity.dataSource,
      latencyMs: Date.now() - started,
      measuredAt: res.integrity.measuredAt,
      details: `${res.healthClassification}: ${res.capabilityMatrix.availableMetrics.join(', ') || res.integrity.errorDetail || 'Unreachable'}`,
      prerequisiteHint: res.integrity.prerequisiteHint,
    };
  }
}
