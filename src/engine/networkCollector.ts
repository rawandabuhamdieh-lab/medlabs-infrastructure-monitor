import type { CredentialVault } from './credentialVault.ts';
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
import { pollNetworkDeviceSnmp, pollSnmpServerMetrics, type SnmpTargetAuth } from '../snmpPoller.ts';
import type {
  ConnectionTestResult,
  MetricIntegrity,
  MonitoringCapabilityMatrix,
  NetworkDevice,
  WindowsServer,
} from '../types/infrastructure.ts';

export async function collectNetworkDevice(
  dev: NetworkDevice,
  vault: CredentialVault,
  timeoutMs = 2000
): Promise<{ ok: boolean; integrity: MetricIntegrity }> {
  const stamp = new Date().toISOString().replace('T', ' ').slice(0, 19);
  const target = dev.ipAddress.trim();

  if (!isValidTargetHost(target)) {
    const integrity: MetricIntegrity = {
      collectionStatus: 'Not Configured',
      dataSource: 'ICMP + SNMP',
      measuredAt: stamp,
      targetIdentifier: target || dev.name,
      errorDetail: 'Invalid network device IP or hostname.',
    };
    dev.integrity = integrity;
    return { ok: false, integrity };
  }

  const portsToProbe =
    Array.isArray(dev.tcpPorts) && dev.tcpPorts.length > 0
      ? dev.tcpPorts.slice(0, 8)
      : [22, 80, 443];

  const [pingRes, portChecks] = await Promise.all([
    pingHostStats(target, 4, Math.min(2000, timeoutMs)),
    Promise.all(
      portsToProbe.map(async (p) => ({
        port: p,
        open: (await checkTcpPort(target, p, 900)).open,
      }))
    ),
  ]);

  dev.openPorts = portChecks.filter((p) => p.open).map((p) => p.port);
  dev.lastCheck = stamp;
  dev.packetLossPct = pingRes.packetLossPct;
  dev.latencyMs = pingRes.avgLatencyMs ?? 0;

  // Attempt SNMPv2c / SNMPv3 polling if configured
  let snmpAuth: SnmpTargetAuth | null = null;
  let credError: string | null = null;

  if (dev.snmpEnabled && dev.credentialId) {
    const dec = vault.getDecrypted(dev.credentialId);
    if (!dec.ok) {
      credError = dec.error;
    } else if (dec.payload.kind === 'snmpv2c' && dec.payload.community) {
      snmpAuth = { version: 'v2c', community: dec.payload.community };
    } else if (dec.payload.kind === 'snmpv3' && dec.payload.username) {
      snmpAuth = {
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

  let snmpResult = null;
  if (snmpAuth) {
    snmpResult = await pollNetworkDeviceSnmp(target, snmpAuth, 161, Math.max(1500, timeoutMs));
    if (snmpResult.ok) {
      dev.interfaces = snmpResult.interfaces;
      dev.snmpVersion = snmpAuth.version;
    }
  }

  const reachable = pingRes.alive || dev.openPorts.length > 0 || Boolean(snmpResult?.ok);
  dev.latencyHistory.push({
    time: stamp.slice(11, 16),
    latencyMs: dev.latencyMs,
    packetLossPct: dev.packetLossPct,
  });
  if (dev.latencyHistory.length > 24) dev.latencyHistory.shift();

  // Compute observed availability percentage from recorded samples
  const validSamples = dev.latencyHistory.filter((h) => h.packetLossPct < 100).length;
  dev.uptimePct30d =
    dev.latencyHistory.length > 0
      ? Number(((validSamples / dev.latencyHistory.length) * 100).toFixed(1))
      : reachable
        ? 100
        : 0;

  if (!reachable) {
    dev.status = 'Offline';
    const integrity: MetricIntegrity = {
      collectionStatus: 'Unreachable',
      dataSource: snmpAuth ? `ICMP + SNMP${snmpAuth.version}` : 'ICMP + TCP',
      measuredAt: stamp,
      targetIdentifier: target,
      errorDetail: pingRes.errorDetail || 'ICMP Echo Request and configured TCP ports timed out.',
      prerequisiteHint:
        'Check IP reachability, firewall ICMP rules, or SNMP UDP/161 access from the central monitoring server.',
    };
    dev.integrity = integrity;
    return { ok: false, integrity };
  }

  if (credError) {
    dev.status = dev.packetLossPct > 0 ? 'Warning' : 'Online';
    const integrity: MetricIntegrity = {
      collectionStatus: 'Authentication Failed',
      dataSource: 'ICMP + Vault',
      measuredAt: stamp,
      targetIdentifier: target,
      errorDetail: credError,
      prerequisiteHint: 'Set MEDLABS_VAULT_KEY in .env or re-save the SNMP credential profile.',
    };
    dev.integrity = integrity;
    return { ok: false, integrity };
  }

  if (snmpResult && !snmpResult.ok) {
    dev.status = dev.packetLossPct > 0 ? 'Warning' : 'Online';
    const integrity: MetricIntegrity = {
      collectionStatus: snmpResult.status,
      dataSource: `ICMP + SNMP${snmpAuth?.version || ''}`,
      measuredAt: stamp,
      targetIdentifier: target,
      errorDetail: snmpResult.errorDetail,
      prerequisiteHint:
        snmpResult.status === 'Authentication Failed'
          ? 'Verify SNMPv3 username / Auth / Priv passphrases or SNMPv2c Read-Only community.'
          : 'Enable Read-Only SNMPv2c/v3 on the switch/router/firewall allowing UDP/161 from this central server IP.',
    };
    dev.integrity = integrity;
    return { ok: false, integrity };
  }

  dev.status =
    dev.packetLossPct >= 2 || dev.latencyMs >= 200
      ? 'Critical'
      : dev.packetLossPct > 0 || dev.latencyMs >= 80
        ? 'Warning'
        : 'Online';

  const integrity: MetricIntegrity = {
    collectionStatus: dev.status === 'Critical' ? 'Critical' : dev.status === 'Warning' ? 'Warning' : 'Healthy',
    dataSource: snmpResult?.ok ? `ICMP + SNMP${snmpAuth?.version}` : 'ICMP + TCP',
    measuredAt: stamp,
    targetIdentifier: target,
  };
  dev.integrity = integrity;
  return { ok: true, integrity };
}

export async function testNetworkConnection(
  dev: NetworkDevice,
  vault: CredentialVault,
  timeoutMs = 2000
): Promise<ConnectionTestResult> {
  const clone: NetworkDevice = structuredClone(dev);
  const res = await collectNetworkDevice(clone, vault, timeoutMs);
  return {
    ok: res.ok,
    status: res.integrity.collectionStatus,
    dataSource: res.integrity.dataSource,
    latencyMs: clone.latencyMs || null,
    measuredAt: res.integrity.measuredAt,
    details: res.ok
      ? `Ping avg=${clone.latencyMs}ms, loss=${clone.packetLossPct}%, open TCP=[${(clone.openPorts || []).join(', ') || 'none'}]${clone.interfaces ? `, SNMP interfaces=${clone.interfaces.length}` : ''}.`
      : res.integrity.errorDetail || 'Network probe failed.',
    prerequisiteHint: res.integrity.prerequisiteHint,
  };
}

export class NetworkServerAdapter implements ServerCollectorAdapter {
  readonly platform = 'network-device' as const;

  async collect(srv: WindowsServer, ctx: CollectorContext): Promise<UnifiedCollectionResult> {
    const stamp = new Date().toISOString().replace('T', ' ').slice(0, 19);
    const target =
      srv.ipAddress && srv.ipAddress !== 'â€”' && srv.ipAddress !== '-' ? srv.ipAddress : srv.hostname;
    const { prohibitedReasons } = getPermittedMethods(srv);
    const restrictions = [...prohibitedReasons];

    const allowIcmp = isMethodPermitted(srv, 'icmp');
    const allowTcp = isMethodPermitted(srv, 'tcp');
    const allowSnmp = isMethodPermitted(srv, 'snmp');
    const allowHttp = isMethodPermitted(srv, 'http-https') && Boolean(srv.httpUrl);

    if (!isValidTargetHost(target)) {
      const integrity: MetricIntegrity = {
        collectionStatus: 'Not Configured',
        dataSource: 'Network Device Probe',
        measuredAt: stamp,
        targetIdentifier: srv.hostname,
        errorDetail: 'Invalid network device IP or hostname.',
      };
      const capabilityMatrix: MonitoringCapabilityMatrix = {
        platformDetected: 'Network Device',
        icmpAvailable: null,
        tcpAvailable: null,
        winrmAvailable: false,
        wmiAvailable: false,
        sshAvailable: false,
        snmpAvailable: null,
        cloudApiAvailable: false,
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

    const ports = Array.isArray(srv.tcpPorts) && srv.tcpPorts.length > 0 ? srv.tcpPorts : [22, 80, 443, 8443];
    const [pingRes, portChecks] = await Promise.all([
      allowIcmp
        ? pingHostStats(target, 3, Math.min(1800, ctx.timeoutMs))
        : Promise.resolve({ alive: false, avgLatencyMs: null, minLatencyMs: null, maxLatencyMs: null, packetLossPct: 100 }),
      allowTcp
        ? Promise.all(ports.slice(0, 6).map(async (p) => ({ port: p, open: (await checkTcpPort(target, p, 900)).open })))
        : Promise.resolve([]),
    ]);

    let snmpAuth: SnmpTargetAuth | null = null;
    let credErr: string | null = null;
    if (allowSnmp && srv.credentialId) {
      const dec = ctx.vault.getDecrypted(srv.credentialId);
      if (!dec.ok) credErr = dec.error;
      else if (dec.payload.kind === 'snmpv2c' && dec.payload.community) {
        snmpAuth = { version: 'v2c', community: dec.payload.community };
      } else if (dec.payload.kind === 'snmpv3' && dec.payload.username) {
        snmpAuth = {
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
    if (!snmpAuth && allowSnmp && srv.snmpCommunity?.trim()) {
      snmpAuth = { version: 'v2c', community: srv.snmpCommunity.trim() };
    }

    let snmpNetOk = false;
    let snmpSysOk = false;
    let snmpError: string | undefined;

    if (snmpAuth) {
      const [netRes, hostMetrics] = await Promise.all([
        pollNetworkDeviceSnmp(target, snmpAuth, 161, Math.min(2500, ctx.timeoutMs)),
        pollSnmpServerMetrics(target, snmpAuth, 161, Math.min(2500, ctx.timeoutMs)),
      ]);
      if (netRes.ok) {
        snmpNetOk = true;
        if (netRes.sysDescr) srv.osVersion = netRes.sysDescr.slice(0, 80);
        if (typeof netRes.uptimeHours === 'number') srv.uptimeHours = netRes.uptimeHours;
        srv.networkInterfaces = netRes.interfaces.slice(0, 12).map((i) => ({
          name: `${i.name} (${i.operStatus})`,
          rxKbps: i.rxKbps,
          txKbps: i.txKbps,
        }));
      } else {
        snmpError = netRes.errorDetail;
      }
      if (hostMetrics) {
        snmpSysOk = true;
        srv.cpuPct = hostMetrics.cpuPct;
        srv.ramPct = hostMetrics.ramPct;
        if (hostMetrics.ramTotalGb > 0) srv.ramTotalGb = hostMetrics.ramTotalGb;
        if (typeof hostMetrics.uptimeHours === 'number') srv.uptimeHours = hostMetrics.uptimeHours;
      }
    }

    let httpOk = false;
    if (allowHttp && srv.httpUrl) {
      try {
        const u = new URL(srv.httpUrl);
        if (u.protocol === 'http:' || u.protocol === 'https:') {
          const resp = await fetch(u.toString(), { method: 'GET', redirect: 'manual', signal: AbortSignal.timeout(3500) });
          httpOk = resp.status < 500;
        }
      } catch {
        httpOk = false;
      }
    }

    const openPorts = portChecks.filter((p) => p.open);
    const reachable = pingRes.alive || openPorts.length > 0 || snmpNetOk || snmpSysOk || httpOk;
    srv.lastCheck = pingRes.avgLatencyMs !== null ? `${stamp} (${pingRes.avgLatencyMs}ms)` : stamp;
    if (reachable) srv.lastSuccessfulCheck = stamp;

    srv.metricsAvailable = {
      cpu: snmpSysOk,
      ram: snmpSysOk && srv.ramTotalGb > 0,
      disk: false,
      uptime: typeof srv.uptimeHours === 'number' && (snmpNetOk || snmpSysOk),
      services: openPorts.length > 0,
      networkTraffic: snmpNetOk && Boolean(srv.networkInterfaces?.length),
    };

    srv.services = portChecks.map((p) => ({
      name: `TCP:${p.port}`,
      displayName: `Mgmt Port ${p.port}`,
      status: p.open ? 'Running' : 'Stopped',
      startupType: 'Automatic',
    }));

    if (snmpSysOk || pingRes.alive) {
      srv.history.push({
        time: stamp.slice(11, 16),
        cpuPct: snmpSysOk ? srv.cpuPct : 0,
        ramPct: snmpSysOk ? srv.ramPct : 0,
        diskPct: 0,
      });
      if (srv.history.length > 24) srv.history.shift();
    }

    const availableMetrics: string[] = [];
    if (pingRes.alive) availableMetrics.push(`ICMP (${pingRes.avgLatencyMs ?? 0}ms, loss ${pingRes.packetLossPct}%)`);
    if (openPorts.length > 0) availableMetrics.push(`TCP (${openPorts.map((p) => p.port).join(', ')})`);
    if (httpOk) availableMetrics.push('Management HTTP/HTTPS');
    if (snmpNetOk) availableMetrics.push(`SNMP Interfaces (${srv.networkInterfaces?.length ?? 0})`);
    if (snmpSysOk) availableMetrics.push('SNMP CPU / Memory');

    const collectionStatus: MetricIntegrity['collectionStatus'] =
      snmpNetOk || snmpSysOk
        ? 'Healthy'
        : credErr
          ? 'Authentication Failed'
          : reachable
            ? 'Warning'
            : 'Unreachable';

    const healthClassification = mapCollectionToHealthClassification({
      reachable,
      hasOsOrPrimaryMetrics: snmpNetOk || snmpSysOk,
      hasAnyPassiveMetric: reachable,
      collectionStatus,
    });

    srv.status = !reachable ? 'Offline' : pingRes.packetLossPct > 0 ? 'Warning' : 'Online';
    srv.healthClassification = healthClassification;

    const integrity: MetricIntegrity = {
      collectionStatus,
      dataSource: snmpNetOk || snmpSysOk ? `SNMP${snmpAuth?.version || 'v2c'} + ICMP` : 'ICMP + TCP Probe',
      measuredAt: stamp,
      targetIdentifier: target,
      errorDetail: !snmpNetOk && !snmpSysOk ? credErr || snmpError : undefined,
      prerequisiteHint:
        !snmpNetOk && allowSnmp
          ? 'Enable Read-Only SNMPv2c/SNMPv3 on the switch/router/firewall allowing UDP/161 from this central server.'
          : undefined,
    };
    srv.integrity = integrity;

    const capabilityMatrix: MonitoringCapabilityMatrix = {
      platformDetected: srv.osVersion || 'Network Device (Router / Switch / Firewall / Storage)',
      icmpAvailable: allowIcmp ? pingRes.alive : false,
      tcpAvailable: allowTcp ? openPorts.length > 0 : false,
      winrmAvailable: false,
      wmiAvailable: false,
      sshAvailable: false,
      snmpAvailable: snmpAuth ? snmpNetOk : null,
      cloudApiAvailable: false,
      hypervHostAccess: false,
      availableMetrics,
      unavailableMetrics: buildDefaultUnavailableMetrics(srv, snmpError || 'SNMP Read-Only OIDs not enabled/configured.'),
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
      details: `${res.healthClassification}: ${res.capabilityMatrix.availableMetrics.join(', ') || res.integrity.errorDetail || 'No response'}`,
      prerequisiteHint: res.integrity.prerequisiteHint,
    };
  }
}


