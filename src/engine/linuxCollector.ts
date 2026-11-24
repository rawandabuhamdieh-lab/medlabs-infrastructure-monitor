import { Client as SshClient } from 'ssh2';
import { pollSnmpServerMetrics, type SnmpTargetAuth } from '../snmpPoller.ts';
import { maskSensitiveText } from './credentialVault.ts';
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
  ServerNetworkInterface,
  WindowsServer,
  WindowsServiceItem,
} from '../types/infrastructure.ts';

// Strictly read-only, non-destructive inspection command (no sudo, no writes, no package installs)
const READ_ONLY_LINUX_TELEMETRY_CMD = [
  'export LC_ALL=C',
  'echo "===OS==="',
  'if [ -f /etc/os-release ]; then . /etc/os-release && echo "${PRETTY_NAME:-$NAME $VERSION_ID}"; else uname -srm; fi',
  'echo "===HOST==="',
  'hostname 2>/dev/null || uname -n',
  'echo "===UPTIME==="',
  'cat /proc/uptime 2>/dev/null || echo "0 0"',
  'echo "===LOAD==="',
  'cat /proc/loadavg 2>/dev/null || echo "0 0 0"',
  'echo "===CPU==="',
  'awk \'/^cpu /{print $2,$3,$4,$5,$6,$7,$8}\' /proc/stat; sleep 0.3; awk \'/^cpu /{print $2,$3,$4,$5,$6,$7,$8}\' /proc/stat',
  'echo "===MEM==="',
  'awk \'/MemTotal:|MemAvailable:|MemFree:|Buffers:|Cached:/{print $1,$2}\' /proc/meminfo 2>/dev/null',
  'echo "===DISK==="',
  'df -B1 -P -x tmpfs -x devtmpfs -x squashfs 2>/dev/null | awk \'NR>1{t+=$2;u+=$3;a+=$4} END{printf "%d %d %d\\n", t, u, a}\'',
  'echo "===NET==="',
  'awk -F: \'NR>2{gsub(/ /,"",$1); if($1!="lo") print $1, $2}\' /proc/net/dev 2>/dev/null | head -n 8',
  'echo "===SVCS==="',
  'if command -v systemctl >/dev/null 2>&1; then systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null | head -n 12; fi',
].join('\n');

export function validateReadOnlySshCommand(cmd: string): boolean {
  // Reject any command that is not strictly our static read-only telemetry command
  return cmd === READ_ONLY_LINUX_TELEMETRY_CMD;
}

interface ParsedLinuxMetrics {
  distro?: string;
  hostname?: string;
  uptimeHours: number;
  loadAverage?: string;
  cpuPct: number;
  ramTotalGb: number;
  ramPct: number;
  diskTotalGb: number;
  diskAvailableGb: number;
  diskPct: number;
  interfaces: ServerNetworkInterface[];
  services: WindowsServiceItem[];
}

function parseLinuxOutput(raw: string): ParsedLinuxMetrics {
  const section = (name: string): string => {
    const marker = `===${name}===`;
    const idx = raw.indexOf(marker);
    if (idx === -1) return '';
    const start = idx + marker.length;
    const next = raw.indexOf('===', start);
    return (next === -1 ? raw.slice(start) : raw.slice(start, next)).trim();
  };

  const distro = section('OS').split('\n')[0]?.trim() || undefined;
  const hostname = section('HOST').split('\n')[0]?.trim() || undefined;
  const uptimeSec = parseFloat(section('UPTIME').split(/\s+/)[0] || '0') || 0;
  const uptimeHours = Math.round(uptimeSec / 3600);
  const loadParts = section('LOAD').split(/\s+/).slice(0, 3);
  const loadAverage = loadParts.length === 3 ? loadParts.join(' ') : undefined;

  // CPU delta from two /proc/stat samples
  let cpuPct = 0;
  const cpuLines = section('CPU').split('\n').filter(Boolean);
  if (cpuLines.length >= 2) {
    const parseCpu = (line: string) => line.trim().split(/\s+/).map(Number);
    const a = parseCpu(cpuLines[0]);
    const b = parseCpu(cpuLines[1]);
    const sumA = a.reduce((s, n) => s + (Number.isFinite(n) ? n : 0), 0);
    const sumB = b.reduce((s, n) => s + (Number.isFinite(n) ? n : 0), 0);
    const idleA = (a[3] || 0) + (a[4] || 0);
    const idleB = (b[3] || 0) + (b[4] || 0);
    const dTotal = sumB - sumA;
    const dIdle = idleB - idleA;
    if (dTotal > 0) {
      cpuPct = Number((((dTotal - dIdle) / dTotal) * 100).toFixed(1));
    }
  }

  // Memory from /proc/meminfo (in kB)
  const memMap = new Map<string, number>();
  for (const line of section('MEM').split('\n')) {
    const [k, v] = line.trim().split(/\s+/);
    if (k && v) memMap.set(k.replace(':', ''), Number(v));
  }
  const totalKb = memMap.get('MemTotal') || 0;
  const availKb =
    memMap.get('MemAvailable') ??
    (memMap.get('MemFree') || 0) + (memMap.get('Buffers') || 0) + (memMap.get('Cached') || 0);
  const ramTotalGb = totalKb > 0 ? Number((totalKb / 1024 / 1024).toFixed(1)) : 0;
  const ramPct = totalKb > 0 ? Number((((totalKb - Math.min(totalKb, availKb)) / totalKb) * 100).toFixed(1)) : 0;

  // Disk from df -B1
  const dfNums = section('DISK').split(/\s+/).map(Number);
  const diskTotalBytes = dfNums[0] || 0;
  const diskUsedBytes = dfNums[1] || 0;
  const diskAvailBytes = dfNums[2] || 0;
  const diskTotalGb = diskTotalBytes > 0 ? Math.round(diskTotalBytes / 1024 ** 3) : 0;
  const diskAvailableGb = diskAvailBytes > 0 ? Math.round(diskAvailBytes / 1024 ** 3) : 0;
  const diskPct = diskTotalBytes > 0 ? Number(((diskUsedBytes / diskTotalBytes) * 100).toFixed(1)) : 0;

  // Network interfaces (report static snapshot indicator; kbps requires delta if cached)
  const interfaces: ServerNetworkInterface[] = [];
  for (const line of section('NET').split('\n').filter(Boolean)) {
    const parts = line.trim().split(/\s+/);
    const name = parts[0];
    const rxBytes = Number(parts[1] || 0);
    const txBytes = Number(parts[9] || 0);
    if (name) {
      interfaces.push({
        name,
        rxKbps: Number(((rxBytes * 8) / 1000 / Math.max(1, uptimeSec)).toFixed(1)),
        txKbps: Number(((txBytes * 8) / 1000 / Math.max(1, uptimeSec)).toFixed(1)),
      });
    }
  }

  // Running systemd services (read-only)
  const services: WindowsServiceItem[] = [];
  for (const line of section('SVCS').split('\n').filter(Boolean)) {
    const clean = line.replace(/^●\s*/, '').trim();
    const cols = clean.split(/\s+/);
    const unitName = cols[0];
    if (unitName && unitName.endsWith('.service')) {
      services.push({
        name: unitName.replace(/\.service$/, ''),
        displayName: cols.slice(4).join(' ') || unitName,
        status: 'Running',
        startupType: 'Automatic',
      });
    }
  }

  return {
    distro,
    hostname,
    uptimeHours,
    loadAverage,
    cpuPct,
    ramTotalGb,
    ramPct,
    diskTotalGb,
    diskAvailableGb,
    diskPct,
    interfaces,
    services,
  };
}

export async function runReadOnlySshTelemetry(params: {
  host: string;
  port: number;
  username: string;
  password?: string;
  privateKey?: string;
  passphrase?: string;
  timeoutMs: number;
}): Promise<{
  ok: boolean;
  status: 'Healthy' | 'Authentication Failed' | 'Permission Denied' | 'Unreachable';
  metrics?: ParsedLinuxMetrics;
  errorDetail?: string;
}> {
  if (!validateReadOnlySshCommand(READ_ONLY_LINUX_TELEMETRY_CMD)) {
    return { ok: false, status: 'Permission Denied', errorDetail: 'SSH command failed read-only allowlist check.' };
  }

  return new Promise((resolve) => {
    const conn = new SshClient();
    let settled = false;
    const finish = (res: {
      ok: boolean;
      status: 'Healthy' | 'Authentication Failed' | 'Permission Denied' | 'Unreachable';
      metrics?: ParsedLinuxMetrics;
      errorDetail?: string;
    }) => {
      if (settled) return;
      settled = true;
      try {
        conn.end();
      } catch {
        // ignore
      }
      resolve(res);
    };

    const timer = setTimeout(() => {
      finish({ ok: false, status: 'Unreachable', errorDetail: `SSH TCP/${params.port} timed out after ${params.timeoutMs}ms.` });
    }, params.timeoutMs + 1000);

    conn.on('ready', () => {
      conn.exec(READ_ONLY_LINUX_TELEMETRY_CMD, (err, stream) => {
        if (err) {
          clearTimeout(timer);
          finish({
            ok: false,
            status: 'Permission Denied',
            errorDetail: maskSensitiveText(err.message),
          });
          return;
        }
        let stdout = '';
        let stderr = '';
        stream.on('data', (chunk: Buffer) => {
          stdout += chunk.toString('utf8');
        });
        stream.stderr.on('data', (chunk: Buffer) => {
          stderr += chunk.toString('utf8');
        });
        stream.on('close', () => {
          clearTimeout(timer);
          if (!stdout.includes('===MEM===') && stderr.trim()) {
            finish({
              ok: false,
              status: 'Permission Denied',
              errorDetail: maskSensitiveText(stderr.trim().slice(0, 240)),
            });
            return;
          }
          finish({
            ok: true,
            status: 'Healthy',
            metrics: parseLinuxOutput(stdout),
          });
        });
      });
    });

    conn.on('error', (err) => {
      clearTimeout(timer);
      const msg = maskSensitiveText(err.message || 'SSH connection error');
      const isAuth = /authentication|all configured authentication methods failed|key|passphrase/i.test(msg);
      finish({
        ok: false,
        status: isAuth ? 'Authentication Failed' : 'Unreachable',
        errorDetail: msg,
      });
    });

    try {
      conn.connect({
        host: params.host,
        port: params.port,
        username: params.username,
        password: params.password,
        privateKey: params.privateKey,
        passphrase: params.passphrase,
        readyTimeout: Math.max(2500, params.timeoutMs),
      });
    } catch (err) {
      clearTimeout(timer);
      finish({
        ok: false,
        status: 'Unreachable',
        errorDetail: maskSensitiveText(err instanceof Error ? err.message : String(err)),
      });
    }
  });
}

function resolveLinuxAuth(srv: WindowsServer, ctx: CollectorContext): {
  sshCred: { username: string; password?: string; privateKey?: string; passphrase?: string } | null;
  snmpAuth: SnmpTargetAuth | null;
  credError: string | null;
} {
  let sshCred: { username: string; password?: string; privateKey?: string; passphrase?: string } | null = null;
  let snmpAuth: SnmpTargetAuth | null = null;
  let credError: string | null = null;

  if (srv.credentialId) {
    const dec = ctx.vault.getDecrypted(srv.credentialId);
    if (!dec.ok) {
      credError = dec.error;
    } else if (dec.payload.kind === 'linux-ssh' && dec.payload.username) {
      sshCred = {
        username: dec.payload.username,
        password: dec.payload.password,
        privateKey: dec.payload.privateKey,
        passphrase: dec.payload.passphrase,
      };
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

  if (!snmpAuth && srv.snmpCommunity?.trim()) {
    snmpAuth = { version: 'v2c', community: srv.snmpCommunity.trim() };
  }

  return { sshCred, snmpAuth, credError };
}

export class LinuxServerCollector implements ServerCollectorAdapter {
  readonly platform = 'linux' as const;

  async collect(srv: WindowsServer, ctx: CollectorContext): Promise<UnifiedCollectionResult> {
    const stamp = new Date().toISOString().replace('T', ' ').slice(0, 19);
    const target =
      srv.ipAddress && srv.ipAddress !== '—' && srv.ipAddress !== '-' ? srv.ipAddress : srv.hostname;
    const sshPort = srv.sshPort || 22;
    const { prohibitedReasons } = getPermittedMethods(srv);
    const restrictions = [...prohibitedReasons];

    if (!isValidTargetHost(target)) {
      const integrity: MetricIntegrity = {
        collectionStatus: 'Not Configured',
        dataSource: 'Linux Agentless Collector',
        measuredAt: stamp,
        targetIdentifier: srv.hostname,
        errorDetail: 'Target Linux IP/hostname is invalid.',
      };
      const capabilityMatrix: MonitoringCapabilityMatrix = {
        platformDetected: srv.osVersion || 'Linux',
        icmpAvailable: null,
        tcpAvailable: null,
        winrmAvailable: false,
        wmiAvailable: false,
        sshAvailable: null,
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

    const allowIcmp = isMethodPermitted(srv, 'icmp');
    const allowTcp = isMethodPermitted(srv, 'tcp');
    const allowSsh = isMethodPermitted(srv, 'ssh');
    const allowSnmp = isMethodPermitted(srv, 'snmp');
    const allowHttp = isMethodPermitted(srv, 'http-https') && Boolean(srv.httpUrl);

    const ports = Array.isArray(srv.tcpPorts) && srv.tcpPorts.length > 0 ? srv.tcpPorts : [sshPort, 80, 443];
    const [pingRes, portResults] = await Promise.all([
      allowIcmp
        ? pingHostStats(target, 2, 1200)
        : Promise.resolve({ alive: false, avgLatencyMs: null, minLatencyMs: null, maxLatencyMs: null, packetLossPct: 100 }),
      allowTcp
        ? Promise.all(ports.slice(0, 6).map(async (p) => ({ port: p, open: (await checkTcpPort(target, p, 900)).open })))
        : Promise.resolve([]),
    ]);

    const openPorts = portResults.filter((p) => p.open);
    const sshPortOpen = openPorts.some((p) => p.port === sshPort) || (!allowTcp && (await checkTcpPort(target, sshPort, 900)).open);
    const { sshCred, snmpAuth, credError } = resolveLinuxAuth(srv, ctx);

    let sshAvailable: boolean | null = allowSsh ? false : false;
    let snmpAvailable: boolean | null = allowSnmp && snmpAuth ? false : null;
    let sshError: string | undefined;
    let sshStatus: MetricIntegrity['collectionStatus'] = 'Unreachable';
    let osTelemetryOk = false;
    let activeMethod = '';

    // 1. Authorized Read-Only SSH Collection
    if (allowSsh && sshCred && (sshPortOpen || !allowTcp)) {
      const bo = !ctx.bypassBackoff ? ctx.backoff.isBackedOff(srv.id, 'ssh') : { active: false };
      if (bo.active) {
        sshError = `SSH temporarily backed off until ${bo.retryAt} (${bo.reason})`;
        restrictions.push(sshError);
      } else {
        const sshRes = await runReadOnlySshTelemetry({
          host: target,
          port: sshPort,
          username: sshCred.username,
          password: sshCred.password,
          privateKey: sshCred.privateKey,
          passphrase: sshCred.passphrase,
          timeoutMs: Math.min(8000, ctx.timeoutMs),
        });
        if (sshRes.ok && sshRes.metrics) {
          ctx.backoff.clearMethod(srv.id, 'ssh');
          sshAvailable = true;
          osTelemetryOk = true;
          activeMethod = `SSH Read-Only (TCP/${sshPort})`;
          const m = sshRes.metrics;
          if (m.distro) srv.osVersion = m.distro;
          srv.cpuPct = m.cpuPct;
          srv.ramPct = m.ramPct;
          srv.ramTotalGb = m.ramTotalGb;
          srv.diskTotalGb = m.diskTotalGb;
          srv.diskAvailableGb = m.diskAvailableGb;
          srv.diskPct = m.diskPct;
          srv.uptimeHours = m.uptimeHours;
          srv.loadAverage = m.loadAverage;
          if (m.interfaces.length > 0) srv.networkInterfaces = m.interfaces;
          if (m.services.length > 0) srv.services = m.services;
          srv.metricsAvailable = {
            cpu: true,
            ram: m.ramTotalGb > 0,
            disk: m.diskTotalGb > 0,
            uptime: true,
            services: m.services.length > 0,
            networkTraffic: m.interfaces.length > 0,
          };
          srv.history.push({
            time: stamp.slice(11, 16),
            cpuPct: srv.cpuPct,
            ramPct: srv.ramPct,
            diskPct: srv.diskPct,
          });
          if (srv.history.length > 24) srv.history.shift();
        } else {
          sshStatus = sshRes.status;
          sshError = sshRes.errorDetail;
          if (sshRes.status === 'Authentication Failed' || sshRes.status === 'Permission Denied') {
            ctx.backoff.recordBlockedOrDenied(srv.id, 'ssh', sshError || sshRes.status);
          }
        }
      }
    } else if (!allowSsh) {
      restrictions.push('SSH remote inspection is disabled by server monitoring policy.');
    } else if (!sshCred) {
      restrictions.push('No Linux SSH Read-Only credential attached (using SNMP/HTTP/ICMP/TCP fallback).');
    }

    // 2. Automatic Fallback: SNMP Read-Only
    if (!osTelemetryOk && allowSnmp && snmpAuth) {
      const snmpRes = await pollSnmpServerMetrics(target, snmpAuth, 161, Math.min(3000, ctx.timeoutMs));
      if (snmpRes) {
        snmpAvailable = true;
        osTelemetryOk = true;
        activeMethod = snmpAuth.version === 'v3' ? 'SNMPv3 Read-Only' : 'SNMPv2c Read-Only';
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

    // 3. Optional HTTP/HTTPS Health Check
    let httpOk = false;
    let httpCode = 0;
    if (allowHttp && srv.httpUrl) {
      try {
        const parsed = new URL(srv.httpUrl);
        if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
          const resp = await fetch(parsed.toString(), { method: 'GET', redirect: 'manual', signal: AbortSignal.timeout(4000) });
          httpCode = resp.status;
          httpOk = resp.status < 500;
        }
      } catch {
        httpOk = false;
      }
    }

    if (!osTelemetryOk) {
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
        displayName: p.port === sshPort ? `SSH Daemon (${sshPort})` : `TCP Service (${p.port})`,
        status: p.open ? 'Running' : 'Stopped',
        startupType: 'Automatic',
      }));
    }

    const reachable = pingRes.alive || openPorts.length > 0 || httpOk || osTelemetryOk;
    srv.lastCheck = pingRes.avgLatencyMs !== null ? `${stamp} (${pingRes.avgLatencyMs}ms)` : stamp;
    if (reachable || osTelemetryOk) srv.lastSuccessfulCheck = stamp;

    const availableMetrics: string[] = [];
    if (pingRes.alive) availableMetrics.push(`ICMP (${pingRes.avgLatencyMs ?? 0}ms)`);
    if (openPorts.length > 0) availableMetrics.push(`TCP (${openPorts.map((p) => p.port).join(', ')})`);
    if (httpOk) availableMetrics.push(`HTTP ${httpCode}`);
    if (osTelemetryOk) availableMetrics.push('CPU', 'RAM', 'Disk', 'Uptime');
    if (srv.loadAverage) availableMetrics.push(`Load (${srv.loadAverage})`);
    if (srv.metricsAvailable?.services) availableMetrics.push('Running Services');
    if (srv.metricsAvailable?.networkTraffic) availableMetrics.push('Network Interfaces');

    const unavailableReason =
      credError ||
      sshError ||
      (!allowSsh
        ? 'SSH disabled by policy; fallback SNMP not configured.'
        : !sshCred
          ? 'No Linux SSH Read-Only or SNMP credential attached.'
          : 'Remote Linux OS telemetry unavailable.');

    const collectionStatus: MetricIntegrity['collectionStatus'] = osTelemetryOk
      ? 'Healthy'
      : credError
        ? 'Authentication Failed'
        : sshError
          ? sshStatus
          : reachable
            ? 'Warning'
            : 'Unreachable';

    const healthClassification = mapCollectionToHealthClassification({
      reachable,
      hasOsOrPrimaryMetrics: osTelemetryOk,
      hasAnyPassiveMetric: pingRes.alive || openPorts.length > 0 || httpOk,
      collectionStatus,
      connectionBlocked: allowSsh && !sshPortOpen && (pingRes.alive || openPorts.length > 0),
    });

    srv.status = osTelemetryOk || reachable ? 'Online' : 'Offline';
    srv.healthClassification = healthClassification;

    const integrity: MetricIntegrity = {
      collectionStatus,
      dataSource: activeMethod || (reachable ? 'Linux Passive (ICMP/TCP/HTTP)' : 'Linux Probe'),
      measuredAt: stamp,
      targetIdentifier: target,
      errorDetail: !osTelemetryOk ? credError || sshError || unavailableReason : undefined,
      prerequisiteHint: !osTelemetryOk
        ? 'Attach an encrypted Read-Only SSH user/key (no sudo required) or enable Read-Only SNMPv2c/v3 on the Linux host.'
        : undefined,
    };
    srv.integrity = integrity;

    const capabilityMatrix: MonitoringCapabilityMatrix = {
      platformDetected: srv.osVersion || 'Linux (Ubuntu/Debian/RHEL/Rocky/Alma/CentOS/CloudLinux)',
      icmpAvailable: allowIcmp ? pingRes.alive : false,
      tcpAvailable: allowTcp ? openPorts.length > 0 : false,
      winrmAvailable: false,
      wmiAvailable: false,
      sshAvailable,
      snmpAvailable,
      cloudApiAvailable: false,
      hypervHostAccess: Boolean(srv.parentHypervHost && srv.hypervVmState),
      availableMetrics,
      unavailableMetrics: buildDefaultUnavailableMetrics(srv, unavailableReason),
      accessRestrictions: restrictions,
      activeMethod: activeMethod || (reachable ? 'ICMP/TCP Fallback' : 'None'),
      evaluatedAt: stamp,
    };
    srv.capabilityMatrix = capabilityMatrix;

    return {
      ok: osTelemetryOk || reachable,
      integrity,
      healthClassification,
      capabilityMatrix,
    };
  }

  async testConnection(srv: WindowsServer, ctx: CollectorContext): Promise<ConnectionTestResult> {
    const started = Date.now();
    const clone: WindowsServer = structuredClone(srv);
    const res = await this.collect(clone, { ...ctx, bypassBackoff: true });
    return {
      ok: res.ok && Boolean(clone.metricsAvailable?.cpu || res.capabilityMatrix.icmpAvailable || res.capabilityMatrix.tcpAvailable),
      status: res.integrity.collectionStatus,
      dataSource: res.integrity.dataSource,
      latencyMs: Date.now() - started,
      measuredAt: res.integrity.measuredAt,
      details: `${res.healthClassification} (${res.capabilityMatrix.platformDetected}): ${res.capabilityMatrix.availableMetrics.join(', ') || res.integrity.errorDetail || 'No response'}`,
      prerequisiteHint: res.integrity.prerequisiteHint,
    };
  }
}
