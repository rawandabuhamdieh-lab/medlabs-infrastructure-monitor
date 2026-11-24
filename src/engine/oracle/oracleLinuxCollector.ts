import { Client as SshClient } from 'ssh2';
import type { CredentialVault } from '../credentialVault.ts';
import { maskSensitiveText } from '../credentialVault.ts';
import { checkTcpPort, isValidTargetHost } from '../networkHelpers.ts';
import type {
  OciInstanceMetrics,
  OracleConnectorHealth,
  OracleHistoryRecord,
  OracleLinuxFilesystem,
  OracleLinuxOsConfig,
  OracleLinuxOsMetrics,
  WindowsServiceItem,
} from '../../types/infrastructure.ts';
import { buildOracleHistoryRecord } from './oracleMetrics.ts';
import type { OracleLinuxCollectionResult } from './oracleTypes.ts';

// Strictly predefined, read-only Oracle Linux 7/8/9+ inspection command (zero sudo, zero writes, zero installs)
export const READ_ONLY_ORACLE_LINUX_CMD = [
  'export LC_ALL=C',
  'echo "===OS==="',
  'if [ -f /etc/oracle-release ]; then cat /etc/oracle-release; elif [ -f /etc/os-release ]; then . /etc/os-release && echo "${PRETTY_NAME:-$NAME $VERSION_ID}"; else uname -srm; fi',
  'echo "===KERNEL==="',
  'uname -r 2>/dev/null || echo ""',
  'echo "===HOST==="',
  'hostname 2>/dev/null || uname -n',
  'echo "===CORES==="',
  'nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo 2>/dev/null || echo "0"',
  'echo "===UPTIME==="',
  'cat /proc/uptime 2>/dev/null || echo "0 0"',
  'echo "===LOAD==="',
  'cat /proc/loadavg 2>/dev/null || echo "0 0 0"',
  'echo "===CPU==="',
  'awk \'/^cpu /{print $2,$3,$4,$5,$6,$7,$8}\' /proc/stat; sleep 0.25; awk \'/^cpu /{print $2,$3,$4,$5,$6,$7,$8}\' /proc/stat',
  'echo "===MEM==="',
  'awk \'/MemTotal:|MemAvailable:|MemFree:|Buffers:|Cached:|SwapTotal:|SwapFree:/{print $1,$2}\' /proc/meminfo 2>/dev/null',
  'echo "===FS==="',
  'df -B1 -P -x tmpfs -x devtmpfs -x squashfs -x overlay 2>/dev/null | awk \'NR>1{print $1"|"$6"|"$2"|"$3"|"$4"|"$5}\'',
  'echo "===NET==="',
  'for n in $(awk -F: \'NR>2{gsub(/ /,"",$1); if($1!="lo") print $1}\' /proc/net/dev 2>/dev/null | head -n 8); do rx=$(cat /sys/class/net/$n/statistics/rx_bytes 2>/dev/null || echo 0); tx=$(cat /sys/class/net/$n/statistics/tx_bytes 2>/dev/null || echo 0); rxe=$(cat /sys/class/net/$n/statistics/rx_errors 2>/dev/null || echo 0); txe=$(cat /sys/class/net/$n/statistics/tx_errors 2>/dev/null || echo 0); st=$(cat /sys/class/net/$n/operstate 2>/dev/null || echo unknown); echo "$n|$rx|$tx|$rxe|$txe|$st"; done',
  'echo "===PROCS==="',
  'ps -e --no-headers 2>/dev/null | wc -l',
  'echo "===SVCS==="',
  'if command -v systemctl >/dev/null 2>&1; then systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null | head -n 15; fi',
].join('\n');

export function validateReadOnlyOracleLinuxCommand(cmd: string): boolean {
  return cmd === READ_ONLY_ORACLE_LINUX_CMD;
}

export function parseOracleLinuxOutput(raw: string): OracleLinuxOsMetrics {
  const stamp = new Date().toISOString().replace('T', ' ').slice(0, 19);
  const section = (name: string): string => {
    const marker = `===${name}===`;
    const idx = raw.indexOf(marker);
    if (idx === -1) return '';
    const start = idx + marker.length;
    const next = raw.indexOf('===', start);
    return (next === -1 ? raw.slice(start) : raw.slice(start, next)).trim();
  };

  const osVersion = section('OS').split('\n')[0]?.trim() || undefined;
  const kernelVersion = section('KERNEL').split('\n')[0]?.trim() || undefined;
  const hostname = section('HOST').split('\n')[0]?.trim() || undefined;
  const cpuCoresNum = Number(section('CORES').split(/\s+/)[0] || 0);
  const cpuCores = Number.isFinite(cpuCoresNum) && cpuCoresNum > 0 ? cpuCoresNum : null;

  const uptimeSec = parseFloat(section('UPTIME').split(/\s+/)[0] || '0') || 0;
  const uptimeHours = uptimeSec > 0 ? Number((uptimeSec / 3600).toFixed(1)) : null;

  const loadParts = section('LOAD').split(/\s+/).slice(0, 3);
  const loadAverage = loadParts.length === 3 ? loadParts.join(' ') : undefined;

  let cpuPct: number | null = null;
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

  const memMap = new Map<string, number>();
  for (const line of section('MEM').split('\n')) {
    const [k, v] = line.trim().split(/\s+/);
    if (k && v) memMap.set(k.replace(':', ''), Number(v));
  }
  const totalKb = memMap.get('MemTotal') || 0;
  const availKb =
    memMap.get('MemAvailable') ??
    (memMap.get('MemFree') || 0) + (memMap.get('Buffers') || 0) + (memMap.get('Cached') || 0);
  const usedKb = totalKb > 0 ? Math.max(0, totalKb - Math.min(totalKb, availKb)) : 0;

  const ramTotalGb = totalKb > 0 ? Number((totalKb / 1024 / 1024).toFixed(1)) : null;
  const ramUsedGb = totalKb > 0 ? Number((usedKb / 1024 / 1024).toFixed(1)) : null;
  const ramAvailableGb = totalKb > 0 ? Number((availKb / 1024 / 1024).toFixed(1)) : null;
  const ramPct = totalKb > 0 ? Number(((usedKb / totalKb) * 100).toFixed(1)) : null;

  const swapTotalKb = memMap.get('SwapTotal') || 0;
  const swapFreeKb = memMap.get('SwapFree') || 0;
  const swapUsedKb = Math.max(0, swapTotalKb - swapFreeKb);
  const swapTotalGb = swapTotalKb > 0 ? Number((swapTotalKb / 1024 / 1024).toFixed(1)) : 0;
  const swapUsedGb = swapTotalKb > 0 ? Number((swapUsedKb / 1024 / 1024).toFixed(1)) : 0;
  const swapPct = swapTotalKb > 0 ? Number(((swapUsedKb / swapTotalKb) * 100).toFixed(1)) : 0;

  const filesystems: OracleLinuxFilesystem[] = [];
  let sumTotalBytes = 0;
  let sumUsedBytes = 0;
  let sumAvailBytes = 0;
  for (const line of section('FS').split('\n').filter(Boolean)) {
    const [fsName, mount, totStr, usedStr, availStr, pctStr] = line.split('|');
    const tot = Number(totStr || 0);
    const used = Number(usedStr || 0);
    const avail = Number(availStr || 0);
    if (!mount || tot <= 0) continue;
    sumTotalBytes += tot;
    sumUsedBytes += used;
    sumAvailBytes += avail;
    filesystems.push({
      filesystem: fsName || 'unknown',
      mountPoint: mount,
      totalGb: Number((tot / 1024 ** 3).toFixed(1)),
      usedGb: Number((used / 1024 ** 3).toFixed(1)),
      availableGb: Number((avail / 1024 ** 3).toFixed(1)),
      usedPct: Number(String(pctStr || '0').replace('%', '')) || Number(((used / tot) * 100).toFixed(1)),
    });
  }

  const diskTotalGb = sumTotalBytes > 0 ? Number((sumTotalBytes / 1024 ** 3).toFixed(1)) : null;
  const diskUsedGb = sumTotalBytes > 0 ? Number((sumUsedBytes / 1024 ** 3).toFixed(1)) : null;
  const diskAvailableGb = sumTotalBytes > 0 ? Number((sumAvailBytes / 1024 ** 3).toFixed(1)) : null;
  const diskPct = sumTotalBytes > 0 ? Number(((sumUsedBytes / sumTotalBytes) * 100).toFixed(1)) : null;

  const networkInterfaces: OracleLinuxOsMetrics['networkInterfaces'] = [];
  for (const line of section('NET').split('\n').filter(Boolean)) {
    const [name, rxStr, txStr, rxErrStr, txErrStr, state] = line.split('|');
    if (!name) continue;
    const rxBytes = Number(rxStr || 0);
    const txBytes = Number(txStr || 0);
    networkInterfaces.push({
      name,
      rxKbps: uptimeSec > 0 ? Number(((rxBytes * 8) / 1000 / uptimeSec).toFixed(1)) : 0,
      txKbps: uptimeSec > 0 ? Number(((txBytes * 8) / 1000 / uptimeSec).toFixed(1)) : 0,
      rxErrors: Number(rxErrStr || 0),
      txErrors: Number(txErrStr || 0),
      state: state || 'unknown',
    });
  }

  const procNum = Number(section('PROCS').split(/\s+/)[0] || 0);
  const processCount = Number.isFinite(procNum) && procNum > 0 ? procNum : null;

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
    osVersion,
    kernelVersion,
    hostname,
    cpuPct,
    cpuCores,
    ramTotalGb,
    ramUsedGb,
    ramAvailableGb,
    ramPct,
    swapTotalGb,
    swapUsedGb,
    swapPct,
    diskTotalGb,
    diskUsedGb,
    diskAvailableGb,
    diskPct,
    filesystems,
    loadAverage,
    uptimeHours,
    networkInterfaces,
    processCount,
    services,
    source: 'SSH',
    collectedAt: stamp,
  };
}

function execOracleLinuxSsh(params: {
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
  metrics?: OracleLinuxOsMetrics;
  errorDetail?: string;
}> {
  if (!validateReadOnlyOracleLinuxCommand(READ_ONLY_ORACLE_LINUX_CMD)) {
    return Promise.resolve({
      ok: false,
      status: 'Permission Denied',
      errorDetail: 'Oracle Linux SSH command failed read-only allowlist check.',
    });
  }

  return new Promise((resolve) => {
    const conn = new SshClient();
    let settled = false;
    const finish = (res: {
      ok: boolean;
      status: 'Healthy' | 'Authentication Failed' | 'Permission Denied' | 'Unreachable';
      metrics?: OracleLinuxOsMetrics;
      errorDetail?: string;
    }) => {
      if (settled) return;
      settled = true;
      try {
        conn.end();
      } catch {
        // ignore close error
      }
      resolve(res);
    };

    const timer = setTimeout(() => {
      finish({
        ok: false,
        status: 'Unreachable',
        errorDetail: `SSH TCP/${params.port} timed out after ${params.timeoutMs}ms.`,
      });
    }, params.timeoutMs + 1000);

    conn.on('ready', () => {
      conn.exec(READ_ONLY_ORACLE_LINUX_CMD, (err, stream) => {
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
            metrics: parseOracleLinuxOutput(stdout),
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

export async function collectOracleLinuxOs(params: {
  targetId: string;
  fallbackHost: string;
  config?: OracleLinuxOsConfig;
  vault: CredentialVault;
  ociMetricsFallback?: OciInstanceMetrics;
  timeoutMs?: number;
}): Promise<OracleLinuxCollectionResult> {
  const stamp = new Date().toISOString().replace('T', ' ').slice(0, 19);
  const started = Date.now();
  const cfg = params.config;
  const timeoutMs = params.timeoutMs ?? 8000;

  const buildOciFallbackMetrics = (): OracleLinuxOsMetrics | undefined => {
    const oci = params.ociMetricsFallback;
    if (!oci) return undefined;
    if (oci.cpuUtilizationPct === null && oci.cpuUtilizationPct === undefined) return undefined;
    return {
      osVersion: 'Oracle Linux (OCI Hypervisor Fallback)',
      cpuPct: oci.cpuUtilizationPct ?? null,
      ramPct: oci.memoryUtilizationPct ?? null,
      loadAverage: oci.loadAverage !== null && oci.loadAverage !== undefined ? String(oci.loadAverage) : undefined,
      filesystems: [],
      networkInterfaces: [],
      services: [],
      fallbackFromOci: true,
      source: 'OCI API',
      collectedAt: oci.collectedAt,
    };
  };

  if (!cfg || !cfg.enabled) {
    const fallback = buildOciFallbackMetrics();
    const connector: OracleConnectorHealth = {
      connector: 'Oracle Linux OS',
      status: fallback ? 'Access Restricted' : 'Not Configured',
      collectionStatus: 'Not Configured',
      source: fallback ? 'OCI API' : 'SSH',
      lastAttemptAt: stamp,
      availableMetrics: fallback ? ['OCI Hypervisor CPU/Load Fallback'] : [],
      unavailableMetrics: [
        {
          metric: 'Oracle Linux Guest OS (SSH)',
          reason: 'Read-only SSH OS monitoring is not authorized/enabled for this target.',
        },
      ],
      prerequisiteHint:
        'Enable Oracle Linux SSH monitoring and attach a Read-Only SSH account (key or password, zero sudo) to inspect OS memory, swap, filesystems, and kernel.',
    };
    return { ok: false, connector, metrics: fallback, historyRecords: [] };
  }

  const host = (cfg.host?.trim() || params.fallbackHost).trim();
  const port = cfg.port || 22;

  if (!isValidTargetHost(host)) {
    const connector: OracleConnectorHealth = {
      connector: 'Oracle Linux OS',
      status: 'Not Configured',
      collectionStatus: 'Not Configured',
      source: 'SSH',
      lastAttemptAt: stamp,
      availableMetrics: [],
      unavailableMetrics: [{ metric: 'Target Host', reason: 'Oracle Linux host/IP is invalid.' }],
      errorDetail: 'Invalid Oracle Linux SSH host.',
    };
    return { ok: false, connector, historyRecords: [] };
  }

  const credRes = cfg.credentialId ? params.vault.getDecrypted(cfg.credentialId) : null;
  if (!credRes || !credRes.ok || credRes.payload.kind !== 'linux-ssh' || !credRes.payload.username) {
    const fallback = buildOciFallbackMetrics();
    const reason = credRes && !credRes.ok ? credRes.error : 'Attach a Linux SSH Read-Only credential profile.';
    const connector: OracleConnectorHealth = {
      connector: 'Oracle Linux OS',
      status: credRes && !credRes.ok ? 'Authentication Failed' : 'Not Configured',
      collectionStatus: credRes && !credRes.ok ? 'Authentication Failed' : 'Not Configured',
      source: fallback ? 'OCI API' : 'SSH',
      lastAttemptAt: stamp,
      availableMetrics: fallback ? ['OCI Hypervisor CPU/Load Fallback'] : [],
      unavailableMetrics: [{ metric: 'SSH OS Telemetry', reason }],
      errorDetail: reason,
    };
    return { ok: false, connector, metrics: fallback, historyRecords: [] };
  }

  const tcpProbe = await checkTcpPort(host, port, Math.min(2500, timeoutMs));
  if (!tcpProbe.open) {
    const fallback = buildOciFallbackMetrics();
    const connector: OracleConnectorHealth = {
      connector: 'Oracle Linux OS',
      status: 'Unreachable',
      collectionStatus: 'Unreachable',
      source: fallback ? 'OCI API' : 'SSH',
      lastAttemptAt: stamp,
      latencyMs: Date.now() - started,
      availableMetrics: fallback ? ['OCI Hypervisor CPU/Load Fallback'] : [],
      unavailableMetrics: [
        { metric: 'Oracle Linux SSH', reason: `TCP/${port} unreachable or blocked by security list (${'timeout'}).` },
      ],
      errorDetail: `SSH port TCP/${port} unreachable on ${host}.`,
      prerequisiteHint: 'Verify OCI Security List / NSG permits read-only SSH from the central monitoring server (or rely on OCI API hypervisor metrics).',
    };
    return { ok: false, connector, metrics: fallback, historyRecords: [] };
  }

  const sshRes = await execOracleLinuxSsh({
    host,
    port,
    username: credRes.payload.username,
    password: credRes.payload.password,
    privateKey: credRes.payload.privateKey,
    passphrase: credRes.payload.passphrase,
    timeoutMs: Math.min(8000, timeoutMs),
  });

  if (!sshRes.ok || !sshRes.metrics) {
    const fallback = buildOciFallbackMetrics();
    const statusMap: Record<string, OracleConnectorHealth['status']> = {
      'Authentication Failed': 'Authentication Failed',
      'Permission Denied': 'Access Restricted',
      Unreachable: 'Unreachable',
    };
    const connector: OracleConnectorHealth = {
      connector: 'Oracle Linux OS',
      status: statusMap[sshRes.status] || 'Unreachable',
      collectionStatus: sshRes.status,
      source: fallback ? 'OCI API' : 'SSH',
      lastAttemptAt: stamp,
      latencyMs: Date.now() - started,
      availableMetrics: fallback ? ['OCI Hypervisor CPU/Load Fallback'] : [],
      unavailableMetrics: [{ metric: 'Oracle Linux SSH', reason: sshRes.errorDetail || 'SSH command failed.' }],
      errorDetail: sshRes.errorDetail,
    };
    return { ok: false, connector, metrics: fallback, historyRecords: [] };
  }

  const m = sshRes.metrics;
  const availableMetrics: string[] = [];
  if (m.osVersion) availableMetrics.push(`OS (${m.osVersion})`);
  if (m.kernelVersion) availableMetrics.push(`Kernel ${m.kernelVersion}`);
  if (m.cpuPct !== null) availableMetrics.push(`CPU (${m.cpuPct}%)`);
  if (m.ramPct !== null) availableMetrics.push(`RAM (${m.ramPct}%)`);
  if (m.diskPct !== null) availableMetrics.push(`Disk (${m.diskPct}%)`);
  if (m.filesystems.length > 0) availableMetrics.push(`Filesystems (${m.filesystems.length})`);
  if (m.networkInterfaces.length > 0) availableMetrics.push(`NICs (${m.networkInterfaces.length})`);

  const isCritical = (m.cpuPct ?? 0) >= 92 || (m.ramPct ?? 0) >= 95 || (m.diskPct ?? 0) >= 92;
  const isWarning = (m.cpuPct ?? 0) >= 80 || (m.ramPct ?? 0) >= 85 || (m.diskPct ?? 0) >= 82;

  const connector: OracleConnectorHealth = {
    connector: 'Oracle Linux OS',
    status: isCritical ? 'Critical' : isWarning ? 'Warning' : 'Healthy',
    collectionStatus: isCritical ? 'Critical' : isWarning ? 'Warning' : 'Healthy',
    source: 'SSH',
    lastAttemptAt: stamp,
    lastSuccessAt: stamp,
    latencyMs: Date.now() - started,
    availableMetrics,
    unavailableMetrics: [],
  };

  const historyRecords: OracleHistoryRecord[] = [];
  const pushHist = (name: string, val: number | string | null | undefined, unit: string) => {
    const rec = buildOracleHistoryRecord({
      serverId: params.targetId,
      platform: 'Oracle Linux',
      metricName: name,
      metricValue: val,
      metricUnit: unit,
      metricSource: 'SSH',
      collectionTime: stamp,
      collectionStatus: connector.status,
    });
    if (rec) historyRecords.push(rec);
  };
  pushHist('Oracle Linux CPU', m.cpuPct, '%');
  pushHist('Oracle Linux RAM', m.ramPct, '%');
  pushHist('Oracle Linux Disk', m.diskPct, '%');

  return {
    ok: true,
    connector,
    metrics: m,
    historyRecords,
  };
}
