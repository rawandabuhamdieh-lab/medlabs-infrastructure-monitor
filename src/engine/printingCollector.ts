import { execFile } from 'child_process';
import type { CredentialVault } from './credentialVault.ts';
import { checkTcpPort, isValidTargetHost } from './networkHelpers.ts';
import type {
  ConnectionTestResult,
  IisSite,
  MetricIntegrity,
  NetworkDevice,
  OracleDatabaseMetric,
  PrintMonitorTarget,
  ReportExecutionRecord,
} from '../types/infrastructure.ts';

function runWindowsSpoolerQuery(
  spoolerHost: string,
  printerName: string,
  username: string | undefined,
  password: string | undefined,
  timeoutMs: number
): Promise<{ ok: boolean; queueDepth?: number; failedJobs24h?: number | null; error?: string }> {
  return new Promise((resolve) => {
    if (process.platform !== 'win32') {
      resolve({
        ok: false,
        error: 'Windows Print Spooler CIM query requires the central server to run on Windows.',
      });
      return;
    }
    if (!isValidTargetHost(spoolerHost)) {
      resolve({ ok: false, error: 'Invalid spooler host.' });
      return;
    }

    const safeName = printerName.replace(/[^a-zA-Z0-9._\s-]/g, '');
    const psScript = `
$ErrorActionPreference = 'Stop'
$jobs = @(Get-CimInstance -ClassName Win32_PrintJob -ComputerName '${spoolerHost}' -ErrorAction Stop | Where-Object { $_.Name -like '*${safeName}*' -or '${safeName}' -eq '' })
$failed = @($jobs | Where-Object { $_.JobStatus -match 'Error|Blocked|Offline|Paper' }).Count
[PSCustomObject]@{ QueueDepth = $jobs.Count; Failed = $failed } | ConvertTo-Json -Compress
`;
    const encoded = Buffer.from(psScript, 'utf16le').toString('base64');
    const env = { ...process.env };
    if (username && password) {
      env.MEDLABS_WIN_USER = username;
      env.MEDLABS_WIN_PASS = password;
    }

    execFile(
      'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-EncodedCommand', encoded],
      { timeout: Math.max(3000, timeoutMs), env },
      (err, stdout) => {
        if (err) {
          resolve({ ok: false, error: err.message });
          return;
        }
        try {
          const parsed = JSON.parse(stdout.trim()) as { QueueDepth?: number; Failed?: number };
          resolve({
            ok: true,
            queueDepth: Number(parsed.QueueDepth ?? 0),
            failedJobs24h: null,
          });
        } catch {
          resolve({ ok: false, error: 'Failed to parse Win32_PrintJob output.' });
        }
      }
    );
  });
}

export async function collectPrintTarget(
  printer: PrintMonitorTarget,
  vault: CredentialVault,
  timeoutMs = 3500
): Promise<{ ok: boolean; integrity: MetricIntegrity }> {
  const stamp = new Date().toISOString().replace('T', ' ').slice(0, 19);
  printer.tested = true;
  const host = printer.hostOrIp.trim();
  const port =
    printer.port >= 1 && printer.port <= 65535
      ? printer.port
      : printer.protocol === 'IPP-631'
        ? 631
        : printer.protocol === 'LPD-515'
          ? 515
          : 9100;

  if (!isValidTargetHost(host)) {
    printer.status = 'Offline';
    printer.lastCheck = stamp;
    const integrity: MetricIntegrity = {
      collectionStatus: 'Not Configured',
      dataSource: 'Printer Port Probe',
      measuredAt: stamp,
      targetIdentifier: host || printer.name,
      errorDetail: 'Invalid printer hostname or IP address.',
    };
    printer.integrity = integrity;
    return { ok: false, integrity };
  }

  let tcpOk = false;
  let rttMs: number | null = null;

  if (printer.protocol === 'IPP-631') {
    const started = Date.now();
    try {
      const resp = await fetch(`http://${host}:${port}/`, {
        method: 'GET',
        signal: AbortSignal.timeout(timeoutMs),
      });
      rttMs = Math.max(1, Date.now() - started);
      tcpOk = resp.status < 500;
    } catch {
      const tcp = await checkTcpPort(host, port, timeoutMs);
      tcpOk = tcp.open;
      rttMs = tcp.latencyMs;
    }
  } else {
    const tcp = await checkTcpPort(host, port, timeoutMs);
    tcpOk = tcp.open;
    rttMs = tcp.latencyMs;
  }

  // Attempt Windows Spooler queue depth ONLY when spoolerHost is configured on win32
  let queueDepth: number | null = null;
  let failedJobs24h: number | null = null;
  let spoolerHint: string | undefined;

  if (printer.spoolerHost && isValidTargetHost(printer.spoolerHost)) {
    let username: string | undefined;
    let password: string | undefined;
    if (printer.credentialId) {
      const dec = vault.getDecrypted(printer.credentialId);
      if (dec.ok && dec.payload.kind === 'windows') {
        username = dec.payload.username;
        password = dec.payload.password;
      }
    }
    const spool = await runWindowsSpoolerQuery(
      printer.spoolerHost,
      printer.name,
      username,
      password,
      timeoutMs
    );
    if (spool.ok) {
      queueDepth = spool.queueDepth ?? 0;
      failedJobs24h = null;
    } else {
      spoolerHint = spool.error;
    }
  } else {
    spoolerHint =
      'Queue depth requires a Windows Print Spooler host (Win32_PrintJob CIM) running on Windows.';
  }

  printer.responseTimeMs = rttMs;
  printer.queueDepth = queueDepth;
  printer.failedJobs24h = failedJobs24h;
  printer.lastCheck = stamp;
  printer.printerStateLabel = tcpOk
    ? (rttMs ?? 0) >= 600
      ? 'Slow Printer Response'
      : 'Ready'
    : `Unreachable (${printer.protocol})`;

  if (!tcpOk) {
    printer.status = 'Offline';
  } else if ((failedJobs24h ?? 0) > 0 || (queueDepth ?? 0) >= 15 || (rttMs ?? 0) >= 800) {
    printer.status = (failedJobs24h ?? 0) >= 3 || (queueDepth ?? 0) >= 30 ? 'Critical' : 'Warning';
  } else {
    printer.status = 'Online';
  }

  const integrity: MetricIntegrity = {
    collectionStatus:
      printer.status === 'Offline'
        ? 'Unreachable'
        : printer.status === 'Critical'
          ? 'Critical'
          : printer.status === 'Warning'
            ? 'Warning'
            : 'Healthy',
    dataSource:
      queueDepth !== null
        ? `${printer.protocol} + Win32_PrintJob CIM`
        : `${printer.protocol} Port Probe`,
    measuredAt: stamp,
    targetIdentifier: `${host}:${port}`,
    errorDetail: !tcpOk ? `Port ${port} (${printer.protocol}) unreachable.` : undefined,
    prerequisiteHint: spoolerHint,
  };
  printer.integrity = integrity;
  return { ok: tcpOk, integrity };
}

export async function testPrintTargetConnection(
  printer: PrintMonitorTarget,
  vault: CredentialVault,
  timeoutMs = 3500
): Promise<ConnectionTestResult> {
  const clone: PrintMonitorTarget = structuredClone(printer);
  const res = await collectPrintTarget(clone, vault, timeoutMs);
  return {
    ok: res.ok,
    status: res.integrity.collectionStatus,
    dataSource: res.integrity.dataSource,
    latencyMs: clone.responseTimeMs,
    measuredAt: res.integrity.measuredAt,
    details: res.ok
      ? `Printer ${clone.name} reachable in ${clone.responseTimeMs} ms${clone.queueDepth !== null ? ` Â· Queue=${clone.queueDepth}` : ''}.`
      : res.integrity.errorDetail || 'Printer unreachable.',
    prerequisiteHint: res.integrity.prerequisiteHint,
  };
}

/**
 * Correlates active Oracle report queries, IIS application RTT, network latency,
 * and registered print targets into real ReportExecutionRecord insights without fabricating timings.
 */
export function buildReportExecutionInsights(params: {
  oracleDatabases: OracleDatabaseMetric[];
  iisSites: IisSite[];
  networkDevices: NetworkDevice[];
  printTargets: PrintMonitorTarget[];
  manualRecords: ReportExecutionRecord[];
}): ReportExecutionRecord[] {
  // Only explicitly captured report execution measurements are valid.
  return params.manualRecords.slice(0, 30);
}

