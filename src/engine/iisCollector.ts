import { formatMedLabsTimestamp } from './time.ts';
import { execFile } from 'child_process';
import tls from 'tls';
import type { CredentialVault } from './credentialVault.ts';
import type {
  ApiEndpointCheck,
  ConnectionTestResult,
  IisAppPool,
  IisSite,
  MetricIntegrity,
} from '../types/infrastructure.ts';

function isValidHttpUrl(raw: string): URL | null {
  try {
    const parsed = new URL(raw.trim());
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return null;
    return parsed;
  } catch {
    return null;
  }
}

function inspectTlsDaysRemaining(hostname: string, port: number, timeoutMs = 2500): Promise<number | null> {
  return new Promise((resolve) => {
    const socket = tls.connect(
      {
        host: hostname,
        port,
        servername: hostname,
        rejectUnauthorized: false,
        timeout: timeoutMs,
      },
      () => {
        try {
          const cert = socket.getPeerCertificate();
          if (cert && cert.valid_to) {
            const expMs = Date.parse(cert.valid_to);
            if (Number.isFinite(expMs)) {
              const days = Math.floor((expMs - Date.now()) / (1000 * 60 * 60 * 24));
              socket.destroy();
              resolve(days);
              return;
            }
          }
        } catch {
          // ignore
        }
        socket.destroy();
        resolve(null);
      }
    );
    socket.on('timeout', () => {
      socket.destroy();
      resolve(null);
    });
    socket.on('error', () => {
      socket.destroy();
      resolve(null);
    });
  });
}

const STATIC_REMOTE_IIS_CIM_PS = `
$ErrorActionPreference = 'Stop'
$target = $env:MEDLABS_IIS_TARGET
$user = $env:MEDLABS_WIN_USER
$pass = $env:MEDLABS_WIN_PASS
$useCred = ($env:MEDLABS_WIN_USE_CRED -eq '1')
$cimSession = $null
try {
  $opt = New-CimSessionOption -Protocol Wsman
  $args = @{ ComputerName = $target; SessionOption = $opt; OperationTimeoutSec = 8 }
  if ($useCred -and -not [string]::IsNullOrWhiteSpace($user) -and $null -ne $pass) {
    $sec = ConvertTo-SecureString -String $pass -AsPlainText -Force
    $args.Credential = New-Object System.Management.Automation.PSCredential($user, $sec)
  }
  $cimSession = New-CimSession @args
  $pools = @()
  $rawPools = Get-CimInstance -CimSession $cimSession -Namespace 'root\\WebAdministration' -ClassName ApplicationPool -Property Name,State,ManagedRuntimeVersion
  foreach ($p in $rawPools) {
    $pools += @{
      name = [string]$p.Name
      serverHostname = $target
      runtime = if ($p.ManagedRuntimeVersion) { "CLR $($p.ManagedRuntimeVersion)" } else { 'No Managed Code / .NET Core' }
      state = if ($p.State -eq 1 -or [string]$p.State -eq 'Started') { 'Started' } else { 'Stopped' }
      workerMemoryMb = 0
      cpuPct = 0
    }
  }
  @{ ok = $true; pools = $pools } | ConvertTo-Json -Depth 4 -Compress
} catch {
  @{ ok = $false; errorMessage = $_.Exception.Message } | ConvertTo-Json -Compress
} finally {
  if ($cimSession) { Remove-CimSession $cimSession }
}
`;

export function collectRemoteIisAppPools(
  host: string,
  username?: string,
  password?: string,
  timeoutMs = 8000
): Promise<{ ok: boolean; pools: IisAppPool[]; errorDetail?: string }> {
  return new Promise((resolve) => {
    if (process.platform !== 'win32') {
      resolve({
        ok: false,
        pools: [],
        errorDetail: 'Remote IIS WebAdministration CIM requires a Windows central monitoring host.',
      });
      return;
    }
    const encoded = Buffer.from(STATIC_REMOTE_IIS_CIM_PS, 'utf16le').toString('base64');
    execFile(
      'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-EncodedCommand', encoded],
      {
        timeout: timeoutMs + 3000,
        env: {
          ...process.env,
          MEDLABS_IIS_TARGET: host,
          MEDLABS_WIN_USE_CRED: username && password ? '1' : '0',
          MEDLABS_WIN_USER: username || '',
          MEDLABS_WIN_PASS: password || '',
        },
      },
      (err, stdout) => {
        const raw = (stdout || '').trim();
        if (raw) {
          try {
            const parsed = JSON.parse(raw) as { ok: boolean; pools?: IisAppPool[]; errorMessage?: string };
            resolve({
              ok: Boolean(parsed.ok),
              pools: parsed.pools || [],
              errorDetail: parsed.errorMessage,
            });
            return;
          } catch {
            // fall through
          }
        }
        resolve({
          ok: false,
          pools: [],
          errorDetail: err?.message || 'Remote IIS CIM query failed.',
        });
      }
    );
  });
}

export async function collectIisSite(
  site: IisSite,
  vault: CredentialVault,
  timeoutMs = 6000
): Promise<{ ok: boolean; integrity: MetricIntegrity; discoveredPools: IisAppPool[] }> {
  const stamp = formatMedLabsTimestamp();
  const parsedUrl = isValidHttpUrl(site.url);
  if (!parsedUrl) {
    const integrity: MetricIntegrity = {
      collectionStatus: 'Not Configured',
      dataSource: 'HTTP/HTTPS Probe',
      measuredAt: stamp,
      targetIdentifier: site.url || site.name,
      errorDetail: 'Site URL must be a valid http:// or https:// URL.',
    };
    site.integrity = integrity;
    return { ok: false, integrity, discoveredPools: [] };
  }

  const started = Date.now();
  let httpStatus = 0;
  let errorDetail: string | undefined;

  try {
    const resp = await fetch(parsedUrl.toString(), {
      method: 'GET',
      redirect: 'manual',
      signal: AbortSignal.timeout(timeoutMs),
    });
    httpStatus = resp.status;
  } catch (err) {
    errorDetail = err instanceof Error ? err.message : String(err);
  }

  const responseTimeMs = httpStatus > 0 ? Math.max(1, Date.now() - started) : 0;
  const sslDays =
    parsedUrl.protocol === 'https:'
      ? await inspectTlsDaysRemaining(
          parsedUrl.hostname,
          Number(parsedUrl.port) || 443,
          Math.min(2500, timeoutMs)
        )
      : null;

  site.httpStatus = httpStatus;
  site.responseTimeMs = responseTimeMs;
  site.sslDaysRemaining = sslDays;
  site.lastCheck = stamp;

  if (httpStatus === 0) {
    site.httpErrors1h += 1;
    site.status = 'Offline';
    site.availabilityPct = Math.max(0, Number((site.availabilityPct * 0.95).toFixed(1)));
    const integrity: MetricIntegrity = {
      collectionStatus: 'Unreachable',
      dataSource: 'Remote HTTP/HTTPS Probe',
      measuredAt: stamp,
      targetIdentifier: site.url,
      errorDetail: errorDetail || 'HTTP/HTTPS request timed out or refused connection.',
      prerequisiteHint: 'Verify IIS site binding, firewall port 80/443, and DNS resolution from the central server.',
    };
    site.integrity = integrity;
    return { ok: false, integrity, discoveredPools: [] };
  }

  if (httpStatus >= 500) {
    site.httpErrors1h += 1;
    site.status = 'Critical';
  } else if (httpStatus >= 400 || responseTimeMs > 1500 || (sslDays !== null && sslDays <= 14)) {
    site.status = 'Warning';
  } else {
    site.status = 'Online';
    site.availabilityPct = 100;
  }

  // Optional native remote WMI root\WebAdministration App Pool read if Windows credential attached
  let discoveredPools: IisAppPool[] = [];
  let appPoolNote: string | undefined;
  if (site.credentialId && site.serverHostname) {
    const dec = vault.getDecrypted(site.credentialId);
    if (dec.ok && dec.payload.kind === 'windows') {
      const fullUser =
        dec.payload.domain && dec.payload.username && !dec.payload.username.includes('\\')
          ? `${dec.payload.domain}\\${dec.payload.username}`
          : dec.payload.username;
      const poolRes = await collectRemoteIisAppPools(
        site.serverHostname,
        dec.payload.useIntegratedAuth ? undefined : fullUser,
        dec.payload.useIntegratedAuth ? undefined : dec.payload.password,
        timeoutMs
      );
      if (poolRes.ok) {
        discoveredPools = poolRes.pools;
      } else if (poolRes.errorDetail) {
        appPoolNote = `HTTP OK (${httpStatus}), AppPool CIM unavailable: ${poolRes.errorDetail.slice(0, 140)}`;
      }
    }
  }

  const integrity: MetricIntegrity = {
    collectionStatus:
      site.status === 'Critical' ? 'Critical' : site.status === 'Warning' ? 'Warning' : 'Healthy',
    dataSource: discoveredPools.length > 0 ? 'HTTP/HTTPS + Native IIS CIM' : 'Remote HTTP/HTTPS Probe',
    measuredAt: stamp,
    targetIdentifier: site.url,
    errorDetail: appPoolNote,
  };
  site.integrity = integrity;
  return { ok: httpStatus < 500, integrity, discoveredPools };
}

export async function collectApiEndpoint(
  api: ApiEndpointCheck,
  timeoutMs = 5000
): Promise<{ ok: boolean; integrity: MetricIntegrity }> {
  const stamp = formatMedLabsTimestamp();
  const parsedUrl = isValidHttpUrl(api.url);
  if (!parsedUrl) {
    const integrity: MetricIntegrity = {
      collectionStatus: 'Not Configured',
      dataSource: 'HTTP/HTTPS API Probe',
      measuredAt: stamp,
      targetIdentifier: api.url,
      errorDetail: 'Invalid http:// or https:// URL.',
    };
    api.integrity = integrity;
    return { ok: false, integrity };
  }

  const started = Date.now();
  try {
    const resp = await fetch(parsedUrl.toString(), {
      method: api.method === 'POST' ? 'POST' : 'GET',
      redirect: 'manual',
      signal: AbortSignal.timeout(timeoutMs),
    });
    api.httpStatus = resp.status;
    api.responseTimeMs = Math.max(1, Date.now() - started);
    api.lastCheck = stamp;
    api.status = resp.status >= 500 ? 'Critical' : resp.status >= 400 ? 'Warning' : 'Online';
    const integrity: MetricIntegrity = {
      collectionStatus:
        api.status === 'Critical' ? 'Critical' : api.status === 'Warning' ? 'Warning' : 'Healthy',
      dataSource: 'HTTP/HTTPS API Probe',
      measuredAt: stamp,
      targetIdentifier: api.url,
    };
    api.integrity = integrity;
    return { ok: resp.status < 500, integrity };
  } catch (err) {
    api.httpStatus = 0;
    api.responseTimeMs = 0;
    api.lastCheck = stamp;
    api.status = 'Offline';
    const integrity: MetricIntegrity = {
      collectionStatus: 'Unreachable',
      dataSource: 'HTTP/HTTPS API Probe',
      measuredAt: stamp,
      targetIdentifier: api.url,
      errorDetail: err instanceof Error ? err.message : String(err),
    };
    api.integrity = integrity;
    return { ok: false, integrity };
  }
}

export async function testIisSiteConnection(
  site: IisSite,
  vault: CredentialVault,
  timeoutMs = 6000
): Promise<ConnectionTestResult> {
  const clone: IisSite = structuredClone(site);
  const res = await collectIisSite(clone, vault, timeoutMs);
  return {
    ok: res.ok,
    status: res.integrity.collectionStatus,
    dataSource: res.integrity.dataSource,
    latencyMs: clone.responseTimeMs || null,
    measuredAt: res.integrity.measuredAt,
    details: res.ok
      ? `HTTP ${clone.httpStatus} in ${clone.responseTimeMs}ms${clone.sslDaysRemaining !== null && clone.sslDaysRemaining !== undefined ? ` · SSL expires in ${clone.sslDaysRemaining} days` : ''}${res.discoveredPools.length > 0 ? ` · ${res.discoveredPools.length} App Pools queried` : ''}.`
      : res.integrity.errorDetail || 'HTTP/HTTPS site unreachable.',
    prerequisiteHint: res.integrity.prerequisiteHint,
  };
}
