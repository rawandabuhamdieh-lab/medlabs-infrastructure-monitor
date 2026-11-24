import { execFile } from 'child_process';
import os from 'os';
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
  HyperVGuestSummary,
  HyperVHostDetails,
  MetricIntegrity,
  MonitoringCapabilityMatrix,
  WindowsServer,
} from '../types/infrastructure.ts';

interface RawHyperVHostResult {
  ok: boolean;
  protocol?: string;
  hostname?: string;
  osVersion?: string;
  cpuPct?: number;
  ramPct?: number;
  ramTotalGb?: number;
  diskTotalGb?: number;
  diskAvailableGb?: number;
  diskPct?: number;
  uptimeHours?: number;
  virtualSwitches?: { name: string; switchType: string; netAdapter?: string }[];
  vms?: HyperVGuestSummary[];
  errorMessage?: string;
}

// Strictly read-only Hyper-V Host telemetry & VM inventory script executed on central server (never creates/modifies VMs or host settings)
const STATIC_HYPERV_HOST_PS = `
$ErrorActionPreference = 'Stop'
$targetRaw = $env:MEDLABS_WIN_TARGET
$hostHint = $env:MEDLABS_WIN_HOSTNAME
$isLocal = ($env:MEDLABS_WIN_IS_LOCAL -eq '1')
$user = $env:MEDLABS_WIN_USER
$pass = $env:MEDLABS_WIN_PASS
$useCred = ($env:MEDLABS_WIN_USE_CRED -eq '1')
$timeoutSec = 10
if ($env:MEDLABS_WIN_TIMEOUT_SEC) { [void][int]::TryParse($env:MEDLABS_WIN_TIMEOUT_SEC, [ref]$timeoutSec) }

$cimSession = $null
$usedProto = 'LocalHyperV'
$resolvedTarget = $targetRaw

try {
  $cred = $null
  if ($useCred -and -not [string]::IsNullOrWhiteSpace($user) -and $null -ne $pass) {
    $sec = ConvertTo-SecureString -String $pass -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential($user, $sec)
  }

  if (-not $isLocal) {
    $candidate = if ($hostHint -and $hostHint -ne 'localhost') { $hostHint } else { $targetRaw }
    try {
      $dnsEntry = [System.Net.Dns]::GetHostEntry($candidate)
      if ($dnsEntry -and $dnsEntry.HostName) { $resolvedTarget = $dnsEntry.HostName }
    } catch {
      if ($hostHint -and ($hostHint -notmatch '^\\d+\\.\\d+\\.\\d+\\.\\d+$')) { $resolvedTarget = $hostHint }
    }

    try {
      $optSsl = New-CimSessionOption -Protocol Wsman -UseSsl -Authentication Kerberos
      $a1 = @{ ComputerName = $resolvedTarget; SessionOption = $optSsl; OperationTimeoutSec = $timeoutSec }
      if ($cred) { $a1.Credential = $cred }
      $cimSession = New-CimSession @a1
      $usedProto = 'WinRM HTTPS (Kerberos)'
    } catch {
      try {
        $optHttp = New-CimSessionOption -Protocol Wsman -Authentication Kerberos
        $a2 = @{ ComputerName = $resolvedTarget; SessionOption = $optHttp; OperationTimeoutSec = $timeoutSec }
        if ($cred) { $a2.Credential = $cred }
        $cimSession = New-CimSession @a2
        $usedProto = 'WinRM HTTP (Kerberos)'
      } catch {
        $optDcom = New-CimSessionOption -Protocol Dcom
        $a3 = @{ ComputerName = $resolvedTarget; SessionOption = $optDcom; OperationTimeoutSec = $timeoutSec }
        if ($cred) { $a3.Credential = $cred }
        $cimSession = New-CimSession @a3
        $usedProto = 'WMI/DCOM'
      }
    }
  }

  $cp = if ($cimSession) { @{ CimSession = $cimSession } } else { @{} }
  $cs = Get-CimInstance Win32_ComputerSystem -Property Name @cp
  $os = Get-CimInstance Win32_OperatingSystem -Property Caption,TotalVisibleMemorySize,FreePhysicalMemory,LastBootUpTime @cp
  $cpus = Get-CimInstance Win32_Processor -Property LoadPercentage @cp
  $disks = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" -Property DeviceID,Size,FreeSpace @cp

  $cpuAvg = ($cpus | Measure-Object -Property LoadPercentage -Average).Average
  $cpuPct = if ($null -ne $cpuAvg) { [math]::Round($cpuAvg, 1) } else { 0 }
  $ramTotalGb = [math]::Round(($os.TotalVisibleMemorySize / 1MB), 1)
  $ramPct = if ($os.TotalVisibleMemorySize -gt 0) { [math]::Round((($os.TotalVisibleMemorySize - $os.FreePhysicalMemory) / $os.TotalVisibleMemorySize) * 100, 1) } else { 0 }
  $diskTotalBytes = ($disks | Measure-Object -Property Size -Sum).Sum
  $diskFreeBytes = ($disks | Measure-Object -Property FreeSpace -Sum).Sum
  $diskTotalGb = if ($diskTotalBytes -gt 0) { [math]::Round($diskTotalBytes / 1GB, 0) } else { 0 }
  $diskAvailGb = if ($diskFreeBytes -gt 0) { [math]::Round($diskFreeBytes / 1GB, 0) } else { 0 }
  $diskPct = if ($diskTotalBytes -gt 0) { [math]::Round((($diskTotalBytes - $diskFreeBytes) / $diskTotalBytes) * 100, 1) } else { 0 }
  $uptimeHours = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalHours, 0)

  $vmList = @()
  $switchList = @()

  # Prefer native CIM root\virtualization\v2 (works cleanly over CimSession without requiring Hyper-V PowerShell module locally)
  $msvmSystems = Get-CimInstance -Namespace 'root\\virtualization\\v2' -ClassName Msvm_ComputerSystem @cp -ErrorAction SilentlyContinue
  $msvmMemSettings = Get-CimInstance -Namespace 'root\\virtualization\\v2' -ClassName Msvm_MemorySettingData @cp -ErrorAction SilentlyContinue
  $msvmSummary = @()
  try {
    # Read-only Hyper-V PowerShell Get-VM if Hyper-V RSAT module is present on central server
    if (Get-Command Get-VM -ErrorAction SilentlyContinue) {
      $vmArgs = if ($isLocal) { @{} } elseif ($cred) { @{ ComputerName = $resolvedTarget; Credential = $cred } } else { @{ ComputerName = $resolvedTarget } }
      $rawVms = Get-VM @vmArgs -ErrorAction SilentlyContinue
      foreach ($v in $rawVms) {
        $vState = switch ([string]$v.State) {
          'Running' { 'Running' }
          'Off' { 'Off' }
          'Paused' { 'Paused' }
          'Saved' { 'Saved' }
          default { 'Other' }
        }
        $nics = @()
        try { $nics = @($v.NetworkAdapters | ForEach-Object { [string]$_.SwitchName } | Where-Object { $_ }) } catch {}
        $disksVm = @()
        try { $disksVm = @($v.HardDrives | ForEach-Object { [string]$_.Path } | Where-Object { $_ }) } catch {}
        $vmList += @{
          name = [string]$v.Name
          state = $vState
          cpuUsagePct = if ($null -ne $v.CPUUsage -and $vState -eq 'Running') { [int]$v.CPUUsage } else { $null }
          cpuAllocated = [int]$v.ProcessorCount
          memoryAssignedMb = [int]([math]::Round($v.MemoryAssigned / 1MB))
          memoryDemandMb = [int]([math]::Round($v.MemoryDemand / 1MB))
          uptimeSeconds = if ($v.Uptime) { [int]$v.Uptime.TotalSeconds } else { 0 }
          integrationServicesVersion = [string]$v.IntegrationServicesVersion
          statusText = [string]$v.Status
          switchNames = $nics
          diskPaths = $disksVm
        }
      }
      $rawSwitches = Get-VMSwitch @vmArgs -ErrorAction SilentlyContinue
      foreach ($sw in $rawSwitches) {
        $switchList += @{
          name = [string]$sw.Name
          switchType = [string]$sw.SwitchType
          netAdapter = [string]$sw.NetAdapterInterfaceDescription
        }
      }
    }
  } catch {}

  # Fallback to root\virtualization\v2 CIM classes if Get-VM module was not available
  if ($vmList.Count -eq 0 -and $msvmSystems) {
    foreach ($m in $msvmSystems) {
      if ($m.Caption -eq 'Virtual Machine') {
        $stateText = switch ([int]$m.EnabledState) {
          2 { 'Running' }
          3 { 'Off' }
          6 { 'Saved' }
          9 { 'Paused' }
          default { 'Other' }
        }
        $upSec = if ($m.OnTimeInMilliseconds) { [int]([math]::Round($m.OnTimeInMilliseconds / 1000)) } else { 0 }
        $vmList += @{
          name = [string]$m.ElementName
          state = $stateText
          cpuUsagePct = $null
          uptimeSeconds = $upSec
          statusText = ($m.StatusDescriptions -join ', ')
        }
      }
    }
    $msvmSw = Get-CimInstance -Namespace 'root\\virtualization\\v2' -ClassName Msvm_VirtualEthernetSwitch @cp -ErrorAction SilentlyContinue
    foreach ($sw in $msvmSw) {
      $switchList += @{
        name = [string]$sw.ElementName
        switchType = 'VirtualSwitch'
      }
    }
  }

  @{
    ok = $true
    protocol = $usedProto
    hostname = [string]$cs.Name
    osVersion = [string]$os.Caption
    cpuPct = $cpuPct
    ramPct = $ramPct
    ramTotalGb = $ramTotalGb
    diskTotalGb = $diskTotalGb
    diskAvailableGb = $diskAvailGb
    diskPct = $diskPct
    uptimeHours = $uptimeHours
    virtualSwitches = $switchList
    vms = $vmList
  } | ConvertTo-Json -Depth 5 -Compress
}
catch {
  @{
    ok = $false
    errorMessage = $_.Exception.Message
  } | ConvertTo-Json -Compress
}
finally {
  if ($cimSession) { Remove-CimSession $cimSession }
}
`;

function isLocalTarget(srv: Pick<WindowsServer, 'hostname' | 'ipAddress'>): boolean {
  const localHost = os.hostname().toLowerCase();
  return (
    srv.hostname.toLowerCase() === localHost ||
    srv.ipAddress === '127.0.0.1' ||
    srv.hostname.toLowerCase() === 'localhost'
  );
}

function runHyperVHostQuery(params: {
  target: string;
  hostnameHint: string;
  isLocal: boolean;
  username?: string;
  password?: string;
  timeoutMs: number;
}): Promise<RawHyperVHostResult> {
  if (process.platform !== 'win32') {
    return Promise.resolve({
      ok: false,
      errorMessage: `Central backend OS (${process.platform}) does not provide native Windows Hyper-V CIM/PowerShell client.`,
    });
  }
  const encoded = Buffer.from(STATIC_HYPERV_HOST_PS, 'utf16le').toString('base64');
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    MEDLABS_WIN_TARGET: params.target,
    MEDLABS_WIN_HOSTNAME: params.hostnameHint,
    MEDLABS_WIN_IS_LOCAL: params.isLocal ? '1' : '0',
    MEDLABS_WIN_TIMEOUT_SEC: String(Math.max(4, Math.round(params.timeoutMs / 1000))),
    MEDLABS_WIN_USE_CRED: params.username && params.password ? '1' : '0',
    MEDLABS_WIN_USER: params.username || '',
    MEDLABS_WIN_PASS: params.password || '',
  };

  return new Promise((resolve) => {
    execFile(
      'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-EncodedCommand', encoded],
      { timeout: params.timeoutMs + 6000, env, maxBuffer: 2 * 1024 * 1024 },
      (err, stdout, stderr) => {
        const raw = (stdout || '').trim();
        if (raw) {
          try {
            resolve(JSON.parse(raw) as RawHyperVHostResult);
            return;
          } catch {
            // fall through
          }
        }
        resolve({
          ok: false,
          errorMessage: err?.message || (stderr || '').trim() || 'Hyper-V read-only query failed.',
        });
      }
    );
  });
}

function resolveHyperVCred(srv: WindowsServer, ctx: CollectorContext): { username?: string; password?: string; err?: string } {
  if (!srv.credentialId) return {};
  const dec = ctx.vault.getDecrypted(srv.credentialId);
  if (!dec.ok) return { err: dec.error };
  if ((dec.payload.kind === 'hyperv' || dec.payload.kind === 'windows') && !dec.payload.useIntegratedAuth) {
    const fullUser =
      dec.payload.domain && dec.payload.username && !dec.payload.username.includes('\\')
        ? `${dec.payload.domain}\\${dec.payload.username}`
        : dec.payload.username;
    return { username: fullUser, password: dec.payload.password };
  }
  return {};
}

export class HyperVHostCollector implements ServerCollectorAdapter {
  readonly platform = 'hyperv-host' as const;

  async collect(srv: WindowsServer, ctx: CollectorContext): Promise<UnifiedCollectionResult> {
    const stamp = new Date().toISOString().replace('T', ' ').slice(0, 19);
    const target =
      srv.ipAddress && srv.ipAddress !== '—' && srv.ipAddress !== '-' ? srv.ipAddress : srv.hostname;
    const { prohibitedReasons } = getPermittedMethods(srv);
    const restrictions = [...prohibitedReasons];

    if (!isValidTargetHost(target)) {
      const integrity: MetricIntegrity = {
        collectionStatus: 'Not Configured',
        dataSource: 'Hyper-V Host Collector',
        measuredAt: stamp,
        targetIdentifier: srv.hostname,
        errorDetail: 'Invalid Hyper-V host target IP or hostname.',
      };
      const capabilityMatrix: MonitoringCapabilityMatrix = {
        platformDetected: 'Hyper-V Host',
        icmpAvailable: null,
        tcpAvailable: null,
        winrmAvailable: null,
        wmiAvailable: null,
        sshAvailable: false,
        snmpAvailable: null,
        cloudApiAvailable: false,
        hypervHostAccess: false,
        availableMetrics: [],
        unavailableMetrics: buildDefaultUnavailableMetrics(srv, 'Invalid Hyper-V host address.'),
        accessRestrictions: restrictions,
        evaluatedAt: stamp,
      };
      srv.integrity = integrity;
      srv.capabilityMatrix = capabilityMatrix;
      srv.healthClassification = 'Unsupported Monitoring Method';
      return { ok: false, integrity, healthClassification: srv.healthClassification, capabilityMatrix };
    }

    const pingRes = await pingHostStats(target, 2, 1200);
    const cred = resolveHyperVCred(srv, ctx);
    const res = cred.err
      ? { ok: false, errorMessage: cred.err }
      : await runHyperVHostQuery({
          target,
          hostnameHint: srv.hostname,
          isLocal: isLocalTarget(srv),
          username: cred.username,
          password: cred.password,
          timeoutMs: Math.max(8000, ctx.timeoutMs),
        });

    if (res.ok) {
      srv.cpuPct = res.cpuPct ?? 0;
      srv.ramPct = res.ramPct ?? 0;
      srv.ramTotalGb = res.ramTotalGb ?? 0;
      srv.diskTotalGb = res.diskTotalGb ?? 0;
      srv.diskAvailableGb = res.diskAvailableGb ?? 0;
      srv.diskPct = res.diskPct ?? 0;
      srv.uptimeHours = res.uptimeHours ?? 0;
      if (res.osVersion) srv.osVersion = res.osVersion;

      const vms = Array.isArray(res.vms) ? res.vms : [];
      const switches = Array.isArray(res.virtualSwitches) ? res.virtualSwitches : [];
      const hostDetails: HyperVHostDetails = {
        hostStatus: 'Online',
        virtualSwitches: switches,
        vms,
        collectedAt: stamp,
      };
      srv.hypervDetails = hostDetails;
      srv.services = vms.slice(0, 15).map((v) => ({
        name: v.name,
        displayName: `Hyper-V VM (${v.cpuAllocated ?? '?'} vCPU · ${v.memoryAssignedMb ?? 0} MB)`,
        status: v.state === 'Running' ? 'Running' : v.state === 'Paused' ? 'Paused' : 'Stopped',
        startupType: 'Automatic',
      }));
      srv.metricsAvailable = {
        cpu: true,
        ram: true,
        disk: (srv.diskTotalGb ?? 0) > 0,
        uptime: true,
        services: vms.length > 0,
        networkTraffic: false,
      };
      srv.history.push({
        time: stamp.slice(11, 16),
        cpuPct: srv.cpuPct,
        ramPct: srv.ramPct,
        diskPct: srv.diskPct,
      });
      if (srv.history.length > 24) srv.history.shift();
      srv.lastCheck = pingRes.avgLatencyMs !== null ? `${stamp} (${pingRes.avgLatencyMs}ms)` : stamp;
      srv.lastSuccessfulCheck = stamp;
      srv.status = 'Online';
      srv.healthClassification = 'Monitoring Healthy';

      const integrity: MetricIntegrity = {
        collectionStatus: 'Healthy',
        dataSource: `Hyper-V Read-Only (${res.protocol || 'CIM/WinRM'})`,
        measuredAt: stamp,
        targetIdentifier: target,
      };
      srv.integrity = integrity;

      const capabilityMatrix: MonitoringCapabilityMatrix = {
        platformDetected: 'Windows Server Hyper-V Host',
        icmpAvailable: pingRes.alive,
        tcpAvailable: true,
        winrmAvailable: Boolean(res.protocol?.includes('WinRM')),
        wmiAvailable: true,
        sshAvailable: false,
        snmpAvailable: null,
        cloudApiAvailable: false,
        hypervHostAccess: true,
        availableMetrics: [
          'Host CPU',
          'Host RAM',
          'Host Disk',
          'Host Uptime',
          `VM Inventory (${vms.length})`,
          `Virtual Switches (${switches.length})`,
        ],
        unavailableMetrics: [],
        accessRestrictions: restrictions,
        activeMethod: res.protocol || 'Hyper-V CIM',
        evaluatedAt: stamp,
      };
      srv.capabilityMatrix = capabilityMatrix;

      return { ok: true, integrity, healthClassification: 'Monitoring Healthy', capabilityMatrix };
    }

    const errMsg = res.errorMessage || 'Hyper-V host read-only query failed.';
    const isDenied = /access is denied|0x80070005|unauthorized/i.test(errMsg);
    const isUnsupported = /does not provide native windows hyper-v/i.test(errMsg);
    const status: MetricIntegrity['collectionStatus'] = cred.err
      ? 'Authentication Failed'
      : isDenied
        ? 'Permission Denied'
        : isUnsupported
          ? 'Unsupported Metric'
          : 'Unreachable';

    srv.lastCheck = stamp;
    srv.metricsAvailable = { cpu: false, ram: false, disk: false, uptime: false, services: false, networkTraffic: false };
    srv.status = pingRes.alive ? 'Online' : 'Offline';

    const healthClassification = mapCollectionToHealthClassification({
      reachable: pingRes.alive,
      hasOsOrPrimaryMetrics: false,
      hasAnyPassiveMetric: pingRes.alive,
      collectionStatus: status,
      connectionBlocked: isDenied || !pingRes.alive,
    });
    srv.healthClassification = healthClassification;

    const integrity: MetricIntegrity = {
      collectionStatus: status,
      dataSource: 'Hyper-V Host Read-Only',
      measuredAt: stamp,
      targetIdentifier: target,
      errorDetail: errMsg.slice(0, 300),
      prerequisiteHint:
        'Grant the monitoring account membership in "Hyper-V Administrators" or read-only root\\virtualization\\v2 WMI permissions + WinRM/DCOM access on the Hyper-V host.',
    };
    srv.integrity = integrity;

    const capabilityMatrix: MonitoringCapabilityMatrix = {
      platformDetected: 'Windows Server Hyper-V Host',
      icmpAvailable: pingRes.alive,
      tcpAvailable: null,
      winrmAvailable: false,
      wmiAvailable: false,
      sshAvailable: false,
      snmpAvailable: null,
      cloudApiAvailable: false,
      hypervHostAccess: false,
      availableMetrics: pingRes.alive ? [`ICMP (${pingRes.avgLatencyMs ?? 0}ms)`] : [],
      unavailableMetrics: buildDefaultUnavailableMetrics(srv, errMsg.slice(0, 180)),
      accessRestrictions: restrictions,
      activeMethod: pingRes.alive ? 'ICMP Only' : 'None',
      evaluatedAt: stamp,
    };
    srv.capabilityMatrix = capabilityMatrix;

    return { ok: false, integrity, healthClassification, capabilityMatrix };
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
      details: res.ok
        ? `Hyper-V Host ${clone.hostname}: Host CPU ${clone.cpuPct}%, RAM ${clone.ramPct}%, ${clone.hypervDetails?.vms.length ?? 0} VMs, ${clone.hypervDetails?.virtualSwitches.length ?? 0} vSwitches.`
        : res.integrity.errorDetail || 'Hyper-V host connection failed.',
      prerequisiteHint: res.integrity.prerequisiteHint,
    };
  }
}

export class HyperVVmCollector implements ServerCollectorAdapter {
  readonly platform = 'hyperv-vm' as const;

  async collect(srv: WindowsServer, ctx: CollectorContext): Promise<UnifiedCollectionResult> {
    const stamp = new Date().toISOString().replace('T', ' ').slice(0, 19);
    const target =
      srv.ipAddress && srv.ipAddress !== '—' && srv.ipAddress !== '-' ? srv.ipAddress : srv.hostname;
    const { prohibitedReasons } = getPermittedMethods(srv);
    const restrictions = [...prohibitedReasons];

    // 1. Locate parent Hyper-V Host in inventory (matches id, hostname, or IP)
    const parentRef = (srv.parentHypervHost || '').trim().toLowerCase();
    const parentHost = ctx.allServers.find(
      (s) =>
        s.id.toLowerCase() === parentRef ||
        s.hostname.toLowerCase() === parentRef ||
        s.ipAddress.toLowerCase() === parentRef
    );

    // If parent host has no cached hypervDetails yet, query parent host directly (read-only)
    if (parentHost && (!parentHost.hypervDetails || parentHost.hypervDetails.vms.length === 0)) {
      const hostCollector = new HyperVHostCollector();
      await hostCollector.collect(parentHost, ctx);
    }

    const matchedVm = parentHost?.hypervDetails?.vms.find(
      (v) => v.name.toLowerCase() === srv.hostname.toLowerCase()
    );

    const allowIcmp = isMethodPermitted(srv, 'icmp');
    const allowTcp = isMethodPermitted(srv, 'tcp');
    const allowHttp = isMethodPermitted(srv, 'http-https') && Boolean(srv.httpUrl);

    const validTarget = isValidTargetHost(target);
    const [pingRes, portResults] = validTarget
      ? await Promise.all([
          allowIcmp
            ? pingHostStats(target, 2, 1200)
            : Promise.resolve({ alive: false, avgLatencyMs: null, minLatencyMs: null, maxLatencyMs: null, packetLossPct: 100 }),
          allowTcp && srv.tcpPorts?.length
            ? Promise.all(srv.tcpPorts.slice(0, 6).map(async (p) => ({ port: p, open: (await checkTcpPort(target, p, 900)).open })))
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

    const availableMetrics: string[] = [];
    const unavailableMetrics: { metric: string; reason: string }[] = [];

    let hostExposedCpu = false;
    let hostExposedRam = false;
    let hostExposedUptime = false;

    if (matchedVm) {
      srv.hypervVmState = matchedVm.state;
      availableMetrics.push(`VM Operational State (${matchedVm.state})`);
      availableMetrics.push(`Hyper-V Host (${parentHost?.hostname}: ${parentHost?.status})`);

      if (typeof matchedVm.cpuUsagePct === 'number') {
        srv.cpuPct = matchedVm.cpuUsagePct;
        hostExposedCpu = true;
        availableMetrics.push(`Host-Exposed VM CPU (${matchedVm.cpuUsagePct}%)`);
      } else {
        unavailableMetrics.push({
          metric: 'Guest CPU Utilization',
          reason: 'Hyper-V host did not expose VM CPUUsage percentage and direct guest OS access is not authorized.',
        });
      }

      if (typeof matchedVm.memoryAssignedMb === 'number' && matchedVm.memoryAssignedMb > 0) {
        srv.ramTotalGb = Number((matchedVm.memoryAssignedMb / 1024).toFixed(1));
        if (typeof matchedVm.memoryDemandMb === 'number' && matchedVm.memoryDemandMb > 0) {
          srv.ramPct = Math.min(100, Number(((matchedVm.memoryDemandMb / matchedVm.memoryAssignedMb) * 100).toFixed(1)));
          hostExposedRam = true;
          availableMetrics.push(`Host-Exposed VM Memory (${matchedVm.memoryDemandMb}/${matchedVm.memoryAssignedMb} MB)`);
        } else {
          unavailableMetrics.push({
            metric: 'Guest RAM Utilization %',
            reason: `Hyper-V reports ${matchedVm.memoryAssignedMb} MB assigned, but Dynamic Memory demand/guest OS access is unavailable.`,
          });
        }
      } else {
        unavailableMetrics.push({
          metric: 'Guest RAM Utilization',
          reason: 'Guest OS memory metrics are unavailable from Hyper-V host.',
        });
      }

      if (typeof matchedVm.uptimeSeconds === 'number' && matchedVm.uptimeSeconds > 0) {
        srv.uptimeHours = Math.round(matchedVm.uptimeSeconds / 3600);
        hostExposedUptime = true;
        availableMetrics.push(`VM Uptime (${srv.uptimeHours}h)`);
      }

      // Never claim guest disk/services unless direct guest OS collection ran separately
      unavailableMetrics.push({
        metric: 'Guest Disk & OS Services',
        reason: 'Monitored via Hyper-V Host only; guest OS administrative access is not required or enabled.',
      });

      srv.hypervGuestOsHealth =
        matchedVm.state === 'Off'
          ? 'Offline'
          : pingRes.alive || httpOk || portResults.some((p) => p.open)
            ? 'Verified'
            : 'Host-Only (Guest OS Restricted)';
    } else {
      srv.hypervGuestOsHealth = pingRes.alive || httpOk ? 'Verified' : 'Offline';
      unavailableMetrics.push({
        metric: 'Hyper-V VM Telemetry',
        reason: parentHost
          ? `VM "${srv.hostname}" was not found in Hyper-V host "${parentHost.hostname}" inventory.`
          : `No Parent Hyper-V Host configured or found (${srv.parentHypervHost || 'unset'}).`,
      });
    }

    if (pingRes.alive) availableMetrics.push(`ICMP (${pingRes.avgLatencyMs ?? 0}ms)`);
    if (httpOk) availableMetrics.push('HTTP/HTTPS Endpoint');

    srv.metricsAvailable = {
      cpu: hostExposedCpu,
      ram: hostExposedRam,
      disk: false,
      uptime: hostExposedUptime,
      services: false,
      networkTraffic: false,
    };

    if (hostExposedCpu || hostExposedRam) {
      srv.history.push({
        time: stamp.slice(11, 16),
        cpuPct: srv.cpuPct,
        ramPct: srv.ramPct,
        diskPct: 0,
      });
      if (srv.history.length > 24) srv.history.shift();
    }

    const vmRunning = matchedVm?.state === 'Running';
    const anyReachable = Boolean(vmRunning || pingRes.alive || httpOk || portResults.some((p) => p.open));
    srv.lastCheck = pingRes.avgLatencyMs !== null ? `${stamp} (${pingRes.avgLatencyMs}ms)` : stamp;
    if (matchedVm || anyReachable) srv.lastSuccessfulCheck = stamp;

    srv.status = matchedVm?.state === 'Off' || !anyReachable ? 'Offline' : 'Online';

    const collectionStatus: MetricIntegrity['collectionStatus'] =
      matchedVm && vmRunning
        ? hostExposedCpu
          ? 'Healthy'
          : 'Warning'
        : matchedVm && matchedVm.state !== 'Running'
          ? 'Critical'
          : anyReachable
            ? 'Warning'
            : 'Unreachable';

    const healthClassification = mapCollectionToHealthClassification({
      reachable: anyReachable,
      hasOsOrPrimaryMetrics: Boolean(matchedVm && vmRunning && hostExposedCpu),
      hasAnyPassiveMetric: Boolean(matchedVm || pingRes.alive || httpOk),
      collectionStatus,
    });
    srv.healthClassification = healthClassification;

    const integrity: MetricIntegrity = {
      collectionStatus,
      dataSource: matchedVm ? `Hyper-V Host (${parentHost?.hostname})` : 'Hyper-V VM Passive Check',
      measuredAt: stamp,
      targetIdentifier: `${srv.parentHypervHost || 'unassigned'} -> ${srv.hostname}`,
      errorDetail:
        !matchedVm
          ? `VM "${srv.hostname}" could not be read from Parent Hyper-V Host "${srv.parentHypervHost || 'None'}".`
          : !hostExposedCpu
            ? `Hyper-V reports VM state=${matchedVm.state}; guest OS internals remain restricted/agentless.`
            : undefined,
      prerequisiteHint: !matchedVm
        ? 'Register the Parent Hyper-V Host and specify its hostname/IP in the VM "Parent Hyper-V Host" field.'
        : undefined,
    };
    srv.integrity = integrity;

    const capabilityMatrix: MonitoringCapabilityMatrix = {
      platformDetected: `Hyper-V VM (State: ${matchedVm?.state || 'Unknown'}, Guest: ${srv.hypervGuestOsHealth})`,
      icmpAvailable: allowIcmp ? pingRes.alive : false,
      tcpAvailable: allowTcp && srv.tcpPorts?.length ? portResults.some((p) => p.open) : null,
      winrmAvailable: false,
      wmiAvailable: false,
      sshAvailable: false,
      snmpAvailable: false,
      cloudApiAvailable: false,
      hypervHostAccess: Boolean(matchedVm),
      availableMetrics,
      unavailableMetrics,
      accessRestrictions: restrictions,
      activeMethod: matchedVm ? `Hyper-V Host (${parentHost?.hostname})` : 'Passive Probe',
      evaluatedAt: stamp,
    };
    srv.capabilityMatrix = capabilityMatrix;

    return {
      ok: Boolean(matchedVm || anyReachable),
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
      details: `${res.healthClassification} | VM State: ${clone.hypervVmState || 'Unknown'} | Guest Health: ${clone.hypervGuestOsHealth || 'Unknown'}`,
      prerequisiteHint: res.integrity.prerequisiteHint,
    };
  }
}
