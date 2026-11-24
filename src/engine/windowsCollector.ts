import { execFile } from 'child_process';
import os from 'os';
import type { CredentialVault } from './credentialVault.ts';
import {
  buildDefaultUnavailableMetrics,
  getPermittedMethods,
  isMethodPermitted,
  mapCollectionToHealthClassification,
  MethodBackoffTracker,
  type CollectorContext,
  type ServerCollectorAdapter,
  type UnifiedCollectionResult,
} from './monitoringCapabilities.ts';
import { checkTcpPort, isValidTargetHost, pingHostStats } from './networkHelpers.ts';
import { pollSnmpServerMetrics, type SnmpTargetAuth } from '../snmpPoller.ts';
import type {
  CollectionStatus,
  ConnectionTestResult,
  DiagnosticCheckItem,
  MetricIntegrity,
  MonitoringCapabilityMatrix,
  ServerHealthClassification,
  ServerNetworkInterface,
  WindowsProcessIdentity,
  WindowsServer,
  WindowsServiceItem,
} from '../types/infrastructure.ts';

interface CimCollectOutput {
  ok: boolean;
  protocol?: string;
  resolvedTarget?: string;
  hostname?: string;
  domainMembership?: string;
  osVersion?: string;
  cpuPct?: number;
  ramPct?: number;
  ramTotalGb?: number;
  diskTotalGb?: number;
  diskAvailableGb?: number;
  diskPct?: number;
  uptimeHours?: number;
  runningProcessesCount?: number;
  iisDetectedSites?: string[];
  eventErrors24h?: number;
  services?: WindowsServiceItem[];
  networkInterfaces?: ServerNetworkInterface[];
  errorCode?: string;
  errorMessage?: string;
}

interface RawDiagnosticOutput {
  fqdn?: string;
  dnsError?: string;
  kerberosOk?: boolean;
  kerberosStatus?: CollectionStatus;
  kerberosDetails?: string;
  kerberosHint?: string;
  kerberosLatencyMs?: number;
  doubleHopDetected?: boolean;
  doubleHopReason?: string;
  dcomOk?: boolean;
  dcomStatus?: CollectionStatus;
  dcomDetails?: string;
  dcomHint?: string;
  dcomLatencyMs?: number;
  winrmHttpsOk?: boolean;
  winrmHttpsStatus?: CollectionStatus;
  winrmHttpsDetails?: string;
  winrmHttpsHint?: string;
  winrmHttpsLatencyMs?: number;
  winrmHttpNote?: string;
  metricsOk?: boolean;
  metricsStatus?: CollectionStatus;
  metricsDetails?: string;
  metricsHint?: string;
  metricsLatencyMs?: number;
  protocolUsed?: string;
}

let cachedIdentity: WindowsProcessIdentity | null = null;
let cachedIdentityAt = 0;

const STATIC_PROCESS_IDENTITY_PS = `
$ErrorActionPreference = 'SilentlyContinue'
$id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$cs = Get-CimInstance Win32_ComputerSystem -Property PartOfDomain,Domain,Name
$partOfDomain = [bool]$cs.PartOfDomain
$machineDomain = [string]$cs.Domain
$machineName = [string]$cs.Name
$name = [string]$id.Name
$authType = [string]$id.AuthenticationType
$impLevel = [string]$id.ImpersonationLevel
$isSystem = [bool]$id.IsSystem

$acctPrefix = if ($name -match '^([^\\\\]+)\\\\') { $Matches[1] } else { '' }
$isSystemAccount = $isSystem -or ($name -match '^(NT AUTHORITY|NT SERVICE)\\\\')
$isDomainUser = $partOfDomain -and (-not $isSystemAccount) -and ($acctPrefix -ne '') -and ($acctPrefix.ToUpperInvariant() -ne $machineName.ToUpperInvariant())

# Inspect logon session type of current process (to detect non-delegated Network LogonType 3)
$logonTypeLabel = 'Unknown'
$logonTypeNum = -1
try {
  $proc = Get-CimInstance Win32_Process -Filter "ProcessId=$PID"
  $assoc = Get-CimAssociatedInstance -InputObject $proc -ResultClassName Win32_LogonSession | Select-Object -First 1
  if ($assoc) {
    $logonTypeNum = [int]$assoc.LogonType
    $logonTypeLabel = switch ($logonTypeNum) {
      2 { 'Interactive (2)' }
      3 { 'Network (3)' }
      4 { 'Batch (4)' }
      5 { 'Service (5)' }
      7 { 'Unlock (7)' }
      10 { 'RemoteInteractive (10)' }
      11 { 'CachedInteractive (11)' }
      default { "LogonType($logonTypeNum)" }
    }
  }
} catch {}

# Inspect local Kerberos TGT on this central process session (never executes anything on targets)
$klistOut = ''
$tgtOk = $false
$forwardable = $false
try {
  $klistOut = (& "$env:SystemRoot\System32\klist.exe" 2>&1 | Out-String)
  if ($klistOut -match 'krbtgt/') {
    $tgtOk = $true
    if ($klistOut -match 'forwardable') { $forwardable = $true }
  }
} catch {}

$doubleHopRisk = $false
$doubleHopReason = ''
if ($logonTypeNum -eq 3) {
  $doubleHopRisk = $true
  $doubleHopReason = 'Central backend process is running inside a Network logon session (LogonType 3, e.g. remote WinRM shell without CredSSP/delegation). Outbound Kerberos delegation to remote targets will fail with double-hop / SEC_E_NO_CREDENTIALS.'
} elseif ($isDomainUser -and -not $tgtOk) {
  $doubleHopRisk = $true
  $doubleHopReason = "Domain user $name has no active Kerberos TGT (krbtgt) in the process logon session (klist check). Remote WMI/WinRM may fall back to NTLM or fail delegation."
} elseif ($isDomainUser -and ($authType -eq 'NTLM')) {
  $doubleHopRisk = $true
  $doubleHopReason = 'Process security context authenticated via NTLM instead of Kerberos; multi-hop Kerberos delegation is unavailable.'
} elseif ($isDomainUser -and $tgtOk -and -not $forwardable) {
  $doubleHopReason = 'Kerberos TGT is present (non-forwardable); single-hop direct collection from this central server is supported, multi-hop forwarding is disabled.'
}

@{
  platform = 'win32'
  hostname = $machineName
  identityName = $name
  domain = $machineDomain
  partOfDomain = $partOfDomain
  isDomainUser = $isDomainUser
  isSystemAccount = $isSystemAccount
  authenticationType = if ($authType) { $authType } else { 'Negotiate' }
  impersonationLevel = $impLevel
  logonType = $logonTypeLabel
  kerberosTgtAvailable = $tgtOk
  doubleHopRisk = $doubleHopRisk
  doubleHopReason = if ($doubleHopReason) { $doubleHopReason } else { $null }
} | ConvertTo-Json -Compress
`;

export async function detectProcessWindowsIdentity(forceRefresh = false): Promise<WindowsProcessIdentity> {
  const now = Date.now();
  if (!forceRefresh && cachedIdentity && now - cachedIdentityAt < 30_000) {
    return cachedIdentity;
  }

  const stamp = new Date().toISOString().replace('T', ' ').slice(0, 19);
  if (process.platform !== 'win32') {
    let uname = 'unknown';
    try {
      uname = os.userInfo().username;
    } catch {
      uname = process.env.USER || 'unknown';
    }
    const nonWin: WindowsProcessIdentity = {
      platform: process.platform,
      hostname: os.hostname(),
      identityName: uname,
      partOfDomain: false,
      isDomainUser: false,
      isSystemAccount: false,
      authenticationType: 'POSIX (Non-Windows)',
      kerberosTgtAvailable: false,
      doubleHopRisk: false,
      doubleHopReason: `Backend host is ${process.platform}; native Windows Integrated Authentication requires running the central engine on a domain-joined Windows Server.`,
      detectedAt: stamp,
    };
    cachedIdentity = nonWin;
    cachedIdentityAt = now;
    return nonWin;
  }

  const encoded = Buffer.from(STATIC_PROCESS_IDENTITY_PS, 'utf16le').toString('base64');
  const detected = await new Promise<WindowsProcessIdentity>((resolve) => {
    execFile(
      'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-EncodedCommand', encoded],
      { timeout: 6000, maxBuffer: 512 * 1024 },
      (err, stdout) => {
        const raw = (stdout || '').trim();
        if (raw) {
          try {
            const parsed = JSON.parse(raw) as Omit<WindowsProcessIdentity, 'detectedAt'>;
            resolve({
              ...parsed,
              detectedAt: stamp,
            });
            return;
          } catch {
            // fall through
          }
        }
        resolve({
          platform: 'win32',
          hostname: os.hostname(),
          identityName: process.env.USERDOMAIN
            ? `${process.env.USERDOMAIN}\\${process.env.USERNAME || 'unknown'}`
            : process.env.USERNAME || 'unknown',
          domain: process.env.USERDOMAIN,
          partOfDomain: Boolean(process.env.USERDNSDOMAIN),
          isDomainUser: Boolean(process.env.USERDNSDOMAIN),
          isSystemAccount: false,
          authenticationType: 'Process Environment Fallback',
          kerberosTgtAvailable: false,
          doubleHopRisk: false,
          doubleHopReason: err?.message || 'Unable to inspect WindowsIdentity token.',
          detectedAt: stamp,
        });
      }
    );
  });

  cachedIdentity = detected;
  cachedIdentityAt = now;
  return detected;
}

const STATIC_LOCAL_AND_REMOTE_CIM_PS = `
$ErrorActionPreference = 'Stop'
$targetRaw = $env:MEDLABS_WIN_TARGET
$hostHint = $env:MEDLABS_WIN_HOSTNAME
$isLocal = ($env:MEDLABS_WIN_IS_LOCAL -eq '1')
$user = $env:MEDLABS_WIN_USER
$pass = $env:MEDLABS_WIN_PASS
$useCred = ($env:MEDLABS_WIN_USE_CRED -eq '1')
$preferKerberos = ($env:MEDLABS_WIN_PREFER_KERBEROS -eq '1')
$allowHttps = ($env:MEDLABS_WIN_ALLOW_HTTPS -ne '0')
$allowHttp = ($env:MEDLABS_WIN_ALLOW_HTTP -ne '0')
$allowDcom = ($env:MEDLABS_WIN_ALLOW_DCOM -ne '0')
$timeoutSec = 8
if ($env:MEDLABS_WIN_TIMEOUT_SEC) { [void][int]::TryParse($env:MEDLABS_WIN_TIMEOUT_SEC, [ref]$timeoutSec) }

$cimSession = $null
$usedProto = 'LocalCIM'
$resolvedTarget = $targetRaw

try {
  if (-not $isLocal) {
    if (-not $allowHttps -and -not $allowHttp -and -not $allowDcom) {
      throw "All WinRM and WMI/DCOM protocols are disabled by server monitoring policy."
    }
    # Prefer FQDN / DNS hostname for Kerberos SPN resolution (WSMAN/fqdn, HOST/fqdn)
    if ($preferKerberos) {
      $candidate = if ($hostHint -and $hostHint -ne 'localhost') { $hostHint } else { $targetRaw }
      try {
        $dnsEntry = [System.Net.Dns]::GetHostEntry($candidate)
        if ($dnsEntry -and $dnsEntry.HostName) {
          $resolvedTarget = $dnsEntry.HostName
        } elseif ($hostHint -and ($hostHint -notmatch '^\\d+\\.\\d+\\.\\d+\\.\\d+$')) {
          $resolvedTarget = $hostHint
        }
      } catch {
        if ($hostHint -and ($hostHint -notmatch '^\\d+\\.\\d+\\.\\d+\\.\\d+$')) {
          $resolvedTarget = $hostHint
        }
      }
    }

    # Integrated process security context uses NO credential object (never requests or stores domain password)
    $cred = $null
    if ($useCred -and -not [string]::IsNullOrWhiteSpace($user) -and $null -ne $pass) {
      $sec = ConvertTo-SecureString -String $pass -AsPlainText -Force
      $cred = New-Object System.Management.Automation.PSCredential($user, $sec)
    }

    $wsmanHttpsErr = if ($allowHttps) { $null } else { 'Disabled by policy' }
    $wsmanHttpErr = if ($allowHttp) { $null } else { 'Disabled by policy' }
    $dcomErr = if ($allowDcom) { $null } else { 'Disabled by policy' }

    # 1. Prefer WinRM HTTPS (5986) with Kerberos
    if ($allowHttps) {
      try {
        $optSsl = if ($preferKerberos) {
          New-CimSessionOption -UseSsl
        } else {
          New-CimSessionOption -UseSsl
        }
        $sArgsSsl = @{ ComputerName = $resolvedTarget; SessionOption = $optSsl; Authentication = $(if ($preferKerberos) { 'Kerberos' } else { 'Negotiate' }); OperationTimeoutSec = $timeoutSec }
        if ($cred) { $sArgsSsl.Credential = $cred }
        $cimSession = New-CimSession @sArgsSsl
        $usedProto = if ($preferKerberos) { 'WinRM HTTPS (Kerberos)' } else { 'WinRM HTTPS' }
      } catch {
        $wsmanHttpsErr = $_.Exception.Message
      }
    }

    # 2. Next prefer WinRM HTTP (5985) with Kerberos (only when approved by policy)
    if (-not $cimSession -and $allowHttp) {
      try {
        $optHttp = if ($preferKerberos) {
          New-CimSessionOption -Protocol Wsman
        } else {
          New-CimSessionOption -Protocol Wsman
        }
        $sArgsHttp = @{ ComputerName = $resolvedTarget; SessionOption = $optHttp; Authentication = $(if ($preferKerberos) { 'Kerberos' } else { 'Negotiate' }); OperationTimeoutSec = $timeoutSec }
        if ($cred) { $sArgsHttp.Credential = $cred }
        $cimSession = New-CimSession @sArgsHttp
        $usedProto = if ($preferKerberos) { 'WinRM HTTP (Kerberos)' } else { 'WinRM HTTP' }
      } catch {
        $wsmanHttpErr = $_.Exception.Message
      }
    }

    # 3. Next fallback to WMI / DCOM (only when approved by policy)
    if (-not $cimSession -and $allowDcom) {
      try {
        $optDcom = New-CimSessionOption -Protocol Dcom
        $dArgs = @{ ComputerName = $resolvedTarget; SessionOption = $optDcom; OperationTimeoutSec = $timeoutSec }
        if ($cred) { $dArgs.Credential = $cred }
        $cimSession = New-CimSession @dArgs
        $usedProto = if ($preferKerberos) { 'WMI/DCOM (Kerberos/Negotiate)' } else { 'WMI/DCOM' }
      } catch {
        $dcomErr = $_.Exception.Message
      }
    }

    if (-not $cimSession) {
      throw "WinRM-HTTPS(5986): $wsmanHttpsErr | WinRM-HTTP(5985): $wsmanHttpErr | WMI-DCOM(135): $dcomErr"
    }
  }

  $cp = if ($cimSession) { @{ CimSession = $cimSession } } else { @{} }
  $cs = Get-CimInstance Win32_ComputerSystem -Property Name,PartOfDomain,Domain @cp
  $os = Get-CimInstance Win32_OperatingSystem -Property Caption,TotalVisibleMemorySize,FreePhysicalMemory,LastBootUpTime @cp
  $cpus = Get-CimInstance Win32_Processor -Property LoadPercentage @cp
  $disks = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" -Property DeviceID,Size,FreeSpace @cp
  $svcs = Get-CimInstance Win32_Service -Filter "Name='W3SVC' OR Name='WAS' OR Name='WinRM' OR Name='Spooler' OR Name='W32Time' OR Name LIKE 'Oracle%' OR Name LIKE 'vmms%' OR Name LIKE 'HealthService%'" -Property Name,DisplayName,State,StartMode @cp | Select-Object -First 15

  $procCount = $null
  try {
    $procCount = @(Get-CimInstance Win32_Process -Property ProcessId @cp).Count
  } catch {}

  $iisSites = @()
  try {
    $rawSites = Get-CimInstance -Namespace 'root\\WebAdministration' -ClassName Site -Property Name,State @cp -ErrorAction SilentlyContinue | Select-Object -First 12
    foreach ($site in $rawSites) {
      if ($site.Name) { $iisSites += "$($site.Name) ($($site.State))" }
    }
  } catch {}

  $eventErrCount = $null
  try {
    $sinceWmi = [System.Management.ManagementDateTimeConverter]::ToDmtfDateTime((Get-Date).AddHours(-24))
    $evts = Get-CimInstance Win32_NTLogEvent -Filter "Logfile='System' AND EventType=1 AND TimeWritten>='$sinceWmi'" -Property RecordNumber @cp -ErrorAction SilentlyContinue | Select-Object -First 100
    $eventErrCount = @($evts).Count
  } catch {}

  $netList = @()
  try {
    $netPerf = Get-CimInstance Win32_PerfFormattedData_Tcpip_NetworkInterface -Property Name,BytesReceivedPersec,BytesSentPersec @cp | Select-Object -First 6
    foreach ($np in $netPerf) {
      $rx = [math]::Round(($np.BytesReceivedPersec * 8) / 1000, 1)
      $tx = [math]::Round(($np.BytesSentPersec * 8) / 1000, 1)
      $netList += @{ name = [string]$np.Name; rxKbps = $rx; txKbps = $tx }
    }
  } catch {}

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

  $svcItems = @()
  foreach ($s in $svcs) {
    $svcItems += @{
      name = [string]$s.Name
      displayName = [string]$s.DisplayName
      status = if ($s.State -eq 'Running') { 'Running' } elseif ($s.State -eq 'Paused') { 'Paused' } else { 'Stopped' }
      startupType = if ($s.StartMode -eq 'Auto') { 'Automatic' } else { 'Manual' }
    }
  }

  $domMem = if ($cs.PartOfDomain) { [string]$cs.Domain } else { 'Workgroup' }

  @{
    ok = $true
    protocol = $usedProto
    resolvedTarget = $resolvedTarget
    hostname = [string]$cs.Name
    domainMembership = $domMem
    osVersion = [string]$os.Caption
    cpuPct = $cpuPct
    ramPct = $ramPct
    ramTotalGb = $ramTotalGb
    diskTotalGb = $diskTotalGb
    diskAvailableGb = $diskAvailGb
    diskPct = $diskPct
    uptimeHours = $uptimeHours
    runningProcessesCount = $procCount
    iisDetectedSites = $iisSites
    eventErrors24h = $eventErrCount
    services = $svcItems
    networkInterfaces = $netList
  } | ConvertTo-Json -Depth 4 -Compress
}
catch {
  @{
    ok = $false
    resolvedTarget = $resolvedTarget
    errorMessage = $_.Exception.Message
  } | ConvertTo-Json -Compress
}
finally {
  if ($cimSession) { Remove-CimSession $cimSession }
}
`;

// Independent diagnostic script executed ONLY on central monitoring server (never on targets)
const STATIC_DIAGNOSTIC_PS = `
$ErrorActionPreference = 'Stop'
$targetRaw = $env:MEDLABS_WIN_TARGET
$hostHint = $env:MEDLABS_WIN_HOSTNAME
$user = $env:MEDLABS_WIN_USER
$pass = $env:MEDLABS_WIN_PASS
$useCred = ($env:MEDLABS_WIN_USE_CRED -eq '1')
$timeoutSec = 7
if ($env:MEDLABS_WIN_TIMEOUT_SEC) { [void][int]::TryParse($env:MEDLABS_WIN_TIMEOUT_SEC, [ref]$timeoutSec) }

$cred = $null
if ($useCred -and -not [string]::IsNullOrWhiteSpace($user) -and $null -ne $pass) {
  $sec = ConvertTo-SecureString -String $pass -AsPlainText -Force
  $cred = New-Object System.Management.Automation.PSCredential($user, $sec)
}

# 1. Resolve FQDN locally for Kerberos SPN compatibility
$fqdn = $targetRaw
$dnsError = $null
$candidate = if ($hostHint -and $hostHint -ne 'localhost') { $hostHint } else { $targetRaw }
try {
  $entry = [System.Net.Dns]::GetHostEntry($candidate)
  if ($entry -and $entry.HostName) { $fqdn = $entry.HostName }
} catch {
  $dnsError = $_.Exception.Message
  if ($hostHint -and ($hostHint -notmatch '^\\d+\\.\\d+\\.\\d+\\.\\d+$')) {
    $fqdn = $hostHint
  }
}

# 2. Independent Kerberos Availability Test (strictly local AD/KDC check on central server)
$kSw = [System.Diagnostics.Stopwatch]::StartNew()
$kerberosOk = $false
$kerberosStatus = 'Unreachable'
$kerberosDetails = ''
$kerberosHint = ''
$doubleHopDetected = $false
$doubleHopReason = ''

if ($fqdn -match '^\\d+\\.\\d+\\.\\d+\\.\\d+$') {
  $kerberosStatus = 'Not Configured'
  $kerberosDetails = "Target resolved only to IPv4 ($fqdn); Kerberos requires a DNS hostname/FQDN SPN (cannot issue Kerberos tickets for raw IP addresses)."
  $kerberosHint = 'Ensure forward/reverse DNS A and PTR records exist in AD DNS for this server and register using its domain hostname/FQDN.'
} else {
  try {
    # Attempt native Kerberos service ticket retrieval for WSMAN/<fqdn> or HOST/<fqdn> via klist on central host
    $kOut = (& klist.exe get "WSMAN/$fqdn" 2>&1 | Out-String)
    if ($LASTEXITCODE -eq 0) {
      $kerberosOk = $true
      $kerberosStatus = 'Healthy'
      $kerberosDetails = "Kerberos service ticket (WSMAN/$fqdn) issued by KDC."
    } else {
      $kOutHost = (& klist.exe get "HOST/$fqdn" 2>&1 | Out-String)
      if ($LASTEXITCODE -eq 0) {
        $kerberosOk = $true
        $kerberosStatus = 'Healthy'
        $kerberosDetails = "Kerberos service ticket (HOST/$fqdn) issued by KDC."
      } else {
        $combined = ($kOut + ' ' + $kOutHost).Trim()
        if ($combined -match '0x8009030e|no credentials|logon session does not exist|0x80070520') {
          $kerberosStatus = 'Authentication Failed'
          $doubleHopDetected = $true
          $doubleHopReason = "Kerberos ticket acquisition failed due to missing/un-delegated logon credentials: $combined"
        } elseif ($combined -match '0x80090303|not found in Kerberos database|KDC_ERR_S_PRINCIPAL_UNKNOWN|0xc0000034') {
          $kerberosStatus = 'Not Configured'
          $kerberosHint = "SPN WSMAN/$fqdn or HOST/$fqdn was not found in Active Directory. Verify the target is domain-joined and DNS resolves to its AD computer account."
        } else {
          $kerberosStatus = 'Authentication Failed'
        }
        $kerberosDetails = $combined
      }
    }
  } catch {
    $kerberosStatus = 'Authentication Failed'
    $kerberosDetails = $_.Exception.Message
  }
}
$kSw.Stop()

# 3. Independent WMI / DCOM Test
$dSw = [System.Diagnostics.Stopwatch]::StartNew()
$dcomOk = $false
$dcomStatus = 'Unreachable'
$dcomDetails = ''
$dcomHint = ''
$dcomSession = $null
try {
  $optDcom = New-CimSessionOption -Protocol Dcom
  $dArgs = @{ ComputerName = $fqdn; SessionOption = $optDcom; OperationTimeoutSec = $timeoutSec }
  if ($cred) { $dArgs.Credential = $cred }
  $dcomSession = New-CimSession @dArgs
  $csD = Get-CimInstance Win32_ComputerSystem -Property Name,Domain -CimSession $dcomSession
  $dcomOk = $true
  $dcomStatus = 'Healthy'
  $dcomDetails = "WMI/DCOM connected to $($csD.Name) ($($csD.Domain)) via $fqdn."
} catch {
  $msg = $_.Exception.Message
  $dcomDetails = $msg
  if ($msg -match '0x8009030e|SEC_E_NO_CREDENTIALS|0x80070520|delegat') {
    $dcomStatus = 'Authentication Failed'
    $doubleHopDetected = $true
    $doubleHopReason = "DCOM security context error (possible double-hop / missing logon credentials): $msg"
  } elseif ($msg -match 'Access is denied|0x80070005') {
    $dcomStatus = 'Permission Denied'
    $dcomHint = 'Target refused DCOM/WMI access (0x80070005). Verify the domain account has remote DCOM/WMI read permissions on the target.'
  } elseif ($msg -match 'Logon failure|unknown user|bad username') {
    $dcomStatus = 'Authentication Failed'
  } else {
    $dcomStatus = 'Unreachable'
    $dcomHint = 'Ensure RPC Endpoint Mapper (TCP 135) and dynamic RPC/WMI-In firewall rules allow the central monitoring server.'
  }
}
$dSw.Stop()

# 4. Independent WinRM HTTPS (5986) Kerberos Test
$wSw = [System.Diagnostics.Stopwatch]::StartNew()
$winrmHttpsOk = $false
$winrmHttpsStatus = 'Unreachable'
$winrmHttpsDetails = ''
$winrmHttpsHint = ''
$winrmHttpsSession = $null
try {
  $optSsl = New-CimSessionOption -UseSsl
  $sArgs = @{ ComputerName = $fqdn; SessionOption = $optSsl; Authentication = 'Kerberos'; OperationTimeoutSec = $timeoutSec }
  if ($cred) { $sArgs.Credential = $cred }
  $winrmHttpsSession = New-CimSession @sArgs
  $csW = Get-CimInstance Win32_ComputerSystem -Property Name -CimSession $winrmHttpsSession
  $winrmHttpsOk = $true
  $winrmHttpsStatus = 'Healthy'
  $winrmHttpsDetails = "WinRM HTTPS (5986) Kerberos session verified on $($csW.Name) via $fqdn."
} catch {
  $msg = $_.Exception.Message
  $winrmHttpsDetails = $msg
  if ($msg -match '0x8009030e|SEC_E_NO_CREDENTIALS|0x80070520|CredSSP|delegat') {
    $winrmHttpsStatus = 'Authentication Failed'
    $doubleHopDetected = $true
    $doubleHopReason = "WinRM HTTPS delegation / logon session failure: $msg"
  } elseif ($msg -match 'Access is denied|0x80070005') {
    $winrmHttpsStatus = 'Permission Denied'
    $winrmHttpsHint = 'WinRM HTTPS connected but target denied access (0x80070005). Verify WinRM Root\\CIMV2 access for the domain account.'
  } elseif ($msg -match 'certificate|SSL|cannot complete the request|2150858770|cannot connect to the destination') {
    $winrmHttpsStatus = 'Unreachable'
    $winrmHttpsHint = 'WinRM HTTPS listener (TCP 5986) or valid AD machine certificate is not enabled/trusted on target.'
  } else {
    $winrmHttpsStatus = 'Unreachable'
  }
}
$wSw.Stop()

# Also probe WinRM HTTP (5985) Kerberos as an optional working transport for metrics
$winrmHttpSession = $null
$winrmHttpNote = ''
if (-not $winrmHttpsOk) {
  try {
    $optHttp = New-CimSessionOption -Protocol Wsman
    $hArgs = @{ ComputerName = $fqdn; SessionOption = $optHttp; Authentication = 'Kerberos'; OperationTimeoutSec = $timeoutSec }
    if ($cred) { $hArgs.Credential = $cred }
    $winrmHttpSession = New-CimSession @hArgs
    $null = Get-CimInstance Win32_ComputerSystem -Property Name -CimSession $winrmHttpSession
    $winrmHttpNote = "WinRM HTTP (5985) Kerberos succeeded."
  } catch {
    $winrmHttpNote = "WinRM HTTP (5985) Kerberos: $($_.Exception.Message)"
    if ($_.Exception.Message -match '0x8009030e|SEC_E_NO_CREDENTIALS|0x80070520|delegat') {
      $doubleHopDetected = $true
      $doubleHopReason = "WinRM HTTP Kerberos delegation error: $($_.Exception.Message)"
    }
  }
}

# 5. Independent CPU, RAM and Disk Collection Test
$mSw = [System.Diagnostics.Stopwatch]::StartNew()
$metricsOk = $false
$metricsStatus = 'Unreachable'
$metricsDetails = ''
$metricsHint = ''
$protocolUsed = ''
$activeSession = $null
if ($winrmHttpsSession) { $activeSession = $winrmHttpsSession; $protocolUsed = 'WinRM HTTPS (Kerberos)' }
elseif ($winrmHttpSession) { $activeSession = $winrmHttpSession; $protocolUsed = 'WinRM HTTP (Kerberos)' }
elseif ($dcomSession) { $activeSession = $dcomSession; $protocolUsed = 'WMI/DCOM' }

if ($activeSession) {
  try {
    $os = Get-CimInstance Win32_OperatingSystem -Property TotalVisibleMemorySize,FreePhysicalMemory,LastBootUpTime -CimSession $activeSession
    $cpus = Get-CimInstance Win32_Processor -Property LoadPercentage -CimSession $activeSession
    $disks = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" -Property DeviceID,Size,FreeSpace -CimSession $activeSession

    $cpuAvg = ($cpus | Measure-Object -Property LoadPercentage -Average).Average
    $cpuPct = if ($null -ne $cpuAvg) { [math]::Round($cpuAvg, 1) } else { 0 }
    $ramPct = if ($os.TotalVisibleMemorySize -gt 0) { [math]::Round((($os.TotalVisibleMemorySize - $os.FreePhysicalMemory) / $os.TotalVisibleMemorySize) * 100, 1) } else { 0 }
    $diskTotalBytes = ($disks | Measure-Object -Property Size -Sum).Sum
    $diskFreeBytes = ($disks | Measure-Object -Property FreeSpace -Sum).Sum
    $diskPct = if ($diskTotalBytes -gt 0) { [math]::Round((($diskTotalBytes - $diskFreeBytes) / $diskTotalBytes) * 100, 1) } else { 0 }

    $metricsOk = $true
    $metricsStatus = 'Healthy'
    $metricsDetails = "Collected live CPU=$cpuPct%, RAM=$ramPct%, Disk=$diskPct% via $protocolUsed."
  } catch {
    $mMsg = $_.Exception.Message
    $metricsStatus = if ($mMsg -match 'Access is denied|0x80070005') { 'Permission Denied' } else { 'Unsupported Metric' }
    $metricsDetails = "Session opened ($protocolUsed), but metric query failed: $mMsg"
    $metricsHint = 'Verify CIM/WMI Read permissions on Root\\CIMV2 (Win32_Processor, Win32_OperatingSystem, Win32_LogicalDisk).'
  }
} else {
  $metricsStatus = if ($dcomStatus -eq 'Permission Denied' -or $winrmHttpsStatus -eq 'Permission Denied') { 'Permission Denied' } elseif ($doubleHopDetected) { 'Authentication Failed' } else { 'Unreachable' }
  $metricsDetails = 'Cannot collect CPU/RAM/Disk because neither WinRM (Kerberos) nor WMI/DCOM established an authenticated session.'
}
$mSw.Stop()

if ($winrmHttpsSession) { Remove-CimSession $winrmHttpsSession }
if ($winrmHttpSession) { Remove-CimSession $winrmHttpSession }
if ($dcomSession) { Remove-CimSession $dcomSession }

@{
  fqdn = $fqdn
  dnsError = $dnsError
  kerberosOk = $kerberosOk
  kerberosStatus = $kerberosStatus
  kerberosDetails = $kerberosDetails
  kerberosHint = $kerberosHint
  kerberosLatencyMs = [int]$kSw.ElapsedMilliseconds
  doubleHopDetected = $doubleHopDetected
  doubleHopReason = $doubleHopReason
  dcomOk = $dcomOk
  dcomStatus = $dcomStatus
  dcomDetails = $dcomDetails
  dcomHint = $dcomHint
  dcomLatencyMs = [int]$dSw.ElapsedMilliseconds
  winrmHttpsOk = $winrmHttpsOk
  winrmHttpsStatus = $winrmHttpsStatus
  winrmHttpsDetails = $winrmHttpsDetails
  winrmHttpsHint = $winrmHttpsHint
  winrmHttpsLatencyMs = [int]$wSw.ElapsedMilliseconds
  winrmHttpNote = $winrmHttpNote
  metricsOk = $metricsOk
  metricsStatus = $metricsStatus
  metricsDetails = $metricsDetails
  metricsHint = $metricsHint
  metricsLatencyMs = [int]$mSw.ElapsedMilliseconds
  protocolUsed = $protocolUsed
} | ConvertTo-Json -Compress
`;

function runPowerShellCim(params: {
  target: string;
  hostnameHint: string;
  isLocal: boolean;
  preferKerberos: boolean;
  allowHttps?: boolean;
  allowHttp?: boolean;
  allowDcom?: boolean;
  username?: string;
  password?: string;
  timeoutMs: number;
}): Promise<CimCollectOutput> {
  return new Promise((resolve) => {
    if (process.platform !== 'win32') {
      resolve({
        ok: false,
        errorCode: 'UNSUPPORTED_OS',
        errorMessage: `Central monitoring server OS (${process.platform}) does not provide native Windows WMI/CIM client libraries.`,
      });
      return;
    }

    const encoded = Buffer.from(STATIC_LOCAL_AND_REMOTE_CIM_PS, 'utf16le').toString('base64');
    const env: NodeJS.ProcessEnv = {
      ...process.env,
      MEDLABS_WIN_TARGET: params.target,
      MEDLABS_WIN_HOSTNAME: params.hostnameHint,
      MEDLABS_WIN_IS_LOCAL: params.isLocal ? '1' : '0',
      MEDLABS_WIN_PREFER_KERBEROS: params.preferKerberos ? '1' : '0',
      MEDLABS_WIN_ALLOW_HTTPS: params.allowHttps === false ? '0' : '1',
      MEDLABS_WIN_ALLOW_HTTP: params.allowHttp === false ? '0' : '1',
      MEDLABS_WIN_ALLOW_DCOM: params.allowDcom === false ? '0' : '1',
      MEDLABS_WIN_TIMEOUT_SEC: String(Math.max(3, Math.round(params.timeoutMs / 1000))),
      // When integrated auth is used, MEDLABS_WIN_USE_CRED=0 and zero password is passed or stored
      MEDLABS_WIN_USE_CRED: params.username && params.password ? '1' : '0',
      MEDLABS_WIN_USER: params.username || '',
      MEDLABS_WIN_PASS: params.password || '',
    };

    execFile(
      'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-EncodedCommand', encoded],
      { timeout: params.timeoutMs + 5000, env, maxBuffer: 1024 * 1024 },
      (err, stdout, stderr) => {
        const raw = (stdout || '').trim();
        if (raw) {
          try {
            const parsed = JSON.parse(raw) as CimCollectOutput;
            resolve(parsed);
            return;
          } catch {
            // fall through
          }
        }
        resolve({
          ok: false,
          errorMessage: err?.message || (stderr || '').trim() || 'PowerShell CIM invocation failed.',
        });
      }
    );
  });
}

function runWindowsDiagnostics(params: {
  target: string;
  hostnameHint: string;
  username?: string;
  password?: string;
  timeoutMs: number;
}): Promise<RawDiagnosticOutput | null> {
  if (process.platform !== 'win32') return Promise.resolve(null);
  const encoded = Buffer.from(STATIC_DIAGNOSTIC_PS, 'utf16le').toString('base64');
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    MEDLABS_WIN_TARGET: params.target,
    MEDLABS_WIN_HOSTNAME: params.hostnameHint,
    MEDLABS_WIN_TIMEOUT_SEC: String(Math.max(3, Math.round(params.timeoutMs / 1000))),
    MEDLABS_WIN_USE_CRED: params.username && params.password ? '1' : '0',
    MEDLABS_WIN_USER: params.username || '',
    MEDLABS_WIN_PASS: params.password || '',
  };

  return new Promise((resolve) => {
    execFile(
      'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-EncodedCommand', encoded],
      { timeout: params.timeoutMs + 8000, env, maxBuffer: 1024 * 1024 },
      (_err, stdout) => {
        const raw = (stdout || '').trim();
        if (raw) {
          try {
            resolve(JSON.parse(raw) as RawDiagnosticOutput);
            return;
          } catch {
            // fall through
          }
        }
        resolve(null);
      }
    );
  });
}

function classifyWindowsError(
  msg: string,
  portResults: { port: number; open: boolean }[],
  identity?: WindowsProcessIdentity
): {
  status: CollectionStatus;
  prerequisiteHint: string;
  doubleHopWarning?: string;
} {
  const lower = msg.toLowerCase();
  const port5985 = portResults.find((p) => p.port === 5985)?.open;
  const port5986 = portResults.find((p) => p.port === 5986)?.open;
  const port135 = portResults.find((p) => p.port === 135)?.open;

  if (
    lower.includes('0x8009030e') ||
    lower.includes('sec_e_no_credentials') ||
    lower.includes('0x80070520') ||
    lower.includes('logon session does not exist') ||
    lower.includes('delegat') ||
    lower.includes('credssp')
  ) {
    return {
      status: 'Authentication Failed',
      doubleHopWarning:
        identity?.doubleHopReason ||
        'Double-hop / delegation failure (0x8009030e / 0x80070520): The central backend process security context does not have a delegatable Kerberos TGT for outbound remote connections.',
      prerequisiteHint:
        'Start the MedLabs central monitoring backend directly on the domain-joined central server (Interactive/Console or Windows Service logged on as MEDLABS\\username), NOT from inside an un-delegated remote PowerShell/WinRM session.',
    };
  }

  if (lower.includes('logon failure') || lower.includes('bad username') || lower.includes('unknown user name')) {
    return {
      status: 'Authentication Failed',
      prerequisiteHint:
        'Kerberos/Logon authentication was rejected by the domain or target server. Verify the process domain identity or Credential Vault account.',
    };
  }

  if (
    lower.includes('access is denied') ||
    lower.includes('0x80070005') ||
    lower.includes('trustedhosts') ||
    lower.includes('negotiate authentication')
  ) {
    const idLabel = identity?.identityName ? ` (process identity: ${identity.identityName})` : '';
    return {
      status: 'Permission Denied',
      doubleHopWarning: identity?.doubleHopRisk ? identity.doubleHopReason : undefined,
      prerequisiteHint: `Target server refused remote WMI/WinRM access${idLabel} without escalation. Ensure the target is domain-joined, DNS/FQDN resolves for Kerberos (avoid raw IP if TrustedHosts is unset), and the domain account has remote WMI/WinRM read access on the target.`,
    };
  }

  if (
    lower.includes('does not provide native windows wmi') ||
    lower.includes('unsupported')
  ) {
    return {
      status: 'Unsupported Metric',
      prerequisiteHint:
        'Run the MedLabs central monitoring backend on a domain-joined Windows Server for native Integrated Auth WMI/CIM, or attach an SNMPv2c/SNMPv3 Read-Only profile.',
    };
  }

  if (!port5985 && !port5986 && !port135) {
    return {
      status: 'Unreachable',
      prerequisiteHint:
        'Native WinRM HTTPS (TCP 5986), WinRM HTTP (TCP 5985), and WMI/DCOM (TCP 135) are closed or firewalled from the central server.',
    };
  }

  return {
    status: 'Unreachable',
    prerequisiteHint:
      'Verify AD DNS FQDN resolution (for Kerberos SPN), WinRM listener (5986/5985), or Windows Firewall WMI/RPC rules from the central server.',
  };
}

export function isServerLocalHost(srv: Pick<WindowsServer, 'hostname' | 'ipAddress'>): boolean {
  const localHost = os.hostname().toLowerCase();
  const h = srv.hostname.toLowerCase();
  const ip = srv.ipAddress;
  if (h === localHost || ip === '127.0.0.1' || h === 'localhost') return true;
  const nets = os.networkInterfaces();
  for (const list of Object.values(nets)) {
    if (list?.some((n) => n.family === 'IPv4' && n.address === ip)) {
      return true;
    }
  }
  return false;
}

function resolveWindowsAuthForServer(
  srv: WindowsServer,
  vault: CredentialVault
): {
  cimCred: { username?: string; password?: string; isIntegrated: boolean } | null;
  snmpAuth: SnmpTargetAuth | null;
  credDecryptError: string | null;
} {
  let cimCred: { username?: string; password?: string; isIntegrated: boolean } | null = null;
  let snmpAuth: SnmpTargetAuth | null = null;
  let credDecryptError: string | null = null;

  if (srv.credentialId) {
    const dec = vault.getDecrypted(srv.credentialId);
    if (!dec.ok) {
      credDecryptError = dec.error;
    } else if (dec.payload.kind === 'windows') {
      if (dec.payload.useIntegratedAuth) {
        // Process security context only â€” never request/store domain password
        cimCred = { isIntegrated: true };
      } else {
        const fullUser =
          dec.payload.domain && dec.payload.username && !dec.payload.username.includes('\\')
            ? `${dec.payload.domain}\\${dec.payload.username}`
            : dec.payload.username;
        cimCred = { username: fullUser, password: dec.payload.password, isIntegrated: false };
      }
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
  } else if (srv.authMode !== 'snmp-only') {
    // Default / integrated mode: use current Windows process security context
    cimCred = { isIntegrated: true };
  }

  if (!snmpAuth && srv.snmpCommunity && srv.snmpCommunity.trim()) {
    snmpAuth = { version: 'v2c', community: srv.snmpCommunity.trim() };
  }

  return { cimCred, snmpAuth, credDecryptError };
}

export class WindowsServerCollector implements ServerCollectorAdapter {
  readonly platform = 'windows' as const;

  async collect(srv: WindowsServer, ctx: CollectorContext): Promise<UnifiedCollectionResult> {
    const stamp = new Date().toISOString().replace('T', ' ').slice(0, 19);
    const target =
      srv.ipAddress && srv.ipAddress !== 'â€”' && srv.ipAddress !== '-' ? srv.ipAddress : srv.hostname;
    const isLocal = isServerLocalHost(srv);
    const { prohibitedReasons } = getPermittedMethods(srv);
    const restrictions = [...prohibitedReasons];

    if (isLocal) {
      const cpus = os.cpus();
      let idleMs = 0;
      let totalMs = 0;
      for (const c of cpus) {
        idleMs += c.times.idle;
        totalMs += c.times.user + c.times.nice + c.times.sys + c.times.irq + c.times.idle;
      }
      const cpuPct = totalMs > 0 ? Number((((totalMs - idleMs) / totalMs) * 100).toFixed(1)) : 0;
      const totalMemGb = Number((os.totalmem() / 1024 / 1024 / 1024).toFixed(1));
      const freeMemGb = os.freemem() / 1024 / 1024 / 1024;
      const ramPct = totalMemGb > 0 ? Number((((totalMemGb - freeMemGb) / totalMemGb) * 100).toFixed(1)) : 0;
      const uptimeHours = Math.round(os.uptime() / 3600);
      const osLabel = `${os.type()} ${os.release()} (${os.arch()})`;
      const nets = os.networkInterfaces();
      let primaryIp = srv.ipAddress || '127.0.0.1';
      for (const list of Object.values(nets)) {
        const ipv4 = list?.find((n) => n.family === 'IPv4' && !n.internal);
        if (ipv4) {
          primaryIp = ipv4.address;
          break;
        }
      }

      let diskAvailable = false;
      let servicesAvailable = false;
      let netAvailable = false;

      if (process.platform === 'win32') {
        const localCim = await runPowerShellCim({
          target: 'localhost',
          hostnameHint: 'localhost',
          isLocal: true,
          preferKerberos: false,
          timeoutMs: ctx.timeoutMs,
        });
        if (localCim.ok) {
          if (typeof localCim.diskTotalGb === 'number' && localCim.diskTotalGb > 0) {
            srv.diskTotalGb = localCim.diskTotalGb;
            srv.diskAvailableGb = localCim.diskAvailableGb ?? 0;
            srv.diskPct = localCim.diskPct ?? 0;
            diskAvailable = true;
          }
          if (Array.isArray(localCim.services) && localCim.services.length > 0) {
            srv.services = localCim.services;
            servicesAvailable = true;
          }
          if (Array.isArray(localCim.networkInterfaces)) {
            srv.networkInterfaces = localCim.networkInterfaces;
            netAvailable = localCim.networkInterfaces.length > 0;
          }
          if (localCim.osVersion) srv.osVersion = localCim.osVersion;
          if (localCim.domainMembership) srv.domainMembership = localCim.domainMembership;
          if (typeof localCim.runningProcessesCount === 'number') srv.runningProcessesCount = localCim.runningProcessesCount;
          if (Array.isArray(localCim.iisDetectedSites)) srv.iisDetectedSites = localCim.iisDetectedSites;
          if (typeof localCim.eventErrors24h === 'number') srv.eventErrors24h = localCim.eventErrors24h;
        }
      } else {
        srv.osVersion = osLabel;
      }

      srv.cpuPct = cpuPct;
      srv.ramPct = ramPct;
      srv.ramTotalGb = totalMemGb;
      srv.uptimeHours = uptimeHours;
      if (!srv.osVersion || srv.osVersion === 'Windows Server') srv.osVersion = osLabel;
      srv.ipAddress = primaryIp;
      srv.lastCheck = stamp;
      srv.lastSuccessfulCheck = stamp;
      srv.status = 'Online';
      srv.metricsAvailable = {
        cpu: true,
        ram: true,
        disk: diskAvailable,
        uptime: true,
        services: servicesAvailable,
        networkTraffic: netAvailable,
      };
      srv.history.push({
        time: stamp.slice(11, 16),
        cpuPct: srv.cpuPct,
        ramPct: srv.ramPct,
        diskPct: srv.diskPct,
      });
      if (srv.history.length > 24) srv.history.shift();

      const integrity: MetricIntegrity = {
        collectionStatus: 'Healthy',
        dataSource: process.platform === 'win32' ? 'Local OS + Native CIM' : 'Central Host OS API',
        measuredAt: stamp,
        targetIdentifier: srv.hostname,
      };
      const capabilityMatrix: MonitoringCapabilityMatrix = {
        platformDetected: srv.osVersion || 'Local Central Host',
        icmpAvailable: true,
        tcpAvailable: true,
        winrmAvailable: process.platform === 'win32',
        wmiAvailable: process.platform === 'win32',
        sshAvailable: false,
        snmpAvailable: null,
        cloudApiAvailable: false,
        hypervHostAccess: false,
        availableMetrics: [
          'CPU',
          'RAM',
          ...(diskAvailable ? ['Disk'] : []),
          'Uptime',
          ...(servicesAvailable ? ['Windows Services'] : []),
          ...(netAvailable ? ['Network Traffic'] : []),
        ],
        unavailableMetrics: buildDefaultUnavailableMetrics(srv, 'Local host CIM query unavailable on non-Windows host.'),
        accessRestrictions: restrictions,
        activeMethod: integrity.dataSource,
        evaluatedAt: stamp,
      };
      srv.integrity = integrity;
      srv.capabilityMatrix = capabilityMatrix;
      srv.healthClassification = 'Monitoring Healthy';
      return { ok: true, integrity, healthClassification: 'Monitoring Healthy', capabilityMatrix };
    }

    if (!isValidTargetHost(target)) {
      const integrity: MetricIntegrity = {
        collectionStatus: 'Not Configured',
        dataSource: 'Validation',
        measuredAt: stamp,
        targetIdentifier: srv.hostname,
        errorDetail: 'Target hostname or IP address is invalid.',
      };
      const capabilityMatrix: MonitoringCapabilityMatrix = {
        platformDetected: 'Windows Server',
        icmpAvailable: null,
        tcpAvailable: null,
        winrmAvailable: false,
        wmiAvailable: false,
        sshAvailable: false,
        snmpAvailable: null,
        cloudApiAvailable: false,
        hypervHostAccess: false,
        availableMetrics: [],
        unavailableMetrics: buildDefaultUnavailableMetrics(srv, 'Target hostname/IP invalid.'),
        accessRestrictions: restrictions,
        evaluatedAt: stamp,
      };
      srv.integrity = integrity;
      srv.capabilityMatrix = capabilityMatrix;
      srv.healthClassification = 'Unsupported Monitoring Method';
      return { ok: false, integrity, healthClassification: 'Unsupported Monitoring Method', capabilityMatrix };
    }

    const allowIcmp = isMethodPermitted(srv, 'icmp');
    const allowTcp = isMethodPermitted(srv, 'tcp');
    const allowHttps = isMethodPermitted(srv, 'winrm-https');
    const allowHttp = isMethodPermitted(srv, 'winrm-http');
    const allowDcom = isMethodPermitted(srv, 'wmi-dcom');
    const allowSnmp = isMethodPermitted(srv, 'snmp');
    const allowHttpProbe = isMethodPermitted(srv, 'http-https') && Boolean(srv.httpUrl);

    if (!allowHttp) {
      restrictions.push('WinRM HTTP (5985) skipped by monitoring policy.');
    }
    if (!allowHttps) {
      restrictions.push('WinRM HTTPS (5986) disabled by server method settings.');
    }
    if (!allowDcom) {
      restrictions.push('WMI/DCOM (135) disabled by server method settings.');
    }

    const portsToCheck = [
      { port: 5986, name: 'TCP:5986', displayName: 'Windows WinRM HTTPS (5986)' },
      { port: 5985, name: 'TCP:5985', displayName: 'Windows WinRM HTTP (5985)' },
      { port: 135, name: 'TCP:135', displayName: 'Windows WMI/RPC Endpoint Mapper (135)' },
      { port: 445, name: 'TCP:445', displayName: 'Windows SMB (445)' },
      { port: 3389, name: 'TCP:3389', displayName: 'Remote Desktop RDP (3389)' },
      { port: 1521, name: 'TCP:1521', displayName: 'Oracle DB Listener (1521)' },
      { port: 443, name: 'TCP:443', displayName: 'HTTPS Web Service (443)' },
      { port: 80, name: 'TCP:80', displayName: 'HTTP Web Service (80)' },
    ];

    const [pingRes, portResults] = await Promise.all([
      allowIcmp
        ? pingHostStats(target, 2, 1000)
        : Promise.resolve({ alive: false, avgLatencyMs: null, minLatencyMs: null, maxLatencyMs: null, packetLossPct: 100, errorDetail: 'ICMP disabled by policy' }),
      allowTcp
        ? Promise.all(
            portsToCheck.map(async (p) => {
              const res = await checkTcpPort(target, p.port, 900);
              return { ...p, open: res.open };
            })
          )
        : Promise.resolve([]),
    ]);

    const openPorts = portResults.filter((p) => p.open);
    const anyPortOpen = openPorts.length > 0;

    let httpProbeOk = false;
    if (allowHttpProbe && srv.httpUrl) {
      try {
        const u = new URL(srv.httpUrl);
        if (u.protocol === 'http:' || u.protocol === 'https:') {
          const resp = await fetch(u.toString(), { method: 'GET', redirect: 'manual', signal: AbortSignal.timeout(4000) });
          httpProbeOk = resp.status < 500;
        }
      } catch {
        httpProbeOk = false;
      }
    }

    const reachable = pingRes.alive || anyPortOpen || httpProbeOk;
    srv.lastCheck =
      pingRes.avgLatencyMs !== null ? `${stamp} (${pingRes.avgLatencyMs}ms)` : stamp;
    if (reachable) srv.lastSuccessfulCheck = stamp;

    const { cimCred, snmpAuth, credDecryptError } = resolveWindowsAuthForServer(srv, ctx.vault);

    // Check exponential backoff per CIM protocol
    const boHttps = !ctx.bypassBackoff ? ctx.backoff.isBackedOff(srv.id, 'winrm-https') : { active: false };
    const boHttp = !ctx.bypassBackoff ? ctx.backoff.isBackedOff(srv.id, 'winrm-http') : { active: false };
    const boDcom = !ctx.bypassBackoff ? ctx.backoff.isBackedOff(srv.id, 'wmi-dcom') : { active: false };

    const tryHttps = allowHttps && !boHttps.active;
    const tryHttp = allowHttp && !boHttp.active;
    const tryDcom = allowDcom && !boDcom.active;
    const anyCimProtocolEligible = tryHttps || tryHttp || tryDcom;

    if (allowHttps && boHttps.active) restrictions.push(`WinRM HTTPS cooled down until ${boHttps.retryAt}.`);
    if (allowDcom && boDcom.active) restrictions.push(`WMI/DCOM cooled down until ${boDcom.retryAt}.`);

    // Step A: Attempt Native WMI/CIM/WinRM collection preferring Kerberos over FQDN
    let cimError: string | null = null;
    if (cimCred !== null && reachable && anyCimProtocolEligible) {
      const cimRes = await runPowerShellCim({
        target,
        hostnameHint: srv.hostname,
        isLocal: false,
        preferKerberos: true,
        allowHttps: tryHttps,
        allowHttp: tryHttp,
        allowDcom: tryDcom,
        username: cimCred.username,
        password: cimCred.password,
        timeoutMs: ctx.timeoutMs,
      });

      if (cimRes.ok) {
        ctx.backoff.clearMethod(srv.id, 'winrm-https');
        ctx.backoff.clearMethod(srv.id, 'winrm-http');
        ctx.backoff.clearMethod(srv.id, 'wmi-dcom');

        srv.cpuPct = cimRes.cpuPct ?? 0;
        srv.ramPct = cimRes.ramPct ?? 0;
        srv.ramTotalGb = cimRes.ramTotalGb ?? 0;
        srv.diskTotalGb = cimRes.diskTotalGb ?? 0;
        srv.diskAvailableGb = cimRes.diskAvailableGb ?? 0;
        srv.diskPct = cimRes.diskPct ?? 0;
        srv.uptimeHours = cimRes.uptimeHours ?? 0;
        if (cimRes.osVersion) srv.osVersion = cimRes.osVersion;
        if (cimRes.domainMembership) srv.domainMembership = cimRes.domainMembership;
        if (typeof cimRes.runningProcessesCount === 'number') srv.runningProcessesCount = cimRes.runningProcessesCount;
        if (Array.isArray(cimRes.iisDetectedSites)) srv.iisDetectedSites = cimRes.iisDetectedSites;
        if (typeof cimRes.eventErrors24h === 'number') srv.eventErrors24h = cimRes.eventErrors24h;
        if (Array.isArray(cimRes.services) && cimRes.services.length > 0) {
          srv.services = cimRes.services;
        }
        if (Array.isArray(cimRes.networkInterfaces)) {
          srv.networkInterfaces = cimRes.networkInterfaces;
        }
        srv.metricsAvailable = {
          cpu: true,
          ram: true,
          disk: (cimRes.diskTotalGb ?? 0) > 0,
          uptime: true,
          services: Array.isArray(cimRes.services) && cimRes.services.length > 0,
          networkTraffic: Array.isArray(cimRes.networkInterfaces) && cimRes.networkInterfaces.length > 0,
        };
        srv.history.push({
          time: stamp.slice(11, 16),
          cpuPct: srv.cpuPct,
          ramPct: srv.ramPct,
          diskPct: srv.diskPct,
        });
        if (srv.history.length > 24) srv.history.shift();
        srv.status = 'Online';
        srv.lastSuccessfulCheck = stamp;
        srv.healthClassification = 'Monitoring Healthy';

        const integrity: MetricIntegrity = {
          collectionStatus: 'Healthy',
          dataSource: `Native ${cimRes.protocol || 'WMI/CIM'}`,
          measuredAt: stamp,
          targetIdentifier: cimRes.resolvedTarget || target,
        };
        const capabilityMatrix: MonitoringCapabilityMatrix = {
          platformDetected: srv.osVersion || 'Windows Server',
          icmpAvailable: allowIcmp ? pingRes.alive : false,
          tcpAvailable: allowTcp ? anyPortOpen : false,
          winrmAvailable: Boolean(cimRes.protocol?.includes('WinRM')),
          wmiAvailable: Boolean(cimRes.protocol?.includes('WMI') || cimRes.protocol?.includes('CIM')),
          sshAvailable: false,
          snmpAvailable: snmpAuth ? null : false,
          cloudApiAvailable: false,
          hypervHostAccess: false,
          availableMetrics: [
            'CPU',
            'RAM',
            ...(srv.metricsAvailable.disk ? ['Disk'] : []),
            'Uptime',
            ...(srv.metricsAvailable.services ? ['Windows Services'] : []),
            ...(srv.metricsAvailable.networkTraffic ? ['Network Traffic'] : []),
            ...(srv.domainMembership ? [`Domain (${srv.domainMembership})`] : []),
            ...(typeof srv.runningProcessesCount === 'number' ? [`Processes (${srv.runningProcessesCount})`] : []),
            ...(srv.iisDetectedSites?.length ? [`IIS Sites (${srv.iisDetectedSites.length})`] : []),
          ],
          unavailableMetrics: [],
          accessRestrictions: restrictions,
          activeMethod: cimRes.protocol || 'WMI/CIM',
          evaluatedAt: stamp,
        };
        srv.integrity = integrity;
        srv.capabilityMatrix = capabilityMatrix;
        return { ok: true, integrity, healthClassification: 'Monitoring Healthy', capabilityMatrix };
      } else {
        cimError = cimRes.errorMessage || 'WMI/CIM remote query failed.';
        if (/access is denied|0x80070005|0x8009030e|logon failure|trustedhosts/i.test(cimError)) {
          if (tryHttps) ctx.backoff.recordBlockedOrDenied(srv.id, 'winrm-https', cimError);
          if (tryHttp) ctx.backoff.recordBlockedOrDenied(srv.id, 'winrm-http', cimError);
          if (tryDcom) ctx.backoff.recordBlockedOrDenied(srv.id, 'wmi-dcom', cimError);
        }
      }
    } else if (cimCred !== null && reachable && !anyCimProtocolEligible) {
      cimError = boHttps.reason || boDcom.reason || 'WinRM/WMI protocols are disabled or in temporary cooldown.';
    }

    // Step B: Attempt SNMPv2c / SNMPv3 Read-Only if configured and permitted
    if (allowSnmp && snmpAuth && reachable) {
      const snmpRes = await pollSnmpServerMetrics(target, snmpAuth, 161, Math.min(3000, ctx.timeoutMs));
      if (snmpRes) {
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

        srv.services = portResults.map((p) => ({
          name: p.name,
          displayName: p.displayName,
          status: p.open ? 'Running' : 'Stopped',
          startupType: 'Automatic',
        }));
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
        srv.status = 'Online';
        srv.lastSuccessfulCheck = stamp;
        srv.healthClassification = 'Monitoring Healthy';

        const integrity: MetricIntegrity = {
          collectionStatus: 'Healthy',
          dataSource: snmpAuth.version === 'v3' ? 'SNMPv3 Read-Only' : 'SNMPv2c Read-Only',
          measuredAt: stamp,
          targetIdentifier: target,
        };
        const capabilityMatrix: MonitoringCapabilityMatrix = {
          platformDetected: srv.osVersion || 'Windows Server (SNMP)',
          icmpAvailable: allowIcmp ? pingRes.alive : false,
          tcpAvailable: allowTcp ? anyPortOpen : false,
          winrmAvailable: false,
          wmiAvailable: false,
          sshAvailable: false,
          snmpAvailable: true,
          cloudApiAvailable: false,
          hypervHostAccess: false,
          availableMetrics: ['CPU', ...(srv.metricsAvailable.ram ? ['RAM'] : []), ...(srv.metricsAvailable.disk ? ['Disk'] : []), 'Uptime'],
          unavailableMetrics: buildDefaultUnavailableMetrics(srv, 'SNMP Read-Only does not expose Windows Services list or Per-NIC traffic here.'),
          accessRestrictions: restrictions,
          activeMethod: integrity.dataSource,
          evaluatedAt: stamp,
        };
        srv.integrity = integrity;
        srv.capabilityMatrix = capabilityMatrix;
        return { ok: true, integrity, healthClassification: 'Monitoring Healthy', capabilityMatrix };
      }
    }

    // No OS telemetry retrieved â€” keep ports real and report exact native status (never fake CPU/RAM!)
    srv.services = portResults.map((p) => ({
      name: p.name,
      displayName: p.displayName,
      status: p.open ? 'Running' : 'Stopped',
      startupType: 'Automatic',
    }));
    srv.metricsAvailable = {
      cpu: false,
      ram: false,
      disk: false,
      uptime: false,
      services: false,
      networkTraffic: false,
    };

    const availablePassive: string[] = [];
    if (pingRes.alive) availablePassive.push(`ICMP (${pingRes.avgLatencyMs ?? 0}ms)`);
    if (anyPortOpen) availablePassive.push(`TCP (${openPorts.map((p) => p.port).join(', ')})`);
    if (httpProbeOk) availablePassive.push('HTTP/HTTPS Endpoint');

    if (!reachable) {
      srv.status = 'Offline';
      const integrity: MetricIntegrity = {
        collectionStatus: 'Unreachable',
        dataSource: 'ICMP + TCP Probe',
        measuredAt: stamp,
        targetIdentifier: target,
        errorDetail: pingRes.errorDetail || `No ICMP or TCP response from ${target}.`,
        prerequisiteHint:
          'Verify network routing/VLAN connectivity and firewall rules from the central monitoring server to this host.',
      };
      const healthClassification: ServerHealthClassification = 'Server Offline';
      const capabilityMatrix: MonitoringCapabilityMatrix = {
        platformDetected: 'Windows Server',
        icmpAvailable: allowIcmp ? false : null,
        tcpAvailable: allowTcp ? false : null,
        winrmAvailable: false,
        wmiAvailable: false,
        sshAvailable: false,
        snmpAvailable: allowSnmp && snmpAuth ? false : null,
        cloudApiAvailable: false,
        hypervHostAccess: false,
        availableMetrics: [],
        unavailableMetrics: buildDefaultUnavailableMetrics(srv, integrity.errorDetail || 'Server unreachable.'),
        accessRestrictions: restrictions,
        activeMethod: 'None',
        evaluatedAt: stamp,
      };
      srv.integrity = integrity;
      srv.capabilityMatrix = capabilityMatrix;
      srv.healthClassification = healthClassification;
      return { ok: false, integrity, healthClassification, capabilityMatrix };
    }

    srv.status = 'Online';
    if (credDecryptError) {
      const integrity: MetricIntegrity = {
        collectionStatus: 'Authentication Failed',
        dataSource: 'Encrypted Credential Vault',
        measuredAt: stamp,
        targetIdentifier: target,
        errorDetail: credDecryptError,
        prerequisiteHint: 'Set MEDLABS_VAULT_KEY in server .env or switch to Windows Integrated Auth.',
      };
      const healthClassification: ServerHealthClassification = 'Authentication Failed';
      const capabilityMatrix: MonitoringCapabilityMatrix = {
        platformDetected: 'Windows Server',
        icmpAvailable: allowIcmp ? pingRes.alive : false,
        tcpAvailable: allowTcp ? anyPortOpen : false,
        winrmAvailable: false,
        wmiAvailable: false,
        sshAvailable: false,
        snmpAvailable: false,
        cloudApiAvailable: false,
        hypervHostAccess: false,
        availableMetrics: availablePassive,
        unavailableMetrics: buildDefaultUnavailableMetrics(srv, credDecryptError),
        accessRestrictions: restrictions,
        activeMethod: 'Passive ICMP/TCP',
        evaluatedAt: stamp,
      };
      srv.integrity = integrity;
      srv.capabilityMatrix = capabilityMatrix;
      srv.healthClassification = healthClassification;
      return { ok: false, integrity, healthClassification, capabilityMatrix };
    }

    if (cimError) {
      const procId = await detectProcessWindowsIdentity(false);
      const classified = classifyWindowsError(cimError, portResults, procId);
      const integrity: MetricIntegrity = {
        collectionStatus: classified.status,
        dataSource: 'WMI/CIM + WinRM (Kerberos)',
        measuredAt: stamp,
        targetIdentifier: target,
        errorDetail: cimError.slice(0, 320),
        prerequisiteHint: classified.doubleHopWarning || classified.prerequisiteHint,
      };
      const healthClassification = mapCollectionToHealthClassification({
        reachable: true,
        hasOsOrPrimaryMetrics: false,
        hasAnyPassiveMetric: availablePassive.length > 0,
        collectionStatus: classified.status,
        connectionBlocked: classified.status === 'Unreachable',
      });
      const capabilityMatrix: MonitoringCapabilityMatrix = {
        platformDetected: 'Windows Server',
        icmpAvailable: allowIcmp ? pingRes.alive : false,
        tcpAvailable: allowTcp ? anyPortOpen : false,
        winrmAvailable: false,
        wmiAvailable: false,
        sshAvailable: false,
        snmpAvailable: allowSnmp && snmpAuth ? false : null,
        cloudApiAvailable: false,
        hypervHostAccess: false,
        availableMetrics: availablePassive,
        unavailableMetrics: buildDefaultUnavailableMetrics(srv, cimError.slice(0, 200)),
        accessRestrictions: restrictions,
        activeMethod: availablePassive.length > 0 ? 'Passive ICMP/TCP Fallback' : 'None',
        evaluatedAt: stamp,
      };
      srv.integrity = integrity;
      srv.capabilityMatrix = capabilityMatrix;
      srv.healthClassification = healthClassification;
      return { ok: false, integrity, healthClassification, capabilityMatrix };
    }

    if (allowSnmp && snmpAuth) {
      const integrity: MetricIntegrity = {
        collectionStatus: 'Unreachable',
        dataSource: snmpAuth.version === 'v3' ? 'SNMPv3 + ICMP/TCP' : 'SNMPv2c + ICMP/TCP',
        measuredAt: stamp,
        targetIdentifier: target,
        errorDetail: `Host ${target} answered ICMP/TCP, but UDP/161 SNMP query timed out or community/USM failed.`,
        prerequisiteHint:
          'Native Windows prerequisite: Enable built-in Windows SNMP Service (Read-Only) permitting UDP/161 from this central server, or use Windows Integrated Auth.',
      };
      const healthClassification = mapCollectionToHealthClassification({
        reachable: true,
        hasOsOrPrimaryMetrics: false,
        hasAnyPassiveMetric: availablePassive.length > 0,
        collectionStatus: 'Unreachable',
        connectionBlocked: true,
      });
      const capabilityMatrix: MonitoringCapabilityMatrix = {
        platformDetected: 'Windows Server',
        icmpAvailable: allowIcmp ? pingRes.alive : false,
        tcpAvailable: allowTcp ? anyPortOpen : false,
        winrmAvailable: false,
        wmiAvailable: false,
        sshAvailable: false,
        snmpAvailable: false,
        cloudApiAvailable: false,
        hypervHostAccess: false,
        availableMetrics: availablePassive,
        unavailableMetrics: buildDefaultUnavailableMetrics(srv, integrity.errorDetail!),
        accessRestrictions: restrictions,
        activeMethod: 'Passive ICMP/TCP',
        evaluatedAt: stamp,
      };
      srv.integrity = integrity;
      srv.capabilityMatrix = capabilityMatrix;
      srv.healthClassification = healthClassification;
      return { ok: false, integrity, healthClassification, capabilityMatrix };
    }

    const integrity: MetricIntegrity = {
      collectionStatus: 'Not Configured',
      dataSource: 'ICMP + TCP Ports',
      measuredAt: stamp,
      targetIdentifier: target,
      errorDetail: 'Reachability & TCP ports verified, but no WMI/WinRM or SNMP Read-Only mode is configured/permitted.',
      prerequisiteHint:
        'Use Windows Integrated Auth (AD domain process context) or attach an encrypted Credential Vault profile.',
    };
    const healthClassification = availablePassive.length > 0 ? 'Partial Monitoring' : 'Unsupported Monitoring Method';
    const capabilityMatrix: MonitoringCapabilityMatrix = {
      platformDetected: 'Windows Server',
      icmpAvailable: allowIcmp ? pingRes.alive : false,
      tcpAvailable: allowTcp ? anyPortOpen : false,
      winrmAvailable: false,
      wmiAvailable: false,
      sshAvailable: false,
      snmpAvailable: false,
      cloudApiAvailable: false,
      hypervHostAccess: false,
      availableMetrics: availablePassive,
      unavailableMetrics: buildDefaultUnavailableMetrics(srv, integrity.errorDetail!),
      accessRestrictions: restrictions,
      activeMethod: availablePassive.length > 0 ? 'Passive ICMP/TCP' : 'None',
      evaluatedAt: stamp,
    };
    srv.integrity = integrity;
    srv.capabilityMatrix = capabilityMatrix;
    srv.healthClassification = healthClassification;
    return { ok: availablePassive.length > 0, integrity, healthClassification, capabilityMatrix };
  }

  async testConnection(srv: WindowsServer, ctx: CollectorContext): Promise<ConnectionTestResult> {
    return testWindowsConnection(srv, ctx.vault, ctx.timeoutMs);
  }
}

const defaultWindowsBackoff = new MethodBackoffTracker();
const defaultWindowsCollector = new WindowsServerCollector();

export async function collectWindowsServer(
  srv: WindowsServer,
  vault: CredentialVault,
  timeoutMs = 8000
): Promise<{ ok: boolean; integrity: MetricIntegrity }> {
  const res = await defaultWindowsCollector.collect(srv, {
    vault,
    timeoutMs,
    allServers: [srv],
    backoff: defaultWindowsBackoff,
  });
  return { ok: res.ok, integrity: res.integrity };
}

export async function testWindowsConnection(
  srv: WindowsServer,
  vault: CredentialVault,
  timeoutMs = 8000
): Promise<ConnectionTestResult> {
  const started = Date.now();
  const stamp = new Date().toISOString().replace('T', ' ').slice(0, 19);
  const target =
    srv.ipAddress && srv.ipAddress !== 'â€”' && srv.ipAddress !== '-' ? srv.ipAddress : srv.hostname;
  const isLocal = isServerLocalHost(srv);
  const processIdentity = await detectProcessWindowsIdentity(true);

  // Check 1: Independent Domain Authentication check (central process context only; never implies target success!)
  const domainAuthCheck: DiagnosticCheckItem = processIdentity.platform !== 'win32'
    ? {
        key: 'domain_auth',
        label: '1. Domain Authentication (Process Context)',
        ok: false,
        status: 'Unsupported Metric',
        latencyMs: 0,
        details: `Central backend is running on ${processIdentity.platform} (${processIdentity.identityName}), not Windows Server.`,
        prerequisiteHint: 'Run the central monitoring engine on a domain-joined Windows Server under MEDLABS\\username.',
      }
    : processIdentity.isSystemAccount
      ? {
          key: 'domain_auth',
          label: '1. Domain Authentication (Process Context)',
          ok: false,
          status: 'Authentication Failed',
          latencyMs: 0,
          details: `Backend runs under ${processIdentity.identityName} instead of a domain administrator/user account.`,
          prerequisiteHint: 'Run the backend process under the MEDLABS\\username domain account (interactive or Windows Service).',
        }
      : {
          key: 'domain_auth',
          label: '1. Domain Authentication (Process Context)',
          ok: processIdentity.partOfDomain && processIdentity.isDomainUser,
          status:
            processIdentity.partOfDomain && processIdentity.isDomainUser
              ? processIdentity.doubleHopRisk
                ? 'Warning'
                : 'Healthy'
              : 'Authentication Failed',
          latencyMs: 0,
          details: `Process identity: ${processIdentity.identityName} | Domain Joined: ${processIdentity.partOfDomain} (${processIdentity.domain || 'None'}) | Auth: ${processIdentity.authenticationType} | Logon: ${processIdentity.logonType || 'Unknown'}. Note: Remote target access is verified independently below.`,
          prerequisiteHint: !processIdentity.partOfDomain || !processIdentity.isDomainUser
            ? 'Central backend process must run as an AD domain user (MEDLABS\\username) on a domain-joined Windows Server.'
            : processIdentity.doubleHopReason,
        };

  if (isLocal) {
    const clone: WindowsServer = structuredClone(srv);
    const res = await collectWindowsServer(clone, vault, timeoutMs);
    const metricsCheck: DiagnosticCheckItem = {
      key: 'metrics_collection',
      label: '5. CPU, RAM & Disk Collection',
      ok: res.ok,
      status: res.integrity.collectionStatus,
      latencyMs: Date.now() - started,
      details: res.ok
        ? `Local central host metrics: CPU ${clone.cpuPct}%, RAM ${clone.ramPct}%, Disk ${clone.diskPct}%.`
        : res.integrity.errorDetail || 'Local host collection failed.',
    };
    return {
      ok: res.ok,
      status: res.integrity.collectionStatus,
      dataSource: res.integrity.dataSource,
      latencyMs: Date.now() - started,
      measuredAt: stamp,
      details: metricsCheck.details,
      processIdentity,
      checks: [domainAuthCheck, metricsCheck],
      doubleHopWarning: processIdentity.doubleHopRisk ? processIdentity.doubleHopReason : undefined,
    };
  }

  const { cimCred, credDecryptError } = resolveWindowsAuthForServer(srv, vault);

  if (process.platform !== 'win32') {
    const checks: DiagnosticCheckItem[] = [
      domainAuthCheck,
      {
        key: 'kerberos',
        label: '2. Kerberos Availability',
        ok: false,
        status: 'Unsupported Metric',
        latencyMs: null,
        details: 'Kerberos SSPI/KDC ticket checks require running on Windows Server.',
      },
      {
        key: 'wmi_dcom',
        label: '3. WMI / DCOM (TCP 135)',
        ok: false,
        status: 'Unsupported Metric',
        latencyMs: null,
        details: 'Native WMI/DCOM client requires Windows Server.',
      },
      {
        key: 'winrm_https',
        label: '4. WinRM HTTPS (TCP 5986)',
        ok: false,
        status: 'Unsupported Metric',
        latencyMs: null,
        details: 'Native WinRM Kerberos client requires Windows Server.',
      },
      {
        key: 'metrics_collection',
        label: '5. CPU, RAM & Disk Collection',
        ok: false,
        status: 'Unsupported Metric',
        latencyMs: null,
        details: 'Remote Windows WMI/CIM collection cannot execute from non-Windows OS.',
      },
    ];
    return {
      ok: false,
      status: 'Unsupported Metric',
      dataSource: 'Windows Integrated Auth Diagnostics',
      latencyMs: Date.now() - started,
      measuredAt: stamp,
      details: `Central backend OS (${process.platform}) cannot execute native Windows Integrated Authentication or Kerberos WMI/WinRM queries.`,
      prerequisiteHint: 'Deploy and run the backend on the domain-joined MedLabs Windows Server (dbmonitoring).',
      processIdentity,
      checks,
    };
  }

  if (credDecryptError) {
    return {
      ok: false,
      status: 'Authentication Failed',
      dataSource: 'Encrypted Credential Vault',
      latencyMs: Date.now() - started,
      measuredAt: stamp,
      details: credDecryptError,
      prerequisiteHint: 'Set MEDLABS_VAULT_KEY in .env or switch the server to Windows Integrated Auth (no password required).',
      processIdentity,
      checks: [domainAuthCheck],
    };
  }

  const diag = await runWindowsDiagnostics({
    target,
    hostnameHint: srv.hostname,
    username: cimCred?.username,
    password: cimCred?.password,
    timeoutMs,
  });

  if (!diag) {
    return {
      ok: false,
      status: 'Unreachable',
      dataSource: 'Windows Diagnostics',
      latencyMs: Date.now() - started,
      measuredAt: stamp,
      details: 'Windows diagnostic runner did not return structured output.',
      processIdentity,
      checks: [domainAuthCheck],
    };
  }

  const checks: DiagnosticCheckItem[] = [
    domainAuthCheck,
    {
      key: 'kerberos',
      label: '2. Kerberos Availability',
      ok: Boolean(diag.kerberosOk),
      status: diag.kerberosStatus || 'Unreachable',
      latencyMs: diag.kerberosLatencyMs ?? null,
      details: diag.kerberosDetails || (diag.dnsError ? `DNS lookup failed: ${diag.dnsError}` : 'Kerberos check failed.'),
      prerequisiteHint: diag.kerberosHint || undefined,
    },
    {
      key: 'wmi_dcom',
      label: '3. WMI / DCOM (TCP 135)',
      ok: Boolean(diag.dcomOk),
      status: diag.dcomStatus || 'Unreachable',
      latencyMs: diag.dcomLatencyMs ?? null,
      details: diag.dcomDetails || 'DCOM check did not complete.',
      prerequisiteHint: diag.dcomHint || undefined,
    },
    {
      key: 'winrm_https',
      label: '4. WinRM HTTPS (TCP 5986)',
      ok: Boolean(diag.winrmHttpsOk),
      status: diag.winrmHttpsStatus || 'Unreachable',
      latencyMs: diag.winrmHttpsLatencyMs ?? null,
      details:
        (diag.winrmHttpsDetails || 'WinRM HTTPS check did not complete.') +
        (diag.winrmHttpNote ? ` [${diag.winrmHttpNote}]` : ''),
      prerequisiteHint: diag.winrmHttpsHint || undefined,
    },
    {
      key: 'metrics_collection',
      label: '5. CPU, RAM & Disk Collection',
      ok: Boolean(diag.metricsOk),
      status: diag.metricsStatus || 'Unreachable',
      latencyMs: diag.metricsLatencyMs ?? null,
      details: diag.metricsDetails || 'CPU, RAM, and Disk collection failed.',
      prerequisiteHint: diag.metricsHint || undefined,
    },
  ];

  const doubleHopWarning =
    diag.doubleHopDetected
      ? diag.doubleHopReason || 'Double-hop authentication / Kerberos delegation error detected.'
      : processIdentity.doubleHopRisk
        ? processIdentity.doubleHopReason
        : undefined;

  // Never claim authentication/test succeeded merely because domainAuthCheck passed!
  const overallOk = Boolean(diag.metricsOk);
  const overallStatus: CollectionStatus = overallOk
    ? 'Healthy'
    : diag.doubleHopDetected
      ? 'Authentication Failed'
      : diag.dcomStatus === 'Permission Denied' || diag.winrmHttpsStatus === 'Permission Denied'
        ? 'Permission Denied'
        : diag.metricsStatus || 'Unreachable';

  const summaryHint = !overallOk
    ? doubleHopWarning ||
      checks.find((c) => !c.ok && c.prerequisiteHint)?.prerequisiteHint ||
      'Remote access was denied or unreachable; no target changes or privilege escalation were attempted.'
    : undefined;

  return {
    ok: overallOk,
    status: overallStatus,
    dataSource: diag.protocolUsed ? `Windows Integrated (${diag.protocolUsed})` : 'Windows Integrated Diagnostics',
    latencyMs: Date.now() - started,
    measuredAt: stamp,
    details: overallOk
      ? `${diag.metricsDetails} (Target FQDN: ${diag.fqdn}, Identity: ${processIdentity.identityName})`
      : `${diag.metricsDetails} | DCOM: ${diag.dcomStatus} | WinRM-HTTPS: ${diag.winrmHttpsStatus} | Identity: ${processIdentity.identityName}`,
    prerequisiteHint: summaryHint,
    processIdentity,
    checks,
    doubleHopWarning,
  };
}

