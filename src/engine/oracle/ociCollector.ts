import crypto from 'crypto';
import type { CredentialVault } from '../credentialVault.ts';
import { maskSensitiveText } from '../credentialVault.ts';
import type {
  OciCloudConfig,
  OciInstanceMetrics,
  OracleConnectorHealth,
  OracleHistoryRecord,
} from '../../types/infrastructure.ts';
import { buildOracleHistoryRecord } from './oracleMetrics.ts';
import type { OciCollectionResult } from './oracleTypes.ts';
import { formatMedLabsTimestamp } from '../time.ts';

const OCI_REGION_REGEX = /^[a-z]{2}-[a-z0-9-]+-\d+$/;
const OCI_OCID_REGEX = /^ocid1\.[a-z0-9_.-]+$/i;

export function isValidOciRegion(region?: string): boolean {
  return Boolean(region && OCI_REGION_REGEX.test(region.trim()));
}

export function isValidOcid(ocid?: string): boolean {
  return Boolean(ocid && OCI_OCID_REGEX.test(ocid.trim()));
}

export function validateSafeOciProxyUrl(raw?: string): { valid: boolean; url?: URL; reason?: string } {
  if (!raw?.trim()) return { valid: false, reason: 'No proxy URL configured.' };
  try {
    const parsed = new URL(raw.trim());
    const isLoopback = parsed.hostname === '127.0.0.1' || parsed.hostname === 'localhost' || parsed.hostname === '::1';
    if (parsed.protocol === 'https:' || (parsed.protocol === 'http:' && isLoopback)) {
      return { valid: true, url: parsed };
    }
    return { valid: false, reason: 'OCI proxy URL must use HTTPS (or loopback HTTP for local testing).' };
  } catch {
    return { valid: false, reason: 'Malformed OCI proxy URL.' };
  }
}

/**
 * Computes an authentic OCI REST API HTTP Signature v1 header (rsa-sha256).
 * Strictly read-only GET/POST telemetry calls; never logs or returns private keys.
 */
export function buildOciSignedHeaders(params: {
  method: 'GET' | 'POST';
  url: URL;
  tenancyOcid: string;
  userOcid: string;
  fingerprint: string;
  privateKeyPem: string;
  passphrase?: string;
  body?: string;
}): Record<string, string> {
  const dateStr = new Date().toUTCString();
  const targetPath = `${params.url.pathname}${params.url.search}`;
  const host = params.url.host;

  const headersToSign: string[] = ['(request-target)', 'date', 'host'];
  const lines: string[] = [
    `(request-target): ${params.method.toLowerCase()} ${targetPath}`,
    `date: ${dateStr}`,
    `host: ${host}`,
  ];

  const outHeaders: Record<string, string> = {
    date: dateStr,
    host,
    accept: 'application/json',
  };

  if (params.method === 'POST') {
    const payloadStr = params.body || '';
    const sha256B64 = crypto.createHash('sha256').update(payloadStr, 'utf8').digest('base64');
    const contentLength = String(Buffer.byteLength(payloadStr, 'utf8'));
    outHeaders['content-type'] = 'application/json';
    outHeaders['content-length'] = contentLength;
    outHeaders['x-content-sha256'] = sha256B64;

    headersToSign.push('x-content-sha256', 'content-type', 'content-length');
    lines.push(
      `x-content-sha256: ${sha256B64}`,
      `content-type: application/json`,
      `content-length: ${contentLength}`
    );
  }

  const signingString = lines.join('\n');
  const keyObj = crypto.createPrivateKey({
    key: params.privateKeyPem,
    ...(params.passphrase ? { passphrase: params.passphrase } : {}),
  });
  const signer = crypto.createSign('RSA-SHA256');
  signer.update(signingString, 'utf8');
  const signature = signer.sign(keyObj, 'base64');

  const keyId = `${params.tenancyOcid}/${params.userOcid}/${params.fingerprint}`;
  outHeaders.authorization = `Signature version="1",keyId="${keyId}",algorithm="rsa-sha256",headers="${headersToSign.join(' ')}",signature="${signature}"`;
  return outHeaders;
}

interface OciSummarizeDatapoint {
  timestamp?: string;
  value?: number;
}

interface OciSummarizeSeries {
  aggregatedDatapoints?: OciSummarizeDatapoint[];
  metadata?: Record<string, string>;
}

async function queryOciMetricValue(params: {
  telemetryBase: string;
  compartmentOcid: string;
  instanceOcid: string;
  namespace: string;
  query: string;
  signParams: {
    authMethod: 'api-key' | 'instance-principal' | 'resource-principal' | 'proxy-url';
    tenancyOcid?: string;
    userOcid?: string;
    fingerprint?: string;
    privateKeyPem?: string;
    passphrase?: string;
    bearerToken?: string;
  };
  timeoutMs: number;
}): Promise<{ ok: boolean; value: number | null; statusCode?: number; error?: string }> {
  const now = new Date();
  const start = new Date(now.getTime() - 15 * 60_000);
  const url = new URL(
    `${params.telemetryBase}/20180401/metrics/actions/summarizeMetricsData?compartmentId=${encodeURIComponent(
      params.compartmentOcid
    )}`
  );

  const bodyStr = JSON.stringify({
    namespace: params.namespace,
    query: params.query,
    startTime: start.toISOString(),
    endTime: now.toISOString(),
    resolution: '5m',
  });

  let headers: Record<string, string>;
  if (
    params.signParams.authMethod === 'api-key' &&
    params.signParams.tenancyOcid &&
    params.signParams.userOcid &&
    params.signParams.fingerprint &&
    params.signParams.privateKeyPem
  ) {
    headers = buildOciSignedHeaders({
      method: 'POST',
      url,
      tenancyOcid: params.signParams.tenancyOcid,
      userOcid: params.signParams.userOcid,
      fingerprint: params.signParams.fingerprint,
      privateKeyPem: params.signParams.privateKeyPem,
      passphrase: params.signParams.passphrase,
      body: bodyStr,
    });
  } else {
    headers = {
      'content-type': 'application/json',
      accept: 'application/json',
      ...(params.signParams.bearerToken ? { authorization: `Bearer ${params.signParams.bearerToken}` } : {}),
    };
  }

  try {
    const resp = await fetch(url.toString(), {
      method: 'POST',
      headers,
      body: bodyStr,
      signal: AbortSignal.timeout(Math.min(8000, params.timeoutMs)),
    });
    if (!resp.ok) {
      const errText = await resp.text().catch(() => '');
      return {
        ok: false,
        value: null,
        statusCode: resp.status,
        error: maskSensitiveText(`HTTP ${resp.status}: ${errText.slice(0, 140)}`),
      };
    }
    const items = (await resp.json()) as OciSummarizeSeries[];
    if (!Array.isArray(items) || items.length === 0) {
      return { ok: true, value: null };
    }
    const dps = items[0]?.aggregatedDatapoints || [];
    if (dps.length === 0) return { ok: true, value: null };
    const latest = dps[dps.length - 1]?.value;
    return {
      ok: true,
      value: typeof latest === 'number' && Number.isFinite(latest) ? Number(latest.toFixed(2)) : null,
    };
  } catch (err) {
    return {
      ok: false,
      value: null,
      error: maskSensitiveText(err instanceof Error ? err.message : String(err)),
    };
  }
}

export async function collectOciInfrastructure(params: {
  targetId: string;
  config?: OciCloudConfig;
  vault: CredentialVault;
  timeoutMs?: number;
}): Promise<OciCollectionResult> {
  const stamp = formatMedLabsTimestamp();
  const started = Date.now();
  const cfg = params.config;
  const timeoutMs = params.timeoutMs ?? 8000;

  if (!cfg || !cfg.enabled) {
    const connector: OracleConnectorHealth = {
      connector: 'OCI Infrastructure',
      status: 'Not Configured',
      collectionStatus: 'Not Configured',
      source: 'OCI API',
      lastAttemptAt: stamp,
      availableMetrics: [],
      unavailableMetrics: [
        { metric: 'OCI Compute Lifecycle & Hypervisor Metrics', reason: 'OCI Infrastructure Connector is not enabled.' },
      ],
      prerequisiteHint:
        'Provide OCI Region, Compartment OCID, Instance OCID, and attach an encrypted OCI API credential profile (read-only IAM group inspect/read metrics) to enable.',
    };
    return { ok: false, connector, historyRecords: [] };
  }

  const credRes = cfg.credentialId ? params.vault.getDecrypted(cfg.credentialId) : null;
  const credPayload = credRes?.ok ? credRes.payload : undefined;

  const region = cfg.region?.trim() || credPayload?.ociRegion?.trim() || '';
  const tenancyOcid = cfg.tenancyOcid?.trim() || credPayload?.ociTenancyOcid?.trim() || '';
  const compartmentOcid = cfg.compartmentOcid?.trim() || tenancyOcid;
  const instanceOcid = cfg.instanceOcid?.trim() || '';
  const authMethod = cfg.authMethod || credPayload?.ociAuthType || 'api-key';

  if (cfg.credentialId && credRes && !credRes.ok) {
    const connector: OracleConnectorHealth = {
      connector: 'OCI Infrastructure',
      status: 'Authentication Failed',
      collectionStatus: 'Authentication Failed',
      source: 'OCI API',
      lastAttemptAt: stamp,
      latencyMs: Date.now() - started,
      availableMetrics: [],
      unavailableMetrics: [{ metric: 'OCI API', reason: credRes.error }],
      errorDetail: credRes.error,
    };
    return { ok: false, connector, historyRecords: [] };
  }

  let iaasBase = '';
  let telemetryBase = '';

  if (authMethod === 'proxy-url') {
    const proxyCheck = validateSafeOciProxyUrl(credPayload?.ociProxyUrl || credPayload?.cloudBaseUrl);
    if (!proxyCheck.valid || !proxyCheck.url) {
      const connector: OracleConnectorHealth = {
        connector: 'OCI Infrastructure',
        status: 'Not Configured',
        collectionStatus: 'Not Configured',
        source: 'OCI API',
        lastAttemptAt: stamp,
        availableMetrics: [],
        unavailableMetrics: [{ metric: 'OCI Proxy Endpoint', reason: proxyCheck.reason || 'Invalid OCI proxy URL.' }],
        errorDetail: proxyCheck.reason,
      };
      return { ok: false, connector, historyRecords: [] };
    }
    const base = proxyCheck.url.toString().replace(/\/+$/, '');
    iaasBase = base;
    telemetryBase = base;
  } else {
    if (!isValidOciRegion(region)) {
      const connector: OracleConnectorHealth = {
        connector: 'OCI Infrastructure',
        status: 'Not Configured',
        collectionStatus: 'Not Configured',
        source: 'OCI API',
        lastAttemptAt: stamp,
        availableMetrics: [],
        unavailableMetrics: [{ metric: 'OCI Region', reason: 'Valid OCI region identifier required (e.g. me-jeddah-1, eu-frankfurt-1).' }],
        errorDetail: 'Invalid or missing OCI Region.',
      };
      return { ok: false, connector, historyRecords: [] };
    }
    iaasBase = `https://iaas.${region}.oraclecloud.com`;
    telemetryBase = `https://telemetry.${region}.oraclecloud.com`;
  }

  if (!isValidOcid(instanceOcid) || !isValidOcid(compartmentOcid)) {
    const connector: OracleConnectorHealth = {
      connector: 'OCI Infrastructure',
      status: 'Not Configured',
      collectionStatus: 'Not Configured',
      source: 'OCI API',
      lastAttemptAt: stamp,
      availableMetrics: [],
      unavailableMetrics: [
        { metric: 'OCI OCIDs', reason: 'Valid Instance OCID and Compartment OCID are required.' },
      ],
      errorDetail: 'Missing or invalid Instance OCID / Compartment OCID.',
    };
    return { ok: false, connector, historyRecords: [] };
  }

  if (authMethod === 'api-key') {
    if (
      !credPayload ||
      !isValidOcid(tenancyOcid) ||
      !isValidOcid(credPayload.ociUserOcid) ||
      !credPayload.ociFingerprint ||
      !credPayload.privateKey
    ) {
      const connector: OracleConnectorHealth = {
        connector: 'OCI Infrastructure',
        status: 'Not Configured',
        collectionStatus: 'Not Configured',
        source: 'OCI API',
        lastAttemptAt: stamp,
        availableMetrics: [],
        unavailableMetrics: [
          {
            metric: 'OCI API Signing Key',
            reason: 'Attach an OCI API credential with Tenancy OCID, User OCID, Key Fingerprint, and PEM RSA Private Key.',
          },
        ],
        errorDetail: 'Incomplete OCI API key credentials.',
        prerequisiteHint:
          'Configure an OCI read-only IAM policy ("Allow group MonitoringRO to read instances in compartment ...", "Allow group MonitoringRO to read metrics in compartment ...") and upload the API signing key to the Credential Vault.',
      };
      return { ok: false, connector, historyRecords: [] };
    }
  }

  let instanceData: {
    lifecycleState?: string;
    shape?: string;
    availabilityDomain?: string;
  } = {};
  let instanceError: string | undefined;
  let instanceStatusCode: number | undefined;

  const instanceUrl = new URL(`${iaasBase}/20160918/instances/${encodeURIComponent(instanceOcid)}`);
  let instanceHeaders: Record<string, string> = { accept: 'application/json' };
  try {
    if (authMethod === 'api-key' && credPayload?.privateKey && credPayload.ociUserOcid && credPayload.ociFingerprint) {
      instanceHeaders = buildOciSignedHeaders({
        method: 'GET',
        url: instanceUrl,
        tenancyOcid,
        userOcid: credPayload.ociUserOcid,
        fingerprint: credPayload.ociFingerprint,
        privateKeyPem: credPayload.privateKey,
        passphrase: credPayload.passphrase,
      });
    } else if (credPayload?.cloudApiToken) {
      instanceHeaders.authorization = `Bearer ${credPayload.cloudApiToken}`;
    }

    const instResp = await fetch(instanceUrl.toString(), {
      method: 'GET',
      headers: instanceHeaders,
      signal: AbortSignal.timeout(Math.min(8000, timeoutMs)),
    });
    instanceStatusCode = instResp.status;
    if (instResp.ok) {
      const body = (await instResp.json()) as {
        lifecycleState?: string;
        shape?: string;
        availabilityDomain?: string;
      };
      instanceData = {
        lifecycleState: body.lifecycleState,
        shape: body.shape,
        availabilityDomain: body.availabilityDomain,
      };
    } else {
      const txt = await instResp.text().catch(() => '');
      instanceError = maskSensitiveText(`OCI Compute API HTTP ${instResp.status}: ${txt.slice(0, 140)}`);
    }
  } catch (err) {
    instanceError = maskSensitiveText(err instanceof Error ? err.message : String(err));
  }

  const signParams = {
    authMethod,
    tenancyOcid,
    userOcid: credPayload?.ociUserOcid,
    fingerprint: credPayload?.ociFingerprint,
    privateKeyPem: credPayload?.privateKey,
    passphrase: credPayload?.passphrase,
    bearerToken: credPayload?.cloudApiToken,
  };

  const metricQueries: { key: keyof OciInstanceMetrics; label: string; namespace: string; query: string }[] = [
    {
      key: 'cpuUtilizationPct',
      label: 'CPU Utilization',
      namespace: 'oci_computeagent',
      query: `CpuUtilization[5m]{resourceId = "${instanceOcid}"}.mean()`,
    },
    {
      key: 'memoryUtilizationPct',
      label: 'Memory Utilization',
      namespace: 'oci_computeagent',
      query: `MemoryUtilization[5m]{resourceId = "${instanceOcid}"}.mean()`,
    },
    {
      key: 'diskBytesRead',
      label: 'Disk Bytes Read',
      namespace: 'oci_computeagent',
      query: `DiskBytesRead[5m]{resourceId = "${instanceOcid}"}.rate()`,
    },
    {
      key: 'diskBytesWritten',
      label: 'Disk Bytes Written',
      namespace: 'oci_computeagent',
      query: `DiskBytesWritten[5m]{resourceId = "${instanceOcid}"}.rate()`,
    },
    {
      key: 'diskIopsRead',
      label: 'Disk IOPS Read',
      namespace: 'oci_computeagent',
      query: `DiskIopsRead[5m]{resourceId = "${instanceOcid}"}.mean()`,
    },
    {
      key: 'diskIopsWrite',
      label: 'Disk IOPS Write',
      namespace: 'oci_computeagent',
      query: `DiskIopsWrite[5m]{resourceId = "${instanceOcid}"}.mean()`,
    },
    {
      key: 'networkBytesIn',
      label: 'Network Bytes In',
      namespace: 'oci_computeagent',
      query: `NetworksBytesIn[5m]{resourceId = "${instanceOcid}"}.rate()`,
    },
    {
      key: 'networkBytesOut',
      label: 'Network Bytes Out',
      namespace: 'oci_computeagent',
      query: `NetworksBytesOut[5m]{resourceId = "${instanceOcid}"}.rate()`,
    },
    {
      key: 'loadAverage',
      label: 'Load Average',
      namespace: 'oci_computeagent',
      query: `LoadAverage[5m]{resourceId = "${instanceOcid}"}.mean()`,
    },
  ];

  const settledMetrics = await Promise.all(
    metricQueries.map(async (mq) => ({
      mq,
      res: await queryOciMetricValue({
        telemetryBase,
        compartmentOcid,
        instanceOcid,
        namespace: mq.namespace,
        query: mq.query,
        signParams,
        timeoutMs,
      }),
    }))
  );

  const metrics: OciInstanceMetrics = {
    lifecycleState: instanceData.lifecycleState,
    shape: instanceData.shape,
    availabilityDomain: instanceData.availabilityDomain,
    source: 'OCI API',
    collectedAt: stamp,
  };

  const availableMetrics: string[] = [];
  const unavailableMetrics: { metric: string; reason: string }[] = [];

  if (instanceData.lifecycleState) {
    availableMetrics.push(`Instance Lifecycle (${instanceData.lifecycleState})`);
  } else {
    unavailableMetrics.push({
      metric: 'Instance Lifecycle State',
      reason: instanceError || 'OCI Compute API did not return lifecycleState.',
    });
  }

  let telemetryAuthOrPermError: string | undefined;
  let telemetryStatusCode: number | undefined;

  for (const item of settledMetrics) {
    const { mq, res } = item;
    if (res.ok && res.value !== null) {
      (metrics as unknown as Record<string, unknown>)[mq.key] = res.value;
      availableMetrics.push(mq.label);
    } else {
      (metrics as unknown as Record<string, unknown>)[mq.key] = null;
      if (!res.ok && res.error && !telemetryAuthOrPermError) {
        telemetryAuthOrPermError = res.error;
        telemetryStatusCode = res.statusCode;
      }
      unavailableMetrics.push({
        metric: mq.label,
        reason: res.error
          ? res.error
          : mq.key === 'memoryUtilizationPct'
            ? 'OCI hypervisor does not emit MemoryUtilization unless Oracle Cloud Agent Monitoring plugin is already enabled.'
            : 'No metric datapoints returned by OCI Monitoring API for the last 15m.',
      });
    }
  }

  const latencyMs = Date.now() - started;
  const anyAuthFail = instanceStatusCode === 401 || telemetryStatusCode === 401;
  const anyPermDenied = instanceStatusCode === 403 || telemetryStatusCode === 403;
  const anySuccess = Boolean(instanceData.lifecycleState) || availableMetrics.length > 0;

  let status: OracleConnectorHealth['status'];
  let collectionStatus: OracleConnectorHealth['collectionStatus'];

  if (anyAuthFail && !anySuccess) {
    status = 'Authentication Failed';
    collectionStatus = 'Authentication Failed';
  } else if (anyPermDenied && !anySuccess) {
    status = 'Access Restricted';
    collectionStatus = 'Permission Denied';
  } else if (!anySuccess) {
    status = 'Unreachable';
    collectionStatus = 'Unreachable';
  } else if (instanceData.lifecycleState && instanceData.lifecycleState !== 'RUNNING') {
    status = 'Critical';
    collectionStatus = 'Critical';
  } else if ((metrics.cpuUtilizationPct ?? 0) >= 90) {
    status = 'Critical';
    collectionStatus = 'Critical';
  } else if ((metrics.cpuUtilizationPct ?? 0) >= 80 || unavailableMetrics.length > 5) {
    status = 'Warning';
    collectionStatus = 'Warning';
  } else {
    status = 'Healthy';
    collectionStatus = 'Healthy';
  }

  const connector: OracleConnectorHealth = {
    connector: 'OCI Infrastructure',
    status,
    collectionStatus,
    source: 'OCI API',
    lastAttemptAt: stamp,
    ...(anySuccess ? { lastSuccessAt: stamp } : {}),
    latencyMs,
    availableMetrics,
    unavailableMetrics,
    errorDetail: !anySuccess ? instanceError || telemetryAuthOrPermError : undefined,
    prerequisiteHint: anyPermDenied
      ? 'Verify IAM read-only policies: Allow group <group> to read instance-family and metrics in compartment <compartment>.'
      : anyAuthFail
        ? 'Verify OCI User OCID, Tenancy OCID, API key fingerprint, and private key.'
        : undefined,
  };

  const historyRecords: OracleHistoryRecord[] = [];
  const pushHist = (name: string, val: number | string | null | undefined, unit: string) => {
    const rec = buildOracleHistoryRecord({
      serverId: params.targetId,
      platform: 'OCI Compute VM',
      metricName: name,
      metricValue: val,
      metricUnit: unit,
      metricSource: 'OCI API',
      collectionTime: stamp,
      collectionStatus: connector.status,
      errorDetails: connector.errorDetail,
    });
    if (rec) historyRecords.push(rec);
  };
  pushHist('OCI Lifecycle State', metrics.lifecycleState, 'state');
  pushHist('OCI CPU Utilization', metrics.cpuUtilizationPct, '%');
  pushHist('OCI Memory Utilization', metrics.memoryUtilizationPct, '%');
  pushHist('OCI Network Bytes In', metrics.networkBytesIn, 'B/s');
  pushHist('OCI Network Bytes Out', metrics.networkBytesOut, 'B/s');

  return {
    ok: anySuccess,
    connector,
    metrics: anySuccess ? metrics : undefined,
    historyRecords,
  };
}
