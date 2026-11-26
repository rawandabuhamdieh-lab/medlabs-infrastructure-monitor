import { checkTcpPort, isValidTargetHost } from './networkHelpers.ts';
import type {
  ConnectionTestResult,
  LoadBalancerBackendNode,
  LoadBalancerTarget,
  MetricIntegrity,
} from '../types/infrastructure.ts';

function parseHttpUrl(raw: string): URL | null {
  try {
    const u = new URL(raw.trim());
    if (u.protocol === 'http:' || u.protocol === 'https:') {
      return u;
    }
    return null;
  } catch {
    return null;
  }
}

async function probeTargetEndpoint(
  urlOrHost: string,
  portOverride: number | undefined,
  timeoutMs: number
): Promise<{
  ok: boolean;
  statusCode: number | null;
  rttMs: number | null;
  error?: string;
}> {
  const parsedUrl = parseHttpUrl(urlOrHost);
  if (parsedUrl) {
    const started = Date.now();
    try {
      const resp = await fetch(parsedUrl.toString(), {
        method: 'GET',
        redirect: 'manual',
        signal: AbortSignal.timeout(timeoutMs),
      });
      const rttMs = Math.max(1, Date.now() - started);
      if (resp.status >= 500) {
        return {
          ok: false,
          statusCode: resp.status,
          rttMs,
          error: `HTTP ${resp.status} server error`,
        };
      }
      return { ok: true, statusCode: resp.status, rttMs };
    } catch (err) {
      return {
        ok: false,
        statusCode: null,
        rttMs: null,
        error: err instanceof Error ? err.message : 'HTTP probe failed',
      };
    }
  }

  const host = urlOrHost.trim();
  const port = portOverride && portOverride >= 1 && portOverride <= 65535 ? portOverride : 80;
  if (!isValidTargetHost(host)) {
    return { ok: false, statusCode: null, rttMs: null, error: 'Invalid host or URL' };
  }
  const tcp = await checkTcpPort(host, port, timeoutMs);
  return {
    ok: tcp.open,
    statusCode: null,
    rttMs: tcp.latencyMs,
    error: tcp.open ? undefined : `TCP/${port} unreachable or timed out`,
  };
}

interface StatsNodePayload {
  name?: string;
  host?: string;
  requests?: number;
  failed?: number;
  failedRequests?: number;
}

export async function collectLoadBalancer(
  lb: LoadBalancerTarget,
  timeoutMs = 4500
): Promise<{ ok: boolean; integrity: MetricIntegrity }> {
  const stamp = new Date().toISOString().replace('T', ' ').slice(0, 19);
  const vipParsed = parseHttpUrl(lb.vipUrl);

  if (!vipParsed) {
    lb.status = 'Offline';
    lb.lastCheck = stamp;
    const integrity: MetricIntegrity = {
      collectionStatus: 'Not Configured',
      dataSource: 'Load Balancer VIP + Node Probe',
      measuredAt: stamp,
      targetIdentifier: lb.vipUrl || lb.name,
      errorDetail: 'Valid HTTP/HTTPS VIP URL is required.',
    };
    lb.integrity = integrity;
    return { ok: false, integrity };
  }

  // 1. Probe VIP and all backend nodes concurrently
  const [vipRes, nodeProbes] = await Promise.all([
    probeTargetEndpoint(lb.vipUrl, undefined, timeoutMs),
    Promise.all(
      lb.nodes.map(async (node) => {
        const res = await probeTargetEndpoint(node.urlOrHost, node.port, Math.min(3500, timeoutMs));
        return { node, res };
      })
    ),
  ]);

  // 2. Optionally fetch structured JSON stats endpoint if configured
  let statsNodes: StatsNodePayload[] | null = null;
  let statsFailedTotal: number | null = null;
  if (lb.statsUrl) {
    const parsedStats = parseHttpUrl(lb.statsUrl);
    if (parsedStats) {
      try {
        const resp = await fetch(parsedStats.toString(), {
          method: 'GET',
          signal: AbortSignal.timeout(Math.min(3500, timeoutMs)),
        });
        if (resp.ok) {
          const json = (await resp.json()) as {
            nodes?: StatsNodePayload[];
            backends?: StatsNodePayload[];
            failedRequests?: number;
          };
          if (Array.isArray(json.nodes)) statsNodes = json.nodes;
          else if (Array.isArray(json.backends)) statsNodes = json.backends;
          if (typeof json.failedRequests === 'number') statsFailedTotal = json.failedRequests;
        }
      } catch {
        // Optional stats URL unavailable — backend node health probing still applies cleanly
      }
    }
  }

  let connectionErrors = vipRes.ok ? 0 : 1;
  let unhealthyNodesCount = 0;

  const updatedNodes: LoadBalancerBackendNode[] = nodeProbes.map(({ node, res }) => {
    const matchedStat = statsNodes?.find(
      (s) =>
        (s.name && s.name.toLowerCase() === node.name.toLowerCase()) ||
        (s.host && node.urlOrHost.toLowerCase().includes(s.host.toLowerCase()))
    );
    const reqCount = typeof matchedStat?.requests === 'number' ? matchedStat.requests : null;
    const nodeFailed =
      typeof matchedStat?.failedRequests === 'number'
        ? matchedStat.failedRequests
        : typeof matchedStat?.failed === 'number'
          ? matchedStat.failed
          : null;

    let nodeStatus: LoadBalancerBackendNode['status'] = 'Unknown';
    if (!res.ok) {
      nodeStatus = 'Down';
      unhealthyNodesCount += 1;
      connectionErrors += 1;
    } else if ((res.rttMs ?? 0) >= 800) {
      nodeStatus = 'Degraded';
    } else {
      nodeStatus = 'Up';
    }

    return {
      ...node,
      status: nodeStatus,
      responseTimeMs: res.rttMs,
      requestsCount: reqCount,
      failedRequests: nodeFailed,
      trafficSharePct: null,
      lastError: res.error,
    };
  });

  // Calculate traffic share & detect uneven traffic ONLY when real request counts are present
  const totalRequests = updatedNodes.reduce((sum, n) => sum + (n.requestsCount ?? 0), 0);
  let unevenTrafficDetected = false;
  if (statsNodes && totalRequests > 0) {
    for (const n of updatedNodes) {
      n.trafficSharePct =
        typeof n.requestsCount === 'number'
          ? Number(((n.requestsCount / totalRequests) * 100).toFixed(1))
          : null;
    }
    const activeShares = updatedNodes
      .filter((n) => n.status === 'Up' && typeof n.trafficSharePct === 'number')
      .map((n) => n.trafficSharePct as number);
    if (activeShares.length >= 2) {
      const maxShare = Math.max(...activeShares);
      const minShare = Math.min(...activeShares);
      if (maxShare - minShare >= 35) {
        unevenTrafficDetected = true;
      }
    }
    lb.trafficDistributionNote = unevenTrafficDetected
      ? 'Traffic distribution skewed (>35% variance across active backend nodes).'
      : 'Traffic distribution measured from LB stats endpoint.';
  } else {
    lb.trafficDistributionNote = lb.statsUrl
      ? 'Configured LB stats endpoint did not return per-node request counters; health & RTT remain actively measured.'
      : 'Unavailable — configure an optional LB Stats JSON URL to measure exact per-node traffic share (%).';
  }

  lb.nodes = updatedNodes;
  lb.responseTimeMs = vipRes.rttMs;
  lb.connectionErrors = connectionErrors;
  lb.unhealthyNodesCount = unhealthyNodesCount;
  lb.unevenTrafficDetected = unevenTrafficDetected;
  lb.failedRequests =
    statsFailedTotal !== null
      ? statsFailedTotal
      : statsNodes
        ? updatedNodes.reduce((sum, n) => sum + (n.failedRequests ?? 0), 0)
        : null;
  lb.lastCheck = stamp;

  if (!vipRes.ok || (updatedNodes.length > 0 && unhealthyNodesCount === updatedNodes.length)) {
    lb.status = 'Offline';
  } else if (unhealthyNodesCount > 0 || (vipRes.rttMs ?? 0) >= 800 || unevenTrafficDetected) {
    lb.status = unhealthyNodesCount >= Math.max(2, Math.ceil(updatedNodes.length / 2)) ? 'Critical' : 'Warning';
  } else {
    lb.status = 'Online';
  }

  const integrity: MetricIntegrity = {
    collectionStatus:
      lb.status === 'Offline'
        ? 'Unreachable'
        : lb.status === 'Critical'
          ? 'Critical'
          : lb.status === 'Warning'
            ? 'Warning'
            : 'Healthy',
    dataSource: statsNodes ? 'VIP Probe + Node Health + LB Stats JSON' : 'VIP HTTP/HTTPS + Backend Node Probes',
    measuredAt: stamp,
    targetIdentifier: lb.vipUrl,
    errorDetail: !vipRes.ok
      ? vipRes.error
      : unhealthyNodesCount > 0
        ? `${unhealthyNodesCount}/${updatedNodes.length} backend node(s) failed health probe.`
        : undefined,
    prerequisiteHint: !lb.statsUrl
      ? 'Optional: attach an LB Stats JSON URL (e.g. HAProxy/NGINX/IIS ARR JSON status) to populate exact per-node traffic share.'
      : undefined,
  };
  lb.integrity = integrity;
  return { ok: vipRes.ok, integrity };
}

export async function testLoadBalancerConnection(
  lb: LoadBalancerTarget,
  timeoutMs = 4500
): Promise<ConnectionTestResult> {
  const clone: LoadBalancerTarget = structuredClone(lb);
  const res = await collectLoadBalancer(clone, timeoutMs);
  return {
    ok: res.ok,
    status: res.integrity.collectionStatus,
    dataSource: res.integrity.dataSource,
    latencyMs: clone.responseTimeMs,
    measuredAt: res.integrity.measuredAt,
    details: res.ok
      ? `VIP responded in ${clone.responseTimeMs} ms · Healthy nodes: ${clone.nodes.length - clone.unhealthyNodesCount}/${clone.nodes.length}.`
      : res.integrity.errorDetail || 'Load Balancer VIP probe failed.',
    prerequisiteHint: res.integrity.prerequisiteHint,
  };
}
