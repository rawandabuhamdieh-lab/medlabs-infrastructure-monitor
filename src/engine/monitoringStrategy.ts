import { CloudVpsCollector } from './cloudCollector.ts';
import { HyperVHostCollector, HyperVVmCollector } from './hypervCollector.ts';
import { LinuxServerCollector } from './linuxCollector.ts';
import {
  MethodBackoffTracker,
  resolveServerPlatform,
  type CollectorContext,
  type ServerCollectorAdapter,
  type UnifiedCollectionResult,
} from './monitoringCapabilities.ts';
import { NetworkServerAdapter } from './networkCollector.ts';
import {
  OciComputeServerAdapter,
  OracleDbServerAdapter,
  OracleLinuxServerAdapter,
} from './oracle/oracleServerAdapters.ts';
import { RestrictedServerCollector } from './restrictedCollector.ts';
import { WindowsServerCollector } from './windowsCollector.ts';
import type {
  ConnectionTestResult,
  MonitoringCapabilityMatrix,
  ServerPlatform,
  WindowsServer,
} from '../types/infrastructure.ts';

const adapterRegistry = new Map<ServerPlatform, ServerCollectorAdapter>([
  ['windows', new WindowsServerCollector()],
  ['linux', new LinuxServerCollector()],
  ['oracle-linux', new OracleLinuxServerAdapter()],
  ['cloud-vps', new CloudVpsCollector()],
  ['oci-compute', new OciComputeServerAdapter()],
  ['oracle-db', new OracleDbServerAdapter()],
  ['hyperv-host', new HyperVHostCollector()],
  ['hyperv-vm', new HyperVVmCollector()],
  ['network-device', new NetworkServerAdapter()],
  ['restricted', new RestrictedServerCollector()],
]);

export function getCollectorAdapterForServer(srv: WindowsServer): ServerCollectorAdapter {
  const platform = resolveServerPlatform(srv);
  return adapterRegistry.get(platform) || adapterRegistry.get('windows')!;
}

export async function collectServerWithStrategy(
  srv: WindowsServer,
  ctx: CollectorContext
): Promise<UnifiedCollectionResult> {
  const adapter = getCollectorAdapterForServer(srv);
  return adapter.collect(srv, ctx);
}

export async function testServerWithStrategy(
  srv: WindowsServer,
  ctx: CollectorContext
): Promise<ConnectionTestResult & { capabilityMatrix?: MonitoringCapabilityMatrix }> {
  ctx.backoff.clearServer(srv.id);
  const adapter = getCollectorAdapterForServer(srv);
  const testCtx: CollectorContext = { ...ctx, bypassBackoff: true };
  const result = await adapter.testConnection(srv, testCtx);

  // If the adapter didn't already populate a capabilityMatrix during testConnection, run a non-mutating collect on a clone
  if (!srv.capabilityMatrix) {
    const clone = structuredClone(srv);
    const colRes = await adapter.collect(clone, testCtx);
    return {
      ...result,
      capabilityMatrix: colRes.capabilityMatrix,
    };
  }

  return {
    ...result,
    capabilityMatrix: srv.capabilityMatrix,
  };
}

export { MethodBackoffTracker };
