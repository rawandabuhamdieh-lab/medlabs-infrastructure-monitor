import type { MetricSourceTag, OracleHistoryRecord } from '../../types/infrastructure.ts';

export function buildOracleHistoryRecord(params: {
  serverId: string;
  platform: string;
  metricName: string;
  metricValue: number | string | null | undefined;
  metricUnit: string;
  metricSource: MetricSourceTag;
  collectionTime: string;
  collectionStatus: string;
  errorDetails?: string;
}): OracleHistoryRecord | null {
  if (params.metricValue === null || params.metricValue === undefined) {
    return null;
  }
  return {
    serverId: params.serverId,
    platform: params.platform,
    metricName: params.metricName,
    metricValue: params.metricValue,
    metricUnit: params.metricUnit,
    metricSource: params.metricSource,
    collectionTime: params.collectionTime,
    collectionStatus: params.collectionStatus,
    errorDetails: params.errorDetails,
  };
}

export function appendOracleMetricHistory(
  existing: OracleHistoryRecord[] | undefined,
  entries: (OracleHistoryRecord | null)[],
  maxEntries = 180
): OracleHistoryRecord[] {
  const valid = entries.filter((e): e is OracleHistoryRecord => e !== null);
  const next = [...valid, ...(existing || [])];
  if (next.length > maxEntries) {
    next.length = maxEntries;
  }
  return next;
}

export function formatBytesCompact(bytes: number | null | undefined): string {
  if (bytes === null || bytes === undefined || !Number.isFinite(bytes)) {
    return 'Unavailable';
  }
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 ** 3) return `${(bytes / 1024 ** 2).toFixed(1)} MB`;
  return `${(bytes / 1024 ** 3).toFixed(2)} GB`;
}
