import type {
  BackupJob,
  CollectionStatus,
  ConnectionTestResult,
  OciCloudConfig,
  OciInstanceMetrics,
  OracleConnectorHealth,
  OracleDatabaseMetric,
  OracleHistoryRecord,
  OracleLinuxOsConfig,
  OracleLinuxOsMetrics,
  OracleScheduleConfig,
  TnsAliasInfo,
} from '../../types/infrastructure.ts';

export const DEFAULT_ORACLE_SCHEDULES: OracleScheduleConfig = {
  availabilitySec: 60,
  sessionsPerfSec: 60,
  memorySec: 120,
  tablespaceSec: 300,
  ociSec: 120,
  linuxSec: 60,
};

export interface TnsDiscoverySnapshot {
  tnsAdminEnv?: string;
  oracleHomeEnv?: string;
  searchedDirectories: string[];
  existingDirectories: string[];
  aliases: TnsAliasInfo[];
  walletDirectoriesDetected: string[];
  oracledbThinSupported: boolean;
  oracledbThickInitialized: boolean;
  checkedAt: string;
}

export interface OracleCollectionCadenceState {
  lastAvailabilityAt: number;
  lastSessionsPerfAt: number;
  lastMemoryAt: number;
  lastTablespaceAt: number;
  lastOciAt: number;
  lastLinuxAt: number;
}

export interface OciCollectionResult {
  ok: boolean;
  connector: OracleConnectorHealth;
  metrics?: OciInstanceMetrics;
  historyRecords: OracleHistoryRecord[];
}

export interface OracleLinuxCollectionResult {
  ok: boolean;
  connector: OracleConnectorHealth;
  metrics?: OracleLinuxOsMetrics;
  historyRecords: OracleHistoryRecord[];
}

export interface OracleDbCollectionResult {
  ok: boolean;
  connector: OracleConnectorHealth;
  rmanBackups: BackupJob[];
  historyRecords: OracleHistoryRecord[];
}

export interface OracleCloudUnifiedResult {
  ok: boolean;
  ociResult: OciCollectionResult;
  linuxResult: OracleLinuxCollectionResult;
  dbResult: OracleDbCollectionResult;
  rmanBackups: BackupJob[];
}

export interface OracleCloudTestSummary extends ConnectionTestResult {
  ociTest?: OracleConnectorHealth;
  linuxTest?: OracleConnectorHealth;
  dbTest?: OracleConnectorHealth;
}

export type {
  OciCloudConfig,
  OciInstanceMetrics,
  OracleConnectorHealth,
  OracleDatabaseMetric,
  OracleHistoryRecord,
  OracleLinuxOsConfig,
  OracleLinuxOsMetrics,
  OracleScheduleConfig,
  TnsAliasInfo,
};
