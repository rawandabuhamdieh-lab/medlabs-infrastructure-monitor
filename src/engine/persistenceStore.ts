import fs from 'fs';
import path from 'path';
import type { EncryptedCredentialRecord } from './credentialVault.ts';
import type {
  AlertRecord,
  AlertThreshold,
  ApiEndpointCheck,
  AuditLogEntry,
  BackupJob,
  CollectorConfig,
  DailyReportRow,
  IisAppPool,
  IisSite,
  NetworkDevice,
  OracleDatabaseMetric,
  TimelineSample,
  WindowsServer,
} from '../types/infrastructure.ts';

export interface PersistedMonitoringState {
  servers: WindowsServer[];
  oracleDatabases: OracleDatabaseMetric[];
  iisSites: IisSite[];
  appPools: IisAppPool[];
  apiEndpoints: ApiEndpointCheck[];
  networkDevices: NetworkDevice[];
  backups: BackupJob[];
  thresholds: AlertThreshold[];
  alerts: AlertRecord[];
  collectors: CollectorConfig[];
  reports: DailyReportRow[];
  timeline?: TimelineSample[];
  auditLogs: AuditLogEntry[];
  credentials: EncryptedCredentialRecord[];
}

const DATA_DIR = path.resolve(process.cwd(), 'data');
const STATE_FILE = path.resolve(DATA_DIR, 'medlabs-monitoring-state.json');

function assertConfinedPath(targetPath: string): void {
  if (!targetPath.startsWith(DATA_DIR + path.sep)) {
    throw new Error('Unsafe storage path outside confined data directory.');
  }
}

export function loadPersistedState(): Partial<PersistedMonitoringState> | null {
  try {
    assertConfinedPath(STATE_FILE);
    if (!fs.existsSync(STATE_FILE)) return null;
    const raw = fs.readFileSync(STATE_FILE, 'utf8');
    if (!raw.trim()) return null;
    return JSON.parse(raw) as Partial<PersistedMonitoringState>;
  } catch {
    return null;
  }
}

let saveTimer: NodeJS.Timeout | null = null;

export function schedulePersistState(getSnapshot: () => PersistedMonitoringState): void {
  if (saveTimer) return;
  saveTimer = setTimeout(() => {
    saveTimer = null;
    try {
      assertConfinedPath(STATE_FILE);
      if (!fs.existsSync(DATA_DIR)) {
        fs.mkdirSync(DATA_DIR, { recursive: true });
      }
      const payload = JSON.stringify(getSnapshot(), null, 2);
      const tmpFile = path.resolve(DATA_DIR, 'medlabs-monitoring-state.tmp.json');
      assertConfinedPath(tmpFile);
      fs.writeFileSync(tmpFile, payload, 'utf8');
      fs.renameSync(tmpFile, STATE_FILE);
    } catch {
      // Persistence failure never breaks central polling loop
    }
  }, 500);
}
