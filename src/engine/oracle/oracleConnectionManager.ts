import fs from 'fs';
import oracledb from 'oracledb';
import type { CollectionStatus, OracleDatabaseMetric } from '../../types/infrastructure.ts';
import { maskSensitiveText, type DecryptedCredentialPayload } from '../credentialVault.ts';
import { inspectOracleWalletDir, resolveCandidateTnsDirectories } from './oracleWalletManager.ts';

const PRIVILEGED_ORACLE_ACCOUNTS = new Set([
  'SYS',
  'SYSTEM',
  'SYSDBA',
  'SYSOPER',
  'SYSBACKUP',
  'SYSDG',
  'SYSKM',
  'SYSRAC',
  'INTERNAL',
]);

export function isPrivilegedOracleUsername(username: string): boolean {
  const clean = username.trim().toUpperCase().replace(/\s+AS\s+SYS(DBA|OPER|BACKUP|DG|KM|RAC)$/i, '').trim();
  if (PRIVILEGED_ORACLE_ACCOUNTS.has(clean)) return true;
  if (/\bAS\s+SYS(DBA|OPER|BACKUP|DG|KM|RAC)\b/i.test(username)) return true;
  return false;
}

let thickInitAttempted = false;
let thickInitialized = false;
let thickInitNote = '';

export function ensureOracleDriverMode(): {
  thinSupported: boolean;
  thickInitialized: boolean;
  note?: string;
} {
  if (!thickInitAttempted) {
    thickInitAttempted = true;
    const libDir = process.env.ORACLE_CLIENT_LIB_DIR?.trim();
    const tnsDir = process.env.TNS_ADMIN?.trim();
    if (libDir && fs.existsSync(libDir)) {
      try {
        if (process.platform === 'win32') {
          const normalizedLibDir = libDir.replace(/[\\/]+$/, '').toLowerCase();
          const pathEntries = (process.env.PATH || '').split(';');
          const alreadyInPath = pathEntries.some(
            (entry) => entry.replace(/[\\/]+$/, '').toLowerCase() === normalizedLibDir
          );

          if (!alreadyInPath) {
            process.env.PATH = `${libDir};${process.env.PATH || ''}`;
          }

          const oracleHome = libDir.replace(/[\\/]bin[\\/]?$/i, '');
          if (oracleHome !== libDir) {
            process.env.ORACLE_HOME = oracleHome;
          }
        }

        oracledb.initOracleClient({
          libDir,
          ...(tnsDir && fs.existsSync(tnsDir) ? { configDir: tnsDir } : {}),
        });

        thickInitialized = true;
        thickInitNote = `Thick mode initialized from ORACLE_CLIENT_LIB_DIR (${libDir}).`;
      } catch (err) {
        thickInitialized = false;
        thickInitNote = `Oracle Client initialization failed (${maskSensitiveText(err instanceof Error ? err.message : String(err))}); using node-oracledb Thin mode.`;
      }
    }
  }

  return {
    thinSupported: Boolean(oracledb.thin),
    thickInitialized,
    note: thickInitNote || undefined,
  };
}

export function classifyOracleConnectionError(err: unknown): {
  status: CollectionStatus;
  connectorState: 'Authentication Failed' | 'Access Restricted' | 'Not Configured' | 'Unreachable';
  errorDetail: string;
  prerequisiteHint: string;
} {
  const raw = err instanceof Error ? err.message : String(err);
  const msg = maskSensitiveText(raw);

  if (/ORA-01017|ORA-28000|ORA-28001|ORA-01005/i.test(msg)) {
    return {
      status: 'Authentication Failed',
      connectorState: 'Authentication Failed',
      errorDetail: msg,
      prerequisiteHint:
        'Verify the dedicated read-only Oracle monitoring account in the encrypted Credential Vault (do not use SYS/SYSTEM/DBA accounts).',
    };
  }

  if (/ORA-00942|ORA-01031/i.test(msg)) {
    return {
      status: 'Permission Denied',
      connectorState: 'Access Restricted',
      errorDetail: msg,
      prerequisiteHint:
        'Grant ONLY CREATE SESSION + SELECT on V$INSTANCE, V$DATABASE, V$SESSION, V$RESOURCE_LIMIT, V$SYSSTAT, V$SYSMETRIC, V$SYSTEM_EVENT, V$SGAINFO, V$PGASTAT, DBA_TABLESPACE_USAGE_METRICS, DBA_DATA_FILES, DBA_TEMP_FREE_SPACE, V$RECOVERY_FILE_DEST, and optionally V$RMAN_BACKUP_JOB_DETAILS.',
    };
  }

  if (/ORA-12154|ORA-12514|ORA-12505|NJS-508/i.test(msg)) {
    return {
      status: 'Not Configured',
      connectorState: 'Not Configured',
      errorDetail: msg,
      prerequisiteHint:
        'TNS alias or Oracle Service Name could not be resolved. Verify TNS_ADMIN / tnsnames.ora on the central server or check "lsnrctl status" on the DB host.',
    };
  }

  if (/ORA-28759|ORA-29024|NJS-516|wallet|certificate|SSL|TCPS/i.test(msg)) {
    return {
      status: 'Authentication Failed',
      connectorState: 'Authentication Failed',
      errorDetail: msg,
      prerequisiteHint:
        'TCPS / Oracle Wallet verification failed. Verify wallet directory permissions (cwallet.sso / ewallet.p12) on the central monitoring server without modifying existing wallet files.',
    };
  }

  // Network blocked / listener unreachable -> explicit Network Access Restricted guidance
  return {
    status: 'Unreachable',
    connectorState: 'Unreachable',
    errorDetail: `Network Access Restricted / Listener Unreachable: ${msg}`,
    prerequisiteHint:
      'Oracle TCP/TCPS port (1521/2484) appears blocked by firewall/NSG or listener is unreachable from this monitoring host. Network access is restricted; no firewall changes are performed automatically.',
  };
}

export interface ResolvedOracleConnectSpec {
  connectString: string;
  configDir?: string;
  walletLocation?: string;
  walletPassword?: string;
  targetLabel: string;
  validationError?: string;
}

export function resolveOracleConnectSpec(
  db: OracleDatabaseMetric,
  credPayload: DecryptedCredentialPayload
): ResolvedOracleConnectSpec {
  const port = db.port || 1521;
  const protocol = db.protocol === 'TCPS' || port === 2484 ? 'TCPS' : 'TCP';
  const useTns = db.connectionType === 'tns' || Boolean(db.tnsAlias?.trim());

  const tnsDirs = resolveCandidateTnsDirectories(db.tnsAdminDir);
  const resolvedConfigDir =
    db.tnsAdminDir?.trim() && tnsDirs.existing.length > 0
      ? tnsDirs.existing[0]
      : tnsDirs.tnsAdminEnv && tnsDirs.existing.includes(tnsDirs.tnsAdminEnv)
        ? tnsDirs.tnsAdminEnv
        : tnsDirs.existing[0];

  let walletLocation: string | undefined;
  if (db.walletDir?.trim()) {
    const wInfo = inspectOracleWalletDir(db.walletDir.trim());
    if (!wInfo.valid) {
      return {
        connectString: '',
        targetLabel: db.tnsAlias || `${db.host}:${port}/${db.serviceName}`,
        validationError: wInfo.error || 'Oracle Wallet directory is inaccessible.',
      };
    }
    walletLocation = wInfo.resolvedPath;
  }

  if (useTns && db.tnsAlias?.trim()) {
    const alias = db.tnsAlias.trim();
    if (!/^[A-Za-z0-9._-]+$/.test(alias)) {
      return {
        connectString: '',
        targetLabel: alias,
        validationError: 'Invalid TNS alias format.',
      };
    }
    return {
      connectString: alias,
      configDir: resolvedConfigDir,
      walletLocation,
      walletPassword: credPayload.walletPassword,
      targetLabel: `TNS:${alias}${protocol === 'TCPS' ? ' (TCPS)' : ''}`,
    };
  }

  if (protocol === 'TCPS') {
    const descriptor = `(DESCRIPTION=(ADDRESS=(PROTOCOL=TCPS)(HOST=${db.host})(PORT=${port}))(CONNECT_DATA=(SERVICE_NAME=${db.serviceName})))`;
    return {
      connectString: descriptor,
      configDir: resolvedConfigDir,
      walletLocation,
      walletPassword: credPayload.walletPassword,
      targetLabel: `TCPS://${db.host}:${port}/${db.serviceName}`,
    };
  }

  return {
    connectString: `${db.host}:${port}/${db.serviceName}`,
    configDir: resolvedConfigDir,
    walletLocation,
    walletPassword: credPayload.walletPassword,
    targetLabel: `${db.host}:${port}/${db.serviceName}`,
  };
}

interface PoolEntry {
  signature: string;
  pool: oracledb.Pool;
}

const poolCache = new Map<string, PoolEntry>();

export async function closeOraclePoolForTarget(targetId: string): Promise<void> {
  const entry = poolCache.get(targetId);
  if (!entry) return;
  poolCache.delete(targetId);
  try {
    await entry.pool.close(2);
  } catch {
    // ignore pool close errors
  }
}

export async function closeAllOraclePools(): Promise<void> {
  const entries = Array.from(poolCache.values());
  poolCache.clear();
  await Promise.allSettled(entries.map((e) => e.pool.close(2)));
}

export async function acquirePooledOracleConnection(params: {
  targetId: string;
  username: string;
  password: string;
  spec: ResolvedOracleConnectSpec;
  connectTimeoutSec: number;
  queryTimeoutMs: number;
}): Promise<oracledb.Connection> {
  ensureOracleDriverMode();

  const signature = [
    params.username,
    params.spec.connectString,
    params.spec.configDir || '',
    params.spec.walletLocation || '',
    params.connectTimeoutSec,
  ].join('|');

  let existing = poolCache.get(params.targetId);
  if (existing && existing.signature !== signature) {
    await closeOraclePoolForTarget(params.targetId);
    existing = undefined;
  }

  if (!existing) {
    const poolAttrs: oracledb.PoolAttributes = {
      user: params.username,
      password: params.password,
      connectString: params.spec.connectString,
      connectTimeout: params.connectTimeoutSec,
      poolMin: 0,
      poolMax: 2,
      poolIncrement: 1,
      poolTimeout: 60,
      ...(params.spec.configDir ? { configDir: params.spec.configDir } : {}),
      ...(params.spec.walletLocation ? { walletLocation: params.spec.walletLocation } : {}),
      ...(params.spec.walletPassword ? { walletPassword: params.spec.walletPassword } : {}),
    };

    const pool = await oracledb.createPool(poolAttrs);
    existing = { signature, pool };
    poolCache.set(params.targetId, existing);
  }

  const conn = await existing.pool.getConnection();
  conn.callTimeout = params.queryTimeoutMs;
  return conn;
}
