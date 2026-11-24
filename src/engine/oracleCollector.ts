import oracledb from 'oracledb';
import { ensureOracleDriverMode } from './oracle/oracleConnectionManager.ts';
import type { CredentialVault } from './credentialVault.ts';
import type {
  BackupJob,
  CollectionStatus,
  ConnectionTestResult,
  MetricIntegrity,
  OracleDatabaseMetric,
  OracleLongQuery,
  OracleTablespace,
  OracleWaitEvent,
} from '../types/infrastructure.ts';

function classifyOracleError(err: unknown): {
  status: CollectionStatus;
  errorDetail: string;
  prerequisiteHint: string;
} {
  const msg = err instanceof Error ? err.message : String(err);
  if (/ORA-01017|ORA-28000|ORA-28001/i.test(msg)) {
    return {
      status: 'Authentication Failed',
      errorDetail: msg,
      prerequisiteHint:
        'Verify the read-only Oracle monitoring username/password in the encrypted Credential Vault (or check account lock/expiry).',
    };
  }
  if (/ORA-00942|ORA-01031/i.test(msg)) {
    return {
      status: 'Permission Denied',
      errorDetail: msg,
      prerequisiteHint:
        'Oracle prerequisite missing: Grant the read-only user CREATE SESSION + SELECT_CATALOG_ROLE (or SELECT on V$INSTANCE, V$DATABASE, V$SESSION, V$PGASTAT, V$SGAINFO, V$SYSMETRIC, V$SYSTEM_EVENT, DBA_TABLESPACE_USAGE_METRICS, V$RMAN_BACKUP_JOB_DETAILS). No objects need to be created.',
    };
  }
  if (/ORA-12514|ORA-12505/i.test(msg)) {
    return {
      status: 'Not Configured',
      errorDetail: msg,
      prerequisiteHint:
        'Listener reached, but the Oracle Service Name / SID is unknown to the listener. Verify exact Service Name from "lsnrctl status".',
    };
  }
  return {
    status: 'Unreachable',
    errorDetail: msg,
    prerequisiteHint:
      'Ensure Oracle TNS Listener (default TCP 1521) is running and accessible from the central monitoring server.',
  };
}

export async function collectOracleDatabase(
  db: OracleDatabaseMetric,
  vault: CredentialVault,
  timeoutMs = 8000
): Promise<{ ok: boolean; integrity: MetricIntegrity; rmanBackups: BackupJob[] }> {
  ensureOracleDriverMode();
  const stamp = new Date().toISOString().replace('T', ' ').slice(0, 19);
  const port = db.port || 1521;
  const connectString = `${db.host}:${port}/${db.serviceName}`;

  const credRes = vault.getDecrypted(db.credentialId);
  if (!credRes.ok) {
    db.lastCheck = stamp;
    const integrity: MetricIntegrity = {
      collectionStatus: db.credentialId ? 'Authentication Failed' : 'Not Configured',
      dataSource: 'Oracle Thin SELECT-only',
      measuredAt: stamp,
      targetIdentifier: connectString,
      errorDetail: credRes.error,
      prerequisiteHint:
        'Attach a saved Read-Only Oracle credential profile (with CREATE SESSION + SELECT_CATALOG_ROLE) to enable agentless polling.',
    };
    db.integrity = integrity;
    return { ok: false, integrity, rmanBackups: [] };
  }

  if (credRes.payload.kind !== 'oracle' || !credRes.payload.username || !credRes.payload.password) {
    db.lastCheck = stamp;
    const integrity: MetricIntegrity = {
      collectionStatus: 'Not Configured',
      dataSource: 'Oracle Thin SELECT-only',
      measuredAt: stamp,
      targetIdentifier: connectString,
      errorDetail: 'Attached credential profile is not a valid Oracle read-only credential.',
    };
    db.integrity = integrity;
    return { ok: false, integrity, rmanBackups: [] };
  }

  let conn: oracledb.Connection | null = null;
  const started = Date.now();
  const rmanBackups: BackupJob[] = [];

  try {
    conn = await oracledb.getConnection({
      user: credRes.payload.username,
      password: credRes.payload.password,
      connectString,
      connectTimeout: Math.max(3, Math.round(timeoutMs / 1000)),
    });
    conn.callTimeout = timeoutMs;

    const opts = { outFormat: oracledb.OUT_FORMAT_OBJECT };

    // 1. Instance availability & status (strict SELECT only)
    const instRes = await conn.execute<{
      INSTANCE_NAME: string;
      HOST_NAME: string;
      STATUS: string;
      DATABASE_STATUS: string;
    }>(
      `SELECT INSTANCE_NAME, HOST_NAME, STATUS, DATABASE_STATUS FROM V$INSTANCE`,
      [],
      opts
    );

    const dbRes = await conn.execute<{ DATABASE_ROLE: string; OPEN_MODE: string }>(
      `SELECT DATABASE_ROLE, OPEN_MODE FROM V$DATABASE`,
      [],
      opts
    );

    // 2. Sessions & Blocking sessions
    const sessRes = await conn.execute<{
      TOTAL_SESSIONS: number;
      ACTIVE_SESSIONS: number;
      BLOCKING_SESSIONS: number;
    }>(
      `SELECT COUNT(*) AS TOTAL_SESSIONS,
              SUM(CASE WHEN STATUS = 'ACTIVE' AND TYPE = 'USER' THEN 1 ELSE 0 END) AS ACTIVE_SESSIONS,
              SUM(CASE WHEN BLOCKING_SESSION IS NOT NULL THEN 1 ELSE 0 END) AS BLOCKING_SESSIONS
       FROM V$SESSION
       WHERE TYPE = 'USER'`,
      [],
      opts
    );

    // 3. Tablespaces (try DBA_TABLESPACE_USAGE_METRICS, fallback DBA_DATA_FILES/DBA_FREE_SPACE)
    let tablespaces: OracleTablespace[] = [];
    let dbSizeGb = 0;
    try {
      const tsRes = await conn.execute<{
        TABLESPACE_NAME: string;
        USED_GB: number;
        MAX_GB: number;
        USED_PCT: number;
      }>(
        `SELECT TABLESPACE_NAME,
                ROUND(USED_SPACE * 8192 / 1024 / 1024 / 1024, 2) AS USED_GB,
                ROUND(TABLESPACE_SIZE * 8192 / 1024 / 1024 / 1024, 2) AS MAX_GB,
                ROUND(USED_PERCENT, 1) AS USED_PCT
         FROM DBA_TABLESPACE_USAGE_METRICS
         ORDER BY USED_PERCENT DESC`,
        [],
        { ...opts, maxRows: 20 }
      );
      tablespaces = (tsRes.rows || []).map((r) => {
        const usedGb = Number(r.USED_GB || 0);
        dbSizeGb += usedGb;
        return {
          name: String(r.TABLESPACE_NAME),
          usedGb,
          maxGb: Number(r.MAX_GB || 0),
          usedPct: Number(r.USED_PCT || 0),
          dailyGrowthGb: 0,
        };
      });
    } catch {
      // Optional dictionary fallback if DBA_TABLESPACE_USAGE_METRICS unavailable
    }

    // 4. Memory (PGA / SGA) & CPU metric
    let pgaUsedMb = 0;
    let sgaUsedPct = 0;
    let cpuUsagePct = 0;
    try {
      const pgaRes = await conn.execute<{ VALUE: number }>(
        `SELECT ROUND(VALUE / 1024 / 1024, 1) AS VALUE FROM V$PGASTAT WHERE NAME = 'total PGA allocated'`,
        [],
        opts
      );
      pgaUsedMb = Number(pgaRes.rows?.[0]?.VALUE || 0);

      const sgaRes = await conn.execute<{ NAME: string; BYTES: number }>(
        `SELECT NAME, BYTES FROM V$SGAINFO WHERE NAME IN ('Free SGA Memory Available', 'Maximum SGA Size')`,
        [],
        opts
      );
      const maxSga = Number(sgaRes.rows?.find((r) => r.NAME === 'Maximum SGA Size')?.BYTES || 0);
      const freeSga = Number(sgaRes.rows?.find((r) => r.NAME === 'Free SGA Memory Available')?.BYTES || 0);
      if (maxSga > 0) {
        sgaUsedPct = Number((((maxSga - freeSga) / maxSga) * 100).toFixed(1));
      }

      const cpuRes = await conn.execute<{ VALUE: number }>(
        `SELECT ROUND(VALUE, 1) AS VALUE FROM V$SYSMETRIC WHERE METRIC_NAME = 'Host CPU Utilization (%)' AND GROUP_ID = 2 AND ROWNUM = 1`,
        [],
        opts
      );
      cpuUsagePct = Number(cpuRes.rows?.[0]?.VALUE || 0);
    } catch {
      // Non-fatal if restricted view
    }

    // 5. Long running queries (>30s) & Top Wait Events
    let longQueries: OracleLongQuery[] = [];
    let waitEvents: OracleWaitEvent[] = [];
    try {
      const lqRes = await conn.execute<{
        SQL_ID: string;
        USERNAME: string;
        ELAPSED_SEC: number;
        WAIT_EVENT: string;
        MODULE: string;
      }>(
        `SELECT SQL_ID, NVL(USERNAME, 'SYSTEM') AS USERNAME, LAST_CALL_ET AS ELAPSED_SEC,
                NVL(EVENT, 'CPU') AS WAIT_EVENT, NVL(MODULE, 'Unknown') AS MODULE
         FROM V$SESSION
         WHERE STATUS = 'ACTIVE' AND TYPE = 'USER' AND LAST_CALL_ET > 30 AND SQL_ID IS NOT NULL
         ORDER BY LAST_CALL_ET DESC`,
        [],
        { ...opts, maxRows: 10 }
      );
      longQueries = (lqRes.rows || []).map((r) => ({
        sqlId: String(r.SQL_ID),
        username: String(r.USERNAME),
        elapsedSec: Number(r.ELAPSED_SEC || 0),
        waitEvent: String(r.WAIT_EVENT),
        module: String(r.MODULE),
      }));

      const weRes = await conn.execute<{
        EVENT: string;
        TOTAL_WAITS: number;
        TIME_WAITED_MS: number;
      }>(
        `SELECT EVENT, TOTAL_WAITS, ROUND(TIME_WAITED_MICRO / 1000, 0) AS TIME_WAITED_MS
         FROM V$SYSTEM_EVENT
         WHERE WAIT_CLASS <> 'Idle'
         ORDER BY TIME_WAITED_MICRO DESC`,
        [],
        { ...opts, maxRows: 6 }
      );
      waitEvents = (weRes.rows || []).map((r) => ({
        event: String(r.EVENT),
        totalWaits: Number(r.TOTAL_WAITS || 0),
        timeWaitedMs: Number(r.TIME_WAITED_MS || 0),
      }));
    } catch {
      // Optional
    }

    // 6. RMAN Backup Status (read-only V$RMAN_BACKUP_JOB_DETAILS)
    try {
      const rmanRes = await conn.execute<{
        SESSION_KEY: number;
        INPUT_TYPE: string;
        STATUS: string;
        END_STR: string;
        DURATION_MIN: number;
        SIZE_GB: number;
        AGE_HOURS: number;
      }>(
        `SELECT SESSION_KEY, INPUT_TYPE, STATUS,
                TO_CHAR(END_TIME, 'YYYY-MM-DD HH24:MI') AS END_STR,
                ROUND(ELAPSED_SECONDS / 60, 1) AS DURATION_MIN,
                ROUND(OUTPUT_BYTES / 1024 / 1024 / 1024, 2) AS SIZE_GB,
                ROUND((SYSDATE - END_TIME) * 24, 1) AS AGE_HOURS
         FROM V$RMAN_BACKUP_JOB_DETAILS
         ORDER BY START_TIME DESC`,
        [],
        { ...opts, maxRows: 6 }
      );
      for (const r of rmanRes.rows || []) {
        const rawStatus = String(r.STATUS || '');
        const status: BackupJob['status'] = rawStatus.includes('COMPLETED WITH ERRORS') || rawStatus.includes('FAILED')
          ? 'Failed'
          : rawStatus.includes('WARNING')
            ? 'Warning'
            : 'Succeeded';
        rmanBackups.push({
          id: `RMAN-${db.serviceName}-${r.SESSION_KEY}`,
          jobName: `RMAN ${r.INPUT_TYPE} (${db.serviceName})`,
          targetSystem: `${db.host}:${port}/${db.serviceName}`,
          backupSource: 'Oracle V$RMAN_BACKUP_JOB_DETAILS (Agentless)',
          status,
          lastSuccessfulRun: r.END_STR || stamp,
          durationMinutes: Number(r.DURATION_MIN || 0),
          sizeGb: Number(r.SIZE_GB || 0),
          ageHours: Math.max(0, Number(r.AGE_HOURS || 0)),
          failures7d: status === 'Failed' ? 1 : 0,
        });
      }
    } catch {
      // V$RMAN_BACKUP_JOB_DETAILS optional
    }

    const rttMs = Math.max(1, Date.now() - started);
    const dbRoleRaw = String(dbRes.rows?.[0]?.DATABASE_ROLE || 'PRIMARY');
    const instStatus = String(instRes.rows?.[0]?.STATUS || 'OPEN');
    const sessRow = sessRes.rows?.[0];

    db.role = dbRoleRaw.includes('STANDBY') ? 'Read-Only Standby' : 'Primary';
    db.responseTimeMs = rttMs;
    db.activeSessions = Number(sessRow?.ACTIVE_SESSIONS || 0);
    db.totalSessions = Number(sessRow?.TOTAL_SESSIONS || 0);
    db.blockingSessions = Number(sessRow?.BLOCKING_SESSIONS || 0);
    db.cpuUsagePct = cpuUsagePct;
    db.sgaUsedPct = sgaUsedPct;
    db.pgaUsedMb = pgaUsedMb;
    db.dbSizeGb = Number(dbSizeGb.toFixed(2));
    db.tablespaces = tablespaces;
    db.longRunningQueries = longQueries;
    db.topWaitEvents = waitEvents;
    db.lastCheck = stamp;
    db.availabilityPct = 100;

    const maxTsPct = tablespaces.reduce((m, t) => Math.max(m, t.usedPct), 0);
    db.status =
      instStatus !== 'OPEN'
        ? 'Critical'
        : db.blockingSessions > 3 || maxTsPct >= 90
          ? 'Critical'
          : db.blockingSessions > 0 || maxTsPct >= 80
            ? 'Warning'
            : 'Online';

    db.responseHistory.push({
      time: stamp.slice(11, 16),
      responseMs: db.responseTimeMs,
      activeSessions: db.activeSessions,
    });
    if (db.responseHistory.length > 24) db.responseHistory.shift();

    const integrity: MetricIntegrity = {
      collectionStatus: db.status === 'Critical' ? 'Critical' : db.status === 'Warning' ? 'Warning' : 'Healthy',
      dataSource: 'Oracle Thin SELECT-only (V$/DBA_)',
      measuredAt: stamp,
      targetIdentifier: connectString,
    };
    db.integrity = integrity;
    return { ok: true, integrity, rmanBackups };
  } catch (err) {
    const classified = classifyOracleError(err);
    db.lastCheck = stamp;
    db.connectionFailures24h += 1;
    db.status = classified.status === 'Unreachable' ? 'Offline' : 'Warning';
    const integrity: MetricIntegrity = {
      collectionStatus: classified.status,
      dataSource: 'Oracle Thin SELECT-only',
      measuredAt: stamp,
      targetIdentifier: connectString,
      errorDetail: classified.errorDetail.slice(0, 260),
      prerequisiteHint: classified.prerequisiteHint,
    };
    db.integrity = integrity;
    return { ok: false, integrity, rmanBackups: [] };
  } finally {
    if (conn) {
      try {
        await conn.close();
      } catch {
        // ignore close error
      }
    }
  }
}

export async function testOracleConnection(
  db: OracleDatabaseMetric,
  vault: CredentialVault,
  timeoutMs = 8000
): Promise<ConnectionTestResult> {
  const started = Date.now();
  const clone: OracleDatabaseMetric = structuredClone(db);
  const res = await collectOracleDatabase(clone, vault, timeoutMs);
  return {
    ok: res.ok,
    status: res.integrity.collectionStatus,
    dataSource: res.integrity.dataSource,
    latencyMs: res.ok ? clone.responseTimeMs : Date.now() - started,
    measuredAt: res.integrity.measuredAt,
    details: res.ok
      ? `Connected read-only to ${clone.host}:${clone.port || 1521}/${clone.serviceName} (${clone.role}) — ${clone.activeSessions} active / ${clone.totalSessions ?? clone.activeSessions} total sessions, ${clone.tablespaces.length} tablespaces.`
      : res.integrity.errorDetail || 'Oracle connection failed.',
    prerequisiteHint: res.integrity.prerequisiteHint,
  };
}
