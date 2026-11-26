import { formatMedLabsTimestamp } from '../time.ts';
import oracledb from 'oracledb';
import type { CredentialVault } from '../credentialVault.ts';
import type {
  BackupJob,
  OracleConnectorHealth,
  OracleDatabaseMetric,
  OracleHistoryRecord,
  OracleLongQuery,
  OracleTablespace,
  OracleWaitEvent,
} from '../../types/infrastructure.ts';
import { collectOciInfrastructure } from './ociCollector.ts';
import {
  acquirePooledOracleConnection,
  classifyOracleConnectionError,
  isPrivilegedOracleUsername,
  resolveOracleConnectSpec,
} from './oracleConnectionManager.ts';
import { ORACLE_READ_ONLY_QUERIES, validateReadOnlyOracleSql } from './oracleDatabaseQueries.ts';
import { collectOracleLinuxOs } from './oracleLinuxCollector.ts';
import { appendOracleMetricHistory, buildOracleHistoryRecord } from './oracleMetrics.ts';
import {
  DEFAULT_ORACLE_SCHEDULES,
  type OciCollectionResult,
  type OracleCloudTestSummary,
  type OracleCloudUnifiedResult,
  type OracleCollectionCadenceState,
  type OracleDbCollectionResult,
  type OracleLinuxCollectionResult,
} from './oracleTypes.ts';

const cadenceState = new Map<string, OracleCollectionCadenceState>();
const inFlightTargets = new Set<string>();

function getSchedules(db: OracleDatabaseMetric) {
  return {
    ...DEFAULT_ORACLE_SCHEDULES,
    ...(db.schedules || {}),
  };
}

function isDue(lastTs: number | undefined, intervalSec: number, force: boolean): boolean {
  if (force || !lastTs) return true;
  return Date.now() - lastTs >= Math.max(15, intervalSec) * 1000;
}

async function runSafeSelect<T>(
  conn: oracledb.Connection,
  sql: string,
  binds: oracledb.BindParameters,
  opts: oracledb.ExecuteOptions,
  viewLabel: string,
  missingPermissions: string[]
): Promise<T[] | null> {
  if (!validateReadOnlyOracleSql(sql)) {
    throw new Error(`Rejected non-SELECT or prohibited Oracle query for ${viewLabel}.`);
  }
  try {
    const res = await conn.execute<T>(sql, binds, opts);
    return (res.rows || []) as T[];
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (/ORA-00942|ORA-01031/i.test(msg)) {
      missingPermissions.push(`${viewLabel}: SELECT privilege missing (${msg.split('\n')[0]})`);
      return null;
    }
    if (/ORA-00904|ORA-00933/i.test(msg)) {
      missingPermissions.push(`${viewLabel}: Column/view mismatch on this Oracle version (${msg.split('\n')[0]})`);
      return null;
    }
    throw err;
  }
}

export async function collectOracleDatabaseOnly(
  db: OracleDatabaseMetric,
  vault: CredentialVault,
  options?: { timeoutMs?: number; forceAllCadences?: boolean }
): Promise<OracleDbCollectionResult> {
  const stamp = formatMedLabsTimestamp();
  const timeoutMs = options?.timeoutMs ?? db.queryTimeoutMs ?? 8000;
  const connectTimeoutSec = Math.max(3, Math.round((db.connectTimeoutMs ?? timeoutMs) / 1000));
  const force = options?.forceAllCadences === true;
  const schedules = getSchedules(db);
  const cadence = cadenceState.get(db.id) ?? {
    lastAvailabilityAt: 0,
    lastSessionsPerfAt: 0,
    lastMemoryAt: 0,
    lastTablespaceAt: 0,
    lastOciAt: 0,
    lastLinuxAt: 0,
  };

  const targetDescriptor =
    db.connectionType === 'tns' && db.tnsAlias
      ? `TNS:${db.tnsAlias}`
      : `${db.protocol || 'TCP'}://${db.host}:${db.port || 1521}/${db.serviceName}`;

  const credRes = vault.getDecrypted(db.credentialId);
  if (!credRes.ok || credRes.payload.kind !== 'oracle' || !credRes.payload.username || !credRes.payload.password) {
    const errMsg = !credRes.ok
      ? credRes.error
      : 'Attached credential profile is not a valid Oracle read-only credential.';
    db.lastCheck = stamp;
    const integrity = {
      collectionStatus: (db.credentialId ? 'Authentication Failed' : 'Not Configured') as
        | 'Authentication Failed'
        | 'Not Configured',
      dataSource: 'Oracle SQL (SELECT-only)',
      measuredAt: stamp,
      targetIdentifier: targetDescriptor,
      errorDetail: errMsg,
      prerequisiteHint:
        'Attach a dedicated read-only Oracle account (CREATE SESSION + approved SELECT views). Never use SYS/SYSTEM/DBA.',
    };
    db.integrity = integrity;
    const connector: OracleConnectorHealth = {
      connector: 'Oracle Database',
      status: db.credentialId ? 'Authentication Failed' : 'Not Configured',
      collectionStatus: integrity.collectionStatus,
      source: 'Oracle SQL',
      lastAttemptAt: stamp,
      availableMetrics: [],
      unavailableMetrics: [{ metric: 'Oracle Database SQL', reason: errMsg }],
      errorDetail: errMsg,
      prerequisiteHint: integrity.prerequisiteHint,
    };
    db.dbConnector = connector;
    return { ok: false, connector, rmanBackups: [], historyRecords: [] };
  }

  if (isPrivilegedOracleUsername(credRes.payload.username)) {
    const errMsg = `Security Policy Blocked: Account "${credRes.payload.username}" is privileged (SYS/SYSTEM/DBA). Configure a dedicated SELECT-only monitoring user.`;
    db.lastCheck = stamp;
    const integrity = {
      collectionStatus: 'Permission Denied' as const,
      dataSource: 'Oracle SQL (Policy Guard)',
      measuredAt: stamp,
      targetIdentifier: targetDescriptor,
      errorDetail: errMsg,
      prerequisiteHint: 'Use a dedicated least-privilege monitoring user (e.g. MEDLABS_MON_RO) with SELECT-only privileges.',
    };
    db.integrity = integrity;
    const connector: OracleConnectorHealth = {
      connector: 'Oracle Database',
      status: 'Access Restricted',
      collectionStatus: 'Permission Denied',
      source: 'Oracle SQL',
      lastAttemptAt: stamp,
      availableMetrics: [],
      unavailableMetrics: [{ metric: 'Oracle Database SQL', reason: errMsg }],
      errorDetail: errMsg,
      prerequisiteHint: integrity.prerequisiteHint,
    };
    db.dbConnector = connector;
    return { ok: false, connector, rmanBackups: [], historyRecords: [] };
  }

  const spec = resolveOracleConnectSpec(db, credRes.payload);
  if (spec.validationError) {
    db.lastCheck = stamp;
    const integrity = {
      collectionStatus: 'Not Configured' as const,
      dataSource: 'Oracle SQL (TNS/Wallet Check)',
      measuredAt: stamp,
      targetIdentifier: spec.targetLabel,
      errorDetail: spec.validationError,
    };
    db.integrity = integrity;
    const connector: OracleConnectorHealth = {
      connector: 'Oracle Database',
      status: 'Not Configured',
      collectionStatus: 'Not Configured',
      source: 'Oracle SQL',
      lastAttemptAt: stamp,
      availableMetrics: [],
      unavailableMetrics: [{ metric: 'Oracle TNS / Wallet', reason: spec.validationError }],
      errorDetail: spec.validationError,
    };
    db.dbConnector = connector;
    return { ok: false, connector, rmanBackups: [], historyRecords: [] };
  }

  let conn: oracledb.Connection | null = null;
  const started = Date.now();
  const rmanBackups: BackupJob[] = [];
  const missingPermissions: string[] = [];
  const availableMetrics: string[] = [];
  const unavailableMetrics: { metric: string; reason: string }[] = [];

  try {
    conn = await acquirePooledOracleConnection({
      targetId: db.id,
      username: credRes.payload.username,
      password: credRes.payload.password,
      spec,
      connectTimeoutSec,
      queryTimeoutMs: timeoutMs,
    });

    const opts: oracledb.ExecuteOptions = { outFormat: oracledb.OUT_FORMAT_OBJECT };

    // 1. Instance availability & version discovery (1m cadence)
    const instRows = await runSafeSelect<{
      INSTANCE_NAME: string;
      HOST_NAME: string;
      VERSION: string;
      STATUS: string;
      DATABASE_STATUS: string;
      STARTUP_TIME_STR?: string;
      UPTIME_HOURS?: number;
    }>(conn, ORACLE_READ_ONLY_QUERIES.instanceOverview, [], opts, 'V$INSTANCE', missingPermissions);

    const dbRows = await runSafeSelect<{
      NAME: string;
      DATABASE_ROLE: string;
      OPEN_MODE: string;
    }>(conn, ORACLE_READ_ONLY_QUERIES.databaseOverview, [], opts, 'V$DATABASE', missingPermissions);

    const instRow = instRows?.[0];
    const dbRow = dbRows?.[0];

    let dbVersion = instRow?.VERSION ? String(instRow.VERSION) : undefined;
    if (!dbVersion) {
      const verRows = await runSafeSelect<{ BANNER: string }>(
        conn,
        ORACLE_READ_ONLY_QUERIES.productVersionFallback,
        [],
        opts,
        'V$VERSION',
        missingPermissions
      );
      dbVersion = verRows?.[0]?.BANNER ? String(verRows[0].BANNER) : undefined;
    }

    if (instRow) {
      db.instanceName = String(instRow.INSTANCE_NAME);
      if (dbVersion) db.dbVersion = dbVersion;
      if (instRow.STARTUP_TIME_STR) db.startupTime = String(instRow.STARTUP_TIME_STR);
      if (typeof instRow.UPTIME_HOURS === 'number') db.uptimeHours = Number(instRow.UPTIME_HOURS);
      availableMetrics.push(`Instance (${instRow.STATUS}${dbVersion ? ` · Oracle ${dbVersion}` : ''})`);
    }
    if (dbRow) {
      db.dbName = String(dbRow.NAME);
      db.openMode = String(dbRow.OPEN_MODE);
      db.role = String(dbRow.DATABASE_ROLE || 'PRIMARY').includes('STANDBY') ? 'Read-Only Standby' : 'Primary';
      availableMetrics.push(`Open Mode (${dbRow.OPEN_MODE})`);
    }
    cadence.lastAvailabilityAt = Date.now();

    // 2. Sessions & Performance (1m cadence)
    if (isDue(cadence.lastSessionsPerfAt, schedules.sessionsPerfSec, force)) {
      const sessRows = await runSafeSelect<{
        TOTAL_SESSIONS: number;
        ACTIVE_SESSIONS: number;
        INACTIVE_SESSIONS: number;
        BLOCKING_SESSIONS: number;
      }>(conn, ORACLE_READ_ONLY_QUERIES.sessionSummary, [], opts, 'V$SESSION', missingPermissions);

      if (sessRows?.[0]) {
        db.totalSessions = Number(sessRows[0].TOTAL_SESSIONS || 0);
        db.activeSessions = Number(sessRows[0].ACTIVE_SESSIONS || 0);
        db.inactiveSessions = Number(sessRows[0].INACTIVE_SESSIONS || 0);
        db.blockingSessions = Number(sessRows[0].BLOCKING_SESSIONS || 0);
        availableMetrics.push(`Sessions (${db.activeSessions}/${db.totalSessions})`);
      }

      const limitRows = await runSafeSelect<{
        RESOURCE_NAME: string;
        CURRENT_UTILIZATION: number;
        MAX_UTILIZATION: number;
        LIMIT_VALUE: string;
      }>(
        conn,
        ORACLE_READ_ONLY_QUERIES.resourceLimits,
        { r1: 'sessions', r2: 'processes' },
        opts,
        'V$RESOURCE_LIMIT',
        missingPermissions
      );
      if (limitRows) {
        db.resourceLimits = limitRows.map((r) => ({
          resourceName: String(r.RESOURCE_NAME),
          currentUtilization: Number(r.CURRENT_UTILIZATION || 0),
          maxUtilization: Number(r.MAX_UTILIZATION || 0),
          limitValue: String(r.LIMIT_VALUE || '').trim(),
        }));
      }

      const lqRows = await runSafeSelect<{
        SID?: number;
        SERIAL_NUM?: number;
        SQL_ID: string;
        USERNAME: string;
        SCHEMA_NAME?: string;
        OS_USER?: string;
        MACHINE?: string;
        PROGRAM?: string;
        ELAPSED_SEC: number;
        WAIT_EVENT: string;
        MODULE: string;
      }>(
        conn,
        ORACLE_READ_ONLY_QUERIES.longRunningQueries,
        { minElapsedSec: 15 },
        { ...opts, maxRows: 10 },
        'V$SESSION (Long Queries)',
        missingPermissions
      );
      if (lqRows) {
        const enriched: OracleLongQuery[] = [];
        for (const r of lqRows) {
          const sqlId = String(r.SQL_ID);
          const program = String(r.PROGRAM || '');
          const mod = String(r.MODULE || 'Unknown');
          let schemaName = String(r.SCHEMA_NAME || r.USERNAME || 'UNKNOWN');
          let sqlText: string | undefined;

          if (enriched.length < 5) {
            const sqlRows = await runSafeSelect<{
              SQL_ID: string;
              PARSING_SCHEMA_NAME?: string;
              SQL_TEXT?: string;
            }>(
              conn,
              ORACLE_READ_ONLY_QUERIES.sqlTextBySqlId,
              { sqlId },
              opts,
              'V$SQL',
              missingPermissions
            );
            if (sqlRows?.[0]) {
              if (sqlRows[0].PARSING_SCHEMA_NAME) {
                schemaName = String(sqlRows[0].PARSING_SCHEMA_NAME);
              }
              if (sqlRows[0].SQL_TEXT) {
                sqlText = String(sqlRows[0].SQL_TEXT);
              }
            }
          }

          const isReportSession = /report|crystal|jasper|ssrs|print|excel|bi|pdf|toad|sqldeveloper/i.test(
            `${program} ${mod}`
          );

          enriched.push({
            sqlId,
            username: String(r.USERNAME),
            schemaName,
            osUser: r.OS_USER ? String(r.OS_USER) : undefined,
            machine: r.MACHINE ? String(r.MACHINE) : undefined,
            program: program || undefined,
            sid: typeof r.SID === 'number' ? Number(r.SID) : undefined,
            serial: typeof r.SERIAL_NUM === 'number' ? Number(r.SERIAL_NUM) : undefined,
            elapsedSec: Number(r.ELAPSED_SEC || 0),
            waitEvent: String(r.WAIT_EVENT),
            module: mod,
            sqlText,
            isReportSession,
          });
        }
        db.longRunningQueries = enriched;
      }

      const weRows = await runSafeSelect<{
        EVENT: string;
        TOTAL_WAITS: number;
        TIME_WAITED_MS: number;
      }>(
        conn,
        ORACLE_READ_ONLY_QUERIES.topWaitEvents,
        [],
        { ...opts, maxRows: 6 },
        'V$SYSTEM_EVENT',
        missingPermissions
      );
      if (weRows) {
        db.topWaitEvents = weRows.map((r) => ({
          event: String(r.EVENT),
          totalWaits: Number(r.TOTAL_WAITS || 0),
          timeWaitedMs: Number(r.TIME_WAITED_MS || 0),
        }));
      }

      const cpuRows = await runSafeSelect<{ VALUE: number }>(
        conn,
        ORACLE_READ_ONLY_QUERIES.hostCpuMetric,
        { metricName: 'Host CPU Utilization (%)' },
        opts,
        'V$SYSMETRIC',
        missingPermissions
      );
      if (cpuRows?.[0]) {
        db.cpuUsagePct = Number(cpuRows[0].VALUE || 0);
        availableMetrics.push(`DB Host CPU (${db.cpuUsagePct}%)`);
      }

      const statRows = await runSafeSelect<{ NAME: string; VALUE: number }>(
        conn,
        ORACLE_READ_ONLY_QUERIES.sysstatMetrics,
        {
          s1: 'execute count',
          s2: 'user commits',
          s3: 'physical reads',
          s4: 'session logical reads',
        },
        opts,
        'V$SYSSTAT',
        missingPermissions
      );
      if (statRows) {
        db.sysstatSummary = statRows.map((r) => ({ name: String(r.NAME), value: Number(r.VALUE || 0) }));
      }

      const sqlAggRows = await runSafeSelect<{
        TOTAL_EXECUTIONS: number;
        DISK_READS: number;
        BUFFER_GETS: number;
        AVG_ELAPSED_MS: number | null;
      }>(conn, ORACLE_READ_ONLY_QUERIES.sqlAreaAggregate, [], opts, 'V$SQLAREA (Aggregate)', missingPermissions);
      if (sqlAggRows?.[0]) {
        db.sqlAreaAggregate = {
          totalExecutions: Number(sqlAggRows[0].TOTAL_EXECUTIONS || 0),
          diskReads: Number(sqlAggRows[0].DISK_READS || 0),
          bufferGets: Number(sqlAggRows[0].BUFFER_GETS || 0),
          avgElapsedMs: Number(sqlAggRows[0].AVG_ELAPSED_MS || 0),
        };
      }

      cadence.lastSessionsPerfAt = Date.now();
    }

    // 3. Memory: SGA & PGA (2m cadence)
    if (isDue(cadence.lastMemoryAt, schedules.memorySec, force)) {
      const pgaRows = await runSafeSelect<{ VALUE: number }>(
        conn,
        ORACLE_READ_ONLY_QUERIES.pgaStat,
        { metricName: 'total PGA allocated' },
        opts,
        'V$PGASTAT',
        missingPermissions
      );
      if (pgaRows?.[0]) {
        db.pgaUsedMb = Number(pgaRows[0].VALUE || 0);
        availableMetrics.push(`PGA (${db.pgaUsedMb} MB)`);
      }

      const sgaRows = await runSafeSelect<{ NAME: string; BYTES: number }>(
        conn,
        ORACLE_READ_ONLY_QUERIES.sgaInfo,
        { n1: 'Free SGA Memory Available', n2: 'Maximum SGA Size' },
        opts,
        'V$SGAINFO',
        missingPermissions
      );
      if (sgaRows) {
        const maxSga = Number(sgaRows.find((r) => r.NAME === 'Maximum SGA Size')?.BYTES || 0);
        const freeSga = Number(sgaRows.find((r) => r.NAME === 'Free SGA Memory Available')?.BYTES || 0);
        if (maxSga > 0) {
          db.sgaUsedPct = Number((((maxSga - freeSga) / maxSga) * 100).toFixed(1));
          availableMetrics.push(`SGA (${db.sgaUsedPct}%)`);
        }
      }
      cadence.lastMemoryAt = Date.now();
    }

    // 4. Storage & Backups: Tablespaces, Datafiles, Temp, FRA, RMAN (5m cadence)
    if (isDue(cadence.lastTablespaceAt, schedules.tablespaceSec, force)) {
      let tsRows = await runSafeSelect<{
        TABLESPACE_NAME: string;
        USED_GB: number;
        MAX_GB: number;
        USED_PCT: number;
      }>(
        conn,
        ORACLE_READ_ONLY_QUERIES.tablespaceUsageMetrics,
        [],
        { ...opts, maxRows: 25 },
        'DBA_TABLESPACE_USAGE_METRICS',
        missingPermissions
      );

      if (!tsRows) {
        tsRows = await runSafeSelect<{
          TABLESPACE_NAME: string;
          USED_GB: number;
          MAX_GB: number;
          USED_PCT: number;
        }>(
          conn,
          ORACLE_READ_ONLY_QUERIES.tablespaceDataFilesFallback,
          [],
          { ...opts, maxRows: 25 },
          'DBA_DATA_FILES / DBA_FREE_SPACE',
          missingPermissions
        );
      }

      if (tsRows) {
        let totalGb = 0;
        const nextTs: OracleTablespace[] = tsRows.map((r) => {
          const usedGb = Number(r.USED_GB || 0);
          totalGb += usedGb;
          return {
            name: String(r.TABLESPACE_NAME),
            usedGb,
            maxGb: Number(r.MAX_GB || 0),
            usedPct: Number(r.USED_PCT || 0),
            dailyGrowthGb: 0,
          };
        });
        db.tablespaces = nextTs;
        db.dbSizeGb = Number(totalGb.toFixed(2));
        availableMetrics.push(`Tablespaces (${nextTs.length})`);
      }

      const dfRows = await runSafeSelect<{
        FILE_COUNT: number;
        TOTAL_GB: number;
        MAX_GB: number;
        AUTOEXT_COUNT: number;
      }>(conn, ORACLE_READ_ONLY_QUERIES.datafilesSummary, [], opts, 'DBA_DATA_FILES', missingPermissions);
      if (dfRows?.[0]) {
        db.datafilesSummary = {
          fileCount: Number(dfRows[0].FILE_COUNT || 0),
          totalGb: Number(dfRows[0].TOTAL_GB || 0),
          maxGb: Number(dfRows[0].MAX_GB || 0),
          autoextensibleCount: Number(dfRows[0].AUTOEXT_COUNT || 0),
        };
      }

      const tempRows = await runSafeSelect<{
        TABLESPACE_NAME: string;
        ALLOCATED_GB: number;
        USED_GB: number;
        FREE_GB: number;
      }>(conn, ORACLE_READ_ONLY_QUERIES.tempTablespaces, [], opts, 'DBA_TEMP_FREE_SPACE', missingPermissions);
      if (tempRows) {
        db.tempTablespaces = tempRows.map((r) => ({
          name: String(r.TABLESPACE_NAME),
          allocatedGb: Number(r.ALLOCATED_GB || 0),
          usedGb: Number(r.USED_GB || 0),
          freeGb: Number(r.FREE_GB || 0),
        }));
      }

      const fraRows = await runSafeSelect<{
        NAME: string;
        SPACE_LIMIT_GB: number;
        SPACE_USED_GB: number;
        SPACE_RECLAIMABLE_GB: number;
      }>(conn, ORACLE_READ_ONLY_QUERIES.fraUsage, [], opts, 'V$RECOVERY_FILE_DEST', missingPermissions);
      if (fraRows?.[0]) {
        const limitGb = Number(fraRows[0].SPACE_LIMIT_GB || 0);
        const usedGb = Number(fraRows[0].SPACE_USED_GB || 0);
        db.fraUsage = {
          name: String(fraRows[0].NAME),
          spaceLimitGb: limitGb,
          spaceUsedGb: usedGb,
          spaceReclaimableGb: Number(fraRows[0].SPACE_RECLAIMABLE_GB || 0),
          usedPct: limitGb > 0 ? Number(((usedGb / limitGb) * 100).toFixed(1)) : 0,
        };
      } else if (fraRows && fraRows.length === 0) {
        db.fraUsage = null;
      }

      if (db.collectRmanBackups !== false) {
        const rmanRows = await runSafeSelect<{
          SESSION_KEY: number;
          INPUT_TYPE: string;
          STATUS: string;
          END_STR: string;
          DURATION_MIN: number;
          SIZE_GB: number;
          AGE_HOURS: number;
        }>(
          conn,
          ORACLE_READ_ONLY_QUERIES.rmanBackups,
          [],
          { ...opts, maxRows: 6 },
          'V$RMAN_BACKUP_JOB_DETAILS',
          missingPermissions
        );
        if (rmanRows) {
          for (const r of rmanRows) {
            const rawStatus = String(r.STATUS || '');
            const status: BackupJob['status'] =
              rawStatus.includes('COMPLETED WITH ERRORS') || rawStatus.includes('FAILED')
                ? 'Failed'
                : rawStatus.includes('WARNING')
                  ? 'Warning'
                  : 'Succeeded';
            rmanBackups.push({
              id: `RMAN-${db.serviceName}-${r.SESSION_KEY}`,
              jobName: `RMAN ${r.INPUT_TYPE} (${db.serviceName})`,
              targetSystem: spec.targetLabel,
              backupSource: 'Oracle V$RMAN_BACKUP_JOB_DETAILS (SELECT-only)',
              status,
              lastSuccessfulRun: r.END_STR || stamp,
              durationMinutes: Number(r.DURATION_MIN || 0),
              sizeGb: Number(r.SIZE_GB || 0),
              ageHours: Math.max(0, Number(r.AGE_HOURS || 0)),
              failures7d: status === 'Failed' ? 1 : 0,
            });
          }
          if (rmanRows.length > 0) availableMetrics.push(`RMAN Jobs (${rmanRows.length})`);
        }
      }

      cadence.lastTablespaceAt = Date.now();
    }

    cadenceState.set(db.id, cadence);

    const rttMs = Math.max(1, Date.now() - started);
    db.responseTimeMs = rttMs;
    db.lastCheck = stamp;
    db.availabilityPct = 100;
    db.missingPermissions = missingPermissions;

    const instStatus = String(instRow?.STATUS || 'OPEN');
    const maxTsPct = db.tablespaces.reduce((m, t) => Math.max(m, t.usedPct), 0);
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

    for (const mp of missingPermissions) {
      unavailableMetrics.push({ metric: mp.split(':')[0], reason: mp });
    }

    const integrity = {
      collectionStatus: (db.status === 'Critical' ? 'Critical' : db.status === 'Warning' ? 'Warning' : 'Healthy') as
        | 'Critical'
        | 'Warning'
        | 'Healthy',
      dataSource: `Oracle SQL SELECT-only (${spec.targetLabel})`,
      measuredAt: stamp,
      targetIdentifier: spec.targetLabel,
    };
    db.integrity = integrity;

    const connector: OracleConnectorHealth = {
      connector: 'Oracle Database',
      status: db.status === 'Critical' ? 'Critical' : db.status === 'Warning' ? 'Warning' : 'Healthy',
      collectionStatus: integrity.collectionStatus,
      source: 'Oracle SQL',
      lastAttemptAt: stamp,
      lastSuccessAt: stamp,
      latencyMs: rttMs,
      availableMetrics,
      unavailableMetrics,
      ...(missingPermissions.length > 0
        ? {
            prerequisiteHint:
              'Some optional dictionary views lacked SELECT privilege; primary database health remains active.',
          }
        : {}),
    };
    db.dbConnector = connector;

    const historyRecords: OracleHistoryRecord[] = [];
    const pushHist = (name: string, val: number | string | null | undefined, unit: string) => {
      const rec = buildOracleHistoryRecord({
        serverId: db.id,
        platform: 'Oracle Database',
        metricName: name,
        metricValue: val,
        metricUnit: unit,
        metricSource: 'Oracle SQL',
        collectionTime: stamp,
        collectionStatus: connector.status,
      });
      if (rec) historyRecords.push(rec);
    };
    pushHist('Oracle Response Time', rttMs, 'ms');
    pushHist('Oracle Active Sessions', db.activeSessions, 'sessions');
    pushHist('Oracle Blocking Sessions', db.blockingSessions, 'sessions');
    pushHist('Oracle SGA Used', db.sgaUsedPct, '%');
    pushHist('Oracle PGA Used', db.pgaUsedMb, 'MB');

    return { ok: true, connector, rmanBackups, historyRecords };
  } catch (err) {
    const classified = classifyOracleConnectionError(err);
    db.lastCheck = stamp;
    db.connectionFailures24h += 1;
    db.status = classified.status === 'Unreachable' ? 'Offline' : 'Warning';
    const integrity = {
      collectionStatus: classified.status,
      dataSource: `Oracle SQL SELECT-only (${spec.targetLabel})`,
      measuredAt: stamp,
      targetIdentifier: spec.targetLabel,
      errorDetail: classified.errorDetail.slice(0, 260),
      prerequisiteHint: classified.prerequisiteHint,
    };
    db.integrity = integrity;
    const connector: OracleConnectorHealth = {
      connector: 'Oracle Database',
      status: classified.connectorState,
      collectionStatus: classified.status,
      source: 'Oracle SQL',
      lastAttemptAt: stamp,
      latencyMs: Date.now() - started,
      availableMetrics: [],
      unavailableMetrics: [{ metric: 'Oracle Database SQL', reason: classified.errorDetail }],
      errorDetail: classified.errorDetail.slice(0, 260),
      prerequisiteHint: classified.prerequisiteHint,
    };
    db.dbConnector = connector;
    return { ok: false, connector, rmanBackups: [], historyRecords: [] };
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

/**
 * Independent 3-connector orchestration for an OCI Oracle Cloud VM + Oracle Linux OS + Oracle Database.
 * Uses Promise.allSettled so failure in any single connector NEVER marks the others offline.
 */
export async function collectOracleCloudVmBundle(
  db: OracleDatabaseMetric,
  vault: CredentialVault,
  options?: { timeoutMs?: number; forceAllCadences?: boolean }
): Promise<OracleCloudUnifiedResult> {
  if (inFlightTargets.has(db.id)) {
    return {
      ok: Boolean(db.dbConnector?.status === 'Healthy' || db.ociConnector?.status === 'Healthy' || db.linuxConnector?.status === 'Healthy'),
      ociResult: {
        ok: Boolean(db.ociMetrics),
        connector: db.ociConnector || {
          connector: 'OCI Infrastructure',
          status: 'Not Configured',
          collectionStatus: 'Not Configured',
          source: 'OCI API',
          lastAttemptAt: db.lastCheck,
          availableMetrics: [],
          unavailableMetrics: [],
        },
        metrics: db.ociMetrics,
        historyRecords: [],
      },
      linuxResult: {
        ok: Boolean(db.linuxMetrics),
        connector: db.linuxConnector || {
          connector: 'Oracle Linux OS',
          status: 'Not Configured',
          collectionStatus: 'Not Configured',
          source: 'SSH',
          lastAttemptAt: db.lastCheck,
          availableMetrics: [],
          unavailableMetrics: [],
        },
        metrics: db.linuxMetrics,
        historyRecords: [],
      },
      dbResult: {
        ok: db.status === 'Online' || db.status === 'Warning',
        connector: db.dbConnector || {
          connector: 'Oracle Database',
          status: 'Not Configured',
          collectionStatus: 'Not Configured',
          source: 'Oracle SQL',
          lastAttemptAt: db.lastCheck,
          availableMetrics: [],
          unavailableMetrics: [],
        },
        rmanBackups: [],
        historyRecords: [],
      },
      rmanBackups: [],
    };
  }

  inFlightTargets.add(db.id);
  try {
    const timeoutMs = options?.timeoutMs ?? 8000;
    const force = options?.forceAllCadences === true;
    const schedules = getSchedules(db);
    const prevCadence = cadenceState.get(db.id) ?? {
      lastAvailabilityAt: 0,
      lastSessionsPerfAt: 0,
      lastMemoryAt: 0,
      lastTablespaceAt: 0,
      lastOciAt: 0,
      lastLinuxAt: 0,
    };

    const runOci = db.ociConfig?.enabled && isDue(prevCadence.lastOciAt, db.ociConfig.collectIntervalSeconds ?? schedules.ociSec, force);
    const ociPromise: Promise<OciCollectionResult> = runOci
      ? collectOciInfrastructure({ targetId: db.id, config: db.ociConfig, vault, timeoutMs })
      : db.ociConfig?.enabled && db.ociConnector
        ? Promise.resolve({ ok: Boolean(db.ociMetrics), connector: db.ociConnector, metrics: db.ociMetrics, historyRecords: [] })
        : collectOciInfrastructure({ targetId: db.id, config: db.ociConfig, vault, timeoutMs });

    const dbPromise = collectOracleDatabaseOnly(db, vault, { timeoutMs, forceAllCadences: force });

    // Run OCI + DB first so OCI metrics are available as fallback label if SSH is disabled/blocked
    const [ociSettled, dbSettled] = await Promise.allSettled([ociPromise, dbPromise]);

    const ociResult: OciCollectionResult =
      ociSettled.status === 'fulfilled'
        ? ociSettled.value
        : {
            ok: false,
            connector: {
              connector: 'OCI Infrastructure',
              status: 'Unreachable',
              collectionStatus: 'Unreachable',
              source: 'OCI API',
              lastAttemptAt: formatMedLabsTimestamp(),
              availableMetrics: [],
              unavailableMetrics: [{ metric: 'OCI API', reason: String(ociSettled.reason) }],
              errorDetail: String(ociSettled.reason),
            },
            historyRecords: [],
          };

    if (ociResult.ok && ociResult.metrics) {
      db.ociMetrics = ociResult.metrics;
      prevCadence.lastOciAt = Date.now();
    }
    db.ociConnector = ociResult.connector;

    const runLinux =
      db.linuxConfig?.enabled &&
      isDue(prevCadence.lastLinuxAt, db.linuxConfig.collectIntervalSeconds ?? schedules.linuxSec, force);
    const linuxResult: OracleLinuxCollectionResult =
      runLinux || !db.linuxConnector || force
        ? await collectOracleLinuxOs({
            targetId: db.id,
            fallbackHost: db.host,
            config: db.linuxConfig,
            vault,
            ociMetricsFallback: db.ociMetrics,
            timeoutMs,
          })
        : { ok: Boolean(db.linuxMetrics && !db.linuxMetrics.fallbackFromOci), connector: db.linuxConnector, metrics: db.linuxMetrics, historyRecords: [] };

    if (linuxResult.metrics) {
      db.linuxMetrics = linuxResult.metrics;
    }
    if (linuxResult.ok) {
      prevCadence.lastLinuxAt = Date.now();
    }
    db.linuxConnector = linuxResult.connector;

    const dbResult: OracleDbCollectionResult =
      dbSettled.status === 'fulfilled'
        ? dbSettled.value
        : {
            ok: false,
            connector: {
              connector: 'Oracle Database',
              status: 'Unreachable',
              collectionStatus: 'Unreachable',
              source: 'Oracle SQL',
              lastAttemptAt: formatMedLabsTimestamp(),
              availableMetrics: [],
              unavailableMetrics: [{ metric: 'Oracle Database', reason: String(dbSettled.reason) }],
              errorDetail: String(dbSettled.reason),
            },
            rmanBackups: [],
            historyRecords: [],
          };

    db.dbConnector = dbResult.connector;

    const nextCadence = cadenceState.get(db.id) ?? prevCadence;
    nextCadence.lastOciAt = prevCadence.lastOciAt;
    nextCadence.lastLinuxAt = prevCadence.lastLinuxAt;
    cadenceState.set(db.id, nextCadence);

    db.metricHistory = appendOracleMetricHistory(db.metricHistory, [
      ...ociResult.historyRecords,
      ...linuxResult.historyRecords,
      ...dbResult.historyRecords,
    ]);

    return {
      ok: ociResult.ok || linuxResult.ok || dbResult.ok,
      ociResult,
      linuxResult,
      dbResult,
      rmanBackups: dbResult.rmanBackups,
    };
  } finally {
    inFlightTargets.delete(db.id);
  }
}

export async function testOracleCloudVmBundle(
  db: OracleDatabaseMetric,
  vault: CredentialVault,
  timeoutMs = 8000
): Promise<OracleCloudTestSummary> {
  const started = Date.now();
  const clone: OracleDatabaseMetric = structuredClone(db);
  const res = await collectOracleCloudVmBundle(clone, vault, { timeoutMs, forceAllCadences: true });

  const dbConn = res.dbResult.connector;
  const ociConn = res.ociResult.connector;
  const linuxConn = res.linuxResult.connector;

  const summaryParts: string[] = [];
  if (db.ociConfig?.enabled) {
    summaryParts.push(`OCI: ${ociConn.status}${ociConn.errorDetail ? ` (${ociConn.errorDetail})` : ''}`);
  }
  if (db.linuxConfig?.enabled) {
    summaryParts.push(`Oracle Linux: ${linuxConn.status}${linuxConn.errorDetail ? ` (${linuxConn.errorDetail})` : ''}`);
  }
  summaryParts.push(
    `Oracle DB: ${dbConn.status}${
      res.dbResult.ok
        ? ` (${clone.dbVersion ? `Oracle ${clone.dbVersion}, ` : ''}${clone.activeSessions}/${clone.totalSessions ?? clone.activeSessions} sessions, ${clone.tablespaces.length} tablespaces)`
        : dbConn.errorDetail
          ? ` (${dbConn.errorDetail})`
          : ''
    }`
  );

  return {
    ok: res.dbResult.ok || res.ociResult.ok || res.linuxResult.ok,
    status: dbConn.collectionStatus,
    dataSource: db.integrity?.dataSource || 'OCI + Oracle Linux + Oracle SQL',
    latencyMs: res.dbResult.ok ? clone.responseTimeMs : Date.now() - started,
    measuredAt: dbConn.lastAttemptAt,
    details: summaryParts.join(' | '),
    prerequisiteHint: dbConn.prerequisiteHint || ociConn.prerequisiteHint || linuxConn.prerequisiteHint,
    ociTest: ociConn,
    linuxTest: linuxConn,
    dbTest: dbConn,
  };
}
