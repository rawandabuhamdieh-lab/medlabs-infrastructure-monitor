import { formatMedLabsTimestamp } from './time.ts';
import type { CredentialVault } from './credentialVault.ts';
import { collectApiEndpoint, collectIisSite } from './iisCollector.ts';
import { collectNetworkDevice } from './networkCollector.ts';
import { collectOracleDatabase } from './oracleCollector.ts';
import { collectWindowsServer } from './windowsCollector.ts';
import type {
  AlertRecord,
  AlertSeverity,
  AlertThreshold,
  ApiEndpointCheck,
  AssetStatus,
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

export interface EngineState {
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
  timeline: TimelineSample[];
}

function nowTimestamp(): string {
  return formatMedLabsTimestamp();
}

export class CentralMonitoringEngine {
  private readonly timers = new Map<string, NodeJS.Timeout>();
  private readonly activeRuns = new Set<string>();
  private readonly previousOracleWaits = new Map<string, Map<string, number>>();

  constructor(
    private readonly state: EngineState,
    private readonly vault: CredentialVault,
    private readonly onPersist: () => void
  ) {}

  private ensureAlert(params: {
    severity: AlertSeverity;
    module: AlertRecord['module'];
    assetId: string;
    assetName: string;
    matchKey: string;
    dedupKey?: string;
    title: string;
    titleAr: string;
    description: string;
    descriptionAr: string;
    schemaName?: string;
    dbUsername?: string;
    sqlId?: string;
    sqlText?: string;
    program?: string;
  }) {
    const key = (params.dedupKey || `${params.module}::${params.assetName}::${params.matchKey}`).toLowerCase();
    const existing = this.state.alerts.find(
      (a) =>
        a.status !== 'Resolved' &&
        ((a.dedupKey && a.dedupKey.toLowerCase() === key) ||
          (a.assetName.toLowerCase() === params.assetName.toLowerCase() &&
            a.title.includes(params.matchKey)))
    );
    const ts = nowTimestamp();
    if (existing) {
      existing.occurrenceCount = (existing.occurrenceCount ?? 1) + 1;
      existing.lastSeenAt = ts;
      existing.dedupKey = existing.dedupKey || key;
      if (params.schemaName) existing.schemaName = params.schemaName;
      if (params.dbUsername) existing.dbUsername = params.dbUsername;
      if (params.sqlId) existing.sqlId = params.sqlId;
      if (params.sqlText) existing.sqlText = params.sqlText;
      if (params.program) existing.program = params.program;
      if (params.severity === 'Critical') existing.severity = 'Critical';
      return;
    }

    this.state.alerts.unshift({
      id: `INC-${Math.floor(4100 + Math.random() * 5800)}`,
      timestamp: ts,
      lastSeenAt: ts,
      occurrenceCount: 1,
      dedupKey: key,
      severity: params.severity,
      status: 'Open',
      module: params.module,
      assetId: params.assetId,
      assetName: params.assetName,
      title: params.title,
      titleAr: params.titleAr,
      description: params.description,
      descriptionAr: params.descriptionAr,
      acknowledgedBy: null,
      assignedTo: null,
      resolutionNotes: '',
      downtimeMinutes: 0,
      notifiedChannels: ['NOC Dashboard'],
      schemaName: params.schemaName,
      dbUsername: params.dbUsername,
      sqlId: params.sqlId,
      sqlText: params.sqlText,
      program: params.program,
    });
    if (this.state.alerts.length > 250) {
      this.state.alerts.length = 250;
    }
  }
  evaluateServerMetrics(srv: WindowsServer) {
    if (!srv.metricsAvailable?.cpu && !srv.metricsAvailable?.ram && !srv.metricsAvailable?.disk) {
      if (srv.integrity?.collectionStatus === 'Unreachable' && srv.integrity?.dataSource === 'ICMP + TCP Probe') {
        srv.status = 'Offline';
        this.ensureAlert({
          severity: 'Critical',
          module: 'Windows Server',
          assetId: srv.id,
          assetName: srv.hostname,
          matchKey: 'unreachable',
          title: `Server unreachable via ICMP/TCP (${srv.ipAddress})`,
          titleAr: `__AR0____AR0____AR0____AR0__ الوصو__AR0__ __AR0____AR0____AR0__ __AR0____AR0____AR0____AR0____AR0____AR0__ ${srv.hostname} (${srv.ipAddress})`,
          description: srv.integrity.errorDetail || 'ICMP/TCP probes failed.',
          descriptionAr: `ف__AR0____AR0__ __AR0____AR0____AR0____AR0____AR0____AR0____AR0__ الشبكي __AR0____AR0____AR0____AR0____AR0____AR0____AR0__ ${srv.hostname}.`,
        });
      }
      return;
    }

    const cpuRule = this.state.thresholds.find((t) => t.id === 'THR-CPU');
    const ramRule = this.state.thresholds.find((t) => t.id === 'THR-RAM');
    const diskRule = this.state.thresholds.find((t) => t.id === 'THR-DISK');

    let nextStatus: AssetStatus = 'Online';
    const breaches: { severity: AlertSeverity; metric: string; value: number; unit: string }[] = [];

    if (cpuRule && srv.metricsAvailable?.cpu) {
      if (srv.cpuPct >= cpuRule.criticalValue) {
        nextStatus = 'Critical';
        breaches.push({ severity: 'Critical', metric: 'CPU', value: srv.cpuPct, unit: '%' });
      } else if (srv.cpuPct >= cpuRule.warningValue) {
        if (nextStatus === 'Online') nextStatus = 'Warning';
        breaches.push({ severity: 'High', metric: 'CPU', value: srv.cpuPct, unit: '%' });
      }
    }

    if (ramRule && srv.metricsAvailable?.ram) {
      if (srv.ramPct >= ramRule.criticalValue) {
        nextStatus = 'Critical';
        breaches.push({ severity: 'Critical', metric: 'RAM', value: srv.ramPct, unit: '%' });
      } else if (srv.ramPct >= ramRule.warningValue) {
        if (nextStatus === 'Online') nextStatus = 'Warning';
        breaches.push({ severity: 'Medium', metric: 'RAM', value: srv.ramPct, unit: '%' });
      }
    }

    if (diskRule && srv.metricsAvailable?.disk) {
      if (srv.diskPct >= diskRule.criticalValue) {
        nextStatus = 'Critical';
        breaches.push({ severity: 'Critical', metric: 'Disk', value: srv.diskPct, unit: '%' });
      } else if (srv.diskPct >= diskRule.warningValue) {
        if (nextStatus === 'Online') nextStatus = 'Warning';
        breaches.push({ severity: 'Medium', metric: 'Disk', value: srv.diskPct, unit: '%' });
      }
    }

    srv.status = nextStatus;
    for (const b of breaches) {
      this.ensureAlert({
        severity: b.severity,
        module: 'Windows Server',
        assetId: srv.id,
        assetName: srv.hostname,
        matchKey: b.metric,
        title: `${b.metric} threshold exceeded (${b.value}${b.unit})`,
        titleAr: `تجاو__AR0__ __AR0____AR0____AR0____AR0__ ${b.metric} (${b.value}${b.unit}) __AR0____AR0____AR0__ ${srv.hostname}`,
        description: `Central collector measured ${b.metric} at ${b.value}${b.unit} on ${srv.hostname} (${srv.ipAddress}).`,
        descriptionAr: `__AR0____AR0____AR0____AR0__ __AR0____AR0____AR0____AR0____AR0____AR0____AR0__ المركزي وصو__AR0__ ${b.metric} __AR0____AR0____AR0__ ${b.value}${b.unit} __AR0____AR0____AR0__ __AR0____AR0____AR0____AR0____AR0____AR0__ ${srv.hostname}.`,
      });
    }
  }

  private evaluateOracleMetrics(db: OracleDatabaseMetric) {
    const oraRule = this.state.thresholds.find((t) => t.id === 'THR-ORA-RESP');
    if (db.integrity?.collectionStatus === 'Unreachable') {
      this.ensureAlert({
        severity: 'Critical',
        module: 'Oracle DB',
        assetId: db.id,
        assetName: db.serviceName,
        matchKey: 'unreachable',
        title: `Oracle DB unreachable (${db.host}:${db.port || 1521}/${db.serviceName})`,
        titleAr: `__AR0____AR0____AR0____AR0__ الوصو__AR0__ __AR0____AR0____AR0__ __AR0____AR0____AR0____AR0____AR0__ Oracle (${db.serviceName})`,
        description: db.integrity.errorDetail || 'Oracle connection failed.',
        descriptionAr: `ف__AR0____AR0__ __AR0____AR0____AR0____AR0____AR0____AR0____AR0__ __AR0____AR0____AR0____AR0____AR0____AR0__ بي__AR0____AR0____AR0____AR0__ Oracle ${db.serviceName}.`,
      });
      return;
    }

    if (oraRule && db.responseTimeMs >= oraRule.criticalValue) {
      this.ensureAlert({
        severity: 'Critical',
        module: 'Oracle DB',
        assetId: db.id,
        assetName: db.serviceName,
        matchKey: 'Response Latency',
        title: `Oracle Response Latency critical (${db.responseTimeMs} ms)`,
        titleAr: `ارتف__AR0____AR0__ __AR0____AR0____AR0__ في __AR0____AR0____AR0__ __AR0____AR0____AR0____AR0____AR0____AR0____AR0__ Oracle (${db.responseTimeMs} ms)`,
        description: `Read-only query RTT reached ${db.responseTimeMs}ms on ${db.serviceName}.`,
        descriptionAr: `و__AR0____AR0__ __AR0____AR0____AR0__ __AR0____AR0____AR0____AR0____AR0____AR0____AR0__ __AR0____AR0____AR0____AR0____AR0__ Oracle __AR0____AR0____AR0__ ${db.responseTimeMs}ms.`,
      });
    }

    if (db.blockingSessions > 0) {
      const topQ = db.longRunningQueries[0];
      this.ensureAlert({
        severity: db.blockingSessions >= 3 ? 'Critical' : 'High',
        module: 'Oracle DB',
        assetId: db.id,
        assetName: db.serviceName,
        matchKey: 'Blocking Sessions',
        dedupKey: `oracle::${db.serviceName}::blocking`,
        title: `Oracle Blocking Sessions detected (${db.blockingSessions})`,
        titleAr: `__AR0____AR0____AR0__ __AR0____AR0____AR0____AR0____AR0__ __AR0____AR0____AR0____AR0____AR0__ في Oracle (${db.blockingSessions})`,
        description: `Detected ${db.blockingSessions} blocked user sessions in V$SESSION on ${db.serviceName}.`,
        descriptionAr: `__AR0____AR0__ __AR0____AR0____AR0__ ${db.blockingSessions} __AR0____AR0____AR0____AR0____AR0__ __AR0____AR0____AR0____AR0____AR0__ في __AR0____AR0____AR0____AR0____AR0__ ${db.serviceName}.`,
        schemaName: topQ?.schemaName,
        dbUsername: topQ?.username,
        sqlId: topQ?.sqlId,
        sqlText: topQ?.sqlText,
        program: topQ?.program || topQ?.module,
      });
    }

    for (const q of db.longRunningQueries.slice(0, 3)) {
      if (q.elapsedSec >= 30) {
        const schema = q.schemaName || q.username;
        const isRep = Boolean(q.isReportSession);
        this.ensureAlert({
          severity: q.elapsedSec >= 120 ? 'Critical' : 'High',
          module: 'Oracle DB',
          assetId: db.id,
          assetName: db.serviceName,
          matchKey: q.sqlId,
          dedupKey: `oracle::${db.serviceName}::sql::${q.sqlId}::${schema}`,
          title: isRep
            ? `Report/User Session impacting DB (${q.username} @ ${schema} Â· ${q.elapsedSec}s)`
            : `Long Running Query ${q.sqlId} in ${schema} (${q.elapsedSec}s)`,
          titleAr: isRep
            ? `تأثي__AR0__ __AR0____AR0____AR0____AR0____AR0__ تقري__AR0__ / __AR0____AR0____AR0____AR0____AR0____AR0__ (${q.username} · سكي__AR0____AR0__ ${schema} · ${q.elapsedSec}__AR0__)`
            : `__AR0____AR0____AR0____AR0____AR0____AR0____AR0__ بطي__AR0__ Long Running Query (${q.sqlId} · سكي__AR0____AR0__ ${schema} · ${q.elapsedSec}__AR0__)`,
          description: `User ${q.username} in schema ${schema} running ${q.sqlId} via ${q.program || q.module} (${q.waitEvent}).`,
          descriptionAr: `__AR0____AR0____AR0____AR0____AR0____AR0____AR0____AR0__ ${q.username} __AR0____AR0____AR0__ السكي__AR0____AR0__ ${schema} ينف__AR0__ __AR0____AR0____AR0____AR0____AR0____AR0____AR0____AR0____AR0__ ${q.sqlId} __AR0____AR0____AR0__ ${q.program || q.module} (${q.waitEvent}).`,
          schemaName: schema,
          dbUsername: q.username,
          sqlId: q.sqlId,
          sqlText: q.sqlText,
          program: q.program || q.module,
        });
      }
    }
  }

  private evaluateNetworkMetrics(dev: NetworkDevice) {
    const lossRule = this.state.thresholds.find((t) => t.id === 'THR-NET-LOSS');
    if (dev.status === 'Offline') {
      this.ensureAlert({
        severity: 'Critical',
        module: 'Network',
        assetId: dev.id,
        assetName: dev.name,
        matchKey: 'unreachable',
        title: `Network device unreachable (${dev.ipAddress})`,
        titleAr: `__AR0____AR0____AR0____AR0____AR0____AR0__ __AR0____AR0____AR0____AR0____AR0____AR0____AR0__ __AR0____AR0____AR0____AR0____AR0__ الشبك__AR0__ ${dev.name} (${dev.ipAddress})`,
        description: dev.integrity?.errorDetail || 'ICMP/SNMP probes failed.',
        descriptionAr: `__AR0____AR0____AR0____AR0__ الوصو__AR0__ __AR0____AR0____AR0__ __AR0____AR0____AR0____AR0__ الشبك__AR0__ ${dev.name}.`,
      });
      return;
    }
    if (lossRule && dev.packetLossPct >= lossRule.criticalValue) {
      this.ensureAlert({
        severity: 'High',
        module: 'Network',
        assetId: dev.id,
        assetName: dev.name,
        matchKey: 'Packet Loss',
        title: `High Packet Loss (${dev.packetLossPct}%) on ${dev.name}`,
        titleAr: `ارتف__AR0____AR0__ ف__AR0____AR0____AR0____AR0__ __AR0____AR0____AR0____AR0____AR0__ (${dev.packetLossPct}%) __AR0____AR0____AR0__ ${dev.name}`,
        description: `ICMP probe measured ${dev.packetLossPct}% loss (${dev.latencyMs}ms avg) to ${dev.ipAddress}.`,
        descriptionAr: `__AR0____AR0____AR0____AR0__ __AR0____AR0____AR0____AR0__ ف__AR0____AR0____AR0____AR0__ __AR0____AR0____AR0____AR0____AR0__ ${dev.packetLossPct}% __AR0____AR0____AR0____AR0____AR0____AR0__ ${dev.name}.`,
      });
    }
  }

  private evaluateIisMetrics(site: IisSite) {
    if (site.status === 'Offline' || site.status === 'Critical') {
      this.ensureAlert({
        severity: 'Critical',
        module: 'IIS & App',
        assetId: site.id,
        assetName: site.name,
        matchKey: 'HTTP',
        title: `IIS Web/App HTTP failure (${site.httpStatus || 'Timeout'}) on ${site.name}`,
        titleAr: `__AR0____AR0____AR0____AR0__ مو__AR0____AR0__/تطبي__AR0__ الوي__AR0__ ${site.name} (${site.httpStatus || 'Timeout'})`,
        description: site.integrity?.errorDetail || `HTTP probe returned ${site.httpStatus} for ${site.url}.`,
        descriptionAr: `__AR0____AR0____AR0____AR0__ ف__AR0____AR0__ المو__AR0____AR0__ ${site.url} __AR0____AR0____AR0____AR0__ ${site.httpStatus || '__AR0____AR0____AR0____AR0____AR0____AR0__'}.`,
      });
    } else if (typeof site.sslDaysRemaining === 'number' && site.sslDaysRemaining <= 14) {
      this.ensureAlert({
        severity: site.sslDaysRemaining <= 5 ? 'Critical' : 'High',
        module: 'IIS & App',
        assetId: site.id,
        assetName: site.name,
        matchKey: 'SSL Certificate',
        title: `SSL Certificate expiring in ${site.sslDaysRemaining} days (${site.name})`,
        titleAr: `__AR0____AR0____AR0__ __AR0____AR0____AR0____AR0____AR0____AR0__ __AR0____AR0____AR0____AR0____AR0__ SSL __AR0____AR0____AR0____AR0__ ${site.sslDaysRemaining} يو__AR0__ (${site.name})`,
        description: `TLS certificate on ${site.url} expires in ${site.sslDaysRemaining} days.`,
        descriptionAr: `تنتهي صلاحي__AR0__ __AR0____AR0____AR0____AR0____AR0__ __AR0____AR0____AR0____AR0____AR0____AR0__ للمو__AR0____AR0__ ${site.url} __AR0____AR0____AR0____AR0__ ${site.sslDaysRemaining} يو__AR0__.`,
      });
    }
  }

  private async runWithRetry<T extends { ok: boolean; integrity?: { collectionStatus?: string } }>(
    fn: () => Promise<T>,
    retryCount: number
  ): Promise<T> {
    let attempt = 0;
    let lastResult = await fn();
    while (
      !lastResult.ok &&
      attempt < retryCount &&
      lastResult.integrity?.collectionStatus === 'Unreachable'
    ) {
      attempt += 1;
      await new Promise((r) => setTimeout(r, 400 * attempt));
      lastResult = await fn();
    }
    return lastResult;
  }

  private recordHistoricalRollup() {
    const srvWithCpu = this.state.servers.filter((s) => s.metricsAvailable?.cpu);
    const avgCpuPct =
      srvWithCpu.length > 0
        ? Number((srvWithCpu.reduce((a, s) => a + s.cpuPct, 0) / srvWithCpu.length).toFixed(1))
        : 0;
    const onlineOra = this.state.oracleDatabases.filter((d) => d.responseTimeMs > 0);
    const avgOracleMs =
      onlineOra.length > 0
        ? Math.round(onlineOra.reduce((a, d) => a + d.responseTimeMs, 0) / onlineOra.length)
        : 0;

    const totalAssets =
      this.state.servers.length +
      this.state.oracleDatabases.length +
      this.state.iisSites.length +
      this.state.networkDevices.length;

    if (totalAssets === 0) return;

    const onlineAssets =
      this.state.servers.filter((s) => s.status !== 'Offline').length +
      this.state.oracleDatabases.filter((d) => d.status !== 'Offline').length +
      this.state.iisSites.filter((i) => i.status !== 'Offline').length +
      this.state.networkDevices.filter((n) => n.status !== 'Offline').length;

    const availabilityPct = Number(((onlineAssets / totalAssets) * 100).toFixed(2));
    const openIncidents = this.state.alerts.filter((a) => a.status !== 'Resolved');
    const totalDowntimeMin = this.state.alerts.reduce((a, al) => a + al.downtimeMinutes, 0);
    const fullTs = nowTimestamp();
    const dateStr = fullTs.slice(0, 10);
    const timeStr = fullTs.slice(11, 19);
    const label = fullTs.slice(11, 16);

    const last = this.state.reports[this.state.reports.length - 1];
    if (last && last.period === label) {
      last.availabilityPct = availabilityPct;
      last.avgCpuPct = avgCpuPct;
      last.avgOracleMs = avgOracleMs;
      last.incidentCount = openIncidents.length;
      last.totalDowntimeMin = totalDowntimeMin;
    } else {
      this.state.reports.push({
        period: label,
        availabilityPct,
        avgCpuPct,
        avgOracleMs,
        incidentCount: openIncidents.length,
        totalDowntimeMin,
      });
      if (this.state.reports.length > 24) {
        this.state.reports.shift();
      }
    }

    // Record minute-level timeline sample for retroactive date/hour/minute inspection
    const srvWithRam = this.state.servers.filter((s) => s.metricsAvailable?.ram);
    const avgRamPct =
      srvWithRam.length > 0
        ? Number((srvWithRam.reduce((a, s) => a + s.ramPct, 0) / srvWithRam.length).toFixed(1))
        : 0;
    const primaryOra = this.state.oracleDatabases[0];
    const totalSessions = this.state.oracleDatabases.reduce((a, d) => a + (d.activeSessions || 0), 0);
    const totalBlocking = this.state.oracleDatabases.reduce((a, d) => a + (d.blockingSessions || 0), 0);
    const onlineIis = this.state.iisSites.filter((s) => s.responseTimeMs > 0);
    const avgAppMs =
      onlineIis.length > 0
        ? Math.round(onlineIis.reduce((a, s) => a + s.responseTimeMs, 0) / onlineIis.length)
        : 0;
    const appErrors1h = this.state.iisSites.reduce((a, s) => a + (s.httpErrors1h || 0), 0);
    const onlineNet = this.state.networkDevices.filter((n) => n.status !== 'Offline');
    const avgNetMs =
      onlineNet.length > 0
        ? Math.round(onlineNet.reduce((a, n) => a + n.latencyMs, 0) / onlineNet.length)
        : 0;
    const maxLossPct =
      this.state.networkDevices.length > 0
        ? Math.max(...this.state.networkDevices.map((n) => n.packetLossPct || 0))
        : 0;

    // Calculate interval wait time from cumulative Oracle counters.
    const topWait = primaryOra?.topWaitEvents?.[0];
    const waitList = primaryOra?.topWaitEvents ?? [];
    const previousWaits = primaryOra
      ? this.previousOracleWaits.get(primaryOra.id)
      : undefined;

    const waitDeltas = waitList.map((w) => ({
      event: w.event,
      deltaMs: previousWaits?.has(w.event)
        ? Math.max(0, w.timeWaitedMs - previousWaits.get(w.event)!)
        : 0,
    }));

    if (primaryOra) {
      this.previousOracleWaits.set(
        primaryOra.id,
        new Map(waitList.map((w) => [w.event, w.timeWaitedMs]))
      );
    }

    const dbCpuMs = 0;
    const dbIoMs = Math.round(waitDeltas
      .filter((w) => /db file|direct path|control file/i.test(w.event))
      .reduce((a, w) => a + w.deltaMs, 0));
    const dbLockMs = Math.round(waitDeltas
      .filter((w) => /enq|lock/i.test(w.event))
      .reduce((a, w) => a + w.deltaMs, 0));

    const criticalAlerts = openIncidents.filter((a) => a.severity === 'Critical' || a.severity === 'High').length;
    const hasOffline =
      this.state.servers.some((s) => s.status === 'Offline' || s.status === 'Critical') ||
      this.state.oracleDatabases.some((d) => d.status === 'Offline' || d.status === 'Critical') ||
      this.state.iisSites.some((i) => i.status === 'Offline' || i.status === 'Critical') ||
      this.state.networkDevices.some((n) => n.status === 'Offline');
    const hasIssue = openIncidents.length > 0 || totalBlocking > 0 || hasOffline;
    const firstAlert = openIncidents[0];

    const sample: TimelineSample = {
      timestamp: fullTs,
      date: dateStr,
      time: timeStr,
      minuteLabel: label,
      dbCpuMs,
      dbIoMs,
      dbLockMs,
      appResponseMs: avgAppMs,
      networkLatencyMs: avgNetMs,
      serverLoadScore: Math.round(avgCpuPct),
      serverCpuPct: avgCpuPct,
      serverRamPct: avgRamPct,
      oracleResponseMs: avgOracleMs,
      activeSessions: totalSessions,
      blockingSessions: totalBlocking,
      appErrors1h,
      packetLossPct: maxLossPct,
      activeAlerts: openIncidents.length,
      criticalAlerts,
      hasIssue,
      issueSummary: firstAlert?.title,
      issueSummaryAr: firstAlert?.titleAr,
      topWaitEvent: topWait?.event,
      topObject: primaryOra?.tablespaces?.[0]?.name,
      affectedTarget: firstAlert?.assetName || primaryOra?.serviceName || this.state.servers[0]?.hostname,
    };

    const prevSample = this.state.timeline[this.state.timeline.length - 1];
    if (prevSample && prevSample.date === dateStr && prevSample.minuteLabel === label) {
      this.state.timeline[this.state.timeline.length - 1] = sample;
    } else {
      this.state.timeline.push(sample);
      if (this.state.timeline.length > 2000) {
        this.state.timeline.shift();
      }
    }
  }

  async runCollector(collectorId: string): Promise<void> {
    const col = this.state.collectors.find((c) => c.id === collectorId);
    if (!col || this.activeRuns.has(collectorId)) return;

    this.activeRuns.add(collectorId);
    const started = Date.now();
    const timeoutMs = col.timeoutMs ?? 8000;
    const retryCount = col.retryCount ?? 1;

    try {
      let targetCount = 0;
      let healthyCount = 0;
      let firstError: string | undefined;

      if (collectorId === 'COL-WIN') {
        targetCount = this.state.servers.length;
        const settled = await Promise.allSettled(
          this.state.servers.map(async (srv) => {
            const res = await this.runWithRetry(
              () => collectWindowsServer(srv, this.vault, timeoutMs),
              retryCount
            );
            this.evaluateServerMetrics(srv);
            return res;
          })
        );
        for (const r of settled) {
          if (r.status === 'fulfilled' && r.value.ok) {
            healthyCount += 1;
          } else if (r.status === 'fulfilled' && !firstError && r.value.integrity.errorDetail) {
            firstError = r.value.integrity.errorDetail;
          } else if (r.status === 'rejected') {
            firstError = String(r.reason);
          }
        }
      } else if (collectorId === 'COL-ORA' || collectorId === 'COL-BKP') {
        targetCount = this.state.oracleDatabases.length;
        const allRman: BackupJob[] = [];
        const settled = await Promise.allSettled(
          this.state.oracleDatabases.map(async (db) => {
            const res = await this.runWithRetry(
              () => collectOracleDatabase(db, this.vault, timeoutMs),
              retryCount
            );
            this.evaluateOracleMetrics(db);
            return res;
          })
        );
        for (const r of settled) {
          if (r.status === 'fulfilled') {
            if (r.value.ok) healthyCount += 1;
            else if (!firstError && r.value.integrity.errorDetail) firstError = r.value.integrity.errorDetail;
            if (r.value.rmanBackups.length > 0) allRman.push(...r.value.rmanBackups);
          } else if (!firstError) {
            firstError = String(r.reason);
          }
        }
        if (allRman.length > 0) {
          this.state.backups.splice(0, this.state.backups.length, ...allRman);
          for (const b of allRman) {
            if (b.status === 'Failed') {
              this.ensureAlert({
                severity: 'Critical',
                module: 'Backup',
                assetId: b.id,
                assetName: b.targetSystem,
                matchKey: b.jobName,
                title: `Oracle RMAN Backup Failed: ${b.jobName}`,
                titleAr: `ف__AR0____AR0__ __AR0____AR0____AR0____AR0____AR0__ الاحتياطي RMAN: ${b.jobName}`,
                description: `V$RMAN_BACKUP_JOB_DETAILS reported ${b.status} on ${b.targetSystem}.`,
                descriptionAr: `__AR0____AR0____AR0____AR0____AR0__ Oracle __AR0____AR0__ ف__AR0____AR0__ __AR0____AR0____AR0____AR0__ __AR0____AR0____AR0____AR0____AR0__ ${b.jobName}.`,
              });
            }
          }
        }
      } else if (collectorId === 'COL-NET') {
        targetCount = this.state.networkDevices.length;
        const settled = await Promise.allSettled(
          this.state.networkDevices.map(async (dev) => {
            const res = await this.runWithRetry(
              () => collectNetworkDevice(dev, this.vault, timeoutMs),
              retryCount
            );
            this.evaluateNetworkMetrics(dev);
            return res;
          })
        );
        for (const r of settled) {
          if (r.status === 'fulfilled' && r.value.ok) {
            healthyCount += 1;
          } else if (r.status === 'fulfilled' && !firstError && r.value.integrity.errorDetail) {
            firstError = r.value.integrity.errorDetail;
          }
        }
      } else if (collectorId === 'COL-IIS') {
        targetCount = this.state.iisSites.length + this.state.apiEndpoints.length;
        const discoveredPools: IisAppPool[] = [];
        const [siteRes, apiRes] = await Promise.all([
          Promise.allSettled(
            this.state.iisSites.map(async (site) => {
              const res = await this.runWithRetry(
                () => collectIisSite(site, this.vault, timeoutMs),
                retryCount
              );
              this.evaluateIisMetrics(site);
              return res;
            })
          ),
          Promise.allSettled(
            this.state.apiEndpoints.map((api) =>
              this.runWithRetry(() => collectApiEndpoint(api, timeoutMs), retryCount)
            )
          ),
        ]);

        for (const r of siteRes) {
          if (r.status === 'fulfilled') {
            if (r.value.ok) healthyCount += 1;
            else if (!firstError && r.value.integrity.errorDetail) firstError = r.value.integrity.errorDetail;
            if (r.value.discoveredPools.length > 0) {
              discoveredPools.push(...r.value.discoveredPools);
            }
          }
        }
        for (const r of apiRes) {
          if (r.status === 'fulfilled' && r.value.ok) healthyCount += 1;
        }
        if (discoveredPools.length > 0) {
          this.state.appPools.splice(0, this.state.appPools.length, ...discoveredPools);
        }
      }

      col.lastRun = nowTimestamp();
      col.lastDurationMs = Math.max(1, Date.now() - started);
      col.targetsTotal = targetCount;
      col.targetsHealthy = healthyCount;
      col.lastError = firstError;

      if (!col.enabled) {
        col.status = 'Paused';
      } else if (targetCount > 0 && healthyCount < targetCount) {
        col.status = 'Degraded';
        col.errorCount24h += targetCount - healthyCount;
      } else {
        col.status = 'Healthy';
      }

      this.recordHistoricalRollup();
      this.onPersist();
    } catch (err) {
      col.lastRun = nowTimestamp();
      col.lastDurationMs = Math.max(1, Date.now() - started);
      col.errorCount24h += 1;
      col.lastError = err instanceof Error ? err.message : String(err);
      col.status = 'Degraded';
    } finally {
      this.activeRuns.delete(collectorId);
    }
  }

  rescheduleAll(): void {
    for (const timer of this.timers.values()) {
      clearInterval(timer);
    }
    this.timers.clear();

    for (const col of this.state.collectors) {
      if (!col.enabled) {
        col.status = 'Paused';
        continue;
      }
      const intervalMs = Math.max(15, col.scheduleSeconds) * 1000;
      const timer = setInterval(() => {
        void this.runCollector(col.id);
      }, intervalMs);
      this.timers.set(col.id, timer);
    }
  }

  start(): void {
    this.rescheduleAll();
    // Trigger initial non-blocking sweep of enabled collectors on startup
    for (const col of this.state.collectors) {
      if (col.enabled) {
        void this.runCollector(col.id);
      }
    }
  }
}



