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
  return new Date().toISOString().replace('T', ' ').slice(0, 19);
}

export class CentralMonitoringEngine {
  private readonly timers = new Map<string, NodeJS.Timeout>();
  private readonly activeRuns = new Set<string>();

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
    title: string;
    titleAr: string;
    description: string;
    descriptionAr: string;
  }) {
    const exists = this.state.alerts.some(
      (a) =>
        a.assetName.toLowerCase() === params.assetName.toLowerCase() &&
        a.status !== 'Resolved' &&
        a.title.includes(params.matchKey)
    );
    if (!exists) {
      this.state.alerts.unshift({
        id: `INC-${Math.floor(4100 + Math.random() * 5800)}`,
        timestamp: nowTimestamp(),
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
      });
      if (this.state.alerts.length > 250) {
        this.state.alerts.length = 250;
      }
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
          titleAr: `تعذر الوصول إلى الخادم ${srv.hostname} (${srv.ipAddress})`,
          description: srv.integrity.errorDetail || 'ICMP/TCP probes failed.',
          descriptionAr: `فشل الاتصال الشبكي بالخادم ${srv.hostname}.`,
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
        titleAr: `تجاوز عتبة ${b.metric} (${b.value}${b.unit}) على ${srv.hostname}`,
        description: `Central collector measured ${b.metric} at ${b.value}${b.unit} on ${srv.hostname} (${srv.ipAddress}).`,
        descriptionAr: `سجّل المجمّع المركزي وصول ${b.metric} إلى ${b.value}${b.unit} على الخادم ${srv.hostname}.`,
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
        titleAr: `تعذر الوصول إلى قاعدة Oracle (${db.serviceName})`,
        description: db.integrity.errorDetail || 'Oracle connection failed.',
        descriptionAr: `فشل الاتصال بقاعدة بيانات Oracle ${db.serviceName}.`,
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
        titleAr: `ارتفاع حرج في زمن استجابة Oracle (${db.responseTimeMs} ms)`,
        description: `Read-only query RTT reached ${db.responseTimeMs}ms on ${db.serviceName}.`,
        descriptionAr: `وصل زمن استجابة قاعدة Oracle إلى ${db.responseTimeMs}ms.`,
      });
    }

    if (db.blockingSessions > 0) {
      this.ensureAlert({
        severity: db.blockingSessions >= 3 ? 'Critical' : 'High',
        module: 'Oracle DB',
        assetId: db.id,
        assetName: db.serviceName,
        matchKey: 'Blocking Sessions',
        title: `Oracle Blocking Sessions detected (${db.blockingSessions})`,
        titleAr: `رصد جلسات حاجبة في Oracle (${db.blockingSessions})`,
        description: `Detected ${db.blockingSessions} blocked user sessions in V$SESSION on ${db.serviceName}.`,
        descriptionAr: `تم رصد ${db.blockingSessions} جلسات حاجبة في قاعدة ${db.serviceName}.`,
      });
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
        titleAr: `انقطاع الاتصال بجهاز الشبكة ${dev.name} (${dev.ipAddress})`,
        description: dev.integrity?.errorDetail || 'ICMP/SNMP probes failed.',
        descriptionAr: `تعذر الوصول إلى جهاز الشبكة ${dev.name}.`,
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
        titleAr: `ارتفاع فقدان الحزم (${dev.packetLossPct}%) على ${dev.name}`,
        description: `ICMP probe measured ${dev.packetLossPct}% loss (${dev.latencyMs}ms avg) to ${dev.ipAddress}.`,
        descriptionAr: `بلغت نسبة فقدان الحزم ${dev.packetLossPct}% للجهاز ${dev.name}.`,
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
        titleAr: `تعطل موقع/تطبيق الويب ${site.name} (${site.httpStatus || 'Timeout'})`,
        description: site.integrity?.errorDetail || `HTTP probe returned ${site.httpStatus} for ${site.url}.`,
        descriptionAr: `أعاد فحص الموقع ${site.url} حالة ${site.httpStatus || 'انقطاع'}.`,
      });
    } else if (typeof site.sslDaysRemaining === 'number' && site.sslDaysRemaining <= 14) {
      this.ensureAlert({
        severity: site.sslDaysRemaining <= 5 ? 'Critical' : 'High',
        module: 'IIS & App',
        assetId: site.id,
        assetName: site.name,
        matchKey: 'SSL Certificate',
        title: `SSL Certificate expiring in ${site.sslDaysRemaining} days (${site.name})`,
        titleAr: `قرب انتهاء شهادة SSL خلال ${site.sslDaysRemaining} يوم (${site.name})`,
        description: `TLS certificate on ${site.url} expires in ${site.sslDaysRemaining} days.`,
        descriptionAr: `تنتهي صلاحية شهادة الأمان للموقع ${site.url} خلال ${site.sslDaysRemaining} يوم.`,
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

    // Derive DB CPU/IO/Lock wait decomposition from real Oracle metrics & topWaitEvents
    const topWait = primaryOra?.topWaitEvents?.[0];
    const waitList = primaryOra?.topWaitEvents ?? [];
    const ioWaits = waitList
      .filter((w) => /io|scattered|sequential|direct path|file/i.test(w.event))
      .reduce((a, w) => a + w.timeWaitedMs, 0);
    const lockWaits = waitList
      .filter((w) => /lock|enq|latch|commit|log file/i.test(w.event))
      .reduce((a, w) => a + w.timeWaitedMs, 0);
    const totalWaitSum = Math.max(1, ioWaits + lockWaits);

    const dbCpuMs =
      avgOracleMs > 0
        ? Math.max(1, Math.round(avgOracleMs * Math.min(0.8, Math.max(0.2, (primaryOra?.cpuUsagePct || 25) / 100))))
        : 0;
    const remainingDbMs = Math.max(0, avgOracleMs - dbCpuMs);
    const dbIoMs =
      ioWaits > 0
        ? Math.round(remainingDbMs * (ioWaits / totalWaitSum))
        : Math.round(remainingDbMs * 0.65);
    const dbLockMs =
      totalBlocking > 0
        ? Math.max(15, totalBlocking * 25 + Math.max(0, remainingDbMs - dbIoMs))
        : Math.max(0, remainingDbMs - dbIoMs);

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
                titleAr: `فشل النسخ الاحتياطي RMAN: ${b.jobName}`,
                description: `V$RMAN_BACKUP_JOB_DETAILS reported ${b.status} on ${b.targetSystem}.`,
                descriptionAr: `أبلغت Oracle عن فشل مهمة النسخ ${b.jobName}.`,
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
