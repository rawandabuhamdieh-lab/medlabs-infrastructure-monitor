import { AlertRecord, OracleTablespace, WindowsServer } from '../types/infrastructure';

export interface ZScoreAnomaly {
  assetName: string;
  metric: string;
  timestamp: string;
  observedValue: number;
  baselineMean: number;
  zScore: number;
  unit: string;
}

export interface CapacityForecast {
  target: string;
  category: 'Server Disk' | 'Oracle Tablespace';
  currentPct: number;
  dailyGrowthPct: number;
  daysTo90Pct: number | null;
  status: 'Stable' | 'Watch' | 'Action Needed';
}

export interface RecurringPattern {
  assetName: string;
  module: string;
  occurrences: number;
  totalDowntimeMinutes: number;
  recommendation: string;
  recommendationAr: string;
}

export function computeZScoreAnomalies(
  servers: WindowsServer[],
  zThreshold = 1.75
): ZScoreAnomaly[] {
  const anomalies: ZScoreAnomaly[] = [];

  for (const srv of servers) {
    if (srv.history.length < 4) continue;
    const values = srv.history.map((h) => h.cpuPct);
    const mean = values.reduce((a, b) => a + b, 0) / values.length;
    const variance =
      values.reduce((acc, v) => acc + Math.pow(v - mean, 2), 0) / values.length;
    const stdDev = Math.sqrt(variance);

    if (stdDev < 0.5) continue;

    for (const point of srv.history) {
      const z = (point.cpuPct - mean) / stdDev;
      if (z >= zThreshold) {
        anomalies.push({
          assetName: srv.hostname,
          metric: 'CPU Utilization',
          timestamp: point.time,
          observedValue: point.cpuPct,
          baselineMean: Number(mean.toFixed(1)),
          zScore: Number(z.toFixed(2)),
          unit: '%',
        });
      }
    }
  }

  return anomalies.sort((a, b) => b.zScore - a.zScore);
}

export function forecastCapacity(
  servers: WindowsServer[],
  tablespaces: OracleTablespace[]
): CapacityForecast[] {
  const results: CapacityForecast[] = [];

  for (const srv of servers) {
    // Ordinary least-squares slope over server disk history samples
    const pts = srv.history;
    if (pts.length >= 2) {
      const n = pts.length;
      const sumX = (n * (n - 1)) / 2;
      const sumY = pts.reduce((a, p) => a + p.diskPct, 0);
      const sumXY = pts.reduce((a, p, idx) => a + idx * p.diskPct, 0);
      const sumX2 = pts.reduce((a, _p, idx) => a + idx * idx, 0);
      const denom = n * sumX2 - sumX * sumX;
      const slopePerStep = denom !== 0 ? (n * sumXY - sumX * sumY) / denom : 0;
      const dailyGrowthPct = Math.max(0.05, Number((slopePerStep * 4).toFixed(2)));
      const remaining = 90 - srv.diskPct;
      const daysTo90Pct =
        remaining <= 0 ? 0 : dailyGrowthPct > 0 ? Math.round(remaining / dailyGrowthPct) : null;

      results.push({
        target: `${srv.hostname} (OS/Data Volume)`,
        category: 'Server Disk',
        currentPct: srv.diskPct,
        dailyGrowthPct,
        daysTo90Pct,
        status:
          daysTo90Pct !== null && daysTo90Pct <= 14
            ? 'Action Needed'
            : daysTo90Pct !== null && daysTo90Pct <= 45
              ? 'Watch'
              : 'Stable',
      });
    }
  }

  for (const ts of tablespaces) {
    const dailyGrowthPct = Number(((ts.dailyGrowthGb / ts.maxGb) * 100).toFixed(2));
    const remaining = 90 - ts.usedPct;
    const daysTo90Pct =
      remaining <= 0 ? 0 : dailyGrowthPct > 0 ? Math.round(remaining / dailyGrowthPct) : null;

    results.push({
      target: `Oracle Tablespace ${ts.name}`,
      category: 'Oracle Tablespace',
      currentPct: ts.usedPct,
      dailyGrowthPct,
      daysTo90Pct,
      status:
        daysTo90Pct !== null && daysTo90Pct <= 14
          ? 'Action Needed'
          : daysTo90Pct !== null && daysTo90Pct <= 45
            ? 'Watch'
            : 'Stable',
    });
  }

  return results.sort((a, b) => (a.daysTo90Pct ?? 9999) - (b.daysTo90Pct ?? 9999));
}

export function detectRecurringIncidents(alerts: AlertRecord[]): RecurringPattern[] {
  const grouped = new Map<
    string,
    { assetName: string; module: string; count: number; downtime: number }
  >();

  for (const a of alerts) {
    const key = `${a.assetName}::${a.module}`;
    const existing = grouped.get(key) ?? {
      assetName: a.assetName,
      module: a.module,
      count: 0,
      downtime: 0,
    };
    existing.count += 1;
    existing.downtime += a.downtimeMinutes;
    grouped.set(key, existing);
  }

  const patterns: RecurringPattern[] = [];
  for (const item of grouped.values()) {
    if (item.count >= 2 || item.downtime >= 15) {
      let recommendation =
        'Review recurring event logs and schedule preventive maintenance window.';
      let recommendationAr =
        'مراجعة السجلات المتكررة وجدولة صيانة وقائية خارج أوقات الذروة.';

      if (item.module === 'Windows Server') {
        recommendation =
          'Audit w3wp/SQL memory limits and expand disk/RAM allocation before peak morning accessioning.';
        recommendationAr =
          'مراجعة استهلاك الذاكرة والقرص وتوسيع الموارد قبل ساعات الذروة الصباحية.';
      } else if (item.module === 'Oracle DB') {
        recommendation =
          'Inspect unindexed queries in V$SQL with DBA and extend tablespace datafile autoextend cap.';
        recommendationAr =
          'مراجعة الاستعلامات البطيئة في V$SQL مع مسؤول قواعد البيانات وتوسيع مساحة الجداول.';
      } else if (item.module === 'Network') {
        recommendation =
          'Verify ISP fiber optical levels and validate automatic SD-WAN SLA failover thresholds.';
        recommendationAr =
          'فحص جودة إشارة الألياف الضوئية والتحقق من عتبات التحويل التلقائي SD-WAN.';
      }

      patterns.push({
        assetName: item.assetName,
        module: item.module,
        occurrences: item.count,
        totalDowntimeMinutes: item.downtime,
        recommendation,
        recommendationAr,
      });
    }
  }

  return patterns.sort((a, b) => b.occurrences - a.occurrences);
}

export interface DiagnosticIssue {
  id: string;
  severity: 'Critical' | 'Warning';
  category: 'Database' | 'Application' | 'Server' | 'Network' | 'Backup';
  categoryLabelEn: string;
  categoryLabelAr: string;
  timestamp: string;
  assetName: string;
  whatEn: string;
  whatAr: string;
  whereEn: string;
  whereAr: string;
  fixEn: string;
  fixAr: string;
  metricBadge: string;
  targetSection: 'oracle' | 'iis' | 'servers' | 'network' | 'backups' | 'alerts';
}

export function buildExecutiveDiagnostics(params: {
  servers: {
    id: string;
    hostname: string;
    ipAddress: string;
    site: string;
    status: string;
    cpuPct: number;
    ramPct: number;
    diskPct: number;
    lastCheck: string;
    metricsAvailable?: { cpu: boolean; ram: boolean; disk: boolean };
    services: { name: string; displayName: string; status: string; startupType: string }[];
    integrity?: { collectionStatus: string; errorDetail?: string; prerequisiteHint?: string };
  }[];
  oracleDatabases: {
    id: string;
    serviceName: string;
    host: string;
    port?: number;
    status: string;
    responseTimeMs: number;
    activeSessions: number;
    blockingSessions: number;
    cpuUsagePct: number;
    sgaUsedPct: number;
    lastCheck: string;
    tablespaces: OracleTablespace[];
    longRunningQueries: { sqlId: string; username: string; elapsedSec: number; waitEvent: string; module: string }[];
    topWaitEvents?: { event: string; totalWaits: number; timeWaitedMs: number }[];
    integrity?: { collectionStatus: string; errorDetail?: string; prerequisiteHint?: string };
  }[];
  iisSites: {
    id: string;
    name: string;
    serverHostname: string;
    url: string;
    appPoolName: string;
    httpStatus: number;
    responseTimeMs: number;
    sslDaysRemaining?: number | null;
    status: string;
    lastCheck: string;
    integrity?: { errorDetail?: string };
  }[];
  appPools: {
    name: string;
    serverHostname?: string;
    state: string;
    cpuPct: number;
    workerMemoryMb: number;
  }[];
  networkDevices: {
    id: string;
    name: string;
    site: string;
    ipAddress: string;
    status: string;
    latencyMs: number;
    packetLossPct: number;
    lastCheck: string;
    integrity?: { errorDetail?: string };
  }[];
  backups: {
    id: string;
    jobName: string;
    targetSystem: string;
    backupSource: string;
    status: string;
    lastSuccessfulRun: string;
    ageHours: number;
  }[];
  alerts: AlertRecord[];
}): DiagnosticIssue[] {
  const issues: DiagnosticIssue[] = [];

  // 1. Oracle Database Issues
  for (const db of params.oracleDatabases) {
    const dbTarget = `${db.host}:${db.port || 1521}/${db.serviceName}`;

    if (db.status === 'Offline' || db.integrity?.collectionStatus === 'Unreachable' || db.integrity?.collectionStatus === 'Authentication Failed') {
      issues.push({
        id: `DIAG-ORA-CONN-${db.id}`,
        severity: 'Critical',
        category: 'Database',
        categoryLabelEn: 'Oracle Database',
        categoryLabelAr: 'قاعدة البيانات Oracle',
        timestamp: db.lastCheck,
        assetName: db.serviceName,
        whatEn: `Cannot connect to Oracle Database (${db.integrity?.collectionStatus || 'Offline'}).`,
        whatAr: `تعذر الاتصال بقاعدة بيانات Oracle (${db.integrity?.collectionStatus || 'متوقفة'}).`,
        whereEn: `Oracle Host ${dbTarget}`,
        whereAr: `خادم قاعدة البيانات ${dbTarget}`,
        fixEn: db.integrity?.prerequisiteHint || 'Verify Oracle Listener (lsnrctl status), firewall port 1521/2484, and read-only Vault credentials.',
        fixAr: 'تأكد من عمل Oracle Listener على الخادم، وفتح المنفذ 1521 في الجدار الناري، وصحة حساب القراءة فقط في الخزنة.',
        metricBadge: db.integrity?.collectionStatus || 'Offline',
        targetSection: 'oracle',
      });
    }

    if (db.blockingSessions > 0) {
      const topQuery = db.longRunningQueries[0];
      issues.push({
        id: `DIAG-ORA-LOCK-${db.id}`,
        severity: db.blockingSessions >= 3 ? 'Critical' : 'Warning',
        category: 'Database',
        categoryLabelEn: 'Oracle Database',
        categoryLabelAr: 'قاعدة البيانات Oracle',
        timestamp: db.lastCheck,
        assetName: db.serviceName,
        whatEn: `${db.blockingSessions} blocking database session(s) slowing down queries and application requests.`,
        whatAr: `يوجد ${db.blockingSessions} جلسة حاجبة (Blocking Sessions) تسبب بطءاً أو تعليقاً في العمليات.`,
        whereEn: topQuery
          ? `${dbTarget} · SQL_ID ${topQuery.sqlId} (${topQuery.username} / ${topQuery.module})`
          : `${dbTarget} · V$SESSION Locks`,
        whereAr: topQuery
          ? `${dbTarget} · استعلام ${topQuery.sqlId} (${topQuery.username} / ${topQuery.module})`
          : `${dbTarget} · أقفال الجلسات V$SESSION`,
        fixEn: 'Open Oracle Database tab -> inspect blocking SID & long-running SQL_ID -> coordinate with DBA/App owner to commit or terminate stuck transaction.',
        fixAr: 'افتح تبويب Oracle لفحص الجلسة الحاجبة ورقم الاستعلام SQL_ID، وتواصل مع مسؤول القاعدة لإنهاء المعاملة المعلّقة أو عمل Commit.',
        metricBadge: `${db.blockingSessions} locks`,
        targetSection: 'oracle',
      });
    }

    if (db.responseTimeMs >= 75) {
      const topWait = db.topWaitEvents?.[0];
      const isIoWait = topWait && /scattered|sequential|direct path|i\/o/i.test(topWait.event);
      issues.push({
        id: `DIAG-ORA-RTT-${db.id}`,
        severity: db.responseTimeMs >= 150 ? 'Critical' : 'Warning',
        category: 'Database',
        categoryLabelEn: 'Oracle Database',
        categoryLabelAr: 'قاعدة البيانات Oracle',
        timestamp: db.lastCheck,
        assetName: db.serviceName,
        whatEn: `High database query response time (${db.responseTimeMs} ms)${topWait ? ` driven by "${topWait.event}"` : ''}.`,
        whatAr: `بطء في استجابة قاعدة البيانات (${db.responseTimeMs} مللي ثانية)${topWait ? ` بسبب انتظار "${topWait.event}"` : ''}.`,
        whereEn: topWait ? `${dbTarget} · Wait Event: ${topWait.event}` : `${dbTarget} · Query Execution`,
        whereAr: topWait ? `${dbTarget} · حدث الانتظار: ${topWait.event}` : `${dbTarget} · تنفيذ الاستعلامات`,
        fixEn: isIoWait
          ? 'High disk/I/O wait detected. Check missing table indexes on heavy queries and verify storage IOPS latency.'
          : 'Check top SQL statements in Oracle tab, review SGA/PGA memory pressure, and verify active session spikes.',
        fixAr: isIoWait
          ? 'يوجد ضغط قراءة من القرص (I/O Wait). راجع الفهارس المفقودة (Indexes) للاستعلامات الثقيلة وافحص سرعة التخزين.'
          : 'راجع الاستعلامات الأبطأ في تبويب Oracle وتحقق من ضغط الذاكرة SGA/PGA وعدد الجلسات النشطة.',
        metricBadge: `${db.responseTimeMs} ms`,
        targetSection: 'oracle',
      });
    }

    for (const ts of db.tablespaces) {
      if (ts.usedPct >= 85) {
        issues.push({
          id: `DIAG-ORA-TS-${db.id}-${ts.name}`,
          severity: ts.usedPct >= 93 ? 'Critical' : 'Warning',
          category: 'Database',
          categoryLabelEn: 'Oracle Storage',
          categoryLabelAr: 'مساحة قاعدة البيانات',
          timestamp: db.lastCheck,
          assetName: db.serviceName,
          whatEn: `Tablespace "${ts.name}" is ${ts.usedPct}% full (${ts.usedGb} / ${ts.maxGb} GB).`,
          whatAr: `مساحة الجداول "${ts.name}" ممتلئة بنسبة ${ts.usedPct}% (${ts.usedGb} من ${ts.maxGb} GB).`,
          whereEn: `${dbTarget} · Tablespace ${ts.name}`,
          whereAr: `${dbTarget} · مساحة الجداول ${ts.name}`,
          fixEn: `Add a datafile or increase MAXSIZE / AUTOEXTEND on tablespace "${ts.name}" before writes fail.`,
          fixAr: `قم بتوسيع ملف البيانات (Datafile) أو تفعيل AUTOEXTEND لمساحة الجداول "${ts.name}" قبل توقف الكتابة.`,
          metricBadge: `${ts.usedPct}%`,
          targetSection: 'oracle',
        });
      }
    }
  }

  // 2. IIS & Application Issues
  for (const site of params.iisSites) {
    if (site.status === 'Offline' || site.status === 'Critical' || site.httpStatus >= 500 || site.httpStatus === 0) {
      issues.push({
        id: `DIAG-IIS-DOWN-${site.id}`,
        severity: 'Critical',
        category: 'Application',
        categoryLabelEn: 'Application / IIS',
        categoryLabelAr: 'التطبيقات و IIS',
        timestamp: site.lastCheck,
        assetName: site.name,
        whatEn: `Application "${site.name}" returned HTTP ${site.httpStatus || 'Timeout'} and is unavailable or failing.`,
        whatAr: `التطبيق "${site.name}" لا يستجيب أو يعيد خطأ HTTP ${site.httpStatus || 'انقطاع'}.`,
        whereEn: `${site.serverHostname} · AppPool "${site.appPoolName}" · ${site.url}`,
        whereAr: `الخادم ${site.serverHostname} · تجمع التطبيقات "${site.appPoolName}" · ${site.url}`,
        fixEn: `Check IIS AppPool "${site.appPoolName}" state on ${site.serverHostname}, inspect Windows Event Viewer / IIS logs, and verify backend Oracle DB connectivity.`,
        fixAr: `تأكد من تشغيل AppPool "${site.appPoolName}" على الخادم ${site.serverHostname}، وافحص سجلات IIS واتصال التطبيق بقاعدة البيانات.`,
        metricBadge: site.httpStatus ? `HTTP ${site.httpStatus}` : 'Timeout',
        targetSection: 'iis',
      });
    } else if (site.responseTimeMs >= 1000) {
      issues.push({
        id: `DIAG-IIS-SLOW-${site.id}`,
        severity: 'Warning',
        category: 'Application',
        categoryLabelEn: 'Application / IIS',
        categoryLabelAr: 'التطبيقات و IIS',
        timestamp: site.lastCheck,
        assetName: site.name,
        whatEn: `Application "${site.name}" response latency is elevated (${site.responseTimeMs} ms).`,
        whatAr: `بطء في استجابة التطبيق "${site.name}" (${site.responseTimeMs} مللي ثانية).`,
        whereEn: `${site.serverHostname} · ${site.url}`,
        whereAr: `الخادم ${site.serverHostname} · ${site.url}`,
        fixEn: `Check worker process CPU/memory in AppPool "${site.appPoolName}" and correlate with Oracle DB query latency at the same minute.`,
        fixAr: `افحص استهلاك المعالج والذاكرة لتجمع "${site.appPoolName}" وطابق التوقيت مع بطء استعلامات Oracle في نفس الدقيقة.`,
        metricBadge: `${site.responseTimeMs} ms`,
        targetSection: 'iis',
      });
    }

    if (typeof site.sslDaysRemaining === 'number' && site.sslDaysRemaining <= 14) {
      issues.push({
        id: `DIAG-IIS-SSL-${site.id}`,
        severity: site.sslDaysRemaining <= 5 ? 'Critical' : 'Warning',
        category: 'Application',
        categoryLabelEn: 'SSL Certificate',
        categoryLabelAr: 'شهادة الأمان SSL',
        timestamp: site.lastCheck,
        assetName: site.name,
        whatEn: `SSL/TLS certificate expires in ${site.sslDaysRemaining} day(s).`,
        whatAr: `شهادة الأمان SSL/TLS ستنتهي خلال ${site.sslDaysRemaining} يوم.`,
        whereEn: `${site.url} (${site.serverHostname})`,
        whereAr: `${site.url} (الخادم ${site.serverHostname})`,
        fixEn: 'Renew and bind the updated TLS certificate in IIS Manager before expiration to prevent browser/API blocks.',
        fixAr: 'جدّد شهادة الأمان واربطها في IIS Manager قبل انتهاء الصلاحية لتجنب توقف المتصفحات والـ API.',
        metricBadge: `${site.sslDaysRemaining}d left`,
        targetSection: 'iis',
      });
    }
  }

  for (const pool of params.appPools) {
    if (pool.state === 'Stopped') {
      issues.push({
        id: `DIAG-POOL-${pool.name}`,
        severity: 'Critical',
        category: 'Application',
        categoryLabelEn: 'IIS App Pool',
        categoryLabelAr: 'تجمع تطبيقات IIS',
        timestamp: 'Live',
        assetName: pool.name,
        whatEn: `IIS Application Pool "${pool.name}" is Stopped.`,
        whatAr: `تجمع التطبيقات "${pool.name}" في IIS متوقف حالياً.`,
        whereEn: `${pool.serverHostname || 'IIS Host'} · AppPool ${pool.name}`,
        whereAr: `${pool.serverHostname || 'خادم IIS'} · تجمع ${pool.name}`,
        fixEn: 'Check Rapid-Fail Protection events in Windows Event Log, fix identity/config error, and restart the Application Pool.',
        fixAr: 'افحص سجل أحداث Windows للتحقق من سبب التوقف (Rapid-Fail)، وأعد تشغيل AppPool بعد معالجة الخطأ.',
        metricBadge: 'Stopped',
        targetSection: 'iis',
      });
    }
  }

  // 3. Server Issues (CPU, RAM, Disk, Services, Offline)
  for (const srv of params.servers) {
    if (srv.status === 'Offline') {
      issues.push({
        id: `DIAG-SRV-OFF-${srv.id}`,
        severity: 'Critical',
        category: 'Server',
        categoryLabelEn: 'Server Health',
        categoryLabelAr: 'حالة الخادم',
        timestamp: srv.lastCheck,
        assetName: srv.hostname,
        whatEn: `Server "${srv.hostname}" is unreachable.`,
        whatAr: `الخادم "${srv.hostname}" غير متصل أو لا يستجيب.`,
        whereEn: `${srv.hostname} (${srv.ipAddress}) · ${srv.site}`,
        whereAr: `${srv.hostname} (${srv.ipAddress}) · موقع ${srv.site}`,
        fixEn: srv.integrity?.prerequisiteHint || 'Verify host power state, VPN/LAN routing, ICMP/TCP reachability, and WinRM/SSH service.',
        fixAr: 'تأكد من تشغيل الخادم، واتصال الشبكة/الراوتر، وفتح منافذ WinRM أو SSH أو ping.',
        metricBadge: 'Offline',
        targetSection: 'servers',
      });
      continue;
    }

    if (srv.metricsAvailable?.cpu && srv.cpuPct >= 85) {
      issues.push({
        id: `DIAG-SRV-CPU-${srv.id}`,
        severity: srv.cpuPct >= 92 ? 'Critical' : 'Warning',
        category: 'Server',
        categoryLabelEn: 'Server CPU',
        categoryLabelAr: 'معالج الخادم',
        timestamp: srv.lastCheck,
        assetName: srv.hostname,
        whatEn: `High CPU utilization (${srv.cpuPct}%) on ${srv.hostname}.`,
        whatAr: `ارتفاع استهلاك المعالج (${srv.cpuPct}%) على الخادم ${srv.hostname}.`,
        whereEn: `${srv.hostname} (${srv.ipAddress}) · CPU`,
        whereAr: `${srv.hostname} (${srv.ipAddress}) · المعالج`,
        fixEn: 'Inspect top CPU-consuming processes (w3wp.exe, oracle.exe, background jobs) and check for stuck loops or heavy reports.',
        fixAr: 'افحص العمليات الأكثر استهلاكاً للمعالج (مثل w3wp أو oracle أو المهام الخلفية) وأوقف أي عملية معلّقة.',
        metricBadge: `CPU ${srv.cpuPct}%`,
        targetSection: 'servers',
      });
    }

    if (srv.metricsAvailable?.ram && srv.ramPct >= 88) {
      issues.push({
        id: `DIAG-SRV-RAM-${srv.id}`,
        severity: srv.ramPct >= 94 ? 'Critical' : 'Warning',
        category: 'Server',
        categoryLabelEn: 'Server Memory',
        categoryLabelAr: 'ذاكرة الخادم',
        timestamp: srv.lastCheck,
        assetName: srv.hostname,
        whatEn: `High RAM utilization (${srv.ramPct}%) on ${srv.hostname}.`,
        whatAr: `امتلاء الذاكرة RAM (${srv.ramPct}%) على الخادم ${srv.hostname}.`,
        whereEn: `${srv.hostname} (${srv.ipAddress}) · Memory`,
        whereAr: `${srv.hostname} (${srv.ipAddress}) · الذاكرة`,
        fixEn: 'Review IIS worker memory limits or DB memory allocation; consider recycling heavy app pools or expanding VM RAM.',
        fixAr: 'راجع استهلاك الذاكرة للتطبيقات أو قاعدة البيانات، وفكّر في تدوير AppPool أو زيادة سعة الذاكرة.',
        metricBadge: `RAM ${srv.ramPct}%`,
        targetSection: 'servers',
      });
    }

    if (srv.metricsAvailable?.disk && srv.diskPct >= 85) {
      issues.push({
        id: `DIAG-SRV-DISK-${srv.id}`,
        severity: srv.diskPct >= 92 ? 'Critical' : 'Warning',
        category: 'Server',
        categoryLabelEn: 'Server Storage',
        categoryLabelAr: 'مساحة القرص',
        timestamp: srv.lastCheck,
        assetName: srv.hostname,
        whatEn: `Disk space is critically low (${srv.diskPct}% used) on ${srv.hostname}.`,
        whatAr: `امتلاء مساحة القرص (${srv.diskPct}% مستخدم) على الخادم ${srv.hostname}.`,
        whereEn: `${srv.hostname} (${srv.ipAddress}) · Disk Storage`,
        whereAr: `${srv.hostname} (${srv.ipAddress}) · وحدة التخزين`,
        fixEn: 'Archive/purge old IIS logs, temp files, or old backup dumps, or extend the virtual disk volume.',
        fixAr: 'نظّف ملفات السجلات القديمة (IIS Logs) والملفات المؤقتة أو قم بتوسيع مساحة القرص فوراً.',
        metricBadge: `Disk ${srv.diskPct}%`,
        targetSection: 'servers',
      });
    }

    const stoppedAuto = srv.services.filter((s) => s.startupType === 'Automatic' && s.status === 'Stopped');
    for (const svc of stoppedAuto.slice(0, 2)) {
      issues.push({
        id: `DIAG-SRV-SVC-${srv.id}-${svc.name}`,
        severity: 'Critical',
        category: 'Server',
        categoryLabelEn: 'Windows Service',
        categoryLabelAr: 'خدمة نظام',
        timestamp: srv.lastCheck,
        assetName: srv.hostname,
        whatEn: `Automatic service "${svc.displayName || svc.name}" is Stopped.`,
        whatAr: `الخدمة التلقائية "${svc.displayName || svc.name}" متوقفة عن العمل.`,
        whereEn: `${srv.hostname} (${srv.ipAddress}) · Service: ${svc.name}`,
        whereAr: `${srv.hostname} (${srv.ipAddress}) · الخدمة: ${svc.name}`,
        fixEn: `Start service "${svc.name}" in Services.msc and check Windows Event Viewer Application/System logs for crash details.`,
        fixAr: `أعد تشغيل الخدمة "${svc.name}" وافحص سجل أحداث النظام لمعرفة سبب توقفها.`,
        metricBadge: 'Stopped',
        targetSection: 'servers',
      });
    }
  }

  // 4. Network & Backup Issues
  for (const net of params.networkDevices) {
    if (net.status === 'Offline' || net.packetLossPct >= 2) {
      issues.push({
        id: `DIAG-NET-${net.id}`,
        severity: net.status === 'Offline' ? 'Critical' : 'Warning',
        category: 'Network',
        categoryLabelEn: 'Network & Branches',
        categoryLabelAr: 'الشبكة والفروع',
        timestamp: net.lastCheck,
        assetName: net.name,
        whatEn:
          net.status === 'Offline'
            ? `Network device "${net.name}" (${net.site}) is Offline.`
            : `High packet loss (${net.packetLossPct}%) and ${net.latencyMs} ms latency on "${net.name}".`,
        whatAr:
          net.status === 'Offline'
            ? `انقطاع الاتصال بجهاز الشبكة "${net.name}" في فرع ${net.site}.`
            : `فقدان حزم مرتفع (${net.packetLossPct}%) وتأخير ${net.latencyMs} ms على "${net.name}".`,
        whereEn: `${net.site} · ${net.name} (${net.ipAddress})`,
        whereAr: `فرع ${net.site} · ${net.name} (${net.ipAddress})`,
        fixEn: 'Check ISP fiber/WAN uplink, SD-WAN failover status, and interface error counters in the Network tab.',
        fixAr: 'افحص خط المزود (ISP) وحالة التحويل التلقائي SD-WAN وعدادات الأخطاء على المنافذ في تبويب الشبكات.',
        metricBadge: net.status === 'Offline' ? 'Offline' : `${net.packetLossPct}% loss`,
        targetSection: 'network',
      });
    }
  }

  for (const bkp of params.backups) {
    if (bkp.status === 'Failed') {
      issues.push({
        id: `DIAG-BKP-${bkp.id}`,
        severity: 'Critical',
        category: 'Backup',
        categoryLabelEn: 'Backup / RMAN',
        categoryLabelAr: 'النسخ الاحتياطي',
        timestamp: bkp.lastSuccessfulRun,
        assetName: bkp.jobName,
        whatEn: `Backup job "${bkp.jobName}" failed on ${bkp.targetSystem}.`,
        whatAr: `فشل مهمة النسخ الاحتياطي "${bkp.jobName}" على ${bkp.targetSystem}.`,
        whereEn: `${bkp.targetSystem} · ${bkp.backupSource}`,
        whereAr: `${bkp.targetSystem} · ${bkp.backupSource}`,
        fixEn: 'Verify backup destination free space/permissions, check RMAN or backup logs, and trigger a manual backup verification.',
        fixAr: 'تأكد من توفر مساحة كافية في وجهة النسخ الاحتياطي وصلاحيات الكتابة، ثم أعد تشغيل المهمة وراقب السجل.',
        metricBadge: 'Failed',
        targetSection: 'backups',
      });
    }
  }

  // 5. Fallback / Additional open alerts not already covered
  for (const al of params.alerts) {
    if (al.status === 'Resolved') continue;
    const alreadyCovered = issues.some(
      (i) => i.assetName.toLowerCase() === al.assetName.toLowerCase() && i.whatEn.toLowerCase().includes(al.title.slice(0, 14).toLowerCase())
    );
    if (!alreadyCovered) {
      const targetMap: Record<AlertRecord['module'], DiagnosticIssue['targetSection']> = {
        'Windows Server': 'servers',
        'Oracle DB': 'oracle',
        'IIS & App': 'iis',
        Network: 'network',
        Backup: 'backups',
      };
      issues.push({
        id: `DIAG-AL-${al.id}`,
        severity: al.severity === 'Critical' || al.severity === 'High' ? 'Critical' : 'Warning',
        category:
          al.module === 'Oracle DB'
            ? 'Database'
            : al.module === 'IIS & App'
              ? 'Application'
              : al.module === 'Network'
                ? 'Network'
                : al.module === 'Backup'
                  ? 'Backup'
                  : 'Server',
        categoryLabelEn: al.module,
        categoryLabelAr:
          al.module === 'Oracle DB'
            ? 'قاعدة البيانات'
            : al.module === 'IIS & App'
              ? 'التطبيقات و IIS'
              : al.module === 'Network'
                ? 'الشبكة'
                : al.module === 'Backup'
                  ? 'النسخ الاحتياطي'
                  : 'الخادم',
        timestamp: al.timestamp,
        assetName: al.assetName,
        whatEn: al.title,
        whatAr: al.titleAr || al.title,
        whereEn: `${al.module} · ${al.assetName}`,
        whereAr: `${al.module} · ${al.assetName}`,
        fixEn: al.resolutionNotes || al.description || 'Review incident details in Alerts & Incidents and inspect the target module.',
        fixAr: al.resolutionNotes || al.descriptionAr || 'راجع تفاصيل البلاغ في تبويب التنبيهات وافحص الأصل المتأثر.',
        metricBadge: al.severity,
        targetSection: targetMap[al.module] || 'alerts',
      });
    }
  }

  // Critical first
  return issues.sort((a, b) => (a.severity === b.severity ? 0 : a.severity === 'Critical' ? -1 : 1));
}
