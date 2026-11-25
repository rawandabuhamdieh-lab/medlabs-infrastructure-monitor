import { useEffect, useMemo, useState } from 'react';
import {
  AlertTriangle,
  ArrowRight,
  Calendar,
  CheckCircle2,
  Clock,
  Database,
  Globe,
  HardDrive,
  Network,
  RotateCcw,
  Server,
  Wrench,
} from 'lucide-react';
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ReferenceArea,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { COPY } from '../data/i18n';
import {
  AlertRecord,
  ApiEndpointCheck,
  BackupJob,
  DailyReportRow,
  IisAppPool,
  IisSite,
  Language,
  ModuleSection,
  NetworkDevice,
  OracleDatabaseMetric,
  TimelineSample,
  WindowsServer,
} from '../types/infrastructure';
import { buildExecutiveDiagnostics, DiagnosticIssue } from '../utils/intelligence';
import { AssetStatusBadge, IncidentStatusText, SeverityText } from './StatusGlyph';

interface ExecutiveDashboardProps {
  servers: WindowsServer[];
  oracleDatabases: OracleDatabaseMetric[];
  iisSites: IisSite[];
  appPools: IisAppPool[];
  apiEndpoints: ApiEndpointCheck[];
  networkDevices: NetworkDevice[];
  backups: BackupJob[];
  alerts: AlertRecord[];
  reports: DailyReportRow[];
  timeline: TimelineSample[];
  lang: Language;
  onNavigate: (section: ModuleSection) => void;
}

type SeriesKey =
  | 'dbCpuMs'
  | 'dbIoMs'
  | 'dbLockMs'
  | 'appResponseMs'
  | 'networkLatencyMs'
  | 'serverLoadScore';

interface ChartPoint {
  idx: number;
  timestamp: string;
  date: string;
  time: string;
  minuteLabel: string;
  dbCpuMs: number;
  dbIoMs: number;
  dbLockMs: number;
  appResponseMs: number;
  networkLatencyMs: number;
  serverLoadScore: number;
  serverCpuPct: number;
  serverRamPct: number;
  oracleResponseMs: number;
  activeSessions: number;
  blockingSessions: number;
  activeAlerts: number;
  criticalAlerts: number;
  hasIssue: boolean;
  issueSummary?: string;
  issueSummaryAr?: string;
  topWaitEvent?: string;
  topObject?: string;
  affectedTarget?: string;
}

function todayIsoDate(): string {
  return new Intl.DateTimeFormat('en-CA', { timeZone: 'Asia/Amman', year: 'numeric', month: '2-digit', day: '2-digit' }).format(new Date());
}

function shiftIsoDate(isoDate: string, deltaDays: number): string {
  const d = new Date(`${isoDate}T00:00:00Z`);
  if (Number.isNaN(d.getTime())) return todayIsoDate();
  d.setUTCDate(d.getUTCDate() + deltaDays);
  return d.toISOString().slice(0, 10);
}

export function ExecutiveDashboard({
  servers,
  oracleDatabases,
  iisSites,
  appPools,
  apiEndpoints,
  networkDevices,
  backups,
  alerts,
  reports,
  timeline,
  lang,
  onNavigate,
}: ExecutiveDashboardProps) {
  const copy = COPY[lang];
  const isAr = lang === 'ar';

  const [selectedDate, setSelectedDate] = useState<string>(todayIsoDate());
  const [fetchedDaySamples, setFetchedDaySamples] = useState<TimelineSample[] | null>(null);
  const [availableDates, setAvailableDates] = useState<string[]>([]);
  const [loadingDate, setLoadingDate] = useState(false);

  const [timeScale, setTimeScale] = useState<'1m' | '5m' | '15m'>('1m');
  const [windowPreset, setWindowPreset] = useState<'all' | '1h' | '15m'>('all');
  const [selectionRange, setSelectionRange] = useState<[number, number] | null>(null);
  const [anchorIdx, setAnchorIdx] = useState<number | null>(null);
  const [hiddenSeries, setHiddenSeries] = useState<Record<SeriesKey, boolean>>({
    dbCpuMs: false,
    dbIoMs: false,
    dbLockMs: false,
    appResponseMs: false,
    networkLatencyMs: false,
    serverLoadScore: false,
  });
  const [panel3Tab, setPanel3Tab] = useState<'diagnosis' | 'sessions'>('diagnosis');

  // Query backend timeline for the selected retroactive date
  useEffect(() => {
    let cancelled = false;
    const loadDay = async () => {
      setLoadingDate(true);
      try {
        const res = await fetch(`/api/infrastructure/timeline?date=${encodeURIComponent(selectedDate)}`);
        if (res.ok && !cancelled) {
          const data = (await res.json()) as {
            availableDates?: string[];
            samples?: TimelineSample[];
          };
          if (Array.isArray(data.availableDates)) {
            setAvailableDates(data.availableDates);
          }
          if (Array.isArray(data.samples)) {
            setFetchedDaySamples(data.samples);
          }
        }
      } catch {
        // Fallback smoothly to in-memory snapshot timeline
      } finally {
        if (!cancelled) setLoadingDate(false);
      }
    };
    void loadDay();
    return () => {
      cancelled = true;
    };
  }, [selectedDate, timeline.length]);

  // Combine backend date query or snapshot timeline + fallback from reports/asset histories
  const rawDaySamples = useMemo<ChartPoint[]>(() => {
    const today = todayIsoDate();
    const fromBackend =
      fetchedDaySamples && fetchedDaySamples.length > 0
        ? fetchedDaySamples
        : timeline.filter((t) => t.date === selectedDate);

    if (fromBackend.length > 0) {
      return fromBackend.map((s, idx) => ({
        idx,
        timestamp: s.timestamp,
        date: s.date,
        time: s.time,
        minuteLabel: s.minuteLabel,
        dbCpuMs: s.dbCpuMs,
        dbIoMs: s.dbIoMs,
        dbLockMs: s.dbLockMs,
        appResponseMs: s.appResponseMs,
        networkLatencyMs: s.networkLatencyMs,
        serverLoadScore: s.serverLoadScore,
        serverCpuPct: s.serverCpuPct,
        serverRamPct: s.serverRamPct,
        oracleResponseMs: s.oracleResponseMs,
        activeSessions: s.activeSessions,
        blockingSessions: s.blockingSessions,
        activeAlerts: s.activeAlerts,
        criticalAlerts: s.criticalAlerts,
        hasIssue: s.hasIssue,
        issueSummary: s.issueSummary,
        issueSummaryAr: s.issueSummaryAr,
        topWaitEvent: s.topWaitEvent,
        topObject: s.topObject,
        affectedTarget: s.affectedTarget,
      }));
    }

    // Fallback for Today if reports or target histories exist before first new TimelineSample
    if (selectedDate === today) {
      if (reports.length > 0) {
        return reports.map((r, idx) => {
          const time = r.period.length === 5 ? `${r.period}:00` : r.period;
          const dbCpu = Math.round(r.avgOracleMs * 0.45);
          const dbIo = Math.max(0, r.avgOracleMs - dbCpu);
          return {
            idx,
            timestamp: `${today} ${time}`,
            date: today,
            time,
            minuteLabel: r.period.slice(0, 5),
            dbCpuMs: dbCpu,
            dbIoMs: dbIo,
            dbLockMs: r.incidentCount > 0 ? r.incidentCount * 12 : 0,
            appResponseMs: iisSites[0]?.responseTimeMs ?? 0,
            networkLatencyMs: networkDevices[0]?.latencyMs ?? 0,
            serverLoadScore: Math.round(r.avgCpuPct),
            serverCpuPct: r.avgCpuPct,
            serverRamPct: servers[0]?.ramPct ?? 0,
            oracleResponseMs: r.avgOracleMs,
            activeSessions: oracleDatabases[0]?.activeSessions ?? 0,
            blockingSessions: oracleDatabases[0]?.blockingSessions ?? 0,
            activeAlerts: r.incidentCount,
            criticalAlerts: r.incidentCount > 0 ? 1 : 0,
            hasIssue: r.incidentCount > 0 || r.totalDowntimeMin > 0,
            affectedTarget: oracleDatabases[0]?.serviceName || servers[0]?.hostname,
          };
        });
      }

      // Single live snapshot point if targets exist
      const hasAnyTarget =
        servers.length > 0 ||
        oracleDatabases.length > 0 ||
        iisSites.length > 0 ||
        networkDevices.length > 0;
      if (hasAnyTarget) {
        const nowStr = new Date().toLocaleString('sv-SE', { timeZone: 'Asia/Amman', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23' }).replace(',', '');
        const ora = oracleDatabases[0];
        const iis = iisSites[0];
        const net = networkDevices[0];
        const srv = servers[0];
        const openCount = alerts.filter((a) => a.status !== 'Resolved').length;
        return [
          {
            idx: 0,
            timestamp: nowStr,
            date: today,
            time: nowStr.slice(11, 19),
            minuteLabel: nowStr.slice(11, 16),
            dbCpuMs: ora ? Math.round(ora.responseTimeMs * 0.45) : 0,
            dbIoMs: ora ? Math.round(ora.responseTimeMs * 0.45) : 0,
            dbLockMs: ora ? ora.blockingSessions * 20 : 0,
            appResponseMs: iis?.responseTimeMs ?? 0,
            networkLatencyMs: net?.latencyMs ?? 0,
            serverLoadScore: Math.round(srv?.cpuPct ?? 0),
            serverCpuPct: srv?.cpuPct ?? 0,
            serverRamPct: srv?.ramPct ?? 0,
            oracleResponseMs: ora?.responseTimeMs ?? 0,
            activeSessions: ora?.activeSessions ?? 0,
            blockingSessions: ora?.blockingSessions ?? 0,
            activeAlerts: openCount,
            criticalAlerts: alerts.filter((a) => a.status !== 'Resolved' && a.severity === 'Critical').length,
            hasIssue: openCount > 0,
            affectedTarget: ora?.serviceName || srv?.hostname || iis?.name,
          },
        ];
      }
    }

    return [];
  }, [
    fetchedDaySamples,
    timeline,
    selectedDate,
    reports,
    servers,
    oracleDatabases,
    iisSites,
    networkDevices,
    alerts,
  ]);

  // Apply window preset (All / Last 1h / Last 15m) & bucket scale (1m / 5m / 15m)
  const chartData = useMemo<ChartPoint[]>(() => {
    let base = rawDaySamples;
    if (windowPreset === '15m' && base.length > 15) {
      base = base.slice(-15);
    } else if (windowPreset === '1h' && base.length > 60) {
      base = base.slice(-60);
    }

    const bucketSize = timeScale === '1m' ? 1 : timeScale === '5m' ? 5 : 15;
    if (bucketSize === 1) {
      return base.map((p, idx) => ({ ...p, idx }));
    }

    const bucketed: ChartPoint[] = [];
    for (let i = 0; i < base.length; i += bucketSize) {
      const slice = base.slice(i, i + bucketSize);
      const last = slice[slice.length - 1];
      const avg = (fn: (x: ChartPoint) => number) =>
        Math.round(slice.reduce((sum, x) => sum + fn(x), 0) / slice.length);
      bucketed.push({
        ...last,
        idx: bucketed.length,
        minuteLabel: `${slice[0].minuteLabel}-${last.minuteLabel}`,
        dbCpuMs: avg((x) => x.dbCpuMs),
        dbIoMs: avg((x) => x.dbIoMs),
        dbLockMs: avg((x) => x.dbLockMs),
        appResponseMs: avg((x) => x.appResponseMs),
        networkLatencyMs: avg((x) => x.networkLatencyMs),
        serverLoadScore: avg((x) => x.serverLoadScore),
        serverCpuPct: avg((x) => x.serverCpuPct),
        serverRamPct: avg((x) => x.serverRamPct),
        oracleResponseMs: avg((x) => x.oracleResponseMs),
        activeSessions: Math.max(...slice.map((x) => x.activeSessions)),
        blockingSessions: Math.max(...slice.map((x) => x.blockingSessions)),
        activeAlerts: Math.max(...slice.map((x) => x.activeAlerts)),
        criticalAlerts: Math.max(...slice.map((x) => x.criticalAlerts)),
        hasIssue: slice.some((x) => x.hasIssue),
        issueSummary: slice.find((x) => x.issueSummary)?.issueSummary,
        issueSummaryAr: slice.find((x) => x.issueSummaryAr)?.issueSummaryAr,
      });
    }
    return bucketed;
  }, [rawDaySamples, windowPreset, timeScale]);

  // Reset selection when day or scale changes
  useEffect(() => {
    setSelectionRange(null);
    setAnchorIdx(null);
  }, [selectedDate, timeScale, windowPreset]);

  const activeSlice = useMemo(() => {
    if (chartData.length === 0) return [];
    if (!selectionRange) return chartData;
    const [start, end] = selectionRange;
    const lo = Math.max(0, Math.min(start, end));
    const hi = Math.min(chartData.length - 1, Math.max(start, end));
    return chartData.slice(lo, hi + 1);
  }, [chartData, selectionRange]);

  const windowFromLabel =
    activeSlice[0]?.timestamp ?? `${selectedDate} 00:00:00`;
  const windowToLabel =
    activeSlice[activeSlice.length - 1]?.timestamp ?? `${selectedDate} 23:59:59`;

  // Retroactive alerts matching selected date
  const alertsForSelectedDate = useMemo(() => {
    return alerts.filter((a) => a.timestamp.startsWith(selectedDate));
  }, [alerts, selectedDate]);

  // Diagnostics Engine (Clear What / Where / Suggested Fix)
  const diagnostics = useMemo<DiagnosticIssue[]>(() => {
    return buildExecutiveDiagnostics({
      servers,
      oracleDatabases,
      iisSites,
      appPools,
      networkDevices,
      backups,
      alerts,
    });
  }, [servers, oracleDatabases, iisSites, appPools, networkDevices, backups, alerts]);

  const criticalIssuesCount = diagnostics.filter((d) => d.severity === 'Critical').length;
  const warningIssuesCount = diagnostics.filter((d) => d.severity === 'Warning').length;

  // Core KPI Summaries (DB, Application, Servers, Network & Backups)
  const primaryOracle = oracleDatabases[0] ?? null;
  const oracleProblem =
    oracleDatabases.some((d) => d.status === 'Critical' || d.status === 'Offline' || d.blockingSessions > 0)
      ? 'Critical'
      : oracleDatabases.some((d) => d.status === 'Warning' || d.responseTimeMs >= 75)
        ? 'Warning'
        : oracleDatabases.length > 0
          ? 'Online'
          : null;

  const iisOnlineCount = iisSites.filter((i) => i.status === 'Online').length;
  const iisProblem =
    iisSites.some((i) => i.status === 'Critical' || i.status === 'Offline') ||
    appPools.some((p) => p.state === 'Stopped')
      ? 'Critical'
      : iisSites.some((i) => i.status === 'Warning')
        ? 'Warning'
        : iisSites.length > 0
          ? 'Online'
          : null;
  const avgIisRtt =
    iisSites.length > 0
      ? Math.round(iisSites.reduce((a, s) => a + s.responseTimeMs, 0) / iisSites.length)
      : 0;

  const onlineServers = servers.filter((s) => s.status === 'Online').length;
  const serverProblem =
    servers.some((s) => s.status === 'Critical' || s.status === 'Offline')
      ? 'Critical'
      : servers.some((s) => s.status === 'Warning')
        ? 'Warning'
        : servers.length > 0
          ? 'Online'
          : null;
  const avgServerCpu =
    servers.length > 0
      ? Math.round(servers.reduce((a, s) => a + s.cpuPct, 0) / servers.length)
      : 0;
  const avgServerRam =
    servers.length > 0
      ? Math.round(servers.reduce((a, s) => a + s.ramPct, 0) / servers.length)
      : 0;

  const netOnline = networkDevices.filter((n) => n.status !== 'Offline').length;
  const failedBackups = backups.filter((b) => b.status === 'Failed').length;
  const netProblem =
    networkDevices.some((n) => n.status === 'Offline') || failedBackups > 0
      ? 'Critical'
      : networkDevices.some((n) => n.status === 'Warning' || n.packetLossPct > 0.5)
        ? 'Warning'
        : networkDevices.length > 0 || backups.length > 0
          ? 'Online'
          : null;
  const avgNetLatency =
    networkDevices.length > 0
      ? Math.round(networkDevices.reduce((a, n) => a + n.latencyMs, 0) / networkDevices.length)
      : 0;

  // Legend Series Configuration (matching MyOra Wait Class Legend style)
  const seriesConfig: {
    key: SeriesKey;
    labelEn: string;
    labelAr: string;
    color: string;
    unit: string;
  }[] = [
    { key: 'dbCpuMs', labelEn: 'DB CPU & Query', labelAr: 'معالج قاعدة البيانات', color: '#10b981', unit: 'ms' },
    { key: 'dbIoMs', labelEn: 'DB User I/O', labelAr: 'قراءة وكتابة الأقراص DB', color: '#8b5cf6', unit: 'ms' },
    { key: 'dbLockMs', labelEn: 'DB Locks & Waits', labelAr: 'الأقفال والانتظار DB', color: '#f59e0b', unit: 'ms' },
    { key: 'appResponseMs', labelEn: 'App / IIS Response', labelAr: 'استجابة التطبيقات IIS', color: '#3b82f6', unit: 'ms' },
    { key: 'networkLatencyMs', labelEn: 'Network Latency', labelAr: 'تأخير الشبكة', color: '#06b6d4', unit: 'ms' },
    { key: 'serverLoadScore', labelEn: 'Server CPU Load', labelAr: 'حمل معالج الخوادم', color: '#e11d48', unit: '%' },
  ];

  const legendTotals = useMemo(() => {
    const src = activeSlice;
    const avgVal = (key: SeriesKey) =>
      src.length > 0 ? Math.round(src.reduce((s, p) => s + p[key], 0) / src.length) : 0;
    return {
      dbCpuMs: avgVal('dbCpuMs'),
      dbIoMs: avgVal('dbIoMs'),
      dbLockMs: avgVal('dbLockMs'),
      appResponseMs: avgVal('appResponseMs'),
      networkLatencyMs: avgVal('networkLatencyMs'),
      serverLoadScore: avgVal('serverLoadScore'),
    };
  }, [activeSlice]);

  // Panel 1: Events & Bottlenecks (from Oracle wait events + Diagnostics + Alerts)
  const waitAndEventRows = useMemo(() => {
    const rows: {
      name: string;
      category: string;
      pct: number;
      detail: string;
      severity: 'Critical' | 'Warning' | 'Normal';
    }[] = [];

    const oraWaits = oracleDatabases.flatMap((d) => d.topWaitEvents ?? []);
    const totalWaitMs = Math.max(
      1,
      oraWaits.reduce((a, w) => a + w.timeWaitedMs, 0)
    );
    for (const w of oraWaits.slice(0, 5)) {
      const pct = Number(((w.timeWaitedMs / totalWaitMs) * 100).toFixed(1));
      rows.push({
        name: w.event,
        category: isAr ? 'قاعدة البيانات' : 'Oracle Wait',
        pct,
        detail: `${w.timeWaitedMs} ms (${w.totalWaits} waits)`,
        severity: pct >= 40 ? 'Warning' : 'Normal',
      });
    }

    for (const diag of diagnostics.slice(0, 5)) {
      rows.push({
        name: isAr ? diag.whatAr : diag.whatEn,
        category: isAr ? diag.categoryLabelAr : diag.categoryLabelEn,
        pct: diag.severity === 'Critical' ? 100 : 65,
        detail: diag.metricBadge,
        severity: diag.severity,
      });
    }

    return rows.slice(0, 8);
  }, [oracleDatabases, diagnostics, isAr]);

  // Panel 2: Exact Location / Objects (Tablespaces, IIS Sites, Servers, Network)
  const locationObjects = useMemo(() => {
    const objs: {
      owner: string;
      objectName: string;
      objectType: string;
      metricLabel: string;
      valuePct: number;
      displayValue: string;
      status: 'Critical' | 'Warning' | 'Normal';
      section: ModuleSection;
    }[] = [];

    for (const db of oracleDatabases) {
      for (const ts of db.tablespaces.slice(0, 4)) {
        objs.push({
          owner: db.serviceName,
          objectName: ts.name,
          objectType: 'TABLESPACE',
          metricLabel: isAr ? 'نسبة الامتلاء' : 'Space Used',
          valuePct: Math.min(100, ts.usedPct),
          displayValue: `${ts.usedPct}% (${ts.usedGb}/${ts.maxGb} GB)`,
          status: ts.usedPct >= 92 ? 'Critical' : ts.usedPct >= 80 ? 'Warning' : 'Normal',
          section: 'oracle',
        });
      }
    }

    for (const site of iisSites.slice(0, 4)) {
      objs.push({
        owner: site.serverHostname,
        objectName: `${site.name} (${site.appPoolName})`,
        objectType: 'IIS APP',
        metricLabel: isAr ? 'زمن الاستجابة' : 'HTTP RTT',
        valuePct: Math.min(100, Math.round((site.responseTimeMs / 1500) * 100)),
        displayValue: `${site.httpStatus || 'ERR'} · ${site.responseTimeMs} ms`,
        status:
          site.status === 'Critical' || site.status === 'Offline'
            ? 'Critical'
            : site.status === 'Warning'
              ? 'Warning'
              : 'Normal',
        section: 'iis',
      });
    }

    for (const srv of servers.slice(0, 4)) {
      const topMetric = Math.max(srv.cpuPct, srv.ramPct, srv.diskPct);
      objs.push({
        owner: srv.site,
        objectName: `${srv.hostname} (${srv.ipAddress})`,
        objectType: 'SERVER',
        metricLabel: 'CPU / RAM / Disk',
        valuePct: Math.min(100, Math.round(topMetric)),
        displayValue: `${srv.cpuPct}% / ${srv.ramPct}% / ${srv.diskPct}%`,
        status:
          srv.status === 'Critical' || srv.status === 'Offline'
            ? 'Critical'
            : srv.status === 'Warning'
              ? 'Warning'
              : 'Normal',
        section: 'servers',
      });
    }

    for (const net of networkDevices.slice(0, 3)) {
      objs.push({
        owner: net.site,
        objectName: `${net.name} (${net.ipAddress})`,
        objectType: 'NETWORK',
        metricLabel: isAr ? 'التأخير / الفقد' : 'Latency / Loss',
        valuePct: Math.min(100, Math.round(net.packetLossPct * 20 + net.latencyMs / 3)),
        displayValue: `${net.latencyMs} ms · ${net.packetLossPct}% loss`,
        status:
          net.status === 'Offline'
            ? 'Critical'
            : net.packetLossPct >= 1 || net.status === 'Warning'
              ? 'Warning'
              : 'Normal',
        section: 'network',
      });
    }

    return objs.sort((a, b) => {
      const rank = { Critical: 0, Warning: 1, Normal: 2 };
      return rank[a.status] - rank[b.status] || b.valuePct - a.valuePct;
    });
  }, [oracleDatabases, iisSites, servers, networkDevices, isAr]);

  const activeDbSessions = useMemo(() => {
    return oracleDatabases.flatMap((db) =>
      db.longRunningQueries.map((q) => ({
        dbName: db.serviceName,
        ...q,
      }))
    );
  }, [oracleDatabases]);

  const handleBarClick = (clickedIdx: number) => {
    if (anchorIdx === null) {
      setAnchorIdx(clickedIdx);
      setSelectionRange([clickedIdx, clickedIdx]);
    } else {
      setSelectionRange([Math.min(anchorIdx, clickedIdx), Math.max(anchorIdx, clickedIdx)]);
      setAnchorIdx(null);
    }
  };

  const toggleSeries = (key: SeriesKey) => {
    setHiddenSeries((prev) => ({ ...prev, [key]: !prev[key] }));
  };

  const quickDates = useMemo(() => {
    const today = todayIsoDate();
    const yesterday = shiftIsoDate(today, -1);
    const merged = Array.from(new Set([today, yesterday, ...availableDates])).sort().reverse();
    return merged.slice(0, 6);
  }, [availableDates]);

  const cardStatusBorder = (status: 'Online' | 'Warning' | 'Critical' | null) => {
    if (status === 'Critical') {
      return 'border-rose-300 dark:border-rose-800 bg-rose-50/40 dark:bg-rose-950/20';
    }
    if (status === 'Warning') {
      return 'border-amber-300 dark:border-amber-800 bg-amber-50/40 dark:bg-amber-950/20';
    }
    return 'border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900';
  };

  return (
    <div className="space-y-5">
      {/* 1. Executive Header + Retroactive Date & Time Range Toolbar */}
      <div className="flex flex-col xl:flex-row xl:items-center xl:justify-between gap-4 pb-4 border-b border-slate-200 dark:border-slate-800">
        <div>
          <h1 className="text-xl font-semibold text-slate-900 dark:text-slate-100 text-balance">
            {isAr
              ? 'لوحة القيادة التنفيذية · مراقبة الأداء وتحليل الأعطال'
              : 'Executive Infrastructure Dashboard · Performance & Wait Analysis'}
          </h1>
          <div className="mt-1 flex flex-wrap items-center gap-2 text-xs text-slate-500 dark:text-slate-400">
            <span>
              {isAr
                ? 'مراقبة قواعد البيانات والتطبيقات والخوادم بدقة الساعة والدقيقة مع الرجوع لأي يوم سابق'
                : 'Minute-by-minute visibility across Oracle DB, Applications/IIS, Servers, and Network'}
            </span>
            <span aria-hidden="true">·</span>
            <span className="font-mono tabular-nums text-slate-700 dark:text-slate-300">
              {isAr ? `من ${windowFromLabel} إلى ${windowToLabel}` : `From ${windowFromLabel} To ${windowToLabel}`}
            </span>
          </div>
        </div>

        {/* Date Picker + Time Scale Controls */}
        <div className="flex flex-wrap items-center gap-2">
          <div className="inline-flex items-center gap-2 px-2.5 py-1.5 rounded-md border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 text-xs">
            <Calendar className="w-3.5 h-3.5 text-slate-500 dark:text-slate-400 shrink-0" />
            <label htmlFor="exec-retro-date" className="text-slate-500 dark:text-slate-400 whitespace-nowrap">
              {isAr ? 'التاريخ:' : 'Date:'}
            </label>
            <input
              id="exec-retro-date"
              type="date"
              value={selectedDate}
              max={todayIsoDate()}
              onChange={(e) => {
                if (e.target.value) setSelectedDate(e.target.value);
              }}
              className="bg-transparent font-mono tabular-nums text-slate-900 dark:text-slate-100 focus:outline-none cursor-pointer"
            />
          </div>

          <div className="inline-flex items-center p-0.5 rounded-md bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-xs">
            {(['all', '1h', '15m'] as const).map((preset) => (
              <button
                key={preset}
                type="button"
                onClick={() => setWindowPreset(preset)}
                className={`px-2.5 py-1 rounded font-medium whitespace-nowrap shrink-0 transition-colors cursor-pointer ${
                  windowPreset === preset
                    ? 'bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100 shadow-xs'
                    : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
                }`}
              >
                {preset === 'all'
                  ? isAr
                    ? 'اليوم كامل'
                    : 'Full Day'
                  : preset === '1h'
                    ? isAr
                      ? 'آخر ساعة'
                      : 'Last 1h'
                    : isAr
                      ? 'آخر 15د'
                      : 'Last 15m'}
              </button>
            ))}
          </div>

          <div className="inline-flex items-center p-0.5 rounded-md bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-xs">
            {(['1m', '5m', '15m'] as const).map((scale) => (
              <button
                key={scale}
                type="button"
                onClick={() => setTimeScale(scale)}
                className={`px-2.5 py-1 rounded font-mono font-medium whitespace-nowrap shrink-0 transition-colors cursor-pointer ${
                  timeScale === scale
                    ? 'bg-white dark:bg-slate-900 text-blue-700 dark:text-blue-400 shadow-xs'
                    : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
                }`}
              >
                {scale}
              </button>
            ))}
          </div>

          {selectionRange && (
            <button
              type="button"
              onClick={() => {
                setSelectionRange(null);
                setAnchorIdx(null);
              }}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md border border-blue-200 dark:border-blue-800 bg-blue-50 dark:bg-blue-950/40 text-xs font-medium text-blue-700 dark:text-blue-300 hover:bg-blue-100 dark:hover:bg-blue-900/50 whitespace-nowrap shrink-0 cursor-pointer"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              <span>{isAr ? 'إعادة ضبط التحديد' : 'Reset Selection'}</span>
            </button>
          )}
        </div>
      </div>

      {/* Quick Retroactive Date Switcher Bar */}
      <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-slate-500 dark:text-slate-400">
            {isAr ? 'أيام سابقة متاحة:' : 'Quick Dates:'}
          </span>
          {quickDates.map((d) => {
            const isToday = d === todayIsoDate();
            const isYesterday = d === shiftIsoDate(todayIsoDate(), -1);
            const active = selectedDate === d;
            return (
              <button
                key={d}
                type="button"
                onClick={() => setSelectedDate(d)}
                className={`px-2.5 py-1 rounded-md border font-mono tabular-nums whitespace-nowrap shrink-0 transition-colors cursor-pointer ${
                  active
                    ? 'bg-blue-600 border-blue-600 text-white font-medium'
                    : 'bg-white dark:bg-slate-900 border-slate-200 dark:border-slate-800 text-slate-700 dark:text-slate-300 hover:border-blue-400'
                }`}
              >
                {isToday ? (isAr ? `اليوم (${d})` : `Today (${d})`) : isYesterday ? (isAr ? `أمس (${d})` : `Yesterday (${d})`) : d}
              </button>
            );
          })}
        </div>
        <div className="font-mono tabular-nums text-slate-500 dark:text-slate-400">
          {loadingDate
            ? isAr
              ? 'جارٍ تحميل السجل...'
              : 'Loading date history...'
            : `${chartData.length} ${isAr ? 'نقطة قياس' : 'samples'}`}
        </div>
      </div>

      {/* 2. Colored Issue & Root-Cause Alert Banner */}
      {diagnostics.length > 0 ? (
        <section
          className={`rounded-lg border p-4 ${
            criticalIssuesCount > 0
              ? 'border-rose-300 dark:border-rose-800 bg-rose-50 dark:bg-rose-950/30'
              : 'border-amber-300 dark:border-amber-800 bg-amber-50 dark:bg-amber-950/30'
          }`}
        >
          <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-3">
            <div className="flex items-start gap-3">
              <AlertTriangle
                className={`w-5 h-5 shrink-0 mt-0.5 ${
                  criticalIssuesCount > 0
                    ? 'text-rose-600 dark:text-rose-400'
                    : 'text-amber-600 dark:text-amber-400'
                }`}
              />
              <div className="space-y-1">
                <div className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                  {criticalIssuesCount > 0
                    ? isAr
                      ? `تنبيه حرج: تم رصد ${criticalIssuesCount} مشكلة حرجة و ${warningIssuesCount} تحذير`
                      : `Critical Alert: ${criticalIssuesCount} critical issue(s) and ${warningIssuesCount} warning(s) detected`
                    : isAr
                      ? `تنبيه تحذيري: تم رصد ${warningIssuesCount} ملاحظة تحتاج متابعة`
                      : `Warning Alert: ${warningIssuesCount} warning(s) require attention`}
                </div>
                <div className="text-xs text-slate-700 dark:text-slate-300">
                  <span className="font-semibold">
                    {isAr ? 'أهم مشكلة حالياً: ' : 'Top Issue: '}
                  </span>
                  <span>{isAr ? diagnostics[0].whatAr : diagnostics[0].whatEn}</span>
                  <span className="mx-1.5" aria-hidden="true">·</span>
                  <span className="font-mono text-slate-600 dark:text-slate-400">
                    {isAr ? diagnostics[0].whereAr : diagnostics[0].whereEn}
                  </span>
                </div>
                <div className="text-xs text-emerald-800 dark:text-emerald-300">
                  <span className="font-semibold">
                    {isAr ? 'اقتراح الحل: ' : 'Suggested Fix: '}
                  </span>
                  <span>{isAr ? diagnostics[0].fixAr : diagnostics[0].fixEn}</span>
                </div>
              </div>
            </div>

            <div className="flex items-center gap-2 shrink-0">
              <button
                type="button"
                onClick={() => {
                  setPanel3Tab('diagnosis');
                  document.getElementById('exec-drilldown-section')?.scrollIntoView({ behavior: 'smooth' });
                }}
                className="px-3.5 py-2 rounded-md bg-slate-900 dark:bg-slate-100 text-white dark:text-slate-900 text-xs font-medium hover:opacity-90 whitespace-nowrap shrink-0 cursor-pointer"
              >
                {isAr ? 'عرض كل التفاصيل والحلول' : 'View All Fixes'}
              </button>
              <button
                type="button"
                onClick={() => onNavigate(diagnostics[0].targetSection)}
                className="inline-flex items-center gap-1 px-3 py-2 rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-800 dark:text-slate-200 text-xs font-medium hover:bg-slate-50 dark:hover:bg-slate-800 whitespace-nowrap shrink-0 cursor-pointer"
              >
                <span>{isAr ? 'فتح القسم المتأثر' : 'Open Affected Tab'}</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        </section>
      ) : (
        (servers.length > 0 || oracleDatabases.length > 0 || iisSites.length > 0 || networkDevices.length > 0) && (
          <section className="rounded-lg border border-emerald-200 dark:border-emerald-900 bg-emerald-50/60 dark:bg-emerald-950/20 px-4 py-3 flex items-center justify-between gap-3">
            <div className="flex items-center gap-2.5 text-xs text-emerald-900 dark:text-emerald-200">
              <CheckCircle2 className="w-4 h-4 text-emerald-600 dark:text-emerald-400 shrink-0" />
              <span className="font-medium">
                {isAr
                  ? 'جميع قواعد البيانات والتطبيقات والخوادم المراقبة تعمل ضمن الحدود الطبيعية بدون تنبيهات نشطة.'
                  : 'All monitored databases, applications, servers, and network links are operating within normal thresholds.'}
              </span>
            </div>
            <span className="font-mono text-[11px] text-emerald-700 dark:text-emerald-400 whitespace-nowrap">
              {isAr ? 'سليم ●' : 'Nominal ●'}
            </span>
          </section>
        )
      )}

      {/* 3. Clear Core Infrastructure Cards (Database, Applications, Servers, Network & Backups) */}
      <section className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
        {/* Database Card */}
        <button
          type="button"
          onClick={() => onNavigate('oracle')}
          className={`text-start rounded-lg border p-4 transition-colors hover:border-blue-500 cursor-pointer ${cardStatusBorder(oracleProblem)}`}
        >
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-2 text-xs font-medium text-slate-600 dark:text-slate-300">
              <Database className="w-4 h-4 text-emerald-600 dark:text-emerald-400 shrink-0" />
              <span>{isAr ? 'أداء قاعدة البيانات (Oracle)' : 'Database Performance'}</span>
            </div>
            {oracleProblem ? (
              <AssetStatusBadge status={oracleProblem} label={copy.status[oracleProblem]} />
            ) : (
              <span className="text-[11px] text-slate-400">{isAr ? 'غير مربوط' : 'Not Connected'}</span>
            )}
          </div>
          <div className="mt-2.5 flex items-baseline justify-between gap-2">
            <div className="text-xl font-semibold font-mono tabular-nums text-slate-900 dark:text-slate-100">
              {primaryOracle ? `${primaryOracle.responseTimeMs} ms` : '—'}
            </div>
            <div className="text-xs font-mono tabular-nums text-slate-500 dark:text-slate-400 truncate">
              {primaryOracle ? primaryOracle.serviceName : isAr ? 'أضف قاعدة بيانات' : 'Configure Oracle'}
            </div>
          </div>
          <div className="mt-2 flex items-center gap-2 text-[11px] font-mono tabular-nums text-slate-600 dark:text-slate-400">
            <span>
              {isAr ? 'جلسات:' : 'Sessions:'} {primaryOracle?.activeSessions ?? 0}
            </span>
            <span aria-hidden="true">·</span>
            <span className={(primaryOracle?.blockingSessions ?? 0) > 0 ? 'text-rose-600 dark:text-rose-400 font-semibold' : ''}>
              {isAr ? 'أقفال:' : 'Locks:'} {primaryOracle?.blockingSessions ?? 0}
            </span>
            <span aria-hidden="true">·</span>
            <span>SGA {primaryOracle?.sgaUsedPct ?? 0}%</span>
          </div>
        </button>

        {/* Applications & IIS Card */}
        <button
          type="button"
          onClick={() => onNavigate('iis')}
          className={`text-start rounded-lg border p-4 transition-colors hover:border-blue-500 cursor-pointer ${cardStatusBorder(iisProblem)}`}
        >
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-2 text-xs font-medium text-slate-600 dark:text-slate-300">
              <Globe className="w-4 h-4 text-blue-600 dark:text-blue-400 shrink-0" />
              <span>{isAr ? 'أداء التطبيقات (IIS / API)' : 'Application & IIS Health'}</span>
            </div>
            {iisProblem ? (
              <AssetStatusBadge status={iisProblem} label={copy.status[iisProblem]} />
            ) : (
              <span className="text-[11px] text-slate-400">{isAr ? 'لا تطبيقات' : 'No Apps'}</span>
            )}
          </div>
          <div className="mt-2.5 flex items-baseline justify-between gap-2">
            <div className="text-xl font-semibold font-mono tabular-nums text-slate-900 dark:text-slate-100">
              {iisSites.length > 0 ? `${avgIisRtt} ms` : '—'}
            </div>
            <div className="text-xs font-mono tabular-nums text-slate-500 dark:text-slate-400">
              {iisOnlineCount}/{iisSites.length} {isAr ? 'موقع متصل' : 'sites online'}
            </div>
          </div>
          <div className="mt-2 flex items-center gap-2 text-[11px] font-mono tabular-nums text-slate-600 dark:text-slate-400">
            <span>AppPools: {appPools.length}</span>
            <span aria-hidden="true">·</span>
            <span>APIs: {apiEndpoints.length}</span>
          </div>
        </button>

        {/* Servers Card */}
        <button
          type="button"
          onClick={() => onNavigate('servers')}
          className={`text-start rounded-lg border p-4 transition-colors hover:border-blue-500 cursor-pointer ${cardStatusBorder(serverProblem)}`}
        >
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-2 text-xs font-medium text-slate-600 dark:text-slate-300">
              <Server className="w-4 h-4 text-violet-600 dark:text-violet-400 shrink-0" />
              <span>{isAr ? 'صحة الخوادم (Servers)' : 'Server Infrastructure'}</span>
            </div>
            {serverProblem ? (
              <AssetStatusBadge status={serverProblem} label={copy.status[serverProblem]} />
            ) : (
              <span className="text-[11px] text-slate-400">{isAr ? 'لا خوادم' : 'No Servers'}</span>
            )}
          </div>
          <div className="mt-2.5 flex items-baseline justify-between gap-2">
            <div className="text-xl font-semibold font-mono tabular-nums text-slate-900 dark:text-slate-100">
              {servers.length > 0 ? `CPU ${avgServerCpu}%` : '—'}
            </div>
            <div className="text-xs font-mono tabular-nums text-slate-500 dark:text-slate-400">
              {onlineServers}/{servers.length} {isAr ? 'متصل' : 'online'}
            </div>
          </div>
          <div className="mt-2 flex items-center gap-2 text-[11px] font-mono tabular-nums text-slate-600 dark:text-slate-400">
            <span>RAM {avgServerRam}%</span>
            <span aria-hidden="true">·</span>
            <span>
              {isAr ? 'تنبيهات:' : 'Alerts:'} {alerts.filter((a) => a.status !== 'Resolved').length}
            </span>
          </div>
        </button>

        {/* Network & Backups Card */}
        <button
          type="button"
          onClick={() => onNavigate('network')}
          className={`text-start rounded-lg border p-4 transition-colors hover:border-blue-500 cursor-pointer ${cardStatusBorder(netProblem)}`}
        >
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-2 text-xs font-medium text-slate-600 dark:text-slate-300">
              <Network className="w-4 h-4 text-cyan-600 dark:text-cyan-400 shrink-0" />
              <span>{isAr ? 'الشبكة والنسخ الاحتياطي' : 'Network & Backups'}</span>
            </div>
            {netProblem ? (
              <AssetStatusBadge status={netProblem} label={copy.status[netProblem]} />
            ) : (
              <span className="text-[11px] text-slate-400">{isAr ? 'لا بيانات' : 'No Data'}</span>
            )}
          </div>
          <div className="mt-2.5 flex items-baseline justify-between gap-2">
            <div className="text-xl font-semibold font-mono tabular-nums text-slate-900 dark:text-slate-100">
              {networkDevices.length > 0 ? `${avgNetLatency} ms` : '—'}
            </div>
            <div className="text-xs font-mono tabular-nums text-slate-500 dark:text-slate-400">
              {netOnline}/{networkDevices.length} {isAr ? 'فرع/جهاز' : 'devices'}
            </div>
          </div>
          <div className="mt-2 flex items-center gap-2 text-[11px] font-mono tabular-nums text-slate-600 dark:text-slate-400">
            <HardDrive className="w-3 h-3 shrink-0" />
            <span>
              {isAr ? 'النسخ الاحتياطي:' : 'Backups:'} {backups.length - failedBackups}/{backups.length}
            </span>
            {failedBackups > 0 && (
              <span className="text-rose-600 dark:text-rose-400 font-semibold">
                ({failedBackups} {isAr ? 'فشل' : 'failed'})
              </span>
            )}
          </div>
        </button>
      </section>

      {/* 4. MyOra-Style Stacked Time-Series Chart + Right-Side Class Legend */}
      <section className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-5">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 pb-4 border-b border-slate-100 dark:border-slate-800">
          <div>
            <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100 flex items-center gap-2">
              <Clock className="w-4 h-4 text-blue-600 dark:text-blue-400" />
              <span>
                {isAr
                  ? 'مخطط المراقبة الزمني (بالساعة والدقيقة) — اضغط على أي عمود لتحديد الفترة'
                  : 'Time-Series Performance & Wait Breakdown (Hour & Minute)'}
              </span>
            </h2>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5 font-mono tabular-nums">
              {isAr
                ? `النطاق المعروض: من ${windowFromLabel} إلى ${windowToLabel}`
                : `Selected Window: From ${windowFromLabel} To ${windowToLabel}`}
              {anchorIdx !== null && (
                <span className="ms-2 text-blue-600 dark:text-blue-400 font-sans font-medium">
                  {isAr ? '· اختر نقطة النهاية لتحديد نطاق زمني' : '· Click a second bar to complete range'}
                </span>
              )}
            </p>
          </div>
          <button
            type="button"
            onClick={() => onNavigate('analytics')}
            className="text-xs font-medium text-blue-600 dark:text-blue-400 hover:underline whitespace-nowrap shrink-0 cursor-pointer"
          >
            {isAr ? 'التحليلات الإحصائية الكاملة' : 'Full Analytics'}
          </button>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 mt-4 items-start">
          {/* Left 9 Columns: Stacked Bar Chart */}
          <div className="lg:col-span-9">
            {chartData.length === 0 ? (
              <div className="h-72 flex flex-col items-center justify-center text-center px-6 border border-dashed border-slate-200 dark:border-slate-800 rounded-md bg-slate-50/50 dark:bg-slate-950/40">
                <p className="text-xs text-slate-600 dark:text-slate-400 max-w-lg leading-relaxed">
                  {selectedDate === todayIsoDate()
                    ? isAr
                      ? 'لا توجد قراءات مسجلة لهذا اليوم بعد. بمجرد ربط قاعدة بيانات Oracle أو تطبيق IIS أو خادم من التبويبات أدناه، سيبدأ النظام تلقائياً برسم الأعمدة الزمنية دقيقة بدقيقة.'
                      : 'No telemetry samples recorded for this date yet. Connect an Oracle Database, IIS site, or Server to begin minute-by-minute stacked wait & performance tracking.'
                    : isAr
                      ? `لا توجد سجلات مراقبة محفوظة لتاريخ ${selectedDate}. اختر تاريخاً آخر من الشريط أعلاه.`
                      : `No recorded telemetry found for ${selectedDate}. Choose another date above.`}
                </p>
                <div className="mt-4 flex flex-wrap items-center justify-center gap-2">
                  <button
                    type="button"
                    onClick={() => onNavigate('oracle')}
                    className="px-3.5 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-md text-xs font-medium whitespace-nowrap cursor-pointer"
                  >
                    {isAr ? 'ربط قاعدة Oracle' : 'Connect Oracle DB'}
                  </button>
                  <button
                    type="button"
                    onClick={() => onNavigate('iis')}
                    className="px-3.5 py-2 border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-200 rounded-md text-xs font-medium hover:bg-slate-50 dark:hover:bg-slate-800 whitespace-nowrap cursor-pointer"
                  >
                    {isAr ? 'ربط تطبيق / موقع IIS' : 'Connect IIS / App'}
                  </button>
                  <button
                    type="button"
                    onClick={() => onNavigate('servers')}
                    className="px-3.5 py-2 border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-200 rounded-md text-xs font-medium hover:bg-slate-50 dark:hover:bg-slate-800 whitespace-nowrap cursor-pointer"
                  >
                    {isAr ? 'ربط خادم Windows / Linux' : 'Connect Server'}
                  </button>
                </div>
              </div>
            ) : (
              <div className="h-72 w-full" dir="ltr">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart
                    data={chartData}
                    margin={{ top: 10, right: 12, left: -12, bottom: 18 }}
                    onClick={(state) => {
                      if (state && typeof state.activeTooltipIndex === 'number') {
                        handleBarClick(state.activeTooltipIndex);
                      }
                    }}
                  >
                    <CartesianGrid strokeDasharray="3 3" stroke="#cbd5e1" strokeOpacity={0.35} vertical={false} />
                    <XAxis
                      dataKey="minuteLabel"
                      tick={{ fontSize: 10, fill: '#64748b' }}
                      angle={-25}
                      textAnchor="end"
                      height={42}
                    />
                    <YAxis tick={{ fontSize: 11, fill: '#64748b' }} />
                    <Tooltip
                      cursor={{ fill: 'rgba(37, 99, 235, 0.08)' }}
                      content={({ active, payload }) => {
                        if (!active || !payload || payload.length === 0) return null;
                        const pt = payload[0].payload as ChartPoint;
                        return (
                          <div className="rounded-md bg-slate-900 border border-slate-700 p-3 text-xs text-slate-100 shadow-md space-y-1.5 min-w-[230px]">
                            <div className="font-mono font-semibold text-blue-300 border-b border-slate-800 pb-1">
                              {pt.timestamp}
                            </div>
                            <div className="grid grid-cols-2 gap-x-4 gap-y-1 font-mono tabular-nums text-[11px]">
                              <span className="text-emerald-400">DB CPU:</span>
                              <span className="text-end">{pt.dbCpuMs} ms</span>
                              <span className="text-violet-400">DB I/O:</span>
                              <span className="text-end">{pt.dbIoMs} ms</span>
                              <span className="text-amber-400">DB Locks:</span>
                              <span className="text-end">{pt.dbLockMs} ms</span>
                              <span className="text-blue-400">App / IIS:</span>
                              <span className="text-end">{pt.appResponseMs} ms</span>
                              <span className="text-cyan-400">Network:</span>
                              <span className="text-end">{pt.networkLatencyMs} ms</span>
                              <span className="text-rose-400">Server CPU:</span>
                              <span className="text-end">{pt.serverCpuPct}%</span>
                            </div>
                            {pt.hasIssue && (
                              <div className="pt-1 border-t border-slate-800 text-[11px] text-rose-300 font-medium">
                                {isAr
                                  ? pt.issueSummaryAr || 'تم رصد مشكلة أو تجاوز عتبة في هذه الدقيقة'
                                  : pt.issueSummary || 'Issue / threshold breach recorded at this minute'}
                              </div>
                            )}
                          </div>
                        );
                      }}
                    />

                    {selectionRange && chartData[selectionRange[0]] && chartData[selectionRange[1]] && (
                      <ReferenceArea
                        x1={chartData[selectionRange[0]].minuteLabel}
                        x2={chartData[selectionRange[1]].minuteLabel}
                        strokeOpacity={0.5}
                        fill="#3b82f6"
                        fillOpacity={0.14}
                      />
                    )}

                    {seriesConfig.map((s) =>
                      hiddenSeries[s.key] ? null : (
                        <Bar
                          key={s.key}
                          dataKey={s.key}
                          stackId="infra"
                          name={isAr ? s.labelAr : s.labelEn}
                          fill={s.color}
                          className="cursor-pointer"
                        >
                          {chartData.map((entry) => (
                            <Cell
                              key={`${s.key}-${entry.idx}`}
                              fill={entry.hasIssue && s.key === 'serverLoadScore' ? '#dc2626' : s.color}
                              fillOpacity={
                                selectionRange &&
                                (entry.idx < selectionRange[0] || entry.idx > selectionRange[1])
                                  ? 0.3
                                  : 0.92
                              }
                            />
                          ))}
                        </Bar>
                      )
                    )}
                  </BarChart>
                </ResponsiveContainer>
              </div>
            )}
          </div>

          {/* Right 3 Columns: MyOra-Style Legend & Window Values Table */}
          <div className="lg:col-span-3 border border-slate-200 dark:border-slate-800 rounded-md overflow-hidden">
            <div className="px-3 py-2 bg-slate-50 dark:bg-slate-800/60 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between text-[11px] font-semibold text-slate-600 dark:text-slate-300">
              <span>{isAr ? 'مكونات الأداء (اضغط للفلترة)' : 'Wait & Load Legend'}</span>
              <span>{isAr ? 'المتوسط' : 'Avg'}</span>
            </div>
            <div className="divide-y divide-slate-100 dark:divide-slate-800">
              {seriesConfig.map((item) => {
                const isHidden = hiddenSeries[item.key];
                const val = legendTotals[item.key];
                return (
                  <button
                    key={item.key}
                    type="button"
                    onClick={() => toggleSeries(item.key)}
                    className={`w-full px-3 py-2 flex items-center justify-between gap-2 text-xs transition-colors hover:bg-slate-50 dark:hover:bg-slate-800/50 cursor-pointer ${
                      isHidden ? 'opacity-45' : ''
                    }`}
                  >
                    <span className="flex items-center gap-2 min-w-0">
                      <span
                        className="w-3 h-3 rounded-xs shrink-0"
                        style={{ backgroundColor: item.color }}
                        aria-hidden="true"
                      />
                      <span className="truncate text-slate-700 dark:text-slate-200">
                        {isAr ? item.labelAr : item.labelEn}
                      </span>
                    </span>
                    <span className="font-mono tabular-nums text-slate-900 dark:text-slate-100 shrink-0">
                      {val} {item.unit}
                    </span>
                  </button>
                );
              })}
            </div>
            <div className="px-3 py-2.5 bg-slate-50 dark:bg-slate-950/60 border-t border-slate-200 dark:border-slate-800 text-[11px] text-slate-500 dark:text-slate-400 space-y-1 font-mono tabular-nums">
              <div className="flex justify-between">
                <span>{isAr ? 'حوادث في هذا اليوم:' : 'Alerts on date:'}</span>
                <span className={alertsForSelectedDate.length > 0 ? 'text-rose-600 dark:text-rose-400 font-semibold' : ''}>
                  {alertsForSelectedDate.length}
                </span>
              </div>
              <div className="flex justify-between">
                <span>{isAr ? 'أقصى جلسات نشطة:' : 'Peak sessions:'}</span>
                <span>
                  {activeSlice.length > 0 ? Math.max(...activeSlice.map((p) => p.activeSessions)) : 0}
                </span>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* 5. MyOra-Style 3-Panel Drilldown: Events | Exact Location / Objects | Clear Diagnosis & Fix + Sessions */}
      <section id="exec-drilldown-section" className="space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
          <div className="font-semibold text-slate-800 dark:text-slate-200">
            {isAr
              ? `تفاصيل الفترة (${windowFromLabel} — ${windowToLabel})`
              : `Window Details From (${windowFromLabel}) To (${windowToLabel})`}
          </div>
          <div className="text-slate-500 dark:text-slate-400">
            {isAr
              ? 'الأحداث والاختناقات · المكان الدقيق للمشكلة · التشخيص واقتراح الحل'
              : 'Events · Exact Objects & Locations · Diagnosis, Suggested Fix & Sessions'}
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 items-stretch">
          {/* Panel 1: Events & Wait Percentages */}
          <div className="lg:col-span-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg overflow-hidden flex flex-col">
            <div className="px-4 py-2.5 bg-slate-50 dark:bg-slate-800/60 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between">
              <h3 className="text-xs font-semibold text-slate-900 dark:text-slate-100">
                {isAr ? '1. الأحداث والاختناقات (Events)' : '1. Events & Bottlenecks'}
              </h3>
              <span className="font-mono text-[11px] text-slate-500 dark:text-slate-400">
                {waitAndEventRows.length}
              </span>
            </div>

            {waitAndEventRows.length === 0 ? (
              <div className="p-6 text-center text-xs text-slate-500 dark:text-slate-400 my-auto">
                {isAr
                  ? 'لا توجد أحداث انتظار أو اختناقات مسجلة في هذه الفترة.'
                  : 'No wait events or bottlenecks recorded in this window.'}
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-xs text-start">
                  <thead className="border-b border-slate-100 dark:border-slate-800 text-[11px] text-slate-500 dark:text-slate-400">
                    <tr>
                      <th className="py-2 px-3 text-start font-medium">{isAr ? 'الحدث' : 'Event'}</th>
                      <th className="py-2 px-2 text-start font-medium">{isAr ? 'القسم' : 'Class'}</th>
                      <th className="py-2 px-3 text-end font-medium">{isAr ? 'التأثير%' : 'Impact%'}</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                    {waitAndEventRows.map((row, idx) => (
                      <tr key={idx} className="hover:bg-slate-50 dark:hover:bg-slate-800/40">
                        <td className="py-2 px-3 font-medium text-slate-800 dark:text-slate-200 max-w-[160px] truncate" title={row.name}>
                          {row.name}
                        </td>
                        <td className="py-2 px-2 text-slate-500 dark:text-slate-400 whitespace-nowrap">
                          {row.category}
                        </td>
                        <td className="py-2 px-3 text-end font-mono tabular-nums">
                          <div className="flex items-center justify-end gap-2">
                            <div className="w-14 h-2 bg-slate-100 dark:bg-slate-800 rounded-xs overflow-hidden">
                              <div
                                className={`h-full ${
                                  row.severity === 'Critical'
                                    ? 'bg-rose-500'
                                    : row.severity === 'Warning'
                                      ? 'bg-amber-500'
                                      : 'bg-violet-500'
                                }`}
                                style={{ width: `${Math.min(100, Math.max(8, row.pct))}%` }}
                              />
                            </div>
                            <span className="w-11 text-end text-slate-700 dark:text-slate-300">
                              {row.pct}%
                            </span>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* Panel 2: Exact Location / Objects */}
          <div className="lg:col-span-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg overflow-hidden flex flex-col">
            <div className="px-4 py-2.5 bg-slate-50 dark:bg-slate-800/60 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between">
              <h3 className="text-xs font-semibold text-slate-900 dark:text-slate-100">
                {isAr ? '2. أين المشكلة بالظبط؟ (Objects & Targets)' : '2. Exact Location & Objects'}
              </h3>
              <span className="font-mono text-[11px] text-slate-500 dark:text-slate-400">
                {locationObjects.length}
              </span>
            </div>

            {locationObjects.length === 0 ? (
              <div className="p-6 text-center text-xs text-slate-500 dark:text-slate-400 my-auto">
                {isAr
                  ? 'ستظهر هنا الجداول ومساحات التخزين وتطبيقات IIS والخوادم المراقبة.'
                  : 'Monitored tablespaces, IIS apps, servers, and network nodes appear here.'}
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-xs text-start">
                  <thead className="border-b border-slate-100 dark:border-slate-800 text-[11px] text-slate-500 dark:text-slate-400">
                    <tr>
                      <th className="py-2 px-3 text-start font-medium">{isAr ? 'المالك / الموقع' : 'Owner'}</th>
                      <th className="py-2 px-2 text-start font-medium">{isAr ? 'العنصر' : 'Object'}</th>
                      <th className="py-2 px-2 text-start font-medium">{isAr ? 'النوع' : 'Type'}</th>
                      <th className="py-2 px-3 text-end font-medium">{isAr ? 'القيمة' : 'Value'}</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                    {locationObjects.slice(0, 8).map((obj, idx) => (
                      <tr
                        key={idx}
                        onClick={() => onNavigate(obj.section)}
                        className={`cursor-pointer transition-colors ${
                          obj.status === 'Critical'
                            ? 'bg-rose-50/60 dark:bg-rose-950/20 hover:bg-rose-100/60 dark:hover:bg-rose-950/30'
                            : obj.status === 'Warning'
                              ? 'bg-amber-50/50 dark:bg-amber-950/15 hover:bg-amber-100/50 dark:hover:bg-amber-950/25'
                              : 'hover:bg-slate-50 dark:hover:bg-slate-800/40'
                        }`}
                      >
                        <td className="py-2 px-3 font-mono text-[11px] text-slate-600 dark:text-slate-400 max-w-[90px] truncate" title={obj.owner}>
                          {obj.owner}
                        </td>
                        <td className="py-2 px-2 font-medium text-slate-900 dark:text-slate-100 max-w-[130px] truncate" title={obj.objectName}>
                          {obj.objectName}
                        </td>
                        <td className="py-2 px-2 font-mono text-[10px] text-slate-500 dark:text-slate-400 whitespace-nowrap">
                          {obj.objectType}
                        </td>
                        <td
                          className={`py-2 px-3 text-end font-mono tabular-nums whitespace-nowrap ${
                            obj.status === 'Critical'
                              ? 'text-rose-700 dark:text-rose-400 font-semibold'
                              : obj.status === 'Warning'
                                ? 'text-amber-700 dark:text-amber-400 font-semibold'
                                : 'text-slate-700 dark:text-slate-300'
                          }`}
                        >
                          {obj.displayValue}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* Panel 3: Clear Problem Diagnosis + Suggested Fix + Active Sessions */}
          <div className="lg:col-span-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg overflow-hidden flex flex-col">
            <div className="px-4 py-2 bg-slate-50 dark:bg-slate-800/60 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between gap-2">
              <div className="inline-flex items-center gap-1">
                <button
                  type="button"
                  onClick={() => setPanel3Tab('diagnosis')}
                  className={`px-2.5 py-1 rounded text-xs font-medium whitespace-nowrap cursor-pointer ${
                    panel3Tab === 'diagnosis'
                      ? 'bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100 shadow-xs'
                      : 'text-slate-600 dark:text-slate-400 hover:text-slate-900'
                  }`}
                >
                  {isAr ? `3. المشكلة والحل (${diagnostics.length})` : `3. Diagnosis & Fix (${diagnostics.length})`}
                </button>
                <button
                  type="button"
                  onClick={() => setPanel3Tab('sessions')}
                  className={`px-2.5 py-1 rounded text-xs font-medium whitespace-nowrap cursor-pointer ${
                    panel3Tab === 'sessions'
                      ? 'bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100 shadow-xs'
                      : 'text-slate-600 dark:text-slate-400 hover:text-slate-900'
                  }`}
                >
                  {isAr ? `الجلسات (${activeDbSessions.length})` : `Sessions (${activeDbSessions.length})`}
                </button>
              </div>
            </div>

            {panel3Tab === 'diagnosis' ? (
              diagnostics.length === 0 ? (
                <div className="p-6 text-center text-xs text-slate-500 dark:text-slate-400 my-auto">
                  {isAr
                    ? 'لا توجد مشاكل مرصودة حالياً. عند حدوث أي عطل أو بطء سيظهر هنا: ما هي المشكلة، مكانها بالضبط، واقتراح الحل.'
                    : 'No issues detected. When a problem occurs, its clear explanation, exact location, and suggested fix will appear here.'}
                </div>
              ) : (
                <div className="divide-y divide-slate-100 dark:divide-slate-800 max-h-[340px] overflow-y-auto">
                  {diagnostics.map((issue) => (
                    <div
                      key={issue.id}
                      className={`p-3.5 space-y-1.5 text-xs ${
                        issue.severity === 'Critical'
                          ? 'bg-rose-50/40 dark:bg-rose-950/15'
                          : 'bg-amber-50/40 dark:bg-amber-950/15'
                      }`}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span
                          className={`font-semibold whitespace-nowrap ${
                            issue.severity === 'Critical'
                              ? 'text-rose-700 dark:text-rose-400'
                              : 'text-amber-700 dark:text-amber-400'
                          }`}
                        >
                          {issue.severity === 'Critical'
                            ? isAr
                              ? '✖ حرج'
                              : '✖ Critical'
                            : isAr
                              ? '▲ تحذير'
                              : '▲ Warning'}{' '}
                          · {isAr ? issue.categoryLabelAr : issue.categoryLabelEn}
                        </span>
                        <span className="font-mono text-[11px] text-slate-500 dark:text-slate-400 tabular-nums">
                          {issue.timestamp}
                        </span>
                      </div>

                      <div className="text-slate-900 dark:text-slate-100 font-medium">
                        <span className="text-slate-500 dark:text-slate-400 font-normal">
                          {isAr ? 'المشكلة: ' : 'Issue: '}
                        </span>
                        {isAr ? issue.whatAr : issue.whatEn}
                      </div>

                      <div className="text-slate-700 dark:text-slate-300 font-mono text-[11px]">
                        <span className="font-sans text-slate-500 dark:text-slate-400">
                          {isAr ? 'المكان بالظبط: ' : 'Exact Location: '}
                        </span>
                        {isAr ? issue.whereAr : issue.whereEn}
                      </div>

                      <div className="text-emerald-800 dark:text-emerald-300 flex items-start gap-1.5 leading-relaxed">
                        <Wrench className="w-3.5 h-3.5 shrink-0 mt-0.5" />
                        <span>
                          <strong className="font-semibold">
                            {isAr ? 'اقتراح الحل: ' : 'Suggested Fix: '}
                          </strong>
                          {isAr ? issue.fixAr : issue.fixEn}
                        </span>
                      </div>

                      <div className="pt-0.5">
                        <button
                          type="button"
                          onClick={() => onNavigate(issue.targetSection)}
                          className="text-[11px] font-medium text-blue-600 dark:text-blue-400 hover:underline cursor-pointer"
                        >
                          {isAr ? 'الانتقال إلى المصدر ←' : 'Inspect target module →'}
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              )
            ) : activeDbSessions.length === 0 ? (
              <div className="p-6 text-center text-xs text-slate-500 dark:text-slate-400 my-auto">
                {isAr
                  ? 'لا توجد جلسات Oracle طويلة أو معلّقة مرصودة حالياً.'
                  : 'No long-running or active Oracle SQL sessions captured.'}
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-xs text-start">
                  <thead className="border-b border-slate-100 dark:border-slate-800 text-[11px] text-slate-500 dark:text-slate-400">
                    <tr>
                      <th className="py-2 px-3 text-start font-medium">SQL_ID</th>
                      <th className="py-2 px-2 text-start font-medium">{isAr ? 'المستخدم' : 'User'}</th>
                      <th className="py-2 px-2 text-start font-medium">{isAr ? 'الانتظار' : 'Wait'}</th>
                      <th className="py-2 px-3 text-end font-medium">{isAr ? 'المدة' : 'Elapsed'}</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                    {activeDbSessions.map((q, idx) => (
                      <tr key={`${q.sqlId}-${idx}`} className="hover:bg-slate-50 dark:hover:bg-slate-800/40">
                        <td className="py-2 px-3 font-mono text-blue-700 dark:text-blue-400">{q.sqlId}</td>
                        <td className="py-2 px-2 font-mono text-slate-700 dark:text-slate-300">{q.username}</td>
                        <td className="py-2 px-2 text-slate-500 dark:text-slate-400 truncate max-w-[110px]" title={q.waitEvent}>
                          {q.waitEvent}
                        </td>
                        <td className="py-2 px-3 text-end font-mono tabular-nums text-amber-700 dark:text-amber-400">
                          {q.elapsedSec}s
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      </section>

      {/* 6. Historical Alerts Log for Selected Date */}
      {alertsForSelectedDate.length > 0 && (
        <section className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg overflow-hidden">
          <div className="px-5 py-3 border-b border-slate-100 dark:border-slate-800 flex items-center justify-between">
            <h2 className="text-xs font-semibold text-slate-900 dark:text-slate-100">
              {isAr
                ? `سجل التنبيهات والحوادث بتاريخ ${selectedDate}`
                : `Alerts & Incidents Recorded on ${selectedDate}`}
            </h2>
            <button
              type="button"
              onClick={() => onNavigate('alerts')}
              className="text-xs font-medium text-blue-600 dark:text-blue-400 hover:underline cursor-pointer"
            >
              {isAr ? 'إدارة كل التنبيهات' : 'Manage All Alerts'}
            </button>
          </div>
          <div className="divide-y divide-slate-100 dark:divide-slate-800">
            {alertsForSelectedDate.slice(0, 6).map((alert) => (
              <div
                key={alert.id}
                onClick={() => onNavigate('alerts')}
                className="px-5 py-3 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 hover:bg-slate-50 dark:hover:bg-slate-800/40 cursor-pointer"
              >
                <div className="space-y-0.5 min-w-0">
                  <div className="flex items-center gap-2">
                    <SeverityText severity={alert.severity} label={copy.severity[alert.severity]} />
                    <span className="text-xs font-semibold text-slate-900 dark:text-slate-100 truncate">
                      {isAr ? alert.titleAr : alert.title}
                    </span>
                  </div>
                  <div className="text-[11px] font-mono text-slate-500 dark:text-slate-400">
                    {alert.timestamp} · {alert.module} · {alert.assetName}
                  </div>
                </div>
                <IncidentStatusText status={alert.status} label={copy.incidentStatus[alert.status]} />
              </div>
            ))}
          </div>
        </section>
      )}
    </div>
  );
}
