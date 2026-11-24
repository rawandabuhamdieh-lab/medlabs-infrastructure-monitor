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
