import {
  AlertSeverity,
  AssetStatus,
  CollectionStatus,
  ConnectorStatusState,
  IncidentStatus,
  Language,
  MetricIntegrity,
  MetricSourceTag,
  OracleConnectorHealth,
  ServerEnvironment,
  ServerHealthClassification,
  ServerPlatform,
} from '../types/infrastructure';

export function getPlatformLabel(platform: ServerPlatform | undefined, lang: Language): string {
  const p = platform ?? 'windows';
  const en: Record<ServerPlatform, string> = {
    windows: 'Windows Server',
    linux: 'Linux Server',
    'oracle-linux': 'Oracle Linux',
    'cloud-vps': 'Cloud Linux VPS',
    'oci-compute': 'OCI Compute VM',
    'oracle-db': 'Oracle Database',
    'hyperv-host': 'Hyper-V Host',
    'hyperv-vm': 'Hyper-V VM',
    'network-device': 'Network Device',
    restricted: 'Restricted Server',
  };
  const ar: Record<ServerPlatform, string> = {
    windows: 'خادم Windows',
    linux: 'خادم Linux',
    'oracle-linux': 'خادم Oracle Linux',
    'cloud-vps': 'خادم سحابي VPS',
    'oci-compute': 'خادم سحابي OCI',
    'oracle-db': 'قاعدة بيانات Oracle',
    'hyperv-host': 'مضيف Hyper-V',
    'hyperv-vm': 'آلة افتراضية Hyper-V',
    'network-device': 'جهاز شبكة',
    restricted: 'خادم مقيد الصلاحيات',
  };
  return lang === 'ar' ? ar[p] : en[p];
}

export function MetricSourceChip({ source }: { source: MetricSourceTag | string }) {
  return (
    <span className="inline-flex items-center px-1.5 py-0.5 rounded border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/80 font-mono text-[10px] font-medium text-slate-600 dark:text-slate-300 whitespace-nowrap">
      {source}
    </span>
  );
}

export function ConnectorStatusBadge({
  status,
  lang,
}: {
  status: ConnectorStatusState;
  lang: Language;
}) {
  const styles: Record<ConnectorStatusState, string> = {
    Healthy: 'bg-emerald-50 dark:bg-emerald-950/50 text-emerald-700 dark:text-emerald-300 border-emerald-200 dark:border-emerald-900',
    Warning: 'bg-amber-50 dark:bg-amber-950/50 text-amber-700 dark:text-amber-300 border-amber-200 dark:border-amber-900',
    Critical: 'bg-rose-50 dark:bg-rose-950/50 text-rose-700 dark:text-rose-300 border-rose-200 dark:border-rose-900',
    'Access Restricted': 'bg-orange-50 dark:bg-orange-950/50 text-orange-700 dark:text-orange-300 border-orange-200 dark:border-orange-900',
    'Authentication Failed': 'bg-rose-50 dark:bg-rose-950/50 text-rose-700 dark:text-rose-300 border-rose-200 dark:border-rose-900',
    'Not Configured': 'bg-blue-50 dark:bg-blue-950/40 text-blue-700 dark:text-blue-300 border-blue-200 dark:border-blue-900',
    Unreachable: 'bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 border-slate-300 dark:border-slate-700',
  };
  const labelsAr: Record<ConnectorStatusState, string> = {
    Healthy: 'سليم',
    Warning: 'تحذير',
    Critical: 'حرج',
    'Access Restricted': 'وصول مقيد',
    'Authentication Failed': 'فشل المصادقة',
    'Not Configured': 'غير مُعد',
    Unreachable: 'تعذر الوصول',
  };
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded border text-[11px] font-medium whitespace-nowrap ${styles[status]}`}>
      {lang === 'ar' ? labelsAr[status] : status}
    </span>
  );
}

export function ConnectorHealthCard({
  connector,
  lang,
}: {
  connector: OracleConnectorHealth;
  lang: Language;
}) {
  return (
    <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-3.5 space-y-2 text-xs">
      <div className="flex items-center justify-between gap-2">
        <div className="font-semibold text-slate-900 dark:text-slate-100">{connector.connector}</div>
        <div className="flex items-center gap-1.5">
          <MetricSourceChip source={connector.source} />
          <ConnectorStatusBadge status={connector.status} lang={lang} />
        </div>
      </div>

      <div className="flex flex-wrap items-center justify-between gap-2 font-mono text-[11px] text-slate-500 dark:text-slate-400">
        <span>
          {lang === 'ar' ? 'آخر محاولة:' : 'Attempt:'} {connector.lastAttemptAt}
        </span>
        {connector.latencyMs !== undefined && connector.latencyMs !== null && (
          <span className="tabular-nums">{connector.latencyMs}ms</span>
        )}
      </div>

      {connector.lastSuccessAt && (
        <div className="font-mono text-[11px] text-emerald-700 dark:text-emerald-400">
          {lang === 'ar' ? 'آخر نجاح:' : 'Last Success:'} {connector.lastSuccessAt}
        </div>
      )}

      {connector.availableMetrics.length > 0 && (
        <div className="text-[11px] text-slate-600 dark:text-slate-300 truncate" title={connector.availableMetrics.join(', ')}>
          <span className="font-semibold text-emerald-700 dark:text-emerald-400">
            {lang === 'ar' ? 'المتوفر: ' : 'Collected: '}
          </span>
          <span className="font-mono">{connector.availableMetrics.join(', ')}</span>
        </div>
      )}

      {connector.errorDetail && (
        <div className="p-2 rounded bg-amber-50/70 dark:bg-amber-950/20 border border-amber-200 dark:border-amber-900 font-mono text-[11px] text-rose-700 dark:text-rose-300 break-words">
          {connector.errorDetail}
        </div>
      )}

      {connector.prerequisiteHint && (
        <div className="text-[11px] text-slate-600 dark:text-slate-400 leading-relaxed">
          {connector.prerequisiteHint}
        </div>
      )}
    </div>
  );
}

export function getEnvironmentLabel(env: ServerEnvironment | undefined, lang: Language): string {
  const e = env ?? 'Production';
  if (lang === 'en') return e;
  const ar: Record<ServerEnvironment, string> = {
    Production: 'إنتاج',
    Testing: 'اختبار',
    Development: 'تطوير',
  };
  return ar[e];
}

export function HealthClassificationBadge({
  classification,
  lang,
}: {
  classification?: ServerHealthClassification;
  lang: Language;
}) {
  if (!classification) return null;

  const styles: Record<ServerHealthClassification, { cls: string; glyph: string }> = {
    'Monitoring Healthy': {
      cls: 'text-emerald-700 dark:text-emerald-400',
      glyph: '●',
    },
    'Partial Monitoring': {
      cls: 'text-sky-700 dark:text-sky-400',
      glyph: '◐',
    },
    'Monitoring Access Denied': {
      cls: 'text-orange-700 dark:text-orange-400',
      glyph: '◆',
    },
    'Connection Blocked': {
      cls: 'text-amber-700 dark:text-amber-400',
      glyph: '▲',
    },
    'Authentication Failed': {
      cls: 'text-rose-700 dark:text-rose-400',
      glyph: '✖',
    },
    'Unsupported Monitoring Method': {
      cls: 'text-slate-600 dark:text-slate-300',
      glyph: '◇',
    },
    'Server Offline': {
      cls: 'text-slate-500 dark:text-slate-400',
      glyph: '○',
    },
  };

  const labelsAr: Record<ServerHealthClassification, string> = {
    'Monitoring Healthy': 'مراقبة سليمة',
    'Partial Monitoring': 'مراقبة جزئية',
    'Monitoring Access Denied': 'رفض صلاحية المراقبة',
    'Connection Blocked': 'الاتصال محجوب',
    'Authentication Failed': 'فشل المصادقة',
    'Unsupported Monitoring Method': 'طريقة مراقبة غير مدعومة',
    'Server Offline': 'الخادم متوقف',
  };

  const { cls, glyph } = styles[classification];

  return (
    <span className={`inline-flex items-center gap-1.5 text-[11px] font-medium whitespace-nowrap ${cls}`}>
      <span aria-hidden="true" className="text-[10px] leading-none">{glyph}</span>
      <span>{lang === 'ar' ? labelsAr[classification] : classification}</span>
    </span>
  );
}

export function AssetStatusBadge({ status, label }: { status: AssetStatus; label: string }) {
  const map: Record<AssetStatus, { cls: string; glyph: string }> = {
    Online: { cls: 'text-emerald-700 dark:text-emerald-400', glyph: '●' },
    Warning: { cls: 'text-amber-700 dark:text-amber-400', glyph: '▲' },
    Critical: { cls: 'text-rose-700 dark:text-rose-400', glyph: '✖' },
    Offline: { cls: 'text-slate-500 dark:text-slate-400', glyph: '○' },
  };
  const { cls, glyph } = map[status];
  return (
    <span className={`inline-flex items-center gap-1.5 text-xs font-medium whitespace-nowrap ${cls}`}>
      <span aria-hidden="true" className="text-[10px] leading-none">{glyph}</span>
      <span>{label}</span>
    </span>
  );
}

export function CollectionStatusBadge({
  status,
  lang,
}: {
  status: CollectionStatus;
  lang: Language;
}) {
  const styles: Record<CollectionStatus, string> = {
    Healthy: 'bg-emerald-50 dark:bg-emerald-950/50 text-emerald-700 dark:text-emerald-300 border-emerald-200 dark:border-emerald-900',
    Warning: 'bg-amber-50 dark:bg-amber-950/50 text-amber-700 dark:text-amber-300 border-amber-200 dark:border-amber-900',
    Critical: 'bg-rose-50 dark:bg-rose-950/50 text-rose-700 dark:text-rose-300 border-rose-200 dark:border-rose-900',
    Unreachable: 'bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 border-slate-300 dark:border-slate-700',
    'Authentication Failed': 'bg-rose-50 dark:bg-rose-950/50 text-rose-700 dark:text-rose-300 border-rose-200 dark:border-rose-900',
    'Permission Denied': 'bg-orange-50 dark:bg-orange-950/50 text-orange-700 dark:text-orange-300 border-orange-200 dark:border-orange-900',
    'Unsupported Metric': 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 border-slate-200 dark:border-slate-700',
    'Not Configured': 'bg-blue-50 dark:bg-blue-950/40 text-blue-700 dark:text-blue-300 border-blue-200 dark:border-blue-900',
  };

  const labelsAr: Record<CollectionStatus, string> = {
    Healthy: 'سليم (قياس فعلي)',
    Warning: 'تحذير',
    Critical: 'حرج',
    Unreachable: 'تعذر الوصول',
    'Authentication Failed': 'فشل المصادقة',
    'Permission Denied': 'رفض الصلاحية',
    'Unsupported Metric': 'مؤشر غير مدعوم',
    'Not Configured': 'غير مُعد',
  };

  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded border text-[11px] font-medium whitespace-nowrap ${styles[status]}`}>
      {lang === 'ar' ? labelsAr[status] : status}
    </span>
  );
}

export function IntegrityBanner({
  integrity,
  lang,
}: {
  integrity?: MetricIntegrity;
  lang: Language;
}) {
  if (!integrity) return null;
  const isOk = integrity.collectionStatus === 'Healthy' || integrity.collectionStatus === 'Warning';

  return (
    <div
      className={`rounded-md border p-3 text-xs space-y-1.5 ${
        isOk && !integrity.errorDetail
          ? 'bg-slate-50 dark:bg-slate-950/60 border-slate-200 dark:border-slate-800'
          : 'bg-amber-50/70 dark:bg-amber-950/20 border-amber-200 dark:border-amber-900'
      }`}
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-2">
          <CollectionStatusBadge status={integrity.collectionStatus} lang={lang} />
          <span className="font-mono text-[11px] text-slate-600 dark:text-slate-400">
            {lang === 'ar' ? 'المصدر:' : 'Source:'} {integrity.dataSource}
          </span>
        </div>
        <span className="font-mono text-[11px] text-slate-500 dark:text-slate-400">
          {integrity.targetIdentifier} · {integrity.measuredAt}
        </span>
      </div>

      {integrity.errorDetail && (
        <div className="text-rose-700 dark:text-rose-300 font-mono text-[11px] break-words">
          {integrity.errorDetail}
        </div>
      )}

      {integrity.prerequisiteHint && (
        <div className="text-slate-700 dark:text-slate-300 text-[11px] leading-relaxed">
          <span className="font-semibold">
            {lang === 'ar' ? 'المتطلب الأصلي (بدون وكيل): ' : 'Native Remote Prerequisite (Agentless): '}
          </span>
          {integrity.prerequisiteHint}
        </div>
      )}
    </div>
  );
}

export function SeverityText({ severity, label }: { severity: AlertSeverity; label: string }) {
  const map: Record<AlertSeverity, { cls: string; glyph: string }> = {
    Critical: { cls: 'text-rose-700 dark:text-rose-400 font-semibold', glyph: '✖' },
    High: { cls: 'text-orange-700 dark:text-orange-400 font-semibold', glyph: '▲' },
    Medium: { cls: 'text-amber-700 dark:text-amber-400 font-medium', glyph: '◆' },
    Low: { cls: 'text-blue-700 dark:text-blue-400 font-medium', glyph: '●' },
    Information: { cls: 'text-slate-600 dark:text-slate-400 font-normal', glyph: '○' },
  };
  const { cls, glyph } = map[severity];
  return (
    <span className={`inline-flex items-center gap-1.5 text-xs whitespace-nowrap ${cls}`}>
      <span aria-hidden="true" className="text-[10px] leading-none">{glyph}</span>
      <span>{label}</span>
    </span>
  );
}

export function IncidentStatusText({ status, label }: { status: IncidentStatus; label: string }) {
  const map: Record<IncidentStatus, string> = {
    Open: 'text-rose-700 dark:text-rose-400 font-medium',
    Acknowledged: 'text-amber-700 dark:text-amber-400 font-medium',
    'In Progress': 'text-blue-700 dark:text-blue-400 font-medium',
    Resolved: 'text-emerald-700 dark:text-emerald-400 font-medium',
  };
  return <span className={`text-xs whitespace-nowrap ${map[status]}`}>{label}</span>;
}
