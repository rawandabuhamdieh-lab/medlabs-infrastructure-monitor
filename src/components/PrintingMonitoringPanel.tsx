import { useState, type FormEvent } from 'react';
import { Activity, AlertTriangle, FileText, Plus, Printer, RefreshCw, Trash2 } from 'lucide-react';
import type {
  ConnectionTestResult,
  Language,
  PrintMonitorTarget,
  ReportExecutionRecord,
  UserRole,
} from '../types/infrastructure';
import { formatDurationMs } from '../utils/rcaEngine';

interface PrintingMonitoringPanelProps {
  printTargets: PrintMonitorTarget[];
  reportExecutions: ReportExecutionRecord[];
  currentRole: UserRole | null;
  lang: Language;
  onRegisterPrinter: (payload: {
    name: string;
    hostOrIp: string;
    site: string;
    protocol: PrintMonitorTarget['protocol'];
    port: number;
    spoolerHost?: string;
  }) => Promise<string | null>;
  onTestPrinter: (id: string) => Promise<{ result?: ConnectionTestResult; error?: string }>;
  onPollAllPrinters: () => Promise<string | null>;
  onDeletePrinter: (id: string) => Promise<string | null>;
}

export function PrintingMonitoringPanel({
  printTargets,
  reportExecutions,
  currentRole,
  lang,
  onRegisterPrinter,
  onTestPrinter,
  onPollAllPrinters,
  onDeletePrinter,
}: PrintingMonitoringPanelProps) {
  const isAr = lang === 'ar';
  const canEdit =
    currentRole !== null && ['Administrator', 'IT Manager', 'IT Engineer'].includes(currentRole);

  const [showAdd, setShowAdd] = useState(false);
  const [name, setName] = useState('');
  const [hostOrIp, setHostOrIp] = useState('');
  const [site, setSite] = useState('MedLabs Central');
  const [protocol, setProtocol] = useState<PrintMonitorTarget['protocol']>('RAW-9100');
  const [port, setPort] = useState(9100);
  const [spoolerHost, setSpoolerHost] = useState('');
  const [feedback, setFeedback] = useState<string | null>(null);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    const err = await onRegisterPrinter({
      name,
      hostOrIp,
      site,
      protocol,
      port,
      spoolerHost: spoolerHost.trim() || undefined,
    });
    if (err) {
      setFeedback(err);
    } else {
      setName('');
      setHostOrIp('');
      setSpoolerHost('');
      setShowAdd(false);
      setFeedback(isAr ? 'تمت إضافة الطابعة. يمكنك إجراء الفحص يدوياً عند الحاجة.' : 'Printer registered. Run a manual test when ready.');
    }
  };

  return (
    <section className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-5 space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 pb-3 border-b border-slate-100 dark:border-slate-800">
        <div>
          <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100 flex items-center gap-2">
            <Printer className="w-4 h-4 text-amber-600 dark:text-amber-400" />
            <span>
              {isAr
                ? 'مراقبة الطباعة والتقارير وتحديد مصدر البطء بدقة'
                : 'Printing & Report Execution Monitoring (Stage Attribution)'}
            </span>
          </h2>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            {isAr
              ? 'تفصيل دقيق بين توليد التقرير، معالجة التطبيق، استعلام Oracle، الشبكة، استجابة الطابعة، وطابور الطباعة.'
              : 'Separates Report Generation, App Processing, Oracle SQL Execution, Network, Printer Response, and Print Queue delays.'}
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            disabled={!canEdit || printTargets.length === 0}
            onClick={async () => {
              const err = await onPollAllPrinters();
              setFeedback(err || (isAr ? 'تم فحص جميع الطابعات.' : 'Printers polled.'));
            }}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md border border-slate-200 dark:border-slate-700 text-xs font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-800 disabled:opacity-40 cursor-pointer"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            <span>{isAr ? 'فحص الطابعات' : 'Poll Printers'}</span>
          </button>
          <button
            type="button"
            onClick={() => setShowAdd((p) => !p)}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-amber-600 hover:bg-amber-700 text-white text-xs font-medium cursor-pointer"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>{isAr ? 'إضافة طابعة' : 'Add Printer'}</span>
          </button>
        </div>
      </div>

      {feedback && (
        <div className="p-2.5 rounded border border-blue-200 dark:border-blue-800 bg-blue-50 dark:bg-blue-950/30 text-xs text-blue-900 dark:text-blue-200">
          {feedback}
        </div>
      )}

      {showAdd && (
        <form
          onSubmit={handleSubmit}
          className="p-4 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/50 space-y-3 text-xs"
        >
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div>
              <label className="block font-medium mb-1">{isAr ? 'اسم الطابعة' : 'Printer Name'}</label>
              <input
                type="text"
                required
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="Lab-Results-LaserJet-01"
                className="w-full px-3 py-1.5 rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900"
              />
            </div>
            <div>
              <label className="block font-medium mb-1">{isAr ? 'عنوان IP / Host' : 'Printer IP / Hostname'}</label>
              <input
                type="text"
                required
                value={hostOrIp}
                onChange={(e) => setHostOrIp(e.target.value)}
                placeholder="10.10.4.55"
                className="w-full px-3 py-1.5 rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 font-mono"
              />
            </div>
            <div>
              <label className="block font-medium mb-1">{isAr ? 'الموقع / الفرع' : 'Site / Branch'}</label>
              <input
                type="text"
                value={site}
                onChange={(e) => setSite(e.target.value)}
                className="w-full px-3 py-1.5 rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900"
              />
            </div>
            <div>
              <label className="block font-medium mb-1">{isAr ? 'البروتوكول' : 'Protocol'}</label>
              <select
                value={protocol}
                onChange={(e) => {
                  const p = e.target.value as PrintMonitorTarget['protocol'];
                  setProtocol(p);
                  setPort(p === 'IPP-631' ? 631 : p === 'LPD-515' ? 515 : 9100);
                }}
                className="w-full px-3 py-1.5 rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900"
              >
                <option value="RAW-9100">RAW TCP/9100</option>
                <option value="IPP-631">IPP TCP/631</option>
                <option value="LPD-515">LPD TCP/515</option>
                <option value="Windows-Spooler">Windows Print Spooler</option>
              </select>
            </div>
            <div>
              <label className="block font-medium mb-1">{isAr ? 'المنفذ' : 'Port'}</label>
              <input
                type="number"
                value={port}
                onChange={(e) => setPort(Number(e.target.value))}
                className="w-full px-3 py-1.5 rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 font-mono"
              />
            </div>
            <div>
              <label className="block font-medium mb-1">
                {isAr ? 'خادم Print Spooler (اختياري)' : 'Windows Spooler Host (Optional)'}
              </label>
              <input
                type="text"
                value={spoolerHost}
                onChange={(e) => setSpoolerHost(e.target.value)}
                placeholder="MLJ-PRINT-01"
                className="w-full px-3 py-1.5 rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 font-mono"
              />
            </div>
          </div>
          <div className="flex justify-end gap-2">
            <button
              type="button"
              onClick={() => setShowAdd(false)}
              className="px-3 py-1.5 rounded border border-slate-300 dark:border-slate-700 cursor-pointer"
            >
              {isAr ? 'إلغاء' : 'Cancel'}
            </button>
            <button
              type="submit"
              disabled={!canEdit}
              className="px-4 py-1.5 rounded bg-amber-600 text-white font-medium disabled:opacity-40 cursor-pointer"
            >
              {canEdit ? (isAr ? 'حفظ الطابعة' : 'Save Printer') : isAr ? 'يتطلب صلاحية مهندس+' : 'Sign in as Engineer+'}
            </button>
          </div>
        </form>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* Left 5 cols: Printers & Spooler Queue Status */}
        <div className="lg:col-span-5 space-y-2.5">
          <div className="text-xs font-semibold text-slate-800 dark:text-slate-200">
            {isAr ? `حالة الطابعات وطوابير الطباعة (${printTargets.length})` : `Printers & Queue Status (${printTargets.length})`}
          </div>
          {printTargets.length === 0 ? (
            <div className="p-4 rounded-lg border border-dashed border-slate-200 dark:border-slate-800 text-xs text-slate-500 dark:text-slate-400">
              {isAr
                ? 'لا توجد طابعات مضافة بعد. أضف طابعة لفحص استجابتها وطابور الطباعة.'
                : 'No print targets configured yet. Add a network printer (9100/631/515) or Windows Print Spooler host to monitor real printing health.'}
            </div>
          ) : (
            <div className="space-y-2">
              {printTargets.map((p) => (
                <div
                  key={p.id}
                  className={`p-3 rounded-lg border text-xs flex items-center justify-between gap-2 ${
                    p.tested === false
                      ? 'border-slate-200 dark:border-slate-800'
                      : p.status === 'Offline' || p.status === 'Critical'
                        ? 'border-rose-300 dark:border-rose-800 bg-rose-50/40 dark:bg-rose-950/20'
                        : p.status === 'Warning'
                          ? 'border-amber-300 dark:border-amber-800 bg-amber-50/40 dark:bg-amber-950/20'
                          : 'border-slate-200 dark:border-slate-800'
                  }`}
                >
                  <div className="min-w-0">
                    <div className="font-semibold text-slate-900 dark:text-slate-100 truncate">
                      {p.name}
                    </div>
                    <div className="font-mono text-[11px] text-slate-500 dark:text-slate-400">
                      {p.hostOrIp}:{p.port} · {p.tested === false ? (isAr ? 'لم يتم الفحص' : 'Not tested') : (p.printerStateLabel || p.status)}
                    </div>
                    <div className="font-mono text-[11px] text-slate-600 dark:text-slate-300 mt-1">
                      {isAr ? 'الاستجابة:' : 'RTT:'}{' '}
                      {p.responseTimeMs !== null ? `${p.responseTimeMs} ms` : 'Unavailable'} ·{' '}
                      {isAr ? 'الطابور:' : 'Queue:'}{' '}
                      {p.queueDepth !== null ? `${p.queueDepth} jobs` : 'Unavailable (Win Spooler)'}
                    </div>
                  </div>
                  <div className="flex items-center gap-1 shrink-0">
                    <button
                      type="button"
                      disabled={!canEdit}
                      onClick={async () => {
                        const r = await onTestPrinter(p.id);
                        setFeedback(r.error || r.result?.details || 'Tested');
                      }}
                      className="p-1.5 rounded border border-slate-200 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800 disabled:opacity-40 cursor-pointer"
                      title="Test Printer"
                    >
                      <Activity className="w-3.5 h-3.5" />
                    </button>
                    {canEdit && (
                      <button
                        type="button"
                        onClick={() => onDeletePrinter(p.id)}
                        className="p-1.5 rounded text-rose-600 hover:bg-rose-50 dark:hover:bg-rose-950/30 cursor-pointer"
                        title="Remove Printer"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Right 7 cols: Report Execution & Bottleneck Isolation */}
        <div className="lg:col-span-7 space-y-2.5">
          <div className="text-xs font-semibold text-slate-800 dark:text-slate-200 flex items-center gap-1.5">
            <FileText className="w-3.5 h-3.5 text-slate-500" />
            <span>
              {isAr
                ? `سجل تنفيذ التقارير وتحديد مرحلة الاختناق (${reportExecutions.length})`
                : `Report Executions & Bottleneck Isolation (${reportExecutions.length})`}
            </span>
          </div>

          {reportExecutions.length === 0 ? (
            <div className="p-4 rounded-lg border border-dashed border-slate-200 dark:border-slate-800 text-xs text-slate-500 dark:text-slate-400">
              {isAr
                ? 'لا توجد قياسات تنفيذ تقارير مسجلة حالياً. ستظهر السجلات هنا عند توفير قياسات فعلية لعمليات التنفيذ.'
                : 'No report execution measurements have been recorded. Entries appear here only when actual execution timings are captured.'}
            </div>
          ) : (
            <div className="overflow-x-auto border border-slate-200 dark:border-slate-800 rounded-lg">
              <table className="w-full text-xs text-start">
                <thead className="bg-slate-50 dark:bg-slate-800/60 text-[11px] text-slate-500 dark:text-slate-400">
                  <tr>
                    <th className="py-2 px-3 text-start">{isAr ? 'التقرير / المستخدم' : 'Report / User'}</th>
                    <th className="py-2 px-2 text-start">{isAr ? 'السبب / المرحلة' : 'Suspected Bottleneck'}</th>
                    <th className="py-2 px-2 text-end">DB SQL</th>
                    <th className="py-2 px-2 text-end">App</th>
                    <th className="py-2 px-2 text-end">{isAr ? 'الطابعة' : 'Printer'}</th>
                    <th className="py-2 px-3 text-end">{isAr ? 'الإجمالي' : 'Total'}</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                  {reportExecutions.slice(0, 8).map((r) => (
                    <tr key={r.id}>
                      <td className="py-2 px-3">
                        <div className="font-medium text-slate-900 dark:text-slate-100 truncate max-w-[180px]" title={r.reportName}>
                          {r.reportName}
                        </div>
                        <div className="font-mono text-[11px] text-slate-500">
                          {r.requestedBy}{r.schemaName ? ` · ${r.schemaName}` : ''}
                        </div>
                      </td>
                      <td className="py-2 px-2">
                        <span className="inline-flex items-center gap-1 font-medium text-amber-700 dark:text-amber-300">
                          {r.status !== 'Completed' && <AlertTriangle className="w-3 h-3 shrink-0" />}
                          <span>{r.suspectedBottleneck}</span>
                        </span>
                      </td>
                      <td className="py-2 px-2 text-end font-mono tabular-nums">
                        {r.dbQueryMs !== null ? formatDurationMs(r.dbQueryMs) : 'N/A'}
                      </td>
                      <td className="py-2 px-2 text-end font-mono tabular-nums">
                        {r.appProcessingMs !== null ? formatDurationMs(r.appProcessingMs) : 'N/A'}
                      </td>
                      <td className="py-2 px-2 text-end font-mono tabular-nums">
                        {r.printerResponseMs !== null ? formatDurationMs(r.printerResponseMs) : 'N/A'}
                      </td>
                      <td className="py-2 px-3 text-end font-mono tabular-nums font-semibold text-slate-900 dark:text-slate-100">
                        {formatDurationMs(r.totalDurationMs)}
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
  );
}
