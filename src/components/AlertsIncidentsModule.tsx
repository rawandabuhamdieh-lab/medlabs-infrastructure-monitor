import { useEffect, useState, type FormEvent } from 'react';
import { Plus } from 'lucide-react';
import { COPY } from '../data/i18n';
import {
  AlertRecord,
  AlertSeverity,
  AlertThreshold,
  IncidentStatus,
  Language,
  UserRole,
} from '../types/infrastructure';
import { IncidentStatusText, SeverityText } from './StatusGlyph';

interface AlertsIncidentsModuleProps {
  alerts: AlertRecord[];
  thresholds: AlertThreshold[];
  currentRole: UserRole | null;
  lang: Language;
  onCreateIncident: (payload: {
    severity: AlertSeverity;
    module: AlertRecord['module'];
    assetName: string;
    title: string;
    description: string;
    downtimeMinutes: number;
  }) => Promise<string | null>;
  onUpdateIncident: (
    id: string,
    patch: {
      acknowledge?: boolean;
      status?: IncidentStatus;
      assignedTo?: string;
      resolutionNotes?: string;
      downtimeMinutes?: number;
    }
  ) => Promise<string | null>;
  onUpdateThreshold: (
    id: string,
    warningValue: number,
    criticalValue: number
  ) => Promise<string | null>;
}

export function AlertsIncidentsModule({
  alerts,
  thresholds,
  currentRole,
  lang,
  onCreateIncident,
  onUpdateIncident,
  onUpdateThreshold,
}: AlertsIncidentsModuleProps) {
  const copy = COPY[lang];
  const [severityFilter, setSeverityFilter] = useState<'all' | AlertSeverity>('all');
  const [selectedId, setSelectedId] = useState<string>(alerts[0]?.id ?? '');
  const [showNewForm, setShowNewForm] = useState(false);
  const [feedback, setFeedback] = useState<string | null>(null);

  // New incident form
  const [newSeverity, setNewSeverity] = useState<AlertSeverity>('High');
  const [newModule, setNewModule] = useState<AlertRecord['module']>('Windows Server');
  const [newAsset, setNewAsset] = useState('');
  const [newTitle, setNewTitle] = useState('');
  const [newDesc, setNewDesc] = useState('');
  const [newDowntime, setNewDowntime] = useState(0);

  // Edit selected incident
  const selected = alerts.find((a) => a.id === selectedId) ?? alerts[0];
  const [assignInput, setAssignInput] = useState(selected?.assignedTo ?? '');
  const [notesInput, setNotesInput] = useState(selected?.resolutionNotes ?? '');
  const [downtimeInput, setDowntimeInput] = useState<number>(selected?.downtimeMinutes ?? 0);

  useEffect(() => {
    setAssignInput(selected?.assignedTo ?? '');
    setNotesInput(selected?.resolutionNotes ?? '');
    setDowntimeInput(selected?.downtimeMinutes ?? 0);
  }, [selected?.id, selected?.assignedTo, selected?.resolutionNotes, selected?.downtimeMinutes]);

  // Threshold inline edit
  const [editingThresholdId, setEditingThresholdId] = useState<string | null>(null);
  const [warnInput, setWarnInput] = useState(0);
  const [critInput, setCritInput] = useState(0);

  const canTriage = currentRole !== null && ['Administrator', 'IT Manager', 'IT Engineer'].includes(currentRole);
  const canEditThresholds = currentRole !== null && ['Administrator', 'IT Manager'].includes(currentRole);

  const filtered = alerts.filter((a) => severityFilter === 'all' || a.severity === severityFilter);

  const selectAlert = (a: AlertRecord) => {
    setSelectedId(a.id);
    setAssignInput(a.assignedTo ?? '');
    setNotesInput(a.resolutionNotes ?? '');
    setDowntimeInput(a.downtimeMinutes);
    setFeedback(null);
  };

  const handleCreate = async (e: FormEvent) => {
    e.preventDefault();
    const err = await onCreateIncident({
      severity: newSeverity,
      module: newModule,
      assetName: newAsset,
      title: newTitle,
      description: newDesc,
      downtimeMinutes: newDowntime,
    });
    if (err) {
      setFeedback(err);
    } else {
      setNewTitle('');
      setNewDesc('');
      setShowNewForm(false);
      setFeedback(lang === 'ar' ? 'تم تسجيل الحادث بنجاح.' : 'Incident logged successfully.');
    }
  };

  const totalDowntime = alerts.reduce((acc, a) => acc + a.downtimeMinutes, 0);

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 pb-4 border-b border-slate-200 dark:border-slate-800">
        <div>
          <h1 className="text-xl font-semibold text-slate-900 dark:text-slate-100">
            {lang === 'ar' ? 'إدارة التنبيهات والحوادث والعتبات' : 'Alerts, Incidents & Threshold Management'}
          </h1>
          <p className="text-sm text-slate-600 dark:text-slate-400 mt-1">
            {lang === 'ar'
              ? 'متابعة 5 مستويات خطورة، الاستلام والتعيين، حساب وقت التوقف، وتعديل العتبات (بدون تدخل تلقائي مدمّر).'
              : '5-level severity triage, assignment, downtime tracking, and configurable thresholds (zero automated destructive actions).'}
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div className="text-xs font-mono tabular-nums text-slate-500 dark:text-slate-400">
            {lang === 'ar' ? 'إجمالي التوقف:' : 'Total Downtime:'} {totalDowntime} min
          </div>
          <button
            type="button"
            onClick={() => setShowNewForm((p) => !p)}
            className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-md whitespace-nowrap shrink-0 cursor-pointer"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>{lang === 'ar' ? 'تسجيل حادث' : 'New Incident'}</span>
          </button>
        </div>
      </div>

      {feedback && (
        <div className="p-3 bg-blue-50 dark:bg-blue-950/40 border border-blue-200 dark:border-blue-900 rounded-md text-xs text-blue-900 dark:text-blue-200">
          {feedback}
        </div>
      )}

      {showNewForm && (
        <form
          onSubmit={handleCreate}
          className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-5 space-y-4 text-xs"
        >
          <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
            {lang === 'ar' ? 'إضافة بلاغ حادث جديد' : 'Create Incident Record'}
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div>
              <label className="block font-medium text-slate-700 dark:text-slate-300 mb-1">
                {lang === 'ar' ? 'الخطورة' : 'Severity'}
              </label>
              <select
                value={newSeverity}
                onChange={(e) => setNewSeverity(e.target.value as AlertSeverity)}
                className="w-full px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md text-slate-900 dark:text-slate-100"
              >
                {(['Critical', 'High', 'Medium', 'Low', 'Information'] as AlertSeverity[]).map((s) => (
                  <option key={s} value={s}>{copy.severity[s]}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="block font-medium text-slate-700 dark:text-slate-300 mb-1">
                {lang === 'ar' ? 'الوحدة' : 'Module'}
              </label>
              <select
                value={newModule}
                onChange={(e) => setNewModule(e.target.value as AlertRecord['module'])}
                className="w-full px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md text-slate-900 dark:text-slate-100"
              >
                <option value="Windows Server">Windows Server</option>
                <option value="Oracle DB">Oracle DB</option>
                <option value="IIS & App">IIS &amp; App</option>
                <option value="Network">Network</option>
                <option value="Backup">Backup</option>
              </select>
            </div>
            <div>
              <label className="block font-medium text-slate-700 dark:text-slate-300 mb-1">
                {lang === 'ar' ? 'الأصل / الخادم' : 'Asset / Host'}
              </label>
              <input
                type="text"
                value={newAsset}
                onChange={(e) => setNewAsset(e.target.value)}
                placeholder="e.g. MLJ-APP-01"
                required
                className="w-full px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md font-mono text-slate-900 dark:text-slate-100"
              />
            </div>
            <div>
              <label className="block font-medium text-slate-700 dark:text-slate-300 mb-1">
                {lang === 'ar' ? 'التوقف (دقائق)' : 'Downtime (min)'}
              </label>
              <input
                type="number"
                min={0}
                value={newDowntime}
                onChange={(e) => setNewDowntime(Number(e.target.value))}
                className="w-full px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md font-mono text-slate-900 dark:text-slate-100"
              />
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block font-medium text-slate-700 dark:text-slate-300 mb-1">
                {lang === 'ar' ? 'الملخص' : 'Summary'}
              </label>
              <input
                type="text"
                value={newTitle}
                onChange={(e) => setNewTitle(e.target.value)}
                required
                className="w-full px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md text-slate-900 dark:text-slate-100"
              />
            </div>
            <div>
              <label className="block font-medium text-slate-700 dark:text-slate-300 mb-1">
                {lang === 'ar' ? 'الوصف' : 'Diagnostic Detail'}
              </label>
              <input
                type="text"
                value={newDesc}
                onChange={(e) => setNewDesc(e.target.value)}
                className="w-full px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md text-slate-900 dark:text-slate-100"
              />
            </div>
          </div>

          <div className="flex justify-end gap-2">
            <button
              type="button"
              onClick={() => setShowNewForm(false)}
              className="px-3 py-1.5 rounded border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300 cursor-pointer"
            >
              {copy.common.cancel}
            </button>
            <button
              type="submit"
              disabled={!canTriage}
              className="px-4 py-1.5 rounded bg-blue-600 text-white hover:bg-blue-700 disabled:opacity-50 cursor-pointer"
            >
              {canTriage
                ? copy.common.save
                : lang === 'ar'
                  ? 'يتطلب صلاحية مهندس/مدير'
                  : 'Sign in as Engineer+ to Save'}
            </button>
          </div>
        </form>
      )}

      {/* Severity Filter Bar */}
      <div className="inline-flex flex-wrap items-center p-1 bg-slate-100 dark:bg-slate-800 rounded-md">
        {(['all', 'Critical', 'High', 'Medium', 'Low', 'Information'] as const).map((sev) => (
          <button
            key={sev}
            type="button"
            onClick={() => setSeverityFilter(sev)}
            className={`px-3 py-1 text-xs font-medium rounded transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
              severityFilter === sev
                ? 'bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100 shadow-xs'
                : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
            }`}
          >
            {sev === 'all' ? copy.common.all : copy.severity[sev]}
          </button>
        ))}
      </div>

      {/* Incidents Table + Triage Drawer */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        <section className={`${selected ? 'lg:col-span-7' : 'lg:col-span-12'} bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg overflow-hidden`}>
          {filtered.length === 0 ? (
            <div className="p-8 text-center text-xs text-slate-500 dark:text-slate-400">
              {alerts.length === 0
                ? lang === 'ar'
                  ? 'لا توجد تنبيهات أو حوادث حالياً — ستظهر تلقائياً عند تجاوز العتبات من قراءات السيرفرات الحقيقية.'
                  : 'No active alerts or incidents — threshold breaches from live collectors appear here automatically.'
                : copy.common.noResults}
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-start border-collapse">
                <thead>
                  <tr className="border-b border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/50 text-[11px] font-semibold text-slate-500 dark:text-slate-400">
                    <th className="py-2.5 px-4 text-start">ID</th>
                    <th className="py-2.5 px-3 text-start">{lang === 'ar' ? 'الخطورة' : 'Severity'}</th>
                    <th className="py-2.5 px-3 text-start">{lang === 'ar' ? 'الحادث' : 'Summary'}</th>
                    <th className="py-2.5 px-3 text-start">{lang === 'ar' ? 'الحالة' : 'Status'}</th>
                    <th className="py-2.5 px-4 text-end">{lang === 'ar' ? 'التوقف' : 'Downtime'}</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 dark:divide-slate-800 text-xs">
                  {filtered.map((alert) => (
                    <tr
                      key={alert.id}
                      onClick={() => selectAlert(alert)}
                      className={`cursor-pointer transition-colors ${
                        selected?.id === alert.id
                          ? 'bg-blue-50/70 dark:bg-blue-950/30'
                          : 'hover:bg-slate-50 dark:hover:bg-slate-800/40'
                      }`}
                    >
                      <td className="py-3 px-4 font-mono font-semibold text-slate-900 dark:text-slate-100 whitespace-nowrap">
                        {alert.id}
                      </td>
                      <td className="py-3 px-3">
                        <SeverityText severity={alert.severity} label={copy.severity[alert.severity]} />
                      </td>
                      <td className="py-3 px-3">
                        <div className="font-medium text-slate-900 dark:text-slate-100">
                          {lang === 'ar' ? alert.titleAr : alert.title}
                        </div>
                        <div className="text-[11px] font-mono text-slate-500 dark:text-slate-400">
                          {alert.module} · {alert.assetName}
                        </div>
                      </td>
                      <td className="py-3 px-3">
                        <IncidentStatusText status={alert.status} label={copy.incidentStatus[alert.status]} />
                      </td>
                      <td className="py-3 px-4 text-end font-mono tabular-nums text-slate-700 dark:text-slate-300">
                        {alert.downtimeMinutes}m
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        {selected && (
          <aside className="lg:col-span-5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-5 space-y-4 text-xs">
            <div className="flex items-start justify-between gap-2 pb-3 border-b border-slate-100 dark:border-slate-800">
              <div>
                <div className="font-mono text-slate-500 dark:text-slate-400">
                  {selected.id} · {selected.timestamp}
                </div>
                <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100 mt-1">
                  {lang === 'ar' ? selected.titleAr : selected.title}
                </h2>
              </div>
              <SeverityText severity={selected.severity} label={copy.severity[selected.severity]} />
            </div>

            <p className="text-slate-600 dark:text-slate-300 leading-relaxed">
              {lang === 'ar' ? selected.descriptionAr : selected.description}
            </p>

            <div className="text-[11px] text-slate-500 dark:text-slate-400 space-y-1">
              <div>
                {lang === 'ar' ? 'المستلم:' : 'Acknowledged by:'}{' '}
                <span className="font-medium text-slate-800 dark:text-slate-200">
                  {selected.acknowledgedBy || '—'}
                </span>
              </div>
              <div>
                {lang === 'ar' ? 'الإشعارات:' : 'Notifications:'}{' '}
                <span className="font-mono">{selected.notifiedChannels.join(' · ')}</span>
              </div>
            </div>

            <div className="space-y-3 pt-2 border-t border-slate-100 dark:border-slate-800">
              <div>
                <label className="block font-medium text-slate-700 dark:text-slate-300 mb-1">
                  {lang === 'ar' ? 'تعيين إلى' : 'Assign To'}
                </label>
                <input
                  type="text"
                  value={assignInput}
                  onChange={(e) => setAssignInput(e.target.value)}
                  placeholder="e.g. Rami Khoury (IT Engineer)"
                  className="w-full px-3 py-1.5 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md text-slate-900 dark:text-slate-100"
                />
              </div>

              <div>
                <label className="block font-medium text-slate-700 dark:text-slate-300 mb-1">
                  {lang === 'ar' ? 'مدة التوقف (دقائق)' : 'Downtime (minutes)'}
                </label>
                <input
                  type="number"
                  min={0}
                  value={downtimeInput}
                  onChange={(e) => setDowntimeInput(Number(e.target.value))}
                  className="w-full px-3 py-1.5 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md font-mono text-slate-900 dark:text-slate-100"
                />
              </div>

              <div>
                <label className="block font-medium text-slate-700 dark:text-slate-300 mb-1">
                  {lang === 'ar' ? 'ملاحظات الحل' : 'Resolution Notes'}
                </label>
                <textarea
                  rows={2}
                  value={notesInput}
                  onChange={(e) => setNotesInput(e.target.value)}
                  className="w-full px-3 py-1.5 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md text-slate-900 dark:text-slate-100"
                />
              </div>

              <div className="flex flex-wrap gap-2 pt-1">
                <button
                  type="button"
                  disabled={!canTriage}
                  onClick={async () => {
                    const err = await onUpdateIncident(selected.id, {
                      acknowledge: true,
                      assignedTo: assignInput,
                      resolutionNotes: notesInput,
                      downtimeMinutes: downtimeInput,
                    });
                    setFeedback(err || (lang === 'ar' ? 'تم استلام وتحديث الحادث.' : 'Incident acknowledged & updated.'));
                  }}
                  className="px-3 py-1.5 rounded border border-slate-200 dark:border-slate-700 text-slate-800 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-800 disabled:opacity-50 cursor-pointer"
                >
                  {lang === 'ar' ? 'استلام / حفظ' : 'Acknowledge & Save'}
                </button>
                <button
                  type="button"
                  disabled={!canTriage}
                  onClick={async () => {
                    const err = await onUpdateIncident(selected.id, {
                      status: 'Resolved',
                      assignedTo: assignInput,
                      resolutionNotes: notesInput,
                      downtimeMinutes: downtimeInput,
                    });
                    setFeedback(err || (lang === 'ar' ? 'تم إغلاق الحادث.' : 'Incident marked Resolved.'));
                  }}
                  className="px-3 py-1.5 rounded bg-emerald-600 text-white hover:bg-emerald-700 disabled:opacity-50 cursor-pointer"
                >
                  {lang === 'ar' ? 'إغلاق كمحلول' : 'Mark Resolved'}
                </button>
              </div>
            </div>
          </aside>
        )}
      </div>

      {/* Configurable Thresholds Table */}
      <section className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-100 dark:border-slate-800">
          <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
            {lang === 'ar' ? 'عتبات التنبيه القابلة للتخصيص' : 'Configurable Alert Thresholds'}
          </h2>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            {lang === 'ar'
              ? 'متاحة للتعديل من قِبل Administrator و IT Manager مع تسجيل التغيير في سجل التدقيق.'
              : 'Editable by Administrator and IT Manager roles; all edits are audit-logged.'}
          </p>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-start border-collapse">
            <thead>
              <tr className="border-b border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/50 text-[11px] font-semibold text-slate-500 dark:text-slate-400">
                <th className="py-2.5 px-4 text-start">{lang === 'ar' ? 'المؤشر' : 'Metric Rule'}</th>
                <th className="py-2.5 px-3 text-end">{lang === 'ar' ? 'عتبة التحذير' : 'Warning'}</th>
                <th className="py-2.5 px-3 text-end">{lang === 'ar' ? 'العتبة الحرجة' : 'Critical'}</th>
                <th className="py-2.5 px-3 text-start">{lang === 'ar' ? 'آخر تعديل' : 'Updated By'}</th>
                <th className="py-2.5 px-4 text-end">{copy.common.actions}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800 text-xs">
              {thresholds.map((t) => {
                const isEditing = editingThresholdId === t.id;
                return (
                  <tr key={t.id} className="hover:bg-slate-50 dark:hover:bg-slate-800/40">
                    <td className="py-3 px-4">
                      <div className="font-medium text-slate-900 dark:text-slate-100">
                        {lang === 'ar' ? t.labelAr : t.label}
                      </div>
                      <div className="font-mono text-[11px] text-slate-500 dark:text-slate-400">{t.metricKey}</div>
                    </td>
                    <td className="py-3 px-3 text-end font-mono tabular-nums">
                      {isEditing ? (
                        <input
                          type="number"
                          step="0.1"
                          value={warnInput}
                          onChange={(e) => setWarnInput(Number(e.target.value))}
                          className="w-20 px-2 py-1 bg-white dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded text-end"
                        />
                      ) : (
                        <span className="text-amber-700 dark:text-amber-400 font-semibold">
                          {t.warningValue} {t.unit}
                        </span>
                      )}
                    </td>
                    <td className="py-3 px-3 text-end font-mono tabular-nums">
                      {isEditing ? (
                        <input
                          type="number"
                          step="0.1"
                          value={critInput}
                          onChange={(e) => setCritInput(Number(e.target.value))}
                          className="w-20 px-2 py-1 bg-white dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded text-end"
                        />
                      ) : (
                        <span className="text-rose-700 dark:text-rose-400 font-semibold">
                          {t.criticalValue} {t.unit}
                        </span>
                      )}
                    </td>
                    <td className="py-3 px-3 text-slate-500 dark:text-slate-400">
                      {t.updatedBy} · {t.updatedAt}
                    </td>
                    <td className="py-3 px-4 text-end">
                      {isEditing ? (
                        <div className="inline-flex gap-2">
                          <button
                            type="button"
                            onClick={async () => {
                              const err = await onUpdateThreshold(t.id, warnInput, critInput);
                              if (err) setFeedback(err);
                              else setEditingThresholdId(null);
                            }}
                            className="text-blue-600 dark:text-blue-400 font-medium cursor-pointer"
                          >
                            {copy.common.save}
                          </button>
                          <button
                            type="button"
                            onClick={() => setEditingThresholdId(null)}
                            className="text-slate-500 cursor-pointer"
                          >
                            {copy.common.cancel}
                          </button>
                        </div>
                      ) : (
                        <button
                          type="button"
                          disabled={!canEditThresholds}
                          onClick={() => {
                            setEditingThresholdId(t.id);
                            setWarnInput(t.warningValue);
                            setCritInput(t.criticalValue);
                          }}
                          className="text-xs font-medium text-blue-600 dark:text-blue-400 hover:underline disabled:opacity-40 cursor-pointer"
                        >
                          {lang === 'ar' ? 'تعديل' : 'Edit'}
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
