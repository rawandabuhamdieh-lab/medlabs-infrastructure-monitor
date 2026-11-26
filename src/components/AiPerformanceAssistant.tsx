import { useState } from 'react';
import { AlertCircle, CheckCircle2, ShieldAlert, Sparkles } from 'lucide-react';
import type { AiAnalysisResponse, Language, MonitoringComponentKey } from '../types/infrastructure';

interface AiPerformanceAssistantProps {
  lang: Language;
  focusComponent?: MonitoringComponentKey | null;
  selectedIncidentId?: string | null;
}

export function AiPerformanceAssistant({
  lang,
  focusComponent,
  selectedIncidentId,
}: AiPerformanceAssistantProps) {
  const isAr = lang === 'ar';
  const [question, setQuestion] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [analysis, setAnalysis] = useState<AiAnalysisResponse | null>(null);

  const runAnalysis = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch('/api/ai/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          lang,
          focusComponent: focusComponent || 'System-Wide',
          incidentId: selectedIncidentId || undefined,
          question: question.trim() || undefined,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data?.error || `AI analysis request failed (${res.status}).`);
        return;
      }
      setAnalysis(data as AiAnalysisResponse);
    } catch {
      setError(
        isAr
          ? 'تعذر الاتصال بخدمة تحليل الذكاء الاصطناعي على الخادم.'
          : 'Network error contacting backend AI analysis endpoint.'
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <section className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-5 space-y-4">
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-3 pb-3 border-b border-slate-100 dark:border-slate-800">
        <div>
          <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100 flex items-center gap-2">
            <Sparkles className="w-4 h-4 text-indigo-600 dark:text-indigo-400" />
            <span>
              {isAr
                ? 'مساعد تحليل الأداء بالذكاء الاصطناعي (للقراءة فقط — بدون تنفيذ تلقائي)'
                : 'AI Performance Assistant (Read-Only Advisory)'}
            </span>
          </h2>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            {isAr
              ? 'يحلل البيانات الحقيقية ونتائج RCA عبر خادم Gemini API ويشرح السبب والأدلة وخطوات التحقق دون أي تعديل تلقائي على النظام.'
              : 'Interprets live collector telemetry & RCA evidence via server-side Gemini API. Zero automated DB or infrastructure changes — admin approval required.'}
          </p>
        </div>

        <button
          type="button"
          disabled={loading}
          onClick={runAnalysis}
          className="inline-flex items-center gap-2 px-4 py-2 rounded-md bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-medium disabled:opacity-50 whitespace-nowrap shrink-0 cursor-pointer"
        >
          <Sparkles className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>
            {loading
              ? isAr
                ? 'جارٍ تحليل البيانات الحقيقية...'
                : 'Analyzing Live Telemetry...'
              : isAr
                ? 'تشغيل التحليل الذكي الآن'
                : 'Analyze Current Telemetry'}
          </span>
        </button>
      </div>

      {/* Optional specific prompt input */}
      <div className="flex flex-col sm:flex-row gap-2">
        <input
          type="text"
          value={question}
          onChange={(e) => setQuestion(e.target.value)}
          placeholder={
            isAr
              ? 'سؤال اختياري (مثال: لماذا النظام بطيء للمستخدمين الآن؟ أو ما سبب تأخر طباعة التقارير؟)'
              : 'Optional question (e.g., Why is the Lab App slow right now? Which user/query is causing wait?)'
          }
          className="flex-1 px-3 py-2 text-xs rounded-md border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100 focus:outline-none focus:border-indigo-500"
        />
      </div>

      {error && (
        <div className="p-3.5 rounded-md border border-rose-200 dark:border-rose-800 bg-rose-50 dark:bg-rose-950/30 text-xs text-rose-800 dark:text-rose-200 flex items-start gap-2.5">
          <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
          <div className="space-y-1">
            <div className="font-semibold">
              {isAr ? 'خدمة التحليل الذكي غير مفعّلة أو حدث خطأ' : 'AI Assistant Unavailable'}
            </div>
            <div>{error}</div>
          </div>
        </div>
      )}

      {analysis && (
        <div className="space-y-4 text-xs border-t border-slate-100 dark:border-slate-800 pt-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <span className="font-mono text-[11px] px-2 py-0.5 rounded bg-indigo-50 dark:bg-indigo-950/50 border border-indigo-200 dark:border-indigo-800 text-indigo-800 dark:text-indigo-300">
                AI-Generated Advisory · {analysis.model}
              </span>
              <span
                className={`font-semibold px-2 py-0.5 rounded border ${
                  analysis.priority === 'Critical'
                    ? 'bg-rose-50 dark:bg-rose-950/40 border-rose-200 text-rose-700 dark:text-rose-300'
                    : analysis.priority === 'High'
                      ? 'bg-orange-50 dark:bg-orange-950/40 border-orange-200 text-orange-700 dark:text-orange-300'
                      : 'bg-slate-100 dark:bg-slate-800 border-slate-200 text-slate-700 dark:text-slate-300'
                }`}
              >
                {isAr ? 'الأولوية:' : 'Priority:'} {analysis.priority}
              </span>
            </div>
            <span className="font-mono text-[11px] text-slate-500">{analysis.generatedAt}</span>
          </div>

          {analysis.insufficientDataNote && (
            <div className="p-3 rounded-md border border-amber-200 dark:border-amber-800 bg-amber-50/70 dark:bg-amber-950/30 text-amber-900 dark:text-amber-200 flex items-start gap-2">
              <ShieldAlert className="w-4 h-4 shrink-0 mt-0.5" />
              <span>{analysis.insufficientDataNote}</span>
            </div>
          )}

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="p-3.5 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50/60 dark:bg-slate-950/50 space-y-1.5">
              <div className="font-semibold text-slate-900 dark:text-slate-100">
                {isAr ? 'شرح المشكلة' : 'Problem Explanation'}
              </div>
              <p className="text-slate-700 dark:text-slate-300 leading-relaxed">{analysis.problemExplanation}</p>
            </div>

            <div className="p-3.5 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50/60 dark:bg-slate-950/50 space-y-1.5">
              <div className="font-semibold text-slate-900 dark:text-slate-100">
                {isAr ? 'السبب الجذري' : 'Root Cause'}
              </div>
              <p className="text-slate-700 dark:text-slate-300 leading-relaxed">{analysis.rootCause}</p>
            </div>
          </div>

          <div className="p-3.5 rounded-lg border border-slate-200 dark:border-slate-800 space-y-1.5">
            <div className="font-semibold text-slate-900 dark:text-slate-100">
              {isAr ? 'تأثير العمل والنظام' : 'Business & System Impact'}
            </div>
            <p className="text-slate-700 dark:text-slate-300 leading-relaxed">{analysis.businessImpact}</p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="p-3.5 rounded-lg border border-slate-200 dark:border-slate-800 space-y-2">
              <div className="font-semibold text-slate-900 dark:text-slate-100">
                {isAr ? 'الأدلة المرصودة' : 'Observed Evidence'}
              </div>
              <ul className="space-y-1 text-slate-600 dark:text-slate-300 list-disc ps-4">
                {analysis.evidence.map((ev, i) => (
                  <li key={i}>{ev}</li>
                ))}
              </ul>
            </div>

            <div className="p-3.5 rounded-lg border border-emerald-200 dark:border-emerald-900 bg-emerald-50/50 dark:bg-emerald-950/20 space-y-2">
              <div className="font-semibold text-emerald-900 dark:text-emerald-200">
                {isAr ? 'الحلول المقترحة (تتطلب موافقة المسؤول)' : 'Recommended Solutions (Admin Approval Required)'}
              </div>
              <ul className="space-y-1 text-emerald-900 dark:text-emerald-200 list-disc ps-4">
                {analysis.recommendedSolution.map((sol, i) => (
                  <li key={i}>{sol}</li>
                ))}
              </ul>
            </div>

            <div className="p-3.5 rounded-lg border border-slate-200 dark:border-slate-800 space-y-2">
              <div className="font-semibold text-slate-900 dark:text-slate-100 flex items-center gap-1.5">
                <CheckCircle2 className="w-3.5 h-3.5 text-blue-600" />
                <span>{isAr ? 'خطوات التحقق' : 'Verification Steps'}</span>
              </div>
              <ul className="space-y-1 text-slate-600 dark:text-slate-300 list-disc ps-4">
                {analysis.verificationSteps.map((step, i) => (
                  <li key={i}>{step}</li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      )}
    </section>
  );
}
