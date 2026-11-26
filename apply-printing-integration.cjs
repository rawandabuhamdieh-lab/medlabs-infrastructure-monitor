const fs = require("fs");

function replaceOnce(file, from, to, label) {
  let s = fs.readFileSync(file, "utf8");
  const n = s.split(from).length - 1;
  if (n !== 1) throw new Error(`${file}: ${label}: expected 1 match, found ${n}`);
  fs.writeFileSync(file, s.replace(from, to), "utf8");
  console.log("Updated:", label);
}

function update(file, fn, label) {
  const s = fs.readFileSync(file, "utf8");
  const next = fn(s);
  if (next === s) {
    console.log("Already updated:", label);
    return;
  }
  fs.writeFileSync(file, next, "utf8");
  console.log("Updated:", label);
}

// SERVER: imports
replaceOnce(
  "server.ts",
  "import { collectNetworkDevice, testNetworkConnection } from './src/engine/networkCollector.ts';",
  "import { collectNetworkDevice, testNetworkConnection } from './src/engine/networkCollector.ts';\nimport { collectPrintTarget } from './src/engine/printingCollector.ts';",
  "server printing collector import"
);

replaceOnce(
  "server.ts",
  "  OracleDatabaseMetric,\n  TimelineSample,",
  "  OracleDatabaseMetric,\n  PrintMonitorTarget,\n  TimelineSample,",
  "server printing type import"
);

// SERVER: persisted state
replaceOnce(
  "server.ts",
  "  reports: persisted?.reports ?? structuredClone(HISTORICAL_REPORTS),\n  timeline:",
  "  reports: persisted?.reports ?? structuredClone(HISTORICAL_REPORTS),\n  printTargets: persisted?.printTargets ?? ([] as PrintMonitorTarget[]),\n  reportExecutions: persisted?.reportExecutions ?? [],\n  timeline:",
  "server printing state"
);

replaceOnce(
  "server.ts",
  "    reports: state.reports,\n    timeline:",
  "    reports: state.reports,\n    printTargets: state.printTargets,\n    reportExecutions: state.reportExecutions,\n    timeline:",
  "server printing persistence"
);

replaceOnce(
  "server.ts",
  "      reports: state.reports,\n      timeline:",
  "      reports: state.reports,\n      printTargets: state.printTargets,\n      reportExecutions: state.reportExecutions,\n      timeline:",
  "server printing snapshot"
);

// SERVER: printer routes inserted before IIS routes
const serverRoutes = `  // ==================== PRINTING & REPORT MONITORING ====================
  app.post(
    '/api/printing/printers',
    requireRole(['Administrator', 'IT Manager', 'IT Engineer']),
    (req: AuthedRequest, res: Response) => {
      const name = typeof req.body?.name === 'string' ? req.body.name.trim().slice(0, 100) : '';
      const hostOrIp = typeof req.body?.hostOrIp === 'string' ? req.body.hostOrIp.trim().slice(0, 253) : '';
      const site = typeof req.body?.site === 'string' ? req.body.site.trim().slice(0, 100) : 'MedLabs Central';
      const protocols: PrintMonitorTarget['protocol'][] = ['RAW-9100', 'IPP-631', 'LPD-515', 'Windows-Spooler'];
      const protocol = protocols.includes(req.body?.protocol) ? req.body.protocol : null;
      const port = Number(req.body?.port);
      const spoolerHost = typeof req.body?.spoolerHost === 'string'
        ? req.body.spoolerHost.trim().slice(0, 253)
        : '';

      if (!name || !hostOrIp || !isValidTargetHost(hostOrIp) || !protocol ||
          !Number.isInteger(port) || port < 1 || port > 65535 ||
          (spoolerHost && !isValidTargetHost(spoolerHost))) {
        res.status(400).json({ error: 'Valid printer name, host, protocol and port are required.' });
        return;
      }

      const created: PrintMonitorTarget = {
        id: nextPrefixedId(state.printTargets, 'PRN'),
        name,
        site: site || 'MedLabs Central',
        hostOrIp,
        protocol,
        port,
        spoolerHost: spoolerHost || undefined,
        status: 'Offline',
        responseTimeMs: null,
        queueDepth: null,
        failedJobs24h: null,
        printerStateLabel: 'Not tested',
        lastCheck: 'Not tested',
        tested: false,
      };

      // Registration only stores configuration. It does not probe the printer.
      state.printTargets.unshift(created);
      persistNow();
      appendAudit(
        req.sessionUser!.username,
        req.sessionUser!.role,
        'PRINT_TARGET_ADDED',
        \`\${name} (\${hostOrIp}:\${port})\`,
        'Success',
        'Printer registered without running a connection test.'
      );
      res.status(201).json(created);
    }
  );

  app.post(
    '/api/printing/printers/:id/test',
    requireRole(['Administrator', 'IT Manager', 'IT Engineer']),
    async (req: AuthedRequest, res: Response) => {
      const printer = state.printTargets.find((p) => p.id === req.params.id);
      if (!printer) {
        res.status(404).json({ error: 'Printer target not found.' });
        return;
      }

      const outcome = await collectPrintTarget(printer, vault);
      persistNow();
      appendAudit(
        req.sessionUser!.username,
        req.sessionUser!.role,
        'PRINT_TARGET_TEST',
        \`\${printer.name} (\${printer.hostOrIp}:\${printer.port})\`,
        outcome.ok ? 'Success' : 'Denied',
        \`\${outcome.integrity.collectionStatus}: \${outcome.integrity.errorDetail || outcome.integrity.dataSource}\`
      );
      res.json({
        ok: outcome.ok,
        status: outcome.integrity.collectionStatus,
        dataSource: outcome.integrity.dataSource,
        latencyMs: printer.responseTimeMs,
        measuredAt: outcome.integrity.measuredAt,
        details: outcome.ok
          ? \`Printer \${printer.name} reachable in \${printer.responseTimeMs} ms\${printer.queueDepth !== null ? \` · Queue=\${printer.queueDepth}\` : ''}.\`
          : outcome.integrity.errorDetail || 'Printer unreachable.',
        prerequisiteHint: outcome.integrity.prerequisiteHint,
      });
    }
  );

  app.post(
    '/api/printing/poll-all',
    requireRole(['Administrator', 'IT Manager', 'IT Engineer']),
    async (req: AuthedRequest, res: Response) => {
      let tested = 0;
      let reachable = 0;
      for (const printer of state.printTargets) {
        const outcome = await collectPrintTarget(printer, vault);
        tested += 1;
        if (outcome.ok) reachable += 1;
      }
      persistNow();
      appendAudit(
        req.sessionUser!.username,
        req.sessionUser!.role,
        'PRINT_TARGETS_POLL_ALL',
        \`\${tested} printers\`,
        'Success',
        \`Manual sweep completed. Reachable=\${reachable}; Unreachable=\${tested - reachable}.\`
      );
      res.json({ polled: tested, reachable });
    }
  );

  app.delete(
    '/api/printing/printers/:id',
    requireRole(['Administrator', 'IT Manager', 'IT Engineer']),
    (req: AuthedRequest, res: Response) => {
      const idx = state.printTargets.findIndex((p) => p.id === req.params.id);
      if (idx === -1) {
        res.status(404).json({ error: 'Printer target not found.' });
        return;
      }
      const [removed] = state.printTargets.splice(idx, 1);
      persistNow();
      appendAudit(
        req.sessionUser!.username,
        req.sessionUser!.role,
        'PRINT_TARGET_DELETED',
        \`\${removed.name} (\${removed.hostOrIp})\`,
        'Success',
        'Removed printer monitoring target.'
      );
      res.json({ deleted: removed.id });
    }
  );

`;

replaceOnce(
  "server.ts",
  "  // ==================== IIS SITES & HTTP/HTTPS ENDPOINTS ====================",
  serverRoutes + "  // ==================== IIS SITES & HTTP/HTTPS ENDPOINTS ====================",
  "server printing API routes"
);

// APP imports
replaceOnce(
  "src/App.tsx",
  "  Network,\n  RefreshCw,",
  "  Network,\n  Printer,\n  RefreshCw,",
  "App Printer icon import"
);

replaceOnce(
  "src/App.tsx",
  "import { OracleModule } from './components/OracleModule';",
  "import { OracleModule } from './components/OracleModule';\nimport { PrintingMonitoringPanel } from './components/PrintingMonitoringPanel';",
  "App printing panel import"
);

replaceOnce(
  "src/App.tsx",
  "  OracleDatabaseMetric,\n  ThemeMode,",
  "  OracleDatabaseMetric,\n  PrintMonitorTarget,\n  ReportExecutionRecord,\n  ThemeMode,",
  "App printing types"
);

// APP state
replaceOnce(
  "src/App.tsx",
  "  const [reports, setReports] = useState<DailyReportRow[]>(HISTORICAL_REPORTS);\n",
  "  const [reports, setReports] = useState<DailyReportRow[]>(HISTORICAL_REPORTS);\n  const [printTargets, setPrintTargets] = useState<PrintMonitorTarget[]>([]);\n  const [reportExecutions, setReportExecutions] = useState<ReportExecutionRecord[]>([]);\n",
  "App printing state"
);

replaceOnce(
  "src/App.tsx",
  "        setReports(d.reports);\n",
  "        setReports(d.reports);\n        setPrintTargets(d.printTargets ?? []);\n        setReportExecutions(d.reportExecutions ?? []);\n",
  "App printing snapshot mapping"
);

// APP navigation
replaceOnce(
  "src/App.tsx",
  "    { id: 'architecture', label: copy.nav.architecture, icon: Cpu },",
  "    { id: 'architecture', label: copy.nav.architecture, icon: Cpu },\n    { id: 'printing', label: lang === 'ar' ? 'مراقبة الطباعة والتقارير' : 'Printing & Reports', icon: Printer },",
  "App printing navigation"
);

// APP render
const printingRender = `          {activeSection === 'printing' && (
            <PrintingMonitoringPanel
              printTargets={printTargets}
              reportExecutions={reportExecutions}
              currentRole={sessionUser?.role ?? null}
              lang={lang}
              onRegisterPrinter={(payload) => authedFetch('/api/printing/printers', 'POST', payload)}
              onTestPrinter={async (id) => {
                const result = await authedTestFetch(\`/api/printing/printers/\${id}/test\`);
                if (result.result) await fetchSnapshot(authToken);
                return result;
              }}
              onPollAllPrinters={() => authedFetch('/api/printing/poll-all', 'POST', {})}
              onDeletePrinter={(id) => authedFetch(\`/api/printing/printers/\${id}\`, 'DELETE')}
            />
          )}

`;
replaceOnce(
  "src/App.tsx",
  "          {activeSection === 'architecture' && (",
  printingRender + "          {activeSection === 'architecture' && (",
  "App printing screen"
);

// PANEL: registration message and button
replaceOnce(
  "src/components/PrintingMonitoringPanel.tsx",
  "setFeedback(isAr ? 'تمت إضافة الطابعة وفحصها.' : 'Printer registered and probed.');",
  "setFeedback(isAr ? 'تمت إضافة الطابعة. يمكنك إجراء الفحص يدوياً عند الحاجة.' : 'Printer registered. Run a manual test when ready.');",
  "panel registration feedback"
);

replaceOnce(
  "src/components/PrintingMonitoringPanel.tsx",
  "{canEdit ? (isAr ? 'حفظ وفحص' : 'Save & Probe') :",
  "{canEdit ? (isAr ? 'حفظ الطابعة' : 'Save Printer') :",
  "panel registration button"
);

// PANEL: report empty state
replaceOnce(
  "src/components/PrintingMonitoringPanel.tsx",
  "? 'لا توجد تقارير ثقيلة أو سجلات طباعة مرصودة حالياً. تظهر هنا تلقائياً عند رصد جلسات تقارير في Oracle V$SESSION أو إرسال قياسات تنفيذ التقارير.'\n                : 'No slow report executions recorded right now. Active Oracle report sessions (Crystal/Jasper/BI/Print in V$SESSION) and logged report timings appear here automatically.'",
  "? 'لا توجد قياسات تنفيذ تقارير مسجلة حالياً. ستظهر السجلات هنا عند توفير قياسات فعلية لعمليات التنفيذ.'\n                : 'No report execution measurements have been recorded. Entries appear here only when actual execution timings are captured.'",
  "panel truthful report empty state"
);

// PANEL: show not-tested state, and neutral styling before first probe
update("src/components/PrintingMonitoringPanel.tsx", s => {
  const oldClass = `p.status === 'Offline' || p.status === 'Critical'
                      ? 'border-rose-300 dark:border-rose-800 bg-rose-50/40 dark:bg-rose-950/20'
                      : p.status === 'Warning'
                        ? 'border-amber-300 dark:border-amber-800 bg-amber-50/40 dark:bg-amber-950/20'
                        : 'border-slate-200 dark:border-slate-800'`;
  const newClass = `p.tested === false
                      ? 'border-slate-200 dark:border-slate-800'
                      : p.status === 'Offline' || p.status === 'Critical'
                        ? 'border-rose-300 dark:border-rose-800 bg-rose-50/40 dark:bg-rose-950/20'
                        : p.status === 'Warning'
                          ? 'border-amber-300 dark:border-amber-800 bg-amber-50/40 dark:bg-amber-950/20'
                          : 'border-slate-200 dark:border-slate-800'`;
  if (!s.includes(oldClass)) throw new Error("Panel printer status class anchor missing");
  s = s.replace(oldClass, newClass);

  const oldStatus = "{p.hostOrIp}:{p.port} · {p.printerStateLabel || p.status}";
  const newStatus = "{p.hostOrIp}:{p.port} · {p.tested === false ? (isAr ? 'لم يتم الفحص' : 'Not tested') : (p.printerStateLabel || p.status)}";
  if (!s.includes(oldStatus)) throw new Error("Panel printer status text anchor missing");
  s = s.replace(oldStatus, newStatus);
  return s;
}, "panel not-tested state");

console.log("\nPrinting monitoring integration edits completed.");
