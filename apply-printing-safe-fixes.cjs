const fs = require("fs");

function update(file, fn) {
  const original = fs.readFileSync(file, "utf8");
  const updated = fn(original);
  if (updated === original) {
    console.log("No change needed:", file);
    return;
  }
  fs.writeFileSync(file, updated, "utf8");
  console.log("Updated:", file);
}

// Types
update("src/types/infrastructure.ts", s => {
  if (!s.includes("| 'printing';")) {
    const anchor = "  | 'architecture';";
    if (!s.includes(anchor)) throw new Error("ModuleSection anchor missing");
    s = s.replace(anchor, "  | 'architecture'\n  | 'printing';");
  }

  const start = s.indexOf("export interface PrintMonitorTarget {");
  if (start < 0) throw new Error("PrintMonitorTarget interface missing");
  const end = s.indexOf("\n}", start);
  if (end < 0) throw new Error("PrintMonitorTarget closing brace missing");
  const block = s.slice(start, end);
  if (!block.includes("tested?: boolean;")) {
    s = s.slice(0, end) + "\n  tested?: boolean;" + s.slice(end);
  }
  return s;
});

// Persistence
update("src/engine/persistenceStore.ts", s => {
  if (!s.includes("  PrintMonitorTarget,")) {
    const anchor = "  OracleDatabaseMetric,\n";
    if (!s.includes(anchor)) throw new Error("Persistence import anchor missing");
    s = s.replace(anchor, anchor + "  PrintMonitorTarget,\n  ReportExecutionRecord,\n");
  }
  if (!s.includes("  printTargets?: PrintMonitorTarget[];")) {
    const anchor = "  reports: DailyReportRow[];\n";
    if (!s.includes(anchor)) throw new Error("Persistence reports anchor missing");
    s = s.replace(anchor, anchor + "  printTargets?: PrintMonitorTarget[];\n  reportExecutions?: ReportExecutionRecord[];\n");
  }
  return s;
});

// Collector
update("src/engine/printingCollector.ts", s => {
  const stamp = "  const stamp = new Date().toISOString().replace('T', ' ').slice(0, 19);\n";
  if (!s.includes("  printer.tested = true;")) {
    const pos = s.indexOf(stamp);
    if (pos < 0) throw new Error("Collector timestamp anchor missing");
    const collectPos = s.indexOf("export async function collectPrintTarget(");
    if (collectPos < 0 || pos < collectPos) throw new Error("Unexpected collector timestamp location");
    s = s.slice(0, pos + stamp.length) + "  printer.tested = true;\n" + s.slice(pos + stamp.length);
  }

  s = s.replace(
    "failedJobs24h: Number(parsed.Failed ?? 0),",
    "failedJobs24h: null,"
  );
  s = s.replace(
    "failedJobs24h = spool.failedJobs24h ?? 0;",
    "failedJobs24h = null;"
  );

  const start = s.indexOf("export function buildReportExecutionInsights(");
  if (start < 0) throw new Error("Report insights function missing");
  const replacement = `export function buildReportExecutionInsights(params: {
  oracleDatabases: OracleDatabaseMetric[];
  iisSites: IisSite[];
  networkDevices: NetworkDevice[];
  printTargets: PrintMonitorTarget[];
  manualRecords: ReportExecutionRecord[];
}): ReportExecutionRecord[] {
  // Only explicitly captured report execution measurements are valid.
  return params.manualRecords.slice(0, 30);
}
`;
  s = s.slice(0, start) + replacement;
  return s;
});

console.log("\nPrinting foundation updates completed.");
