/** Output formatters: human, JSON, SARIF 2.1.0. */

const LEVEL = { HIGH: "error", MEDIUM: "warning", LOW: "note", INFO: "note" };

export function formatHuman(report) {
  const lines = [];
  lines.push("toolshield v" + report.tool.version + " — MCP tool-manifest poisoning scan");
  lines.push("Scanned " + report.scannedFiles + " file(s); " + report.manifests + " tool manifest(s).");
  lines.push("");
  if (report.errors.length) {
    lines.push("Parse errors:");
    for (const e of report.errors) lines.push("  ! " + e.file + ": " + e.error);
    lines.push("");
  }
  if (!report.findings.length) {
    lines.push("No findings.");
    return lines.join("\n");
  }
  lines.push(
    `Findings: ${report.counts.HIGH} high, ${report.counts.MEDIUM} medium, ` +
      `${report.counts.LOW} low, ${report.counts.INFO} info`
  );
  lines.push("");
  let lastFile = null;
  for (const f of report.findings) {
    if (f.file !== lastFile) {
      lines.push("  " + f.file);
      lastFile = f.file;
    }
    lines.push(`  [${f.severity.padEnd(6)}] ${f.ruleId}  ${f.tool} :: ${f.field}`);
    lines.push(`      ${f.message}`);
    lines.push(`      fix: ${f.remediation}`);
    lines.push(`      at line ${f.startLine}, column ${f.startColumn}`);
  }
  return lines.join("\n");
}

export function formatJson(report) {
  return JSON.stringify(report, null, 2);
}

export function formatSarif(report) {
  const usedRules = [...new Set(report.findings.map((f) => f.ruleId))].sort();
  const ruleMeta = new Map();
  for (const f of report.findings) {
    if (!ruleMeta.has(f.ruleId)) {
      ruleMeta.set(f.ruleId, {
        id: f.ruleId,
        name: f.title.replace(/[^A-Za-z0-9]/g, ""),
        shortDescription: { text: f.title },
        fullDescription: { text: f.rationale },
        defaultConfiguration: { level: LEVEL[f.severity] || "warning" },
        help: { text: f.remediation },
        properties: { tags: ["security", "mcp", "tool-poisoning", "static-analysis"] }
      });
    }
  }
  const results = report.findings.map((f) => ({
    ruleId: f.ruleId,
    level: LEVEL[f.severity] || "warning",
    message: { text: f.message },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: f.file.replace(/\\/g, "/") },
          region: { startLine: f.startLine, startColumn: f.startColumn }
        }
      }
    ],
    properties: {
      tool: f.tool,
      field: f.field,
      sourceKey: f.sourceKey,
      severity: f.severity
    }
  }));

  return JSON.stringify(
    {
      $schema: "https://json.schemastore.org/sarif-2.1.0.json",
      version: "2.1.0",
      runs: [
        {
          tool: {
            driver: {
              name: report.tool.name,
              version: report.tool.version,
              informationUri: "https://github.com/sidsri14/toolshield",
              rules: usedRules.map((id) => ruleMeta.get(id)).filter(Boolean)
            }
          },
          results
        }
      ]
    },
    null,
    2
  );
}
