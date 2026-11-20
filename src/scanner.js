/** Core scanning logic: discover manifests, parse them, run rules. */
import fs from "node:fs";
import path from "node:path";
import { RULES, SEVERITY_ORDER } from "./rules.js";
import { extractTools, locateInRaw } from "./util.js";

const SKIP_DIRS = new Set([
  "node_modules",
  ".git",
  ".cache",
  "dist",
  "build",
  "coverage",
  ".venv",
  "venv",
  "target"
]);

export function findJsonFiles(dir, out = []) {
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const entry of entries) {
    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name)) findJsonFiles(path.join(dir, entry.name), out);
    } else if (entry.isFile() && entry.name.toLowerCase().endsWith(".json")) {
      out.push(path.join(dir, entry.name));
    }
  }
  return out;
}

export function expandInputs(inputs) {
  const files = [];
  for (const input of inputs) {
    let stat;
    try {
      stat = fs.statSync(input);
    } catch {
      continue;
    }
    if (stat.isDirectory()) files.push(...findJsonFiles(input));
    else if (stat.isFile()) files.push(input);
  }
  return [...new Set(files)];
}

/** Scan one manifest file. Returns { file, findings, error, hasManifest }. */
export function scanFile(file) {
  let raw;
  let doc;
  try {
    raw = fs.readFileSync(file, "utf8");
    doc = JSON.parse(raw);
  } catch (err) {
    return { file, findings: [], error: `Could not parse JSON: ${err.message}` };
  }

  const extracted = extractTools(doc);
  if (!extracted) return { file, findings: [], error: null, hasManifest: false };

  const findings = [];
  for (const tool of extracted.tools) {
    if (!tool || typeof tool !== "object" || Array.isArray(tool)) continue;
    const toolName = typeof tool.name === "string" ? tool.name : "(unnamed)";
    for (const rule of RULES) {
      let matches = [];
      try {
        matches = rule.check({ file, toolName, tool, raw }) || [];
      } catch (err) {
        matches = [{ field: "(rule error)", value: "", message: `${rule.id} failed: ${err.message}` }];
      }
      for (const match of matches) {
        const loc = locateInRaw(raw, String(match.value ?? ""));
        findings.push({
          ruleId: rule.id,
          severity: rule.severity,
          title: rule.title,
          rationale: rule.rationale,
          remediation: rule.remediation,
          file,
          tool: toolName,
          sourceKey: extracted.sourceKey,
          field: match.field,
          value: match.value,
          message: match.message,
          ...loc
        });
      }
    }
  }

  findings.sort((a, b) => {
    const s = SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
    if (s !== 0) return s;
    return a.ruleId.localeCompare(b.ruleId);
  });
  return { file, findings, error: null, hasManifest: true };
}

export function scan(inputs) {
  const files = expandInputs(inputs);
  const results = files.map(scanFile);
  const findings = results.flatMap((r) => r.findings);
  const errors = results.filter((r) => r.error).map((r) => ({ file: r.file, error: r.error }));
  const counts = { HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  for (const f of findings) counts[f.severity] = (counts[f.severity] || 0) + 1;
  return {
    tool: { name: "toolshield", version: "0.1.0" },
    scannedFiles: files.length,
    manifests: results.filter((r) => r.hasManifest).length,
    findings,
    errors,
    counts
  };
}
