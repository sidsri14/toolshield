#!/usr/bin/env node
/** Generate a buyer-facing sample report from a real toolshield scan. No invented findings. */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { scan } from "../src/scanner.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const fixture = path.join(root, "test", "fixtures", "bad-tools.json");
const out = path.join(root, "docs", "sample-report.html");

const report = scan([fixture]);
const esc = (s) =>
  String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

const rows = report.findings
  .map(
    (f) => `
      <tr>
        <td><span class="sev ${f.severity.toLowerCase()}">${esc(f.severity)}</span></td>
        <td><code>${esc(f.ruleId)}</code></td>
        <td>${esc(f.tool)}</td>
        <td><code>${esc(f.field)}</code></td>
        <td>${esc(f.message)}</td>
        <td>${esc(f.remediation)}</td>
      </tr>`
  )
  .join("\n");

const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>toolshield — sample MCP tool-manifest poisoning review</title>
<style>
  body{font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;max-width:1100px;margin:40px auto;padding:0 20px;color:#1a1a1a}
  h1{font-size:26px;margin-bottom:4px}
  .sub{color:#666;margin-bottom:28px}
  .card{border:1px solid #e2e2e2;border-radius:8px;padding:18px 20px;margin-bottom:22px}
  table{border-collapse:collapse;width:100%;font-size:14px}
  th,td{border-bottom:1px solid #eee;padding:9px 8px;text-align:left;vertical-align:top}
  th{background:#fafafa;font-weight:600}
  code{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:13px}
  .sev{display:inline-block;padding:2px 8px;border-radius:10px;font-size:12px;font-weight:700}
  .high{background:#ffe3e3;color:#b00020}.medium{background:#fff3cd;color:#7a5b00}
  .note{background:#f6f6f6;border-left:4px solid #888;padding:12px 16px;color:#444}
  .counts span{margin-right:16px;font-weight:600}
</style>
</head>
<body>
<h1>toolshield — sample MCP tool-manifest poisoning review</h1>
<div class="sub">Generated from a real scan of <code>${esc(path.basename(fixture))}</code> — a synthetic fixture, not a customer's system.</div>

<div class="card counts">
  <strong>${report.scannedFiles}</strong> file scanned &nbsp;·&nbsp;
  <span class="high">${report.counts.HIGH} high</span>
  <span class="medium">${report.counts.MEDIUM} medium</span>
  <strong>${report.findings.length}</strong> total findings
</div>

<div class="card">
<h2>Findings</h2>
<table>
<thead><tr><th>Severity</th><th>Rule</th><th>Tool</th><th>Field</th><th>What it means</th><th>How to fix</th></tr></thead>
<tbody>${rows}
</tbody>
</table>
</div>

<div class="note">
<strong>Scope of this review.</strong> toolshield performs static inspection of tool-manifest JSON only.
It does not execute tools, call MCP servers, make network requests, or review tool implementation code.
A clean result means none of the seven documented patterns were found — not that the manifest is safe.
Invisible Unicode matches are reported as codepoint names, never printed raw.
</div>

<div class="card">
<h2>What a paid review includes</h2>
<ol>
<li>Run toolshield across the supplied tool manifests (<code>tools/list</code> exports, OpenAI-style function files, or JSON arrays).</li>
<li>Written finding-by-finding report with severity, field, rationale, and concrete fix.</li>
<li>Corrected example manifest with instruction-like text removed and parameters constrained.</li>
<li>Optional SARIF file for GitHub code-scanning integration.</li>
<li>One recheck after fixes are applied.</li>
</ol>
<p>Source and test suite: <a href="https://github.com/sidsri14/toolshield">github.com/sidsri14/toolshield</a></p>
</div>
</body>
</html>
`;

fs.mkdirSync(path.dirname(out), { recursive: true });
fs.writeFileSync(out, html, "utf8");
console.log(`Wrote ${out} with ${report.findings.length} real findings`);
