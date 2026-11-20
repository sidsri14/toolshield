import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { scan, scanFile, expandInputs } from "../src/scanner.js";
import { extractTools } from "../src/util.js";
import { RULES } from "../src/rules.js";
import { formatJson, formatSarif, formatHuman } from "../src/format.js";
import { run, EXIT } from "../src/cli.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const fixture = (name) => path.join(here, "fixtures", name);

test("RULES has 7 documented rules with unique IDs", () => {
  assert.equal(RULES.length, 7);
  assert.equal(new Set(RULES.map((r) => r.id)).size, 7);
  for (const r of RULES) {
    assert.match(r.id, /^TS\d{3}$/);
    assert.ok(["HIGH", "MEDIUM", "LOW"].includes(r.severity));
    assert.ok(r.rationale && r.remediation);
  }
});

test("extractTools supports MCP tools/list, OpenAI functions, and bare arrays", () => {
  assert.equal(extractTools({ tools: [{ name: "a" }] }).sourceKey, "tools");
  assert.equal(extractTools({ functions: [{ name: "a" }] }).sourceKey, "functions");
  assert.equal(extractTools([{ name: "a" }]).sourceKey, "(array)");
  assert.equal(extractTools({ theme: "dark" }), null);
});

test("OpenAI-style wrapper unwraps function definitions", () => {
  const ex = extractTools({ tools: [{ type: "function", function: { name: "x", description: "ok" } }] });
  assert.equal(ex.tools[0].name, "x");
});

test("bad manifest triggers the expected rules", () => {
  const res = scanFile(fixture("bad-tools.json"));
  assert.equal(res.error, null);
  assert.equal(res.hasManifest, true);
  const ids = new Set(res.findings.map((f) => f.ruleId));
  for (const id of ["TS001", "TS002", "TS003", "TS004", "TS005", "TS006", "TS007"]) {
    assert.ok(ids.has(id), `expected ${id}`);
  }
  assert.ok(res.findings.every((f) => f.startLine >= 1 && f.startColumn >= 1));
});

test("good manifest is clean", () => {
  const res = scanFile(fixture("good-tools.json"));
  assert.equal(res.error, null);
  assert.deepEqual(res.findings, []);
});

test("TS007 does not treat 'description' as the sensitive word 'script'", () => {
  // Regression: a plain `description` string param was flagged via the substring "script".
  const dir = path.join(here, "fixtures");
  const manifest = {
    tools: [
      {
        name: "note",
        description: "Stores a note.",
        inputSchema: { type: "object", properties: { description: { type: "string" } }, additionalProperties: false }
      }
    ]
  };
  const f = path.join(dir, ".tmp-description-param.json");
  fs.writeFileSync(f, JSON.stringify(manifest));
  try {
    const ids = scanFile(f).findings.map((x) => x.ruleId);
    assert.ok(!ids.includes("TS007"), "description param must not be flagged as a script field");
  } finally {
    fs.unlinkSync(f);
  }
});

test("non-manifest JSON is skipped without error", () => {
  const res = scanFile(fixture("not-a-manifest.json"));
  assert.equal(res.error, null);
  assert.equal(res.hasManifest, false);
});

test("invalid JSON yields a parse error", () => {
  const bad = path.join(here, "fixtures", "broken.json");
  const res = scanFile(bad);
  assert.match(res.error, /Could not parse JSON/);
});

test("expandInputs deduplicates and scans a directory", () => {
  const files = expandInputs([fixture("bad-tools.json"), fixture("bad-tools.json")]);
  assert.equal(files.length, 1);
  const dirFiles = expandInputs([path.join(here, "fixtures")]);
  assert.ok(dirFiles.length >= 4);
});

test("aggregate report counts severities correctly", () => {
  const report = scan([fixture("bad-tools.json")]);
  assert.equal(report.tool.name, "toolshield");
  assert.equal(report.manifests, 1);
  assert.ok(report.counts.HIGH >= 4);
  assert.ok(report.counts.MEDIUM >= 3);
});

test("formatters emit valid JSON/SARIF and human text", () => {
  const report = scan([fixture("bad-tools.json")]);
  const json = JSON.parse(formatJson(report));
  assert.equal(json.tool.name, "toolshield");
  const sarif = JSON.parse(formatSarif(report));
  assert.equal(sarif.version, "2.1.0");
  assert.ok(sarif.runs[0].results.length > 0);
  assert.ok(sarif.runs[0].tool.driver.rules.length > 0);
  assert.match(formatHuman(report), /toolshield v0\.1\.0/);
});

test("CLI fail-on high returns findings exit code, clean scan returns OK", () => {
  assert.equal(run(["scan", fixture("bad-tools.json"), "--format", "json", "--quiet"]), EXIT.FINDINGS);
  assert.equal(run(["scan", fixture("good-tools.json"), "--format", "json", "--quiet"]), EXIT.OK);
});

test("CLI usage errors return ERROR", () => {
  assert.equal(run(["scan"]), EXIT.ERROR);
  assert.equal(run(["scan", fixture("bad-tools.json"), "--format", "nope"]), EXIT.ERROR);
  assert.equal(run(["bogus"]), EXIT.ERROR);
});

test("CLI rules/version/help return OK", () => {
  assert.equal(run(["rules"]), EXIT.OK);
  assert.equal(run(["--version"]), EXIT.OK);
  assert.equal(run(["--help"]), EXIT.OK);
});
