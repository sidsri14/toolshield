/** Helpers: extract tool definitions from a JSON document, locate values in raw text. */

export function extractTools(doc) {
  if (Array.isArray(doc)) return { tools: doc, sourceKey: "(array)" };
  if (!doc || typeof doc !== "object" || Array.isArray(doc)) return null;

  if (Array.isArray(doc.tools)) {
    const tools = doc.tools.map((t) => {
      if (t && typeof t === "object" && t.function && typeof t.function === "object") return t.function;
      return t;
    });
    return { tools, sourceKey: "tools" };
  }
  if (Array.isArray(doc.functions)) return { tools: doc.functions, sourceKey: "functions" };
  return null;
}

/** Approximate line/column of a literal value in the raw JSON text. */
export function locateInRaw(raw, needle) {
  if (!needle) return { startLine: 1, startColumn: 1 };
  const idx = raw.indexOf(String(needle));
  if (idx < 0) return { startLine: 1, startColumn: 1 };
  const before = raw.slice(0, idx);
  const startLine = before.split("\n").length;
  const lastNl = before.lastIndexOf("\n");
  return { startLine, startColumn: idx - lastNl };
}
