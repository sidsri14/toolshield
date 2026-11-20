/** Rule definitions for tool-manifest poisoning checks. */

export const SEVERITY_ORDER = { HIGH: 0, MEDIUM: 1, LOW: 2, INFO: 3 };

const INSTRUCTION_PATTERNS = [
  { re: /ignore\s+(all\s+)?(previous|prior|above)\s+instructions?/i, label: "instruction-override text" },
  { re: /(system|developer)\s+prompt/i, label: "system/developer prompt reference" },
  { re: /do\s+not\s+(tell|inform|mention|reveal|disclose)/i, label: "concealment instruction" },
  { re: /exfiltrat/i, label: "exfiltration instruction" },
  { re: /send\s+(the\s+)?(secret|token|key|data|file|contents?|credentials?)\s+to/i, label: "data-sending instruction" },
  { re: /(curl|wget|fetch|download)[^.]{0,80}(execute|run|eval|bash|\bsh\b)/i, label: "download-and-execute instruction" },
  { re: /before\s+(using|calling|answering|responding|invoking)/i, label: "pre-use instruction" },
  { re: /jailbreak|bypass\s+(the\s+)?(safety|guardrail|filter|policy)/i, label: "guardrail-bypass instruction" },
  { re: /(privileged|admin|root)\s+mode/i, label: "privilege-mode instruction" }
];

const INVISIBLE_RE = /[\u200B-\u200F\u202A-\u202E\u2060\u2066-\u2069\uFEFF]/g;
const CREDENTIAL_PARAM_RE = /api[-_]?key|access[-_]?key|token|password|passwd|secret|private[-_]?key|authorization|auth[-_]?header|cookie/i;
const IMPERSONATION_RE = /(^|[_.\-])(bash|sh|shell|execute|exec|run_shell|run_command|sudo|admin|system|terminal)$/i;
// Names commonly use snake_case / dotted names, so treat non-letters as separators.
const READ_VERB_RE = /(?:^|[^A-Za-z])(read|get|list|fetch|view|search|lookup)(?:[^A-Za-z]|$)/i;
const WRITE_VERB_RE = /(?:^|[^A-Za-z])(write|delete|remove|upload|send|execute|modify|update|run shell)(?:[^A-Za-z]|$)/i;
// Separator-aware: "description" must NOT count as "script"; snake_case must still match.
const SENSITIVE_PARAM_RE = /(?:^|[^A-Za-z])(command|cmd|path|file|url|uri|script|code|query)(?:[^A-Za-z]|$)/i;

function textOf(tool) {
  const parts = [];
  if (typeof tool?.description === "string") parts.push(["description", tool.description]);
  if (typeof tool?.name === "string") parts.push(["name", tool.name]);
  return parts;
}

export const RULES = [
  {
    id: "TS001",
    severity: "HIGH",
    title: "Instruction-like text in tool description",
    rationale:
      "Tool descriptions are injected into the model's context. Text that tells the model to ignore instructions, hide actions, exfiltrate data, or fetch-and-execute content is a known tool-poisoning pattern.",
    remediation:
      "Rewrite the description as a neutral capability statement. Move usage policy into your own system prompt, never into untrusted tool metadata.",
    check({ tool }) {
      const out = [];
      for (const [field, text] of textOf(tool)) {
        for (const p of INSTRUCTION_PATTERNS) {
          const m = text.match(p.re);
          if (m) {
            out.push({
              field,
              value: m[0].slice(0, 120),
              message: `${field} contains ${p.label}: "${m[0].slice(0, 120)}"`
            });
          }
        }
      }
      return out;
    }
  },
  {
    id: "TS002",
    severity: "HIGH",
    title: "Invisible Unicode control characters in tool metadata",
    rationale:
      "Zero-width characters, joiners, and bidi overrides can hide instructions or reverse displayed text inside a name or description while looking harmless to a human reviewer.",
    remediation:
      "Strip zero-width and bidi control characters from tool names and descriptions; require review of any non-printing characters.",
    check({ tool }) {
      const out = [];
      for (const [field, text] of textOf(tool)) {
        const seen = new Set();
        for (const ch of text.match(INVISIBLE_RE) || []) {
          seen.add("U+" + ch.charCodeAt(0).toString(16).toUpperCase().padStart(4, "0"));
        }
        if (seen.size) {
          out.push({
            field,
            value: [...seen].join(", "),
            message: `${field} contains ${seen.size} invisible control character codepoint(s): ${[...seen].join(", ")}`
          });
        }
      }
      return out;
    }
  },
  {
    id: "TS003",
    severity: "MEDIUM",
    title: "Credential-like parameter name in input schema",
    rationale:
      "A tool that accepts a raw password, token, or cookie parameter invites secrets to be passed through model context, logs, and transcripts.",
    remediation:
      "Accept a reference to a secret store or an environment variable name instead of the secret value; never require the raw credential as a tool argument.",
    check({ tool }) {
      const out = [];
      const props = tool?.inputSchema?.properties;
      if (!props || typeof props !== "object" || Array.isArray(props)) return out;
      for (const key of Object.keys(props)) {
        if (CREDENTIAL_PARAM_RE.test(key)) {
          out.push({ field: `inputSchema.properties.${key}`, value: key, message: `Parameter '${key}' looks like a raw credential input` });
        }
      }
      return out;
    }
  },
  {
    id: "TS004",
    severity: "MEDIUM",
    title: "Unbounded additional properties in input schema",
    rationale:
      "additionalProperties: true allows arbitrary undeclared arguments to reach the tool implementation, weakening the contract a reviewer can verify.",
    remediation: "Set additionalProperties to false and declare every accepted argument explicitly.",
    check({ tool }) {
      if (tool?.inputSchema?.additionalProperties === true) {
        return [{ field: "inputSchema.additionalProperties", value: "true", message: "inputSchema accepts arbitrary undeclared properties" }];
      }
      return [];
    }
  },
  {
    id: "TS005",
    severity: "MEDIUM",
    title: "Read-sounding tool name with side-effecting description",
    rationale:
      "A tool named like a read-only operation but described as writing, sending, uploading, or executing can be approved under a false assumption of safety.",
    remediation: "Rename the tool to reflect its side effects, or remove the side-effecting behavior from the described scope.",
    check({ tool }) {
      const name = tool?.name;
      const desc = tool?.description;
      if (typeof name !== "string" || typeof desc !== "string") return [];
      if (READ_VERB_RE.test(name) && WRITE_VERB_RE.test(desc)) {
        return [{ field: "name/description", value: name, message: `Tool '${name}' sounds read-only but its description mentions side effects` }];
      }
      return [];
    }
  },
  {
    id: "TS006",
    severity: "HIGH",
    title: "Tool name impersonates a shell or privileged built-in",
    rationale:
      "Names like bash, sudo, admin, or system can make an untrusted third-party tool appear to be a trusted built-in, increasing the chance it is approved.",
    remediation: "Use a unique, namespaced tool name that identifies the actual provider.",
    check({ tool }) {
      const name = tool?.name;
      if (typeof name === "string" && IMPERSONATION_RE.test(name)) {
        return [{ field: "name", value: name, message: `Tool name '${name}' impersonates a shell or privileged built-in` }];
      }
      return [];
    }
  },
  {
    id: "TS007",
    severity: "MEDIUM",
    title: "Unconstrained string parameter for a sensitive field",
    rationale:
      "A free-form string for command, path, URL, script, or code parameters gives unvalidated input a direct route into the tool implementation.",
    remediation: "Constrain the field with enum, pattern, or format, and validate it server-side before use.",
    check({ tool }) {
      const out = [];
      const props = tool?.inputSchema?.properties;
      if (!props || typeof props !== "object" || Array.isArray(props)) return out;
      for (const [key, spec] of Object.entries(props)) {
        if (!SENSITIVE_PARAM_RE.test(key)) continue;
        if (!spec || typeof spec !== "object") continue;
        if (spec.type !== "string") continue;
        const constrained = spec.enum || spec.pattern || spec.format || spec.const;
        if (!constrained) {
          out.push({
            field: `inputSchema.properties.${key}`,
            value: key,
            message: `Sensitive parameter '${key}' is an unconstrained free-form string`
          });
        }
      }
      return out;
    }
  }
];
