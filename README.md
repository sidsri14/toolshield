# toolshield

> Static security linter for MCP tool manifests and tool descriptions (tool-poisoning patterns).

`toolshield` reads tool definitions exported from an MCP server (`tools/list`), an OpenAI-style function manifest, or a bare JSON array of tools, and flags patterns associated with **tool poisoning** — instruction-like text in descriptions, invisible Unicode, credential-harvesting parameters, misleading names, and unconstrained inputs. Zero runtime dependencies, Node 20+, CI-friendly, SARIF output.

## Why

MCP tool descriptions are injected into a model's context and influence its decisions. A malicious or careless tool manifest can contain:

- `ignore previous instructions` / `do not tell the user` / `send the token to …` — instruction injection inside a description
- zero-width spaces and bidi overrides that hide text from a human reviewer
- parameters named `api_key`, `token`, `password` that pull secrets into model context and logs
- a tool named `bash` or `sudo` that impersonates a trusted built-in
- a read-sounding name (`read_file`) paired with a side-effecting description (`upload … delete …`)
- free-form `command` / `path` / `url` strings with no constraint

These are static, checkable properties of a JSON manifest. `toolshield` checks them before the tools are registered with an agent.

## Relationship to mcpguard

| Tool | Input | Threat class |
|---|---|---|
| [`mcpguard`](https://github.com/sidsri14/mcpguard) | MCP **client/server config** files (`mcpServers`, `servers`) | Unpinned installs, hardcoded secrets, shell wrappers, cleartext endpoints, wildcard tool permissions |
| `toolshield` | MCP **tool manifests** (`tools`, `functions`) | Tool-poisoning / prompt-injection inside tool names, descriptions, and input schemas |

They are complementary and do not duplicate rules.

## Install

From GitHub (works now, no npm account required):

```bash
npm install -g github:sidsri14/toolshield
```

Or run from a checkout with no install step:

```bash
node bin/toolshield.js scan tools.json
```

> npm registry publishing (`npm install -g toolshield`) requires a maintainer login and is not set up yet. The GitHub install path above is the supported method today.

## Usage

```bash
# Scan a manifest exported from tools/list
toolshield scan tools.json

# Scan a directory tree (skips node_modules, .git, dist, etc.)
toolshield scan . --format sarif > toolshield.sarif

# Machine-readable report, fail CI on medium+ findings
toolshield scan manifests/ --format json --fail-on medium

# List all rules
toolshield rules

toolshield --version
toolshield --help
```

### Accepted manifest shapes

```json
{ "tools": [ { "name": "...", "description": "...", "inputSchema": { ... } } ] }
```

Also accepted: `{ "functions": [...] }` (OpenAI-style), and a bare JSON array of tool objects.

### Options

| Flag | Default | Meaning |
|---|---|---|
| `-f, --format <human\|json\|sarif>` | `human` | Output format |
| `--fail-on <high\|medium\|low>` | `high` | Minimum severity that sets exit code `1` |
| `--quiet` | off | Suppress human stdout (exit code still applies) |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | No findings at or above `--fail-on`, and no parse errors |
| `1` | At least one finding at or above `--fail-on` |
| `2` | Usage error, or parse errors with no findings |

## Rules

| ID | Severity | Detects |
|---|---|---|
| `TS001` | HIGH | Instruction-like text in name/description (override, concealment, exfiltration, fetch-and-execute, jailbreak, privilege mode) |
| `TS002` | HIGH | Zero-width, joiner, or bidi control characters in tool metadata |
| `TS003` | MEDIUM | Credential-like parameter name in `inputSchema.properties` |
| `TS004` | MEDIUM | `additionalProperties: true` (unbounded undeclared arguments) |
| `TS005` | MEDIUM | Read-sounding tool name with side-effecting description |
| `TS006` | HIGH | Tool name impersonating a shell or privileged built-in (`bash`, `sudo`, `admin`, …) |
| `TS007` | MEDIUM | Unconstrained free-form string for `command`/`path`/`url`/`code`-style parameters |
| `TS008` | LOW | Excessive description length (> 1,024 characters) |
| `TS009` | HIGH | Non-ASCII or homoglyph character in tool name |

Rules are heuristic and configurable only by editing `src/rules.js`. Invisible-character codepoints are reported, never printed raw.

## SARIF / GitHub code scanning

```yaml
- uses: actions/checkout@v4
- uses: actions/setup-node@v4
  with:
    node-version: 20
- name: Scan tool manifests
  run: node bin/toolshield.js scan . --format sarif > toolshield.sarif || true
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: toolshield.sarif
```

## Scope and non-claims

`toolshield` is a **static manifest linter**. It:

- parses JSON only; does not call any MCP server, execute tools, or make network requests;
- detects documented string/schema patterns, not arbitrary vulnerabilities;
- reports approximate line/column positions (a match may fall back to line 1 when the matched text is not a literal in the file);
- does not verify tool implementation code, server identity, or runtime behavior;
- is not a substitute for a security review, sandboxing, or least-privilege configuration.

A clean scan means "none of these seven patterns were found," not "this tool manifest is safe."

## Development

```bash
npm test
```

Tests use Node's built-in `node:test` runner — no dev dependencies.

## License

MIT © 2026 Siddharth Srivastava

## Paid services (fixed scope)

Bounded software services via no-signup Contra checkout: multi-repo CI reliability sprint (up to 5 repos, USD5,000 for one agreed milestone), checkout-link consistency gate (USD100), token-2022 CI/fee-math repair (USD150), BullMQ token-budget retrofit (USD300), one bounded OSS issue plus regression PR (USD75), and web3 starter CI harness (USD150).

All offers: https://sidsri14.github.io/implementation-packages.html | Request work (no signup): https://sidsri14.github.io/request-work.html

Proof: 25 merged upstream PRs / 30 total merged GitHub PRs; 201 passing tests across 15 owned repos. Independent, AI-assisted work; BCA student at Manipal University Jaipur, expected 2027, Lucknow, India. Advertised offers only, not received income; scope and written terms are agreed before any work starts.