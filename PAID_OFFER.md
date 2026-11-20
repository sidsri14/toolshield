# MCP Tool-Manifest Security Review — proposed paid offer

**Status: PROPOSED. Not income. No payment received. Requires explicit approval before any external send.**

This document ties the `toolshield` OSS tool to a paid, tightly-scoped service. It is a companion to the
[`mcpguard` paid offer](../mcpguard/PAID_OFFER.md) — different input (tool manifests, not client configs),
different threat class (tool poisoning, not config hygiene). No buyer has accepted either offer.

## Live proof

- Tool source: https://github.com/sidsri14/toolshield (CI green on Node 20/22/24)
- Landing page: https://sidsri14.github.io/toolshield/
- Sample review report (generated from a real scan): https://sidsri14.github.io/toolshield/sample-report.html
- Test suite: `npm test` — 14/14 passing, zero runtime dependencies

## Service

**MCP Tool-Manifest Security Review** — a static review of a customer's exported tool definitions
(`tools/list` output, OpenAI-style function manifests, or JSON arrays of tool objects) using `toolshield`,
plus a human-written remediation report.

### Deliverables (fixed scope)

1. Run `toolshield` over the customer-supplied tool-manifest files.
2. A written report listing each finding: rule ID, severity, exact tool/field, why it matters, and a concrete fix.
3. A corrected example manifest with instruction-like text removed and sensitive parameters constrained.
4. A SARIF file suitable for upload to GitHub code scanning, if the customer wants CI gating.
5. One follow-up pass after the customer applies fixes, to confirm findings are resolved.

### Out of scope (explicit)

- No tool execution, no calls to the customer's MCP servers, no penetration testing.
- No review of tool implementation source code — manifest metadata only.
- No guarantee of "fully safe"; the report covers the seven documented rules and static inspection only.
- No tax, legal, or compliance advice.

### Proposed pricing (NOT received, NOT agreed with any buyer)

| Tier | Scope | Proposed price |
|---|---|---|
| Single review | Up to 10 tool definitions, report + corrected examples + one recheck | USD $150 |
| Team review | Up to 50 tool definitions, SARIF + CI guidance + one recheck | USD $350 |

These are ask prices for a future buyer. Not booked revenue, not an invoice, not an accepted offer.
Adjust only with user approval.

### Payout boundary

- Bank transfer or PayPal **only** (PayPal payout account: `sidsri1302@gmail.com`).
- No crypto, no wallet, no voucher, no escrow funding by the assistant.
- No spending, no platform fee payment, no tax attestation made by the assistant.

### Truthful seller qualification (use verbatim or not at all)

> I'm Siddharth, an independent developer and BCA candidate (expected 2027). I built `toolshield`, an
> open-source, zero-dependency static linter for MCP tool manifests, with 7 documented tool-poisoning
> rules and 14 passing tests. I'm offering a fixed-scope static manifest review — no tool execution, no
> source-code audit. I'll show the tool's source and test results before you pay.

Do **not** claim: years of professional security experience, production deployments, penetration-testing
certifications, named enterprise customers, or a number of "vulnerabilities found" that cannot be shown.

## Where to offer (requires approval; daily first-contact cap applies)

- Only where a real buyer has an actual MCP tool-manifest need.
- No unsolicited mass email. No duplicate sends.
- Do not post to Fiverr without a real on-platform order and agreed payment.

## README truth cross-check

All capabilities claimed here are implemented in `src/` and covered by `npm test` (14/14).
No benchmark numbers, no production claims.
