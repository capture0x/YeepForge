---
name: yeepforge-sast
description: "Static application security testing (SAST) of a source-code directory using YeepForge's static analyzer. Use when the user provides a local code path and wants a vulnerability review - SQLi, XSS, RCE, SSRF, path traversal, XXE, SSTI, JWT, IDOR, missing auth, business logic, GraphQL. Requires the 'yeepforge' MCP server."
---

# YeepForge - Source Code Security Analysis (SAST)

Drives YeepForge's `analyze_source_code` MCP tool (`mcp__yeepforge__analyze_source_code`)
to review a codebase for vulnerabilities before or alongside dynamic testing.

## When to use

- The user hands you a **local source path** and wants a security code review.
- You have dynamic findings and want to **confirm the root cause** in code.
- You want to find issues black-box testing can't reach (logic flaws, secrets,
  unreachable-but-present sinks).

## How to run

1. Confirm the absolute path to the code directory.
2. Call `analyze_source_code` with:
   - `code_path`: absolute path to the source directory.
   - `skill`: `"all"` for a full pass, or a focused skill:
     `architecture`, `sqli`, `xss`, `ssrf`, `rce`, `xxe`, `pathtraversal`,
     `ssti`, `jwt`, `idor`, `missingauth`, `businesslogic`, `graphql`, `report`.
3. Start with `architecture` to map the app, then run targeted skills for the
   sinks that matter (e.g. `sqli`, `rce`) rather than always running `all` on a
   large codebase.

## Turning results into findings

- For each confirmed code-level vuln, record it with `report_finding`
  (title, severity, OWASP category, the file/line evidence, remediation).
- Cross-check against dynamic results: a sink confirmed in code **and** reachable
  at runtime is a high-confidence finding worth exploiting with
  `exploit_vulnerability` (in scope only).
- Use `security-patterns` (vendored skill) regexes to sweep the code for leaked
  API keys, tokens, and PII.

## Guardrails

- Only analyze code you are authorized to review.
- SAST flags **potential** sinks - validate reachability before reporting as
  confirmed; note uncertain items as informational.
