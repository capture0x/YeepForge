# Third-Party Skill Attribution

YeepForge ships two kinds of Claude Agent Skills under `.claude/skills/`:

## 1. YeepForge-native skills (authored for this project, MIT)

- `yeepforge-pentest/` - orchestrates a full web-app engagement through
  YeepForge's MCP tools.
- `yeepforge-sast/` - drives YeepForge's source-code analysis tool.

These are original to YeepForge and covered by the repository's root `LICENSE`.

## 2. Vendored reference skills (SecLists, MIT)

The following skills are redistributed **payload/wordlist/pattern reference
data**, not original YeepForge work:

- `security-fuzzing/`  - SQL/NoSQL/command/LDAP injection fuzzing payloads
- `security-payloads/`  - XSS, XXE, template-injection, file-upload payloads
- `security-patterns/`  - regexes for API keys, tokens, PII, secrets

**Source:** [Eyadkelleh/awesome-skills-security](https://github.com/Eyadkelleh/awesome-skills-security)
(a curated redistribution of [SecLists](https://github.com/danielmiessler/SecLists)
by Daniel Miessler).

**License:** MIT - the same terms as SecLists and YeepForge. All credit for the
underlying payloads/wordlists goes to the SecLists project and its contributors.
The upstream README is preserved as `UPSTREAM-README.md`.

The web-shell samples from the upstream collection were **deliberately excluded**
to keep the repository free of server-executable payloads.

---

⚠️ All skills are for **authorized security testing only** - pentest engagements
with written permission, bug-bounty programs in scope, CTFs, or your own systems.
