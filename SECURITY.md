# Security Policy

YeepForge is an offensive security tool. That cuts two ways: it has its own
attack surface as a piece of software, and it is capable of causing damage when
pointed at the wrong target. This document covers both.

---

## Reporting a vulnerability in YeepForge

**Do not open a public issue for a security bug.**

Report it privately through GitHub's
[private vulnerability reporting](https://github.com/capture0x/YeepForge/security/advisories/new)
on this repository. If that is unavailable to you, open a normal issue that says
only *"security report, requesting a private channel"* - with no technical
detail - and a maintainer will follow up.

Please include:

- The affected version or commit hash
- What an attacker gains, and what access they need to start
- Reproduction steps, ideally the smallest input that triggers it
- Any proof-of-concept you already have

**What to expect:** an acknowledgement within 7 days, and an assessment with a
fix plan or a reasoned decline within 30 days. YeepForge is maintained by one
person as an unfunded project - there is no bounty, but every valid report gets
credited in the release notes unless you ask otherwise.

Please give the maintainer a chance to ship a fix before disclosing publicly.
90 days is a reasonable default; if a fix is taking longer than that, say so and
publish.

### What counts as a vulnerability here

This is a tool that runs attacker-controlled data on the operator's machine, so
the interesting bugs are the ones that turn *the tester* into the victim:

- **Local command execution from target data** - a hostile target returns a
  header, cookie, or URL that reaches a shell (see *Shell interpolation* below).
  This is the highest-severity class in this codebase.
- **Path traversal in output handling** - a target-controlled filename escaping
  `output/` or `reports/`.
- **Scope enforcement bypass** - a URL that `utils/scope.py` accepts when it
  should deny, or any request path that skips the scope check entirely. On a
  bounty program this gets the operator banned; on an engagement it is
  unauthorised access.
- **Credential leakage** - cookies, tokens, or API keys written unredacted into
  a report, a log, or the terminal.
- **Deserialisation, SSRF, or injection** in YeepForge's own parsing of target
  responses.

### Out of scope

- **The payloads themselves.** YeepForge ships SQLi, XSS, RCE, and command
  injection payloads on purpose. Malicious strings in `.claude/skills/` and the
  wordlists are the product, not a bug - as is antivirus flagging them.
- **"The tool can attack systems."** That is its stated function.
- Findings that require the operator to already have code execution on their own
  machine.
- Vulnerabilities in target applications you discovered *using* YeepForge -
  those go to that application's vendor or bounty program, not here.
- Reports from automated scanners with no analysis of exploitability.

---

## Known security posture

Being honest about the current state, so you can make an informed decision about
where you run this:

**Shell interpolation debt.** YeepForge historically shelled out to `curl` with
a per-call-site f-string. A value interpolated into such a string - a cookie, a
URL, a payload - is parsed by *your* shell, so a `$(...)` in a target-controlled
value executes locally. Migration to the HTTP engine in `utils/http.py` is
underway but incomplete. `scripts/audit_shell_safety.py` reports the exact
remaining count, and `tests/test_shell_safety.py` freezes it as a baseline so
the number can only go down. **Treat every target as hostile and run YeepForge
in a VM or container, not on a machine that holds credentials you care about.**

**Requests through the engine are safer.** Anything going through
`utils.http.get_client()` is scope-checked, rate-limited, proxied, and captured
as evidence with secrets redacted - no shell involved. New code must use it.

**Secrets in `.env`.** `ANTHROPIC_API_KEY`, session cookies, and auth tokens live
in `.env`, which is git-ignored. It is your responsibility to keep it that way;
verify with `git status --ignored` before pushing a fork.

**Engagement output is loot.** `output/`, `sast/`, and generated reports contain
real target data and are git-ignored for that reason. Do not commit them, and
delete them when the engagement ends.

---

## Using YeepForge safely and legally

YeepForge sends real attacks. Unauthorised use is a crime in most jurisdictions
regardless of intent.

- **Get written authorization before you point this at anything.** A bug bounty
  program's published scope counts; a verbal "sure, go ahead" does not.
- **Set the scope.** Use `--scope '*.example.com,!admin.example.com'` so a
  crawler redirect cannot walk you out of the engagement.
- **Set a rate limit.** Use `--rps` to stay under the program's cap. Hammering a
  target is the fastest way to get banned, and can constitute a denial-of-service
  in its own right.
- **Exploitation modules cause change.** Anything that writes, uploads, or
  executes on the target needs explicit permission for *that*, beyond permission
  to scan.
- **Handle the findings like the sensitive data they are.** Reports contain
  working exploits against someone else's system.

The maintainer assumes no liability for misuse. Using YeepForge is your
confirmation that you have proper authorization for every target you give it.
