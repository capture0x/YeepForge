"""
modules/crypto_failures.py
tmrswrr - A02: Cryptographic Failures
Sensitive data exposure, weak crypto, SSL/TLS issues, cleartext transmission
"""
import os
import re
import shutil

from config.settings import OUTPUT_DIR, SESSION, add_vuln, save_session
from utils.helpers import (
    DIM,
    NEON_CYN,
    NEON_GRN,
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
from utils.http import get_client, looks_like_notfound, notfound_signature


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


#: What each sensitive path must actually contain to count as exposed.
_FILE_SIGNATURES = {
    ".env":        ("=",),
    ".git/config": ("[core]", "[remote"),
    ".git/HEAD":   ("ref:",),
    ".json":       ("{", "["),
    ".yml":        (":",),
    ".sql":        ("INSERT", "CREATE", "DROP", "--"),
    ".log":        ("",),
    ".key":        ("-----BEGIN",),
    "id_rsa":      ("-----BEGIN",),
    "Dockerfile":  ("FROM ",),
}


def _looks_like_the_real_file(path: str, content: str, resp) -> bool:
    """True when the body plausibly *is* the requested file.

    A single-page app answers unknown paths with index.html and HTTP 200. That
    made every entry in the path list an 'Exposed File' finding. An HTML body
    for a `.env` or `.key` request is the app, not the file.
    """
    if not content.strip():
        return False
    ctype = (resp.headers.get("Content-Type") or "").lower()
    lowered = content.lstrip().lower()
    serves_html = "text/html" in ctype or lowered.startswith(("<!doctype html", "<html"))

    for suffix, markers in _FILE_SIGNATURES.items():
        if path.endswith(suffix) or suffix in path:
            if serves_html:
                return False
            return any(m in content for m in markers) if any(markers) else True

    # Unknown extension: an HTML response is still almost certainly the app.
    return not serves_html


#: Secret patterns hunted in client-side JavaScript, each with its own severity:
#: a live AWS key is not the same finding as a `password:` assignment that may
#: well be a form field name. The previous table matched any quoted 40-character
#: string as an "AWS Secret", which fires on every hash and base64 chunk in a
#: minified bundle - that entry now requires surrounding AWS context.
JS_SECRET_PATTERNS = {
        "AWS Access Key":   (r"AKIA[0-9A-Z]{16}", "Critical"),
        "AWS Secret Key":   (r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]", "Critical"),
        "Google API Key":   (r"AIza[0-9A-Za-z\-_]{35}", "High"),
        "Private Key":      (r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----", "Critical"),
        "Slack Token":      (r"xox[baprs]-[0-9A-Za-z-]{10,}", "Critical"),
        "GitHub Token":     (r"gh[pousr]_[A-Za-z0-9]{36,}", "Critical"),
        "Stripe Key":       (r"sk_live_[0-9a-zA-Z]{24,}", "Critical"),
        "JWT Token":        (r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}", "Medium"),
        "Bearer Token":     (r"[Bb]earer [a-zA-Z0-9._-]{20,}", "Medium"),
        "Basic Auth (b64)": (r"[Bb]asic [a-zA-Z0-9+/=]{20,}", "High"),
        "Password in JS":   (r"(?:password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{4,}['\"]", "Medium"),
        "API Key in JS":    (r"(?:api[_-]?key|apikey|api_secret)\s*[=:]\s*['\"][^'\"]{8,}['\"]", "Medium"),
    }


def sensitive_data_exposure():
    section("SENSITIVE DATA EXPOSURE")
    url = _target()

    paths = [
        ("/.env",              "Environment variables"),
        ("/.env.local",        "Local environment variables"),
        ("/.env.production",   "Production environment"),
        ("/config.json",       "Configuration file"),
        ("/config.yml",        "YAML configuration"),
        ("/settings.json",     "Settings file"),
        ("/secrets.json",      "Secrets file"),
        ("/.git/config",       "Git configuration"),
        ("/.git/HEAD",         "Git HEAD"),
        ("/backup.sql",        "SQL backup"),
        ("/dump.sql",          "SQL dump"),
        ("/db.sqlite",         "SQLite database"),
        ("/database.sql",      "Database dump"),
        ("/wp-config.php.bak", "WordPress config backup"),
        ("/application.log",   "Application log"),
        ("/error.log",         "Error log"),
        ("/debug.log",         "Debug log"),
        ("/private.key",       "Private key"),
        ("/server.key",        "Server key"),
        ("/id_rsa",            "SSH private key"),
        ("/.ssh/id_rsa",       "SSH private key"),
        ("/api-key.txt",       "API key file"),
        ("/credentials.json",  "GCP credentials"),
        ("/aws-credentials",   "AWS credentials"),
        ("/Dockerfile",        "Dockerfile"),
        ("/docker-compose.yml","Docker Compose"),
        ("/package.json",      "Node.js package info"),
        ("/package-lock.json", "Node.js dependencies"),
    ]

    info(f"Scanning {len(paths)} common sensitive file paths...")
    client = get_client()
    notfound = notfound_signature(client, url)
    if notfound and notfound[0] == 200:
        warn(f"Target answers missing paths with HTTP 200 ({notfound[1]} bytes) - filtering soft-404s")
    print()

    found = []
    for path, desc in paths:
        resp = client.safe_get(url.rstrip("/") + path, timeout=5)
        if resp is None:
            print(f"  {DIM}[!] {path} (request failed){RST}")
            continue
        code = resp.status_code

        if code == 200 and not looks_like_notfound(resp, notfound):
            content = resp.text
            if not _looks_like_the_real_file(path, content, resp):
                # An SPA serving index.html for every unknown path would
                # otherwise turn this whole list into High findings.
                print(f"  {DIM}[200] {path} (served the app, not the file){RST}")
                continue

            size = len(content)
            success(f"[{code}] {url}{path}  ({desc}, {size} bytes)")
            found.append((path, desc, size))
            if any(k in content.lower() for k in
                   ["password", "secret", "api_key", "private", "-----begin"]):
                add_vuln(f"Sensitive File Exposed: {path}", "Critical", "A02:2021",
                         f"Contains credentials/secrets - {desc}",
                         url.rstrip("/") + path, evidence=resp.evidence,
                         confidence="Confirmed", cwe="CWE-200")
            else:
                add_vuln(f"Exposed File: {path}", "Medium", "A02:2021",
                         f"{desc} is publicly readable ({size} bytes)",
                         url.rstrip("/") + path, evidence=resp.evidence,
                         confidence="Confirmed", cwe="CWE-200")
        elif code == 403:
            info(f"[403] {path}  (forbidden - file exists)")
        else:
            print(f"  {DIM}[{code}] {path}{RST}")

    if found:
        success(f"\n{len(found)} sensitive files found!")
    else:
        info("No obvious sensitive files discovered")


def cleartext_check():
    section("CLEARTEXT TRANSMISSION CHECK")
    url = _target()

    client = get_client()

    if url.startswith("http://"):
        warn("Target is using HTTP (not HTTPS) - cleartext transmission!")
        https_url = url.replace("http://", "https://")
        https_resp = client.safe_get(https_url, timeout=5)
        add_vuln("Cleartext HTTP", "High", "A02:2021",
                 "Application is served over unencrypted HTTP", url,
                 evidence=client.history[-1] if client.history else None,
                 confidence="Confirmed", cwe="CWE-319")
        if https_resp is not None and https_resp.status_code in (200, 301, 302):
            success(f"HTTPS available at: {https_url}")
            info("No automatic redirect from HTTP → HTTPS configured")
        else:
            warn("HTTPS not available or not responding")
        head = client.safe_get(url, timeout=5)
    else:
        success("Target is using HTTPS")
        http_url = url.replace("https://", "http://")
        redirect = client.safe_get(http_url, timeout=5, allow_redirects=False)
        if redirect is None:
            info("Plain HTTP did not respond (good)")
        else:
            location = redirect.headers.get("Location", "")
            if redirect.status_code in (301, 302, 307, 308) and location.startswith("https://"):
                success(f"HTTP → HTTPS redirect in place ({redirect.status_code} → {location})")
            else:
                warn(f"Plain HTTP answered {redirect.status_code} without redirecting to HTTPS")
                add_vuln("No HTTPS Redirect", "Medium", "A02:2021",
                         f"http:// is served directly (HTTP {redirect.status_code}) instead of "
                         "redirecting to https://", http_url,
                         evidence=redirect.evidence, confidence="Confirmed", cwe="CWE-319")
        head = client.safe_get(url, timeout=5)

    # HSTS is only meaningful over HTTPS - a header on a cleartext response
    # is ignored by browsers, so do not credit or fault it there.
    if head is None:
        warn("Could not read response headers for the HSTS check")
        return
    hsts = head.headers.get("Strict-Transport-Security", "")
    if hsts:
        success(f"HSTS: {hsts}")
    elif url.startswith("https://"):
        warn("HSTS header missing - HTTP downgrade possible")
        add_vuln("Missing HSTS", "Medium", "A02:2021",
                 "No Strict-Transport-Security header on the HTTPS response", url,
                 evidence=head.evidence, confidence="Confirmed", cwe="CWE-319")


def hash_analysis():
    section("PASSWORD HASH ANALYSIS")
    print(f"""
  {NEON_CYN}Common weak hash patterns:{RST}

  MD5:    32 hex chars  e.g. 5f4dcc3b5aa765d61d8327deb882cf99 (= "password")
  SHA1:   40 hex chars
  SHA256: 64 hex chars
  bcrypt: $2a$/2b$/2y$ prefix (STRONG)
  Argon2: $argon2 prefix (STRONG)
  scrypt: $scrypt prefix (STRONG)

  {NEON_CYN}Crack MD5/SHA1 with hashcat:{RST}
    hashcat -m 0 hash.txt /usr/share/wordlists/rockyou.txt   # MD5
    hashcat -m 100 hash.txt /usr/share/wordlists/rockyou.txt # SHA1

  {NEON_CYN}Online lookup (authorized use only):{RST}
    https://crackstation.net
    https://hashes.com
""")
    hash_val = prompt("Paste hash to identify (optional)")
    if hash_val:
        length = len(hash_val)
        if length == 32:
            warn(f"Looks like MD5 ({length} chars) - weak, crackable")
        elif length == 40:
            warn(f"Looks like SHA1 ({length} chars) - weak, crackable")
        elif length == 64:
            info(f"Looks like SHA256 ({length} chars) - better but still brute-forceable")
        elif hash_val.startswith("$2"):
            success("Looks like bcrypt - strong password hashing")
        elif hash_val.startswith("$argon2"):
            success("Looks like Argon2 - strong password hashing")
        else:
            info(f"Unknown hash format (length={length})")

        if shutil.which("hashid"):
            run_and_print(f"hashid '{hash_val}'")


def js_secrets():
    section("JAVASCRIPT SECRET HUNTING")
    url = _target()

    info("Analyzing JavaScript files for embedded secrets/API keys...")

    patterns = JS_SECRET_PATTERNS

    client = get_client()
    page = client.safe_get(url, timeout=15)
    if page is None:
        error("Could not fetch the page")
        return
    js_urls = re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', page.text, re.I)

    sources = [(url, page)]
    for js in js_urls[:10]:
        if not js.startswith("http"):
            js = url.rstrip("/") + "/" + js.lstrip("/")
        js_resp = client.safe_get(js, timeout=10)
        if js_resp is not None:
            sources.append((js, js_resp))

    info(f"Scanning page + {len(sources) - 1} JS files for {len(patterns)} secret patterns...")
    print()
    found_any = False
    seen: set[tuple[str, str]] = set()

    for source_url, resp in sources:
        for name, (pattern, severity) in patterns.items():
            for match in re.findall(pattern, resp.text):
                snippet = match if isinstance(match, str) else match[0]
                key = (name, snippet)
                if key in seen:
                    continue
                seen.add(key)
                found_any = True
                masked = snippet[:8] + "…" + snippet[-4:] if len(snippet) > 16 else snippet
                warn(f"[{name}] in {source_url[:60]}: {masked}")
                add_vuln(f"Secret in JS: {name}", severity, "A02:2021",
                         f"{name} found in client-side source at {source_url}: {masked}",
                         source_url, evidence=resp.evidence,
                         confidence="Firm", cwe="CWE-798")

    if not found_any:
        info("No obvious secrets found in JavaScript sources")


def run():
    print_banner("CRYPTOGRAPHIC FAILURES", "A02:2021 - OWASP Top 10 #2")
    while True:
        url = SESSION.get("target_url", "-")
        print(f"""
  {NEON_GRN}Target:{RST} {PURE_WHITE}{url}{RST}

  {NEON_CYN}[1]{RST} Sensitive Data Exposure (files, backups, configs)
  {NEON_CYN}[2]{RST} Cleartext Transmission Check (HTTP/HSTS)
  {NEON_CYN}[3]{RST} Hash Strength Analysis & Cracking
  {NEON_CYN}[4]{RST} JavaScript Secret Hunting (API keys, tokens)
  {NEON_GRN}[0]{RST} Back to main menu
""")
        c = prompt("Choice")
        if c == "0":
            break
        elif c == "1":
            sensitive_data_exposure()
        elif c == "2":
            cleartext_check()
        elif c == "3":
            hash_analysis()
        elif c == "4":
            js_secrets()
        save_session()
