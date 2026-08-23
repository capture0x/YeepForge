"""
modules/session_security.py
tmrswrr - Comprehensive Session Security Testing
Complete coverage: fixation, timeout, logout, exposed vars, cookie attr
"""
import os
import re

from config.settings import OUTPUT_DIR, SESSION, add_vuln, save_session
from utils.helpers import (
    DIM,
    NEON_CYN,
    NEON_GRN,
    NEON_YEL,
    PURE_WHITE,
    RST,
    SOFT_WHITE,
    error,
    info,
    print_banner,
    prompt,
    section,
    success,
    warn,
)
from utils.http import (
    get_client,
    looks_like_notfound,
    notfound_signature,
    set_cookie_headers,
)

#: Reserved documentation host used as the cross-origin probe for the logout
#: CSRF check - never a domain someone else owns.
LOGOUT_CSRF_CANARY = "yeepforge-canary.example.net"


def _out(name):
    d = str(OUTPUT_DIR); os.makedirs(d, exist_ok=True)
    return os.path.join(d, name)


def _target():
    url = SESSION.get("target_url", "")
    if not url:
        url = prompt("Target URL"); SESSION["target_url"] = url
    return url


#: Name fragments that mark a cookie as carrying authentication state.
_SESSION_COOKIE_HINTS = ("sess", "auth", "token", "sid", "login", "jwt", "remember")


def is_session_cookie(name: str) -> bool:
    return any(hint in name.lower() for hint in _SESSION_COOKIE_HINTS)


def _cookie_severity(name: str, attribute: str, over_https: bool) -> str:
    """Grade a missing cookie attribute by what it actually exposes.

    Every missing attribute used to be Medium, which put a locale cookie's
    absent SameSite next to a session cookie readable from JavaScript.
    """
    session = is_session_cookie(name)
    if attribute == "secure" and not over_https:
        # The site is plain HTTP; the transport is the finding, not the flag.
        return "Low"
    if attribute == "httponly":
        return "Medium" if session else "Low"
    if attribute == "secure":
        return "Medium" if session else "Low"
    return "Low"  # SameSite: browsers default to Lax


def cookie_attributes():
    section("COOKIE SECURITY ATTRIBUTES ")
    url = _target()

    info("Checking ALL Set-Cookie headers for security attributes...")
    client = get_client()
    resp = client.safe_get(url, timeout=10)
    set_cookies = set_cookie_headers(resp) if resp is not None else []

    if not set_cookies:
        info("No Set-Cookie headers on homepage - try login endpoint")
        login = prompt("Login endpoint (e.g. /login)")
        if login:
            try:
                resp = client.post(url.rstrip("/") + "/" + login.lstrip("/"),
                                   data={"username": "admin", "password": "admin"},
                                   timeout=10)
                set_cookies = set_cookie_headers(resp)
            except Exception as exc:
                warn(f"Login probe failed: {exc}")

    over_https = url.lower().startswith("https://")
    issues = []
    for ck in set_cookies:
        ck_lower = ck.lower()
        name = ck.split("=")[0].strip()
        print(f"\n  {NEON_CYN}Cookie: {name}{RST}")
        print(f"  {DIM}{ck[:120]}{RST}")

        checks = [
            ("httponly",  "HttpOnly",  "Accessible via JavaScript - XSS can steal this cookie"),
            ("secure",    "Secure",    "Sent over HTTP - MITM can intercept"),
            ("samesite",  "SameSite",  "No CSRF protection via SameSite"),
        ]
        for attr, label, risk in checks:
            if attr in ck_lower:
                success(f"  ✓ {label} set")
                if attr == "samesite":
                    if "strict" in ck_lower:
                        info("  SameSite=Strict (strongest)")
                    elif "lax" in ck_lower:
                        info("  SameSite=Lax (GET CSRF still possible)")
                    elif "none" in ck_lower:
                        warn("  SameSite=None - cross-site requests allowed")
                        issues.append(f"Cookie {name}: SameSite=None")
            else:
                warn(f"  ✗ {label} MISSING - {risk}")
                issues.append(f"Cookie {name}: missing {label}")
                add_vuln(f"Cookie Missing {label}: {name}",
                         _cookie_severity(name, attr, over_https), "A07:2021",
                         f"{risk} (cookie '{name}')", url,
                         evidence=resp.evidence if resp is not None else None,
                         confidence="Confirmed", cwe="CWE-1004" if attr == "httponly" else "CWE-614")

        # Check for session ID in URL
        if "path=/" in ck_lower:
            info("  Path=/ (sent to all paths - expected for session cookies)")

    if issues:
        print(f"\n  {NEON_YEL}Issues found: {len(issues)}{RST}")
        for i in issues:
            print(f"    ✗ {i}")
    elif set_cookies:
        success("All cookie attributes look good!")


def _cookie_value(response, name: str) -> str:
    """Value of `name` from a response's Set-Cookie headers, or ''."""
    if response is None:
        return ""
    for header in set_cookie_headers(response):
        key, _, rest = header.partition("=")
        if key.strip().lower() == name.lower():
            return rest.split(";")[0].strip()
    return ""


#: Wording that means the credentials were rejected, whatever the status code.
_LOGIN_FAILURE_MARKERS = ("invalid", "incorrect", "failed", "try again",
                          "wrong password", "authentication failed", "unauthor")


def _looks_like_failed_login(response) -> bool:
    body = (response.text or "").lower()[:4000]
    return any(marker in body for marker in _LOGIN_FAILURE_MARKERS)


def session_fixation():
    section("SESSION FIXATION TESTING ")
    url = _target()
    cookies = SESSION.get("cookies", "")

    print(f"""
  {NEON_CYN}Session Fixation Attack:{RST}
    1. Attacker visits app, gets pre-auth session ID
    2. Attacker tricks victim into using same session ID
    3. Victim logs in → session ID becomes authenticated
    4. Attacker uses original session ID → logged in as victim!

  {NEON_CYN}Test procedure:{RST}
""")
    login_endpoint = prompt("Login endpoint (e.g. /login)")
    session_param  = prompt("Session cookie name (e.g. PHPSESSID, session)") or "PHPSESSID"
    if not login_endpoint:
        return

    # Step 1: Get pre-auth session
    info("Step 1: Getting pre-auth session ID...")
    client = get_client()
    first = client.safe_get(url, timeout=8)
    pre_session = _cookie_value(first, session_param)

    if not pre_session:
        warn(f"No {session_param} cookie found on initial request")
        pre_session = prompt("Enter a pre-auth session ID to test (or Enter to skip)")

    if not pre_session:
        return

    info(f"Pre-auth session: {pre_session[:20]}...")

    # Step 2: Login with this session
    info("Step 2: Logging in with fixed session ID...")
    username = SESSION.get("username") or "admin"
    password = SESSION.get("password") or "admin"
    try:
        login_resp = client.post(
            url.rstrip("/") + "/" + login_endpoint.lstrip("/"),
            data={"username": username, "password": password},
            # An explicit Cookie header wins over the client's jar, which is
            # what pins the session to the pre-auth ID we are testing.
            headers={"Cookie": f"{session_param}={pre_session}"},
            timeout=10, allow_redirects=False,
        )
    except Exception as exc:
        error(f"Login request failed: {exc}")
        return

    # Step 3: Check if session changed
    post_session = _cookie_value(login_resp, session_param)

    authenticated = login_resp.status_code in (200, 301, 302, 303) and \
        not _looks_like_failed_login(login_resp)

    if not post_session:
        info("No new session cookie issued after login - check if pre-auth cookie is still valid")
    elif post_session == pre_session:
        if not authenticated:
            # Without a successful login there is nothing to regenerate, so an
            # unchanged ID proves nothing. The old code reported it as High.
            warn("Session ID unchanged, but the login does not appear to have succeeded - "
                 "supply working credentials before trusting this result")
            return
        success("SESSION FIXATION CONFIRMED - session ID did NOT change after login!")
        warn("Pre-auth and post-auth session ID are identical")
        add_vuln("Session Fixation", "High", "A07:2021",
                 f"The {session_param} cookie was not regenerated after a successful "
                 "authentication, so a pre-set session ID stays valid post-login.",
                 url, evidence=login_resp.evidence, confidence="Firm", cwe="CWE-384")
    else:
        success(f"Session correctly regenerated after login: {post_session[:20]}...")
        info("Session fixation NOT present (session ID changes on login)")


def session_timeout():
    section("SESSION TIMEOUT TESTING ")
    url = _target()

    print(f"""
  {NEON_CYN}Testing absolute and idle session timeout:{RST}
    - Absolute timeout: session expires after X time regardless of activity
    - Idle timeout: session expires after X minutes of inactivity
    - Both should be set for proper session management
""")
    protected = prompt("Protected endpoint to test (e.g. /dashboard or /api/profile)")
    if not protected:
        protected = "/dashboard"

    if not SESSION.get("cookies"):
        warn("No session cookies set - login first and set cookies in Session Manager")
        return

    # Baseline check
    client = get_client()
    target = url.rstrip("/") + "/" + protected.lstrip("/")
    resp = client.safe_get(target, timeout=8)
    if resp is None:
        error("Could not reach the protected endpoint")
        return
    info(f"Current session status: HTTP {resp.status_code}")

    if resp.status_code in (200, 201):
        success("Session active - testing timeout behavior")
        info("Wait period: test every 5 minutes for up to 30 minutes")
        info("Manual test: come back after session inactivity and run:")
        info(f"  {resp.evidence.curl}")
    elif resp.status_code in (401, 403, 302):
        warn(f"Session already expired or requires auth (HTTP {resp.status_code})")

    # Check for timeout-related headers
    for hdr in ("Session-Expiry", "X-Session-Timeout", "Expires", "Cache-Control"):
        value = resp.headers.get(hdr)
        if value:
            info(f"Session expiry hint - {hdr}: {value}")


def logout_testing():
    section("LOGOUT FUNCTIONALITY TESTING ")
    url = _target()

    print(f"""
  {NEON_CYN}Logout security checks:{RST}
    1. Does logout invalidate server-side session?
    2. Is the session token blacklisted after logout?
    3. Can you reuse cookies after logout?
    4. Does CSRF protection exist on logout?
""")
    logout_endpoint = prompt("Logout endpoint (e.g. /logout or /api/logout)")
    protected       = prompt("Protected endpoint to verify (e.g. /dashboard)")
    if not logout_endpoint or not SESSION.get("cookies"):
        warn("Need cookies set (login first) and logout endpoint")
        return

    client = get_client()
    protected_url = url.rstrip("/") + "/" + protected.lstrip("/")
    logout_url = url.rstrip("/") + "/" + logout_endpoint.lstrip("/")

    # Step 1: Verify session is active
    info("Step 1: Verifying session is active before logout...")
    before = client.safe_get(protected_url, timeout=8)
    if before is None:
        error("Could not reach the protected endpoint")
        return
    info(f"  Before logout: HTTP {before.status_code}")

    # Step 2: Perform logout
    info("Step 2: Performing logout...")
    client.safe_get(logout_url, timeout=8)

    # Step 3: Try to reuse cookies
    info("Step 3: Trying to reuse session cookie after logout...")
    after = client.safe_get(protected_url, timeout=8)
    if after is None:
        error("Could not re-check the protected endpoint")
        return

    if after.status_code == before.status_code and before.status_code in (200, 201):
        success("LOGOUT VULNERABILITY - Session still valid after logout!")
        warn("Server did NOT invalidate session token")
        add_vuln("Insufficient Session Invalidation on Logout", "High", "A07:2021",
                 f"The protected endpoint still answered HTTP {after.status_code} with the "
                 "same session cookie after logout, so the token was not revoked server-side.",
                 protected_url, evidence=after.evidence, confidence="Firm", cwe="CWE-613")
    elif after.status_code in (401, 403, 302):
        success(f"Logout correctly invalidates session (HTTP {after.status_code})")
    else:
        info(f"Before logout: {before.status_code} | After: {after.status_code} - verify manually")

    # CSRF on logout check
    info("Checking CSRF protection on logout endpoint...")
    cross = client.safe_get(logout_url, timeout=8, headers={
        "Origin": f"https://{LOGOUT_CSRF_CANARY}",
        "Referer": f"https://{LOGOUT_CSRF_CANARY}/csrf.html",
    })
    if cross is not None and cross.status_code in (200, 204):
        warn("Logout may be CSRF-able from cross-origin request")
        add_vuln("CSRF on Logout", "Low", "A07:2021",
                 "The logout endpoint accepted a request carrying a cross-origin "
                 "Origin/Referer header", logout_url,
                 evidence=cross.evidence, confidence="Tentative", cwe="CWE-352")


def browser_cache():
    section("BROWSER CACHE WEAKNESS ")
    url = _target()

    print(f"""
  {NEON_CYN}Browser Cache Attack Scenario:{RST}
    1. User logs into banking/sensitive app on shared computer
    2. User logs out
    3. Attacker presses Back button in browser
    4. Browser shows CACHED sensitive page → attacker sees private data!
""")
    sensitive_pages = [
        "/dashboard", "/profile", "/account", "/settings",
        "/admin", "/api/user/me", "/transactions", "/orders"
    ]

    info("Checking Cache-Control headers on sensitive pages...")
    client = get_client()
    notfound = notfound_signature(client, url)
    print()
    for page in sensitive_pages:
        resp = client.safe_get(url.rstrip("/") + page, timeout=5)
        # Only pages that actually exist and are served to us can leak into the
        # browser cache; the old check merely looked for '404' anywhere in the
        # header block.
        if resp is None or resp.status_code != 200 or looks_like_notfound(resp, notfound):
            continue

        # Parse the directive list instead of substring-matching the whole
        # header block, where 'private' could come from any other header.
        cc_val = resp.headers.get("Cache-Control", "")
        directives = {d.strip().lower() for d in cc_val.split(",") if d.strip()}

        if "no-store" in directives:
            success(f"[OK] {page}  Cache-Control: {cc_val}")
        elif "no-cache" in directives and "private" in directives:
            info(f"[~] {page}  Cache-Control: {cc_val}  (no-cache + private but not no-store)")
        else:
            warn(f"[!] {page}  Cache-Control: {cc_val or '(not set)'}  ← MAY BE CACHED")
            add_vuln("Browser Cache Weakness", "Low", "A02:2021",
                     f"{page} is served without Cache-Control: no-store "
                     f"(got: {cc_val or 'no header'}), so a shared browser may retain it",
                     url.rstrip("/") + page, evidence=resp.evidence,
                     confidence="Confirmed", cwe="CWE-525")


def exposed_session_vars():
    section("EXPOSED SESSION VARIABLES")
    url = _target()

    print(f"""
  {NEON_CYN}Checking for session data exposed in responses:{RST}
""")
    endpoints = [url, f"{url}/dashboard", f"{url}/api/user", f"{url}/api/me",
                 f"{url}/profile", f"{url}/debug", f"{url}/api/session"]

    # A CSRF token in the page is *how the defence works*, so it is no longer
    # on this list. The rest carry their own severity rather than all being
    # reported as High.
    sensitive_patterns = {
        "Session token in HTML": (
            r'(?:session[_-]?(?:id|token|key)|PHPSESSID|jsessionid)\s*[=:]\s*["\']([^"\']{8,})',
            "High"),
        "User password hash": (
            r'(?:password_hash|hashed_password|pwd_hash)\s*[=:]\s*["\']([^"\']{20,})', "High"),
        "Debug info / stack": (
            r'(?:stack trace|traceback|exception in|debug=true|APP_DEBUG)', "Medium"),
        "API key in response": (
            r'(?:api[_-]?key|apikey|api_secret)\s*[=:]\s*["\']([^"\']{8,})', "High"),
        "JWT in response body": (
            r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}', "Medium"),
        "Internal IP address": (
            r'\b(?:10\.|172\.1[6-9]\.|172\.2\d\.|172\.3[01]\.|192\.168\.)\d+\.\d+\b', "Low"),
    }

    client = get_client()
    notfound = notfound_signature(client, url)
    for endpoint in endpoints:
        resp = client.safe_get(endpoint, timeout=8)
        if resp is None or len(resp.text) < 50 or looks_like_notfound(resp, notfound):
            continue

        for pattern_name, (pattern, severity) in sensitive_patterns.items():
            matches = re.findall(pattern, resp.text, re.I)
            if matches:
                warn(f"[{pattern_name}] in {endpoint}:")
                for m in matches[:2]:
                    print(f"  {NEON_YEL}{str(m)[:80]}{RST}")
                add_vuln(f"Exposed Session Data: {pattern_name}", severity, "A07:2021",
                         f"{pattern_name} appears in the response body of {endpoint} "
                         f"({len(matches)} match(es))",
                         endpoint, evidence=resp.evidence,
                         confidence="Firm", cwe="CWE-200")


def run():
    print_banner("SESSION SECURITY", "tmrswrr - Attributes · Fixation · Timeout · Logout · Browser Cache")
    while True:
        url = SESSION.get("target_url", "-")
        print(f"""
  {NEON_GRN}Target:{RST} {PURE_WHITE}{url}{RST}

  {NEON_CYN}[1]{RST} Cookie Security Attributes {SOFT_WHITE}(HttpOnly · Secure · SameSite · Path){RST}
  {NEON_CYN}[2]{RST} Session Fixation           {SOFT_WHITE}(session ID regeneration after login){RST}
  {NEON_CYN}[3]{RST} Session Timeout            {SOFT_WHITE}(absolute · idle timeout check){RST}
  {NEON_CYN}[4]{RST} Logout Functionality       {SOFT_WHITE}(server-side invalidation · CSRF logout){RST}
  {NEON_CYN}[5]{RST} Browser Cache Weakness     {SOFT_WHITE}(Cache-Control: no-store on sensitive pages){RST}
  {NEON_CYN}[6]{RST} Exposed Session Variables  {SOFT_WHITE}(tokens/hashes/IPs in responses){RST}
  {NEON_GRN}[0]{RST} Back to main menu
""")
        c = prompt("Choice")
        if c == "0": break
        elif c == "1": cookie_attributes()
        elif c == "2": session_fixation()
        elif c == "3": session_timeout()
        elif c == "4": logout_testing()
        elif c == "5": browser_cache()
        elif c == "6": exposed_session_vars()
        save_session()
