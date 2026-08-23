"""
modules/insecure_design.py
tmrswrr - A04: Insecure Design
Business logic flaws, race conditions, mass assignment, API abuse
"""
import os

from config.settings import OUTPUT_DIR, SESSION, add_vuln, save_session
from utils.helpers import (
    DIM,
    NEON_CYN,
    NEON_GRN,
    PURE_WHITE,
    RST,
    ask_int,
    info,
    print_banner,
    prompt,
    run_cmd,
    section,
    success,
    warn,
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


def business_logic():
    section("BUSINESS LOGIC FLAWS")
    url = _target()

    print(f"""
  {NEON_CYN}Common Business Logic Flaws to Test:{RST}

  {NEON_GRN}[1] Price/Quantity Manipulation:{RST}
    - Change price parameter to 0 or negative in checkout
    - Change quantity to negative (get credit)
    - Apply same coupon code multiple times
    - Manipulate discount fields in API requests

  {NEON_GRN}[2] Workflow Bypass:{RST}
    - Skip payment step in multi-step checkout
    - Access step 3 without completing steps 1 & 2
    - Try to access /checkout/confirm without /checkout/pay

  {NEON_GRN}[3] Account Enumeration:{RST}
    - Different error messages for valid vs invalid users
    - Timing differences in responses reveal user existence

  {NEON_GRN}[4] Transfer/Balance Manipulation:{RST}
    - Transfer more than available balance
    - Race condition: transfer same amount simultaneously

  {NEON_GRN}[5] Privilege Logic:{RST}
    - Regular user performing admin actions via API
    - Accessing other users' data by changing account ID
""")

    c = prompt("Which test? [1-5] or [0] Back")

    if c == "1":
        endpoint = prompt("Checkout/order endpoint")
        price_param = prompt("Price parameter name")
        info("Testing negative price and zero price:")
        cookies = SESSION.get("cookies", "")
        cookie_flag = f'-H "Cookie: {cookies}"' if cookies else ""
        for price in ["0", "-1", "-100", "0.001"]:
            data = f"{price_param}={price}&quantity=1"
            out, _, _ = run_cmd(
                f'curl -sk -X POST "{url}{endpoint}" '
                f'-H "Content-Type: application/x-www-form-urlencoded" '
                f'{cookie_flag} -d "{data}" -m 10'
            )
            if any(x in out.lower() for x in ["success", "order", "confirmed", "payment"]):
                success(f"Business logic bypass with price={price}!")
                add_vuln("Business Logic: Price Manipulation", "Critical", "A04:2021",
                         f"Order accepted with price={price}", url + endpoint)
            else:
                print(f"  {DIM}[-] price={price} rejected{RST}")

    elif c == "3":
        endpoint = prompt("Login endpoint")
        fail_msg1 = prompt("Error for valid user, wrong password (exact text)")
        fail_msg2 = prompt("Error for invalid user (exact text)")
        if fail_msg1 != fail_msg2:
            warn("Different error messages detected - username enumeration possible!")
            add_vuln("Username Enumeration", "Medium", "A04:2021",
                     f"Different messages: '{fail_msg1}' vs '{fail_msg2}'", url + endpoint)
        else:
            success("Same error message for both cases - enumeration protected")


def race_condition():
    section("RACE CONDITION TESTING")
    url = _target()
    cookies = SESSION.get("cookies", "")
    cookie_flag = f'-H "Cookie: {cookies}"' if cookies else ""

    print(f"""
  {NEON_CYN}Race Condition Test Setup:{RST}
  Send multiple concurrent requests to exploit timing windows.
  Common targets: coupon redemption, balance transfer, gift card use, file upload
""")

    endpoint  = prompt("Target endpoint (e.g. /api/redeem-coupon)")
    method    = prompt("[1] GET  [2] POST") or "2"
    data      = prompt("POST data (for POST requests)") if method == "2" else ""
    threads   = ask_int("Number of parallel requests", 10, minimum=1, maximum=200)

    info(f"Sending {threads} concurrent requests to {url}{endpoint}...")

    import threading
    import time

    results = []
    def send_request():
        if method == "2":
            out, _, rc = run_cmd(
                f'curl -sk -X POST "{url}{endpoint}" '
                f'-H "Content-Type: application/x-www-form-urlencoded" '
                f'{cookie_flag} -d "{data}" -m 10 -w "\\n%{{http_code}}"'
            )
        else:
            out, _, rc = run_cmd(
                f'curl -sk "{url}{endpoint}" {cookie_flag} -m 10 -w "\\n%{{http_code}}"'
            )
        results.append(out)

    thread_list = [threading.Thread(target=send_request) for _ in range(threads)]
    start = time.time()
    for t in thread_list:
        t.start()
    for t in thread_list:
        t.join()
    elapsed = time.time() - start

    success_count = sum(1 for r in results if any(
        x in r.lower() for x in ["success", "redeemed", "applied", "200"]
    ))
    info(f"Done in {elapsed:.2f}s - {success_count}/{threads} appeared successful")

    if success_count > 1:
        success(f"RACE CONDITION CONFIRMED! {success_count} requests succeeded simultaneously!")
        add_vuln("Race Condition", "High", "A04:2021",
                 f"{success_count}/{threads} concurrent requests succeeded", url + endpoint)
    else:
        info("No obvious race condition - may be protected or need more threads")


def mass_assignment():
    section("MASS ASSIGNMENT VULNERABILITY")
    url = _target()
    cookies = SESSION.get("cookies", "")
    cookie_flag = f'-H "Cookie: {cookies}"' if cookies else ""

    info("Mass assignment: adding extra fields to API requests that shouldn't be user-modifiable")

    endpoint = prompt("API endpoint (e.g. /api/user/update or /register)")
    normal_data = prompt("Normal JSON payload (e.g. {\"name\":\"test\"})")

    extra_fields = [
        '"role":"admin"',
        '"isAdmin":true',
        '"admin":true',
        '"is_admin":1',
        '"permissions":["admin","superuser"]',
        '"balance":9999999',
        '"credits":9999999',
        '"verified":true',
        '"active":true',
        '"subscription":"premium"',
        '"plan":"enterprise"',
    ]

    info(f"Testing {len(extra_fields)} extra privilege fields...")
    print()

    import json
    try:
        base = json.loads(normal_data)
    except Exception:
        base = {}

    for field in extra_fields:
        try:
            extra_key, _, extra_val = field.strip('"').partition('":')
            test_data = dict(base)
            test_data[extra_key.strip('"')] = json.loads(extra_val.strip())
            test_json = json.dumps(test_data)
        except Exception:
            test_json = f"{{{normal_data.strip('{}')}, {field}}}"

        out, _, _ = run_cmd(
            f'curl -sk -X POST "{url}{endpoint}" '
            f'-H "Content-Type: application/json" '
            f'{cookie_flag} -d \'{test_json}\' -m 10'
        )
        if any(x in out.lower() for x in ["success", "updated", "ok", "true"]):
            info(f"[?] Accepted field: {field} - verify in app if it actually applied")
            print(f"  Response: {out[:200]}")
        else:
            print(f"  {DIM}[-] {field}{RST}")


def api_rate_limit():
    section("API RATE LIMITING CHECK")
    url = _target()
    cookies = SESSION.get("cookies", "")
    cookie_flag = f'-H "Cookie: {cookies}"' if cookies else ""

    endpoint = prompt("Endpoint to test rate limiting (e.g. /api/forgot-password or /login)")
    requests = ask_int("Number of requests to send", 50, minimum=1, maximum=1000)

    info(f"Sending {requests} rapid requests to {url}{endpoint}...")
    rate_limited = False
    for i in range(requests):
        out, _, _ = run_cmd(
            f'curl -sk -X POST "{url}{endpoint}" '
            f'{cookie_flag} -w "\\n%{{http_code}}" -m 5 -o /dev/null'
        )
        code = out.strip()
        if code in ("429", "403"):
            info(f"Rate limited after {i+1} requests (HTTP {code})")
            rate_limited = True
            break
        if (i + 1) % 10 == 0:
            print(f"  {DIM}[{i+1}/{requests}] requests sent, no rate limit yet{RST}")

    if not rate_limited:
        warn(f"No rate limiting detected after {requests} requests!")
        add_vuln("Missing Rate Limiting", "Medium", "A04:2021",
                 f"No rate limit on {endpoint} after {requests} requests", url + endpoint)
    else:
        success("Rate limiting is active")


def run():
    print_banner("INSECURE DESIGN", "A04:2021 - OWASP Top 10 #4")
    while True:
        url = SESSION.get("target_url", "-")
        print(f"""
  {NEON_GRN}Target:{RST} {PURE_WHITE}{url}{RST}

  {NEON_CYN}[1]{RST} Business Logic Flaws
  {NEON_CYN}[2]{RST} Race Condition Testing
  {NEON_CYN}[3]{RST} Mass Assignment Vulnerability
  {NEON_CYN}[4]{RST} API Rate Limiting Check
  {NEON_GRN}[0]{RST} Back to main menu
""")
        c = prompt("Choice")
        if c == "0":
            break
        elif c == "1":
            business_logic()
        elif c == "2":
            race_condition()
        elif c == "3":
            mass_assignment()
        elif c == "4":
            api_rate_limit()
        save_session()
