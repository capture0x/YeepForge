"""
modules/subdomain_takeover.py
tmrswrr - Subdomain Takeover Detection & Validation
Dangling DNS, unclaimed cloud services, CNAME hijacking
"""
import os

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
    run_and_print,
    run_cmd,
    section,
    success,
    warn,
)


def _out(name):
    d = str(OUTPUT_DIR); os.makedirs(d, exist_ok=True)
    return os.path.join(d, name)


# Known fingerprints for unclaimed cloud services
TAKEOVER_FINGERPRINTS = {
    "GitHub Pages":      ["There isn't a GitHub Pages site here", "github.com"],
    "Heroku":            ["No such app", "herokuapp.com"],
    "AWS S3":            ["NoSuchBucket", "s3.amazonaws.com"],
    "AWS CloudFront":    ["Bad request", "cloudfront.net"],
    "Shopify":           ["Sorry, this shop is currently unavailable"],
    "Fastly":            ["Fastly error: unknown domain", "fastly.net"],
    "SendGrid":          ["The item you requested could not be found", "sendgrid.net"],
    "Zendesk":           ["Help Center Closed", "zendesk.com"],
    "Tumblr":            ["There's nothing here", "tumblr.com"],
    "Ghost":             ["The thing you were looking for is no longer here"],
    "Cargo Collective":  ["404 Not Found", "cargocollective.com"],
    "StatusPage.io":     ["Better luck next time", "statuspage.io"],
    "Desk.com":          ["Please try again or try Desk.com free for 14 days"],
    "UserVoice":         ["This UserVoice subdomain is currently available!", "uservoice.com"],
    "Pantheon":          ["The gods are wise", "pantheon.io"],
    "Vercel":            ["The deployment could not be found", "vercel.app"],
    "Netlify":           ["Not found - Request ID", "netlify.app", "netlify.com"],
    "Azure":             ["404 Web Site not found", "azurewebsites.net", "cloudapp.net"],
    "Bitbucket":         ["Repository not found", "bitbucket.io"],
    "Acquia":            ["Web Site Not Found", "acquia-sites.com"],
    "ReadTheDocs":       ["unknown to Read the Docs", "readthedocs.io"],
    "HelpJuice":         ["We could not find what you're looking for"],
    "LaunchRock":        ["It looks like you may have taken a wrong turn somewhere"],
    "WPEngine":          ["The site you were looking for couldn't be found"],
    "Surge.sh":          ["project not found", "surge.sh"],
    "Squarespace":       ["You need a Squarespace account"],
}


def enumerate_subdomains():
    section("SUBDOMAIN ENUMERATION FOR TAKEOVER")
    url = SESSION.get("target_url", "")
    host = url.split("//")[-1].split("/")[0] if url else ""
    domain = prompt(f"Target domain to enumerate [{host}]") or host
    if not domain:
        return

    SESSION["_takeover_domain"] = domain
    info(f"Enumerating subdomains of: {domain}")

    subs = []
    # subfinder
    import shutil
    if shutil.which("subfinder"):
        out = _out("takeover_subdomains.txt")
        stdout, _, _ = run_cmd(f"subfinder -d {domain} -silent -o {out}", timeout=120)
        if os.path.exists(out):
            with open(out) as f:
                subs = [l.strip() for l in f if l.strip()]
            success(f"subfinder: {len(subs)} subdomains → {out}")
    elif shutil.which("amass"):
        out = _out("takeover_subdomains.txt")
        run_cmd(f"amass enum -passive -d {domain} -o {out}", timeout=180)
        if os.path.exists(out):
            with open(out) as f:
                subs = [l.strip() for l in f if l.strip()]
    else:
        warn("Install subfinder or amass for enumeration")
        manual = prompt("Paste comma-separated subdomains to check")
        if manual:
            subs = [s.strip() for s in manual.split(",")]

    if subs:
        info(f"Found {len(subs)} subdomains - checking for takeover candidates...")
        check_subdomains(subs)


def check_subdomains(subs=None):
    section("TAKEOVER VULNERABILITY CHECK")
    domain = SESSION.get("_takeover_domain", "")

    if not subs:
        sub_file = _out("takeover_subdomains.txt")
        if os.path.exists(sub_file):
            with open(sub_file) as f:
                subs = [l.strip() for l in f if l.strip()]
        else:
            manual = prompt("Paste subdomains to check (comma or newline separated)")
            subs = [s.strip() for s in manual.replace("\n", ",").split(",") if s.strip()]

    if not subs:
        warn("No subdomains to check")
        return

    vulnerable = []
    info(f"Checking {len(subs)} subdomains for CNAME + service fingerprints...")
    print()

    for sub in subs:
        # Step 1: Get CNAME
        cname_out, _, _ = run_cmd(f"dig +short CNAME {sub}", timeout=5)
        cname = cname_out.strip().rstrip(".")

        if not cname:
            # Check A record - if no DNS resolution, dangling
            a_out, _, _ = run_cmd(f"dig +short A {sub}", timeout=5)
            if not a_out.strip():
                print(f"  {NEON_YEL}[NO DNS]{RST} {sub} - may be dangling")
            continue

        # Step 2: Check if CNAME points to a known cloud service
        for service, fingerprints in TAKEOVER_FINGERPRINTS.items():
            service_domains = [f for f in fingerprints if "." in f]
            if any(sd in cname for sd in service_domains):
                # Step 3: Fetch the subdomain and check for unclaimed fingerprint
                http_out, _, _ = run_cmd(f"curl -sk http://{sub} -m 8 -L", timeout=10)
                https_out, _, _ = run_cmd(f"curl -sk https://{sub} -m 8 -L", timeout=10)
                content = (http_out + https_out).lower()

                text_fps = [f for f in fingerprints if "." not in f]
                if any(fp.lower() in content for fp in text_fps):
                    success(f"TAKEOVER POSSIBLE: {sub}")
                    success(f"  Service: {service}")
                    success(f"  CNAME: {cname}")
                    warn("  Register/claim this service with CNAME target to take over!")
                    vulnerable.append((sub, service, cname))
                    add_vuln(f"Subdomain Takeover: {sub} ({service})", "Critical", "A01:2021",
                             f"Dangling CNAME {cname} → unclaimed {service}", f"http://{sub}")
                else:
                    print(f"  {NEON_CYN}[CNAME→{service}]{RST} {sub} → {cname} (claimed or different response)")
                break
        else:
            print(f"  {DIM}[CNAME]{RST} {sub} → {cname}")

    if vulnerable:
        out_file = _out("subdomain_takeovers.txt")
        with open(out_file, "w") as f:
            f.write("\n".join(f"{s},{svc},{c}" for s, svc, c in vulnerable))
        success(f"{len(vulnerable)} takeover candidates → {out_file}")
    else:
        info("No obvious takeover candidates found")


def check_single_subdomain():
    section("CHECK SINGLE SUBDOMAIN")
    sub = prompt("Subdomain to check (e.g. old.example.com)")
    if not sub:
        return

    info(f"Checking: {sub}")

    # DNS resolution
    cname_out, _, _ = run_cmd(f"dig +short CNAME {sub}", timeout=5)
    a_out, _, _ = run_cmd(f"dig +short A {sub}", timeout=5)
    print(f"  CNAME: {cname_out.strip() or 'none'}")
    print(f"  A:     {a_out.strip() or 'none (dangling!)'}")

    if not cname_out.strip() and not a_out.strip():
        warn("No DNS records - subdomain is dangling!")
        info("If you can register this subdomain, you control it completely")

    # Fetch HTTP response
    http_out, _, _ = run_cmd(f"curl -sk http://{sub} -m 8 -L --max-redirs 3")
    https_out, _, _ = run_cmd(f"curl -sk https://{sub} -m 8 -L --max-redirs 3")
    content = http_out + https_out

    if content:
        print(f"\n  {NEON_CYN}Response preview:{RST}")
        print(f"  {content[:400]}")

        for service, fps in TAKEOVER_FINGERPRINTS.items():
            text_fps = [f for f in fps if "." not in f]
            if any(fp.lower() in content.lower() for fp in text_fps):
                success(f"MATCH: {service} fingerprint detected → TAKEOVER LIKELY!")
                add_vuln(f"Subdomain Takeover ({service})", "Critical", "A01:2021",
                         f"Unclaimed {service} at {sub}", f"http://{sub}")


def nuclei_takeover():
    section("NUCLEI - AUTOMATED TAKEOVER SCAN")
    import shutil
    if not shutil.which("nuclei"):
        warn("nuclei not found. Install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
        return

    sub_file = _out("takeover_subdomains.txt")
    if not os.path.exists(sub_file):
        warn(f"No subdomain file found at {sub_file}")
        info("Run subdomain enumeration first [1]")
        return

    out = _out("nuclei_takeover.txt")
    info("Running nuclei with subdomain-takeover templates...")
    run_and_print(
        f"nuclei -l {sub_file} -t ~/nuclei-templates/http/takeovers/ "
        f"-o {out} -silent -severity critical,high",
        timeout=600
    )
    success(f"Results → {out}")


def run():
    print_banner("SUBDOMAIN TAKEOVER",
                 "CNAME Hijacking · 25+ Service Fingerprints · Nuclei Scan")
    while True:
        domain = SESSION.get("_takeover_domain", "-")
        url    = SESSION.get("target_url", "-")
        print(f"""
  {NEON_GRN}Target Domain:{RST} {PURE_WHITE}{domain}{RST}
  {NEON_GRN}Target URL:{RST}    {PURE_WHITE}{url}{RST}

  {NEON_CYN}[1]{RST} Enumerate Subdomains        {SOFT_WHITE}(subfinder/amass){RST}
  {NEON_CYN}[2]{RST} Check All Subdomains        {SOFT_WHITE}(CNAME + 25 service fingerprints){RST}
  {NEON_CYN}[3]{RST} Check Single Subdomain
  {NEON_CYN}[4]{RST} Nuclei Takeover Scan        {SOFT_WHITE}(automated templates){RST}
  {NEON_GRN}[0]{RST} Back to main menu
""")
        c = prompt("Choice")
        if c == "0": break
        elif c == "1": enumerate_subdomains()
        elif c == "2": check_subdomains()
        elif c == "3": check_single_subdomain()
        elif c == "4": nuclei_takeover()
        save_session()
