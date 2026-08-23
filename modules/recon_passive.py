"""
modules/recon_passive.py
Passive Reconnaissance - OSINT, DNS, Google Dorks, GitHub Leaks, Shodan, Certs
"""
import json
import os
import re
import shlex

from config.settings import OUTPUT_DIR, SESSION, add_vuln, save_session
from utils.helpers import (
    BOLD,
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


def _out(name):
    d = str(OUTPUT_DIR); os.makedirs(d, exist_ok=True)
    return os.path.join(d, name)


def _target():
    url = SESSION.get("target_url", "")
    if not url:
        url = prompt("Target URL"); SESSION["target_url"] = url
    return url


def _domain(url):
    return re.sub(r'^https?://', '', url).split('/')[0].split(':')[0]


def _run(cmd, timeout=30):
    out, err, _ = run_cmd(cmd, timeout=timeout)
    return ((out or "") + ("\n" + err if err else "")).strip() or "(no output)"


# ── 1. WHOIS & DNS ────────────────────────────────────────────────────────────

def whois_dns():
    section("WHOIS & DNS ENUMERATION")
    url    = _target()
    domain = _domain(url)
    info(f"Domain: {domain}")

    # WHOIS
    info("Running WHOIS...")
    out = _run(f"whois {shlex.quote(domain)} 2>&1 | head -60", timeout=20)
    print(out)

    # DNS records
    info("\nDNS Records:")
    for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]:
        out = _run(f"dig {shlex.quote(domain)} {rtype} +short 2>&1", timeout=10)
        if out and "(no output)" not in out:
            print(f"  {NEON_CYN}{rtype:6}{RST} {out[:200]}")

    # Zone transfer attempt
    info("\nZone transfer attempt (AXFR)...")
    ns_out = _run(f"dig {shlex.quote(domain)} NS +short 2>&1", timeout=10)
    nameservers = [ns.strip().rstrip('.') for ns in ns_out.splitlines() if ns.strip()]
    for ns in nameservers[:3]:
        zt = _run(f"dig @{shlex.quote(ns)} {shlex.quote(domain)} AXFR 2>&1 | head -30", timeout=15)
        if "Transfer failed" not in zt and "connection refused" not in zt.lower() and len(zt) > 100:
            success(f"ZONE TRANSFER SUCCEEDED via {ns}!")
            print(zt[:500])
            add_vuln("DNS Zone Transfer Enabled", "High", "A05:2021",
                     f"Full DNS zone transferred from {ns}", url)
        else:
            print(f"  {DIM}[-] {ns}: zone transfer refused{RST}")

    # Reverse DNS
    info("\nReverse DNS:")
    a_out = _run(f"dig {shlex.quote(domain)} A +short 2>&1", timeout=10)
    for ip in a_out.splitlines()[:3]:
        ip = ip.strip()
        if re.match(r'\d+\.\d+\.\d+\.\d+', ip):
            rdns = _run(f"dig -x {shlex.quote(ip)} +short 2>&1", timeout=8)
            print(f"  {ip} → {rdns.strip()}")


# ── 2. Subdomain Enumeration ──────────────────────────────────────────────────

def subdomain_enum():
    section("SUBDOMAIN ENUMERATION")
    url    = _target()
    domain = _domain(url)
    info(f"Enumerating subdomains for: {domain}")

    found_subs = set()

    # subfinder
    if os.path.exists("/usr/local/bin/subfinder") or _run("which subfinder") != "(no output)":
        info("Running subfinder...")
        out = _run(f"subfinder -d {shlex.quote(domain)} -silent 2>&1", timeout=120)
        for line in out.splitlines():
            line = line.strip()
            if domain in line and not line.startswith("["):
                found_subs.add(line)
        success(f"subfinder: {len(found_subs)} subdomains")

    # amass passive
    if _run("which amass") != "(no output)":
        info("Running amass (passive)...")
        out = _run(f"amass enum -passive -d {shlex.quote(domain)} 2>&1", timeout=120)
        for line in out.splitlines():
            if domain in line:
                found_subs.add(line.strip())

    # Certificate transparency (crt.sh)
    info("Querying crt.sh certificate transparency...")
    try:
        import urllib.request
        with urllib.request.urlopen(
            f"https://crt.sh/?q=%25.{domain}&output=json", timeout=20
        ) as r:
            data = json.loads(r.read())
            for entry in data:
                for name in entry.get("name_value", "").splitlines():
                    name = name.strip().lstrip("*.")
                    if domain in name:
                        found_subs.add(name)
        success(f"crt.sh: found {len(found_subs)} unique names so far")
    except Exception as e:
        warn(f"crt.sh query failed: {e}")

    # dnsx - resolve and check live
    live_subs = []
    if found_subs:
        info(f"\nResolving {len(found_subs)} subdomains...")
        sub_list = "\n".join(sorted(found_subs))
        sub_file = _out("subdomains_raw.txt")
        with open(sub_file, "w") as f:
            f.write(sub_list)

        if _run("which dnsx") != "(no output)":
            out = _run(f"dnsx -l {shlex.quote(sub_file)} -silent -a -resp 2>&1", timeout=120)
            for line in out.splitlines():
                if "[" in line:
                    live_subs.append(line.strip())
        else:
            # Manual resolve
            from concurrent.futures import ThreadPoolExecutor
            def _resolve(sub):
                out = _run(f"dig {shlex.quote(sub)} A +short 2>&1", timeout=6)
                return sub if out.strip() and "NXDOMAIN" not in out else None
            with ThreadPoolExecutor(max_workers=20) as ex:
                for result in ex.map(_resolve, list(found_subs)[:50]):
                    if result:
                        live_subs.append(result)

    out_file = _out("subdomains_live.txt")
    with open(out_file, "w") as f:
        f.write("\n".join(live_subs or sorted(found_subs)))

    print(f"\n  {NEON_GRN}Total subdomains found: {len(found_subs)}{RST}")
    print(f"  {NEON_GRN}Live/responding:        {len(live_subs)}{RST}")
    for s in (live_subs or sorted(found_subs))[:30]:
        print(f"  {s}")
    success(f"Saved → {out_file}")
    SESSION["found_subdomains"] = list(found_subs)


# ── 3. Google Dorks ───────────────────────────────────────────────────────────

def google_dorks():
    section("GOOGLE DORKS - PASSIVE OSINT")
    url    = _target()
    domain = _domain(url)

    dorks = [
        (f'site:{domain} filetype:pdf',                         "PDF documents"),
        (f'site:{domain} filetype:xls OR filetype:xlsx',       "Excel spreadsheets"),
        (f'site:{domain} filetype:sql OR filetype:bak',        "Database/backup files"),
        (f'site:{domain} inurl:admin OR inurl:dashboard',      "Admin panels"),
        (f'site:{domain} inurl:login OR inurl:signin',         "Login pages"),
        (f'site:{domain} inurl:api OR inurl:swagger',          "API endpoints"),
        (f'site:{domain} "index of" OR intitle:"index of"',    "Open directories"),
        (f'site:{domain} ext:php inurl:?',                     "PHP pages with parameters"),
        (f'site:{domain} intext:"sql syntax" OR "mysql error"',"SQL error messages"),
        (f'site:{domain} "DB_PASSWORD" OR "API_KEY" OR "SECRET_KEY"', "Exposed secrets"),
        (f'site:{domain} "Internal Server Error" OR "stack trace"',  "Error pages"),
        (f'"{domain}" site:github.com OR site:gitlab.com',     "GitHub/GitLab leaks"),
        (f'"{domain}" site:pastebin.com',                      "Pastebin leaks"),
        (f'"{domain}" site:trello.com',                        "Trello boards"),
        (f'site:{domain} ext:env OR ext:config',               "Config files"),
    ]

    print(f"\n  {NEON_CYN}Google Dorks for: {domain}{RST}")
    print(f"  {DIM}(Use these in browser - direct Google API access blocked){RST}\n")

    out_file = _out("google_dorks.txt")
    with open(out_file, "w") as f:
        f.write(f"# Google Dorks - {domain}\n\n")
        for dork, desc in dorks:
            encoded = dork.replace(" ", "+")
            gurl = f"https://www.google.com/search?q={encoded}"
            print(f"  {NEON_GRN}[*]{RST} {BOLD}{desc}{RST}")
            print(f"      {dork}")
            print(f"      {DIM}{gurl}{RST}\n")
            f.write(f"# {desc}\n{dork}\n{gurl}\n\n")

    success(f"Dorks saved → {out_file}")

    # Auto-query with curl (rate-limited, user-agent spoofed)
    auto = prompt("Auto-query Google? (may get blocked) [y/N]")
    if auto.lower() == "y":
        warn("Querying Google - rate limiting may apply")
        for dork, desc in dorks[:5]:
            encoded = dork.replace(" ", "+").replace('"', '%22')
            out = _run(
                f'curl -sk -A "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0" '
                f'"https://www.google.com/search?q={encoded}&num=5" 2>&1 | '
                f'grep -oP "(?<=<cite>)[^<]+" | head -5',
                timeout=15,
            )
            if out and "(no output)" not in out:
                print(f"  {desc}: {out}")
            import time  # noqa: I001
            time.sleep(2)


# ── 4. GitHub Secret Leak Scan ────────────────────────────────────────────────

def github_leaks():
    section("GITHUB / GITLAB SECRET LEAK DETECTION")
    url    = _target()
    domain = _domain(url)

    # Org name guessing
    org = domain.split('.')[0]
    info(f"Checking GitHub for org/repos related to: {org}, {domain}")

    # GitHub API (no token needed for public search)
    try:
        import urllib.parse
        import urllib.request
        query = urllib.parse.quote(f'"{domain}" OR "{org}"')
        api_url = f"https://api.github.com/search/repositories?q={query}&per_page=5"
        req = urllib.request.Request(api_url, headers={"User-Agent": "YeepForge"})
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.loads(r.read())
        repos = [item["full_name"] for item in data.get("items", [])]
        if repos:
            info(f"Related GitHub repos: {repos}")
            SESSION["github_repos"] = repos
    except Exception as e:
        warn(f"GitHub API: {e}")

    # Secret patterns to look for
    secret_patterns = [
        "password", "passwd", "api_key", "apikey", "secret", "token",
        "aws_access_key", "aws_secret", "private_key", "db_password",
        "database_url", "jwt_secret", "client_secret",
    ]

    print(f"""
  {NEON_CYN}Tools for GitHub secret scanning:{RST}

  {NEON_GRN}[1] trufflehog (recommended):{RST}
    trufflehog github --org={org}
    trufflehog github --repo=https://github.com/{org}/REPO

  {NEON_GRN}[2] gitleaks:{RST}
    gitleaks detect --source=. --report-path=leaks.json
    git clone https://github.com/{org}/REPO && gitleaks detect --source REPO

  {NEON_GRN}[3] GitDorker:{RST}
    python3 GitDorker.py -t TOKEN -d dorks.txt -q {domain}

  {NEON_GRN}[4] Manual GitHub search queries:{RST}""")

    gh_dorks = [
        f'"{domain}" password',
        f'"{domain}" api_key',
        f'"{domain}" secret',
        f'"{org}" DB_PASSWORD',
        f'"{org}" AWS_SECRET',
        f'filename:.env "{domain}"',
        f'filename:config.php "{domain}"',
        f'filename:settings.py "{domain}"',
    ]
    for d in gh_dorks:
        enc = d.replace('"', '%22').replace(' ', '+')
        print(f"    https://github.com/search?q={enc}&type=code")

    # Run trufflehog if available
    if _run("which trufflehog") != "(no output)":
        info("\nRunning trufflehog on GitHub org...")
        out = _run(
            f"trufflehog github --org={shlex.quote(org)} --json 2>&1 | head -100",
            timeout=120,
        )
        if "SourceMetadata" in out or "DetectorName" in out:
            success("trufflehog found potential secrets!")
            print(out[:1000])
            add_vuln("GitHub Secret Leak", "Critical", "A02:2021",
                     f"Secrets found in GitHub repos for org '{org}'", f"https://github.com/{org}")
        else:
            print(f"  {DIM}{out[:200]}{RST}")


# ── 5. Shodan / FOFA Lookup ───────────────────────────────────────────────────

def shodan_lookup():
    section("SHODAN / FOFA - INTERNET EXPOSURE")
    url    = _target()
    domain = _domain(url)

    # Resolve IP
    ip_out = _run(f"dig {shlex.quote(domain)} A +short 2>&1", timeout=10)
    ip = ip_out.strip().splitlines()[0] if ip_out.strip() else ""
    if ip:
        info(f"Target IP: {ip}")

    # Shodan CLI
    if _run("which shodan") != "(no output)":
        info("Querying Shodan...")
        for query in [domain, ip] if ip else [domain]:
            out = _run(f"shodan search {shlex.quote(query)} 2>&1 | head -30", timeout=30)
            if "Error" not in out and "(no output)" not in out:
                print(out)
            out2 = _run(f"shodan host {shlex.quote(ip)} 2>&1 | head -50", timeout=20) if ip else ""
            if out2 and "Error" not in out2:
                print(out2)
    else:
        warn("shodan CLI not installed: pip install shodan")
        info("Initialize with: shodan init YOUR_API_KEY")

    # Manual Shodan query hints
    print(f"""
  {NEON_CYN}Shodan manual queries:{RST}
    hostname:{domain}
    ssl.cert.subject.cn:{domain}
    ip:{ip or 'TARGET_IP'}
    org:"{org_name(domain)}"

  {NEON_CYN}FOFA (fofa.info):{RST}
    domain="{domain}"
    cert="{domain}"
    ip="{ip or 'TARGET_IP'}"

  {NEON_CYN}Censys:{RST}
    censys.io/search#q={domain}&resource=hosts

  {NEON_CYN}What you look for:{RST}
    - Open ports beyond 80/443 (admin interfaces, databases)
    - Leaked SSL cert SANs (internal subdomains)
    - Server version banners (CVE lookup)
    - Historical data (old vulnerable versions)
    - Related infrastructure
""")


def org_name(domain):
    return domain.split('.')[-2] if '.' in domain else domain


# ── 6. Email Harvesting ───────────────────────────────────────────────────────

def email_harvest():
    section("EMAIL HARVESTING - OSINT")
    url    = _target()
    domain = _domain(url)

    emails = set()

    # theHarvester
    if _run("which theHarvester") != "(no output)":
        info("Running theHarvester...")
        for source in ["google", "bing", "linkedin", "hunter"]:
            out = _run(
                f"theHarvester -d {shlex.quote(domain)} -b {source} -l 50 2>&1",
                timeout=60,
            )
            found = re.findall(r'[\w\.-]+@[\w\.-]+\.' + re.escape(domain.split('.')[-1]), out)
            emails.update(found)
        if emails:
            success(f"Found {len(emails)} emails: {list(emails)[:10]}")
            SESSION["emails"] = list(emails)
    else:
        warn("theHarvester not found: apt install theharvester")

    # Email format guessing
    print(f"""
  {NEON_CYN}Common email formats to test:{RST}
    firstname.lastname@{domain}
    f.lastname@{domain}
    firstname@{domain}
    flastname@{domain}

  {NEON_CYN}Spray targets (password spray):{RST}
    - Found emails → spray with common passwords
    - Tool: ruler, o365spray, spray.py
""")


# ── Menu ──────────────────────────────────────────────────────────────────────

def run():
    print_banner("PASSIVE RECONNAISSANCE", "OSINT · DNS · Google Dorks · GitHub Leaks · Shodan · Email")
    while True:
        url = SESSION.get("target_url", "-")
        print(f"""
  {NEON_GRN}Target:{RST} {PURE_WHITE}{url}{RST}

  {NEON_CYN}[1]{RST} WHOIS & DNS            {SOFT_WHITE}(WHOIS · DNS records · zone transfer · reverse DNS){RST}
  {NEON_CYN}[2]{RST} Subdomain Enumeration  {SOFT_WHITE}(subfinder · amass · crt.sh · dnsx live check){RST}
  {NEON_CYN}[3]{RST} Google Dorks           {SOFT_WHITE}(admin panels · exposed files · error pages · leaks){RST}
  {NEON_CYN}[4]{RST} GitHub Secret Leaks    {SOFT_WHITE}(trufflehog · gitleaks · code search dorks){RST}
  {NEON_CYN}[5]{RST} Shodan / FOFA          {SOFT_WHITE}(internet exposure · open ports · banners · certs){RST}
  {NEON_CYN}[6]{RST} Email Harvesting       {SOFT_WHITE}(theHarvester · email format guessing · spray prep){RST}
  {NEON_GRN}[0]{RST} Back to main menu
""")
        c = prompt("Choice")
        if c == "0":    break
        elif c == "1":  whois_dns()
        elif c == "2":  subdomain_enum()
        elif c == "3":  google_dorks()
        elif c == "4":  github_leaks()
        elif c == "5":  shodan_lookup()
        elif c == "6":  email_harvest()
        save_session()
