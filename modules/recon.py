"""
modules/recon.py
tmrswrr - Phase 0: Reconnaissance
Subdomain enumeration, directory bruteforce, tech fingerprinting, port scan
"""
import os
import shutil

from config.settings import OUTPUT_DIR, SESSION, save_session
from utils.helpers import (
    NEON_CYN,
    NEON_GRN,
    PURE_WHITE,
    RST,
    info,
    print_banner,
    prompt,
    run_and_print,
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
        url = prompt("Target URL (e.g. https://example.com)")
        SESSION["target_url"] = url
    return url


def _host() -> str:
    url = _target()
    import re
    m = re.search(r"https?://([^/:]+)", url)
    return m.group(1) if m else url


def subdomain_enum():
    section("SUBDOMAIN ENUMERATION")
    host = _host()
    print(f"""
  {NEON_CYN}[1]{RST} subfinder
  {NEON_CYN}[2]{RST} amass (passive)
  {NEON_CYN}[3]{RST} assetfinder
  {NEON_CYN}[4]{RST} crt.sh (certificate transparency)
  {NEON_CYN}[5]{RST} All of the above
  {NEON_GRN}[0]{RST} Back
""")
    c = prompt("Choice")

    if c in ("1", "5"):
        if shutil.which("subfinder"):
            out = _out("subdomains_subfinder.txt")
            run_and_print(f"subfinder -d {host} -o {out} -silent")
            success(f"Saved → {out}")
        else:
            warn("subfinder not found. Install: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")

    if c in ("2", "5"):
        if shutil.which("amass"):
            out = _out("subdomains_amass.txt")
            run_and_print(f"amass enum -passive -d {host} -o {out}")
            success(f"Saved → {out}")
        else:
            warn("amass not found. Install: apt install amass")

    if c in ("3", "5"):
        if shutil.which("assetfinder"):
            out = _out("subdomains_assetfinder.txt")
            run_and_print(f"assetfinder --subs-only {host} | tee {out}")
            success(f"Saved → {out}")
        else:
            warn("assetfinder not found. Install: go install github.com/tomnomnom/assetfinder@latest")

    if c in ("4", "5"):
        info(f"Querying crt.sh for {host}...")
        out_data, _, _ = run_cmd(
            f"curl -s 'https://crt.sh/?q=%.{host}&output=json' | python3 -c \""
            "import json,sys; data=json.load(sys.stdin); "
            "[print(d['name_value']) for d in data]\""
        )
        if out_data:
            out = _out("subdomains_crtsh.txt")
            with open(out, "w") as f:
                f.write(out_data)
            print(out_data[:2000])
            success(f"Saved → {out}")
        else:
            warn("crt.sh query failed or no results")


def directory_brute():
    section("DIRECTORY & FILE BRUTEFORCE")
    url = _target()
    print(f"""
  {NEON_CYN}[1]{RST} gobuster dir (fast)
  {NEON_CYN}[2]{RST} ffuf (flexible, recursive)
  {NEON_CYN}[3]{RST} feroxbuster (recursive)
  {NEON_CYN}[4]{RST} dirb (classic)
  {NEON_CYN}[5]{RST} dirsearch
  {NEON_GRN}[0]{RST} Back
""")
    c = prompt("Choice")
    wordlist = SESSION.get("wordlist", "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt")
    if not os.path.exists(wordlist):
        wordlist = "/usr/share/wordlists/dirb/common.txt"
    cookies = SESSION.get("cookies", "")
    cookie_flag = f'-c "{cookies}"' if cookies else ""

    if c == "1":
        if shutil.which("gobuster"):
            out = _out("gobuster.txt")
            ext = prompt("Extensions (e.g. php,html,js,txt) [Enter=none]") or ""
            ext_flag = f"-x {ext}" if ext else ""
            proxy = SESSION.get("proxy", "")
            proxy_flag = f"--proxy {proxy}" if proxy else ""
            cmd = (f"gobuster dir -u {url} -w {wordlist} {ext_flag} "
                   f"-t 50 -q {proxy_flag} -o {out}")
            run_and_print(cmd, timeout=300)
            success(f"Saved → {out}")
        else:
            warn("gobuster not found. Install: apt install gobuster")

    elif c == "2":
        if shutil.which("ffuf"):
            out = _out("ffuf.json")
            ext = prompt("Extensions (e.g. php,html) [Enter=none]") or ""
            ext_flag = f"-e .{ext.replace(',',',.') }" if ext else ""
            proxy = SESSION.get("proxy", "")
            proxy_flag = f"-x {proxy}" if proxy else ""
            cmd = (f"ffuf -u {url}/FUZZ -w {wordlist} {ext_flag} "
                   f"-t 50 -mc 200,204,301,302,307,401,403 "
                   f"-o {out} -of json {proxy_flag}")
            run_and_print(cmd, timeout=300)
            success(f"Saved → {out}")
        else:
            warn("ffuf not found. Install: apt install ffuf")

    elif c == "3":
        if shutil.which("feroxbuster"):
            out = _out("feroxbuster.txt")
            cmd = f"feroxbuster -u {url} -w {wordlist} -t 50 -q -o {out}"
            run_and_print(cmd, timeout=300)
        else:
            warn("feroxbuster not found. Install: apt install feroxbuster")

    elif c == "4":
        if shutil.which("dirb"):
            out = _out("dirb.txt")
            cmd = f"dirb {url} {wordlist} -o {out}"
            run_and_print(cmd, timeout=300)
        else:
            warn("dirb not found. Install: apt install dirb")

    elif c == "5":
        if shutil.which("dirsearch"):
            out = _out("dirsearch.txt")
            cmd = f"dirsearch -u {url} -o {out} -q"
            run_and_print(cmd, timeout=300)
        else:
            warn("dirsearch not found. Install: pip install dirsearch")


def tech_fingerprint():
    section("TECHNOLOGY FINGERPRINTING")
    url = _target()
    print(f"""
  {NEON_CYN}[1]{RST} whatweb (comprehensive fingerprint)
  {NEON_CYN}[2]{RST} wappalyzer-cli
  {NEON_CYN}[3]{RST} nikto (full scan)
  {NEON_CYN}[4]{RST} curl headers analysis
  {NEON_CYN}[5]{RST} wafw00f (WAF detection)
  {NEON_GRN}[0]{RST} Back
""")
    c = prompt("Choice")

    if c == "1":
        if shutil.which("whatweb"):
            out = _out("whatweb.txt")
            run_and_print(f"whatweb -a 3 {url} | tee {out}")
        else:
            warn("whatweb not found. Install: apt install whatweb")

    elif c == "2":
        if shutil.which("wappalyzer"):
            run_and_print(f"wappalyzer {url}")
        else:
            warn("wappalyzer-cli not found. Install: npm install -g wappalyzer-cli")

    elif c == "3":
        if shutil.which("nikto"):
            out = _out("nikto.txt")
            proxy = SESSION.get("proxy", "")
            proxy_flag = f"-useproxy {proxy}" if proxy else ""
            run_and_print(f"nikto -h {url} {proxy_flag} -o {out} -Format txt", timeout=600)
            success(f"Saved → {out}")
        else:
            warn("nikto not found. Install: apt install nikto")

    elif c == "4":
        info("Analyzing HTTP response headers...")
        out, err, _ = run_cmd(f"curl -sI {url}")
        if out:
            print(f"\n{NEON_CYN}{out}{RST}")
            # Check security headers
            missing = []
            checks = [
                "Strict-Transport-Security",
                "Content-Security-Policy",
                "X-Frame-Options",
                "X-Content-Type-Options",
                "Referrer-Policy",
                "Permissions-Policy",
            ]
            for h in checks:
                if h.lower() not in out.lower():
                    missing.append(h)
                    warn(f"Missing security header: {h}")
            if not missing:
                success("All key security headers present")

    elif c == "5":
        if shutil.which("wafw00f"):
            run_and_print(f"wafw00f {url}")
        else:
            warn("wafw00f not found. Install: pip install wafw00f")


def port_scan():
    section("PORT & SERVICE SCAN")
    host = _host()
    print(f"""
  {NEON_CYN}[1]{RST} nmap quick web ports
  {NEON_CYN}[2]{RST} nmap full scan
  {NEON_CYN}[3]{RST} rustscan (fast)
  {NEON_GRN}[0]{RST} Back
""")
    c = prompt("Choice")

    if c == "1":
        out = _out("nmap_web.txt")
        run_and_print(
            f"nmap -sV -sC -p 80,443,8080,8443,8000,8888,3000,4000,9000 "
            f"--open {host} -oN {out}",
            timeout=120
        )

    elif c == "2":
        out = _out("nmap_full.txt")
        run_and_print(f"nmap -sV -sC -p- --open -T4 {host} -oN {out}", timeout=600)

    elif c == "3":
        if shutil.which("rustscan"):
            out = _out("rustscan.txt")
            run_and_print(f"rustscan -a {host} --ulimit 5000 | tee {out}", timeout=120)
        else:
            warn("rustscan not found. Install: cargo install rustscan")


def run():
    print_banner("RECONNAISSANCE", "Phase 0 - Information Gathering & Target Mapping")
    while True:
        url = SESSION.get("target_url", "-")
        print(f"""
  {NEON_GRN}Target:{RST} {PURE_WHITE}{url}{RST}

  {NEON_CYN}[1]{RST} Subdomain Enumeration
  {NEON_CYN}[2]{RST} Directory & File Bruteforce
  {NEON_CYN}[3]{RST} Technology Fingerprinting
  {NEON_CYN}[4]{RST} Port & Service Scan
  {NEON_GRN}[0]{RST} Back to main menu
""")
        c = prompt("Choice")
        if c == "0":
            break
        elif c == "1":
            subdomain_enum()
        elif c == "2":
            directory_brute()
        elif c == "3":
            tech_fingerprint()
        elif c == "4":
            port_scan()
        save_session()
