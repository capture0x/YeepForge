"""
modules/crawler.py
tmrswrr - Smart Web Crawler & Endpoint Discovery
Link extraction, form enumeration, JS analysis, API discovery, sitemap, robots
"""
import json
import os
import re
import threading
from urllib.parse import parse_qs, urljoin, urlparse

from config.settings import OUTPUT_DIR, SESSION, save_session
from utils.browser import BrowserCrawler
from utils.browser import available as browser_available
from utils.browser import install_hint as browser_install_hint
from utils.helpers import (
    NEON_CYN,
    NEON_GRN,
    PURE_WHITE,
    RST,
    SOFT_WHITE,
    ask_int,
    error,
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


def _get(url, timeout=10):
    cookies = SESSION.get("cookies", "")
    auth    = SESSION.get("auth_token", "")
    proxy   = SESSION.get("proxy", "")
    cookie_flag = f'-b "{cookies}"' if cookies else ""
    auth_flag   = f'-H "Authorization: {auth}"' if auth else ""
    proxy_flag  = f'-x "{proxy}"' if proxy else ""
    out, _, rc = run_cmd(
        f'curl -sk {cookie_flag} {auth_flag} {proxy_flag} -L --max-redirs 3 "{url}" -m {timeout}',
        timeout=timeout + 2
    )
    return out


def _same_origin(url, base):
    try:
        b = urlparse(base)
        u = urlparse(url)
        return u.netloc == b.netloc or not u.netloc
    except Exception:
        return False


def _browser_default() -> bool:
    """Whether to render, absent an explicit choice from the caller.

    --browser/--no-browser set YEEPFORGE_BROWSER for the whole run. With no
    flag, rendering happens whenever Playwright is installed: installing it is
    itself the opt-in, and defaulting to off would silently return the empty
    surface that made this module necessary.
    """
    flag = os.environ.get("YEEPFORGE_BROWSER", "").strip()
    if flag in ("0", "false", "no"):
        return False
    if flag in ("1", "true", "yes"):
        return True
    return browser_available()


class Crawler:
    def __init__(self, base_url: str, max_depth: int = 3, max_pages: int = 200,
                 threads: int = 5, browser: bool | None = None):
        #: Render pages in a headless browser as well as parsing the served
        #: HTML. Default: on when Playwright is installed, because on a
        #: JavaScript application the served HTML has no surface in it at all.
        #: --browser/--no-browser overrides it for the whole run.
        self.browser    = _browser_default() if browser is None else browser
        self.base       = base_url.rstrip("/")
        self.parsed     = urlparse(base_url)
        self.max_depth  = max_depth
        self.max_pages  = max_pages
        self.threads    = threads
        self.visited:   set[str] = set()
        self.queue:     list[tuple[str, int]] = [(base_url, 0)]
        self.endpoints: list[dict] = []     # {url, method, params, forms}
        self.js_files:  set[str] = set()
        self.lock       = threading.Lock()

    def _normalize(self, url: str) -> str:
        if url.startswith("//"):
            url = self.parsed.scheme + ":" + url
        elif url.startswith("/"):
            url = f"{self.parsed.scheme}://{self.parsed.netloc}{url}"
        elif not url.startswith("http"):
            url = urljoin(self.base + "/", url)
        # Remove fragment
        url = url.split("#")[0].rstrip("/") or url
        return url

    def _extract_links(self, html: str, page_url: str) -> set[str]:
        links = set()
        # href / src / action / data-src
        for attr in ["href", "src", "action", "data-href", "data-url"]:
            for m in re.finditer(rf'{attr}=["\']([^"\']+)["\']', html, re.I):
                raw = m.group(1).strip()
                if raw and not raw.startswith(("javascript:", "mailto:", "tel:", "#", "data:")):
                    links.add(self._normalize(raw))
        return links

    def _extract_forms(self, html: str, page_url: str) -> list[dict]:
        forms = []
        for m in re.finditer(r'<form([^>]*)>(.*?)</form>', html, re.S | re.I):
            attrs  = m.group(1)
            body   = m.group(2)
            action = re.search(r'action=["\']([^"\']+)["\']', attrs, re.I)
            method = re.search(r'method=["\']([^"\']+)["\']', attrs, re.I)
            inputs = []
            for inp in re.finditer(r'<input([^>]*)>', body, re.I):
                name = re.search(r'name=["\']([^"\']+)["\']', inp.group(1), re.I)
                typ  = re.search(r'type=["\']([^"\']+)["\']', inp.group(1), re.I)
                val  = re.search(r'value=["\']([^"\']*)["\']', inp.group(1), re.I)
                if name:
                    inputs.append({
                        "name":  name.group(1),
                        "type":  typ.group(1) if typ else "text",
                        "value": val.group(1) if val else "",
                    })
            form_url = self._normalize(action.group(1)) if action else page_url
            forms.append({
                "url":    form_url,
                "method": method.group(1).upper() if method else "GET",
                "inputs": inputs,
                "page":   page_url,
            })
        return forms

    def _extract_js_endpoints(self, js_content: str, base: str) -> set[str]:
        endpoints = set()
        patterns = [
            r'["\'](/[a-zA-Z0-9_/.-]+(?:\?[^"\']*)?)["\']',
            r'fetch\(["\']([^"\']+)["\']',
            r'axios\.(get|post|put|delete|patch)\(["\']([^"\']+)["\']',
            r'url:\s*["\']([^"\']+)["\']',
            r'\$\.ajax\([^)]*url:\s*["\']([^"\']+)["\']',
        ]
        for pat in patterns:
            for m in re.finditer(pat, js_content, re.I):
                raw = m.group(1) if m.lastindex == 1 else m.group(2)
                if raw and len(raw) > 1 and raw.startswith("/"):
                    endpoints.add(self._normalize(raw))
        return endpoints

    def _crawl_page(self, url: str, depth: int):
        with self.lock:
            if url in self.visited or len(self.visited) >= self.max_pages:
                return
            self.visited.add(url)

        html = _get(url)
        if not html:
            return

        # Register endpoint
        parsed = urlparse(url)
        params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        with self.lock:
            self.endpoints.append({
                "url":    url,
                "method": "GET",
                "params": params,
                "forms":  [],
            })

        # Extract forms
        forms = self._extract_forms(html, url)
        for form in forms:
            with self.lock:
                self.endpoints.append({
                    "url":    form["url"],
                    "method": form["method"],
                    "params": {i["name"]: i["value"] for i in form["inputs"]},
                    "forms":  form["inputs"],
                })

        if depth >= self.max_depth:
            return

        # Extract links
        links = self._extract_links(html, url)
        # Extract JS files
        for m in re.finditer(r'src=["\']([^"\']+\.js[^"\']*)["\']', html, re.I):
            js = self._normalize(m.group(1))
            if _same_origin(js, self.base):
                with self.lock:
                    self.js_files.add(js)

        for link in links:
            if _same_origin(link, self.base) and link not in self.visited:
                self._crawl_page(link, depth + 1)

    def run(self) -> dict:
        info(f"Crawling {self.base} (max_depth={self.max_depth}, max_pages={self.max_pages})...")
        self._crawl_page(self.base, 0)

        # Also check robots.txt and sitemap.xml
        for special in ["/robots.txt", "/sitemap.xml", "/sitemap_index.xml"]:
            content = _get(self.base + special)
            if content:
                for m in re.finditer(r'https?://[^\s<>"]+', content):
                    link = m.group(0)
                    if _same_origin(link, self.base) and link not in self.visited:
                        self._crawl_page(link, 0)

        # Analyze JS files for hidden endpoints
        js_endpoints = set()
        for js_url in list(self.js_files)[:20]:
            js_content = _get(js_url)
            if js_content:
                for ep in self._extract_js_endpoints(js_content, js_url):
                    js_endpoints.add(ep)
                    if ep not in self.visited:
                        parsed = urlparse(ep)
                        params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
                        with self.lock:
                            self.endpoints.append({
                                "url": ep, "method": "GET",
                                "params": params, "forms": [],
                                "source": f"JS: {js_url[-40:]}"
                            })

        if self.browser:
            self._merge_browser_crawl()

        # Deduplicate endpoints
        seen = set()
        deduped = []
        for ep in self.endpoints:
            # "http://host" and "http://host/" are the same endpoint; the two
            # crawlers spell the root differently and would otherwise both
            # register it, doubling every downstream test on the home page.
            url = ep["url"]
            if url.endswith("/") and urlparse(url).path == "/":
                url = url[:-1]
            key = f"{ep['method']}:{url}"
            if key not in seen:
                seen.add(key)
                deduped.append(ep)
        self.endpoints = deduped

        return {
            "base":      self.base,
            "pages":     len(self.visited),
            "endpoints": self.endpoints,
            "js_files":  list(self.js_files),
            "js_endpoints": list(js_endpoints),
            "renderer":  "html+browser" if self.browser else "html",
        }

    def _merge_browser_crawl(self) -> None:
        """Add what a rendered browser saw to what the served HTML contained.

        The two are merged rather than one replacing the other: the regex pass
        reaches pages behind robots.txt and sitemap.xml that no link points at,
        and the browser pass reaches the API calls that only exist at runtime.
        """
        if not browser_available():
            warn("Headless crawling requested but Playwright is unavailable - "
                 "JavaScript-rendered endpoints will be missed.")
            info(browser_install_hint())
            return

        try:
            crawler = BrowserCrawler(
                self.base,
                max_pages=max(1, min(self.max_pages, 40)),
                max_depth=self.max_depth,
            )
            rendered = crawler.run()
        except Exception as exc:            # a browser failure must not lose the HTML crawl
            warn(f"Headless crawl failed ({exc}) - keeping the HTML-only results.")
            return

        before = len(self.endpoints)
        with self.lock:
            self.endpoints.extend(rendered["endpoints"])
            self.js_files.update(rendered["js_files"])
        success(f"Headless pass: {rendered['pages']} pages rendered, "
                f"{len(rendered['endpoints'])} endpoints "
                f"({len(self.endpoints) - before} added before dedup)")


def run_crawl():
    section("SMART WEB CRAWLER")
    url     = _target()
    depth   = ask_int("Max crawl depth", 3, minimum=1, maximum=10)
    pages   = ask_int("Max pages", 200, minimum=1)

    crawler = Crawler(url, max_depth=depth, max_pages=pages)
    result  = crawler.run()

    endpoints = result["endpoints"]
    success(f"\nCrawl complete: {result['pages']} pages, {len(endpoints)} endpoints")
    if result.get("renderer") == "html":
        info("Served HTML only. If this target is a single-page application, the "
             "surface below is incomplete - install Playwright and re-run with "
             "--browser.")

    # Show summary
    by_method = {}
    for ep in endpoints:
        m = ep.get("method", "GET")
        by_method[m] = by_method.get(m, 0) + 1
    for method, count in sorted(by_method.items()):
        print(f"  {NEON_CYN}{method:<6}{RST} {count} endpoints")

    # Show endpoints with params (juicy targets)
    juicy = [ep for ep in endpoints if ep.get("params") or ep.get("forms")]
    if juicy:
        print(f"\n  {NEON_GRN}Endpoints with parameters ({len(juicy)}):{RST}")
        for ep in juicy[:30]:
            params_str = ", ".join(ep.get("params", {}).keys()) or \
                         ", ".join(i["name"] for i in ep.get("forms", []))
            print(f"  {NEON_CYN}[{ep['method']}]{RST} {ep['url'][:70]}  "
                  f"{SOFT_WHITE}{params_str[:40]}{RST}")

    # Save
    out_file = _out("crawl_results.json")
    with open(out_file, "w") as f:
        json.dump(result, f, indent=2)
    success(f"Full results → {out_file}")

    # Store in session for auto_scanner
    SESSION["_crawl_results"] = result
    SESSION["endpoints"] = [ep["url"] for ep in endpoints]
    save_session()
    return result


def show_js_analysis():
    section("JAVASCRIPT ENDPOINT ANALYSIS")
    url = _target()
    js_url = prompt("JavaScript file URL (or Enter to auto-discover)")
    if not js_url:
        html = _get(url)
        js_files = []
        for m in re.finditer(r'src=["\']([^"\']+\.js[^"\']*)["\']', html, re.I):
            js = m.group(1)
            if not js.startswith("http"):
                js = urljoin(url, js)
            js_files.append(js)
        info(f"Found {len(js_files)} JS files")
        for j in js_files[:5]:
            print(f"  {NEON_CYN}→{RST} {j}")
        if not js_files:
            return
        js_url = js_files[0]

    info(f"Analyzing: {js_url}")
    content = _get(js_url)
    if not content:
        error("Could not fetch JS file")
        return

    # Find API endpoints
    api_patterns = {
        "Fetch calls":        r'fetch\(["\']([^"\']+)["\']',
        "Axios calls":        r'axios\.\w+\(["\']([^"\']+)["\']',
        "URL paths":          r'["\'](/api/[a-zA-Z0-9_/.-]+)["\']',
        "GraphQL":            r'query\s*{?\s*\w+',
        "JWT tokens":         r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}',
        "API keys":           r'(?:api[_-]?key|token)\s*[=:]\s*["\'][^"\']{8,}["\']',
        "Internal IPs":       r'\b(?:10|172|192\.168)\.\d+\.\d+\.\d+\b',
        "S3 buckets":         r's3[.-][a-zA-Z0-9-]+\.amazonaws\.com',
        "Hardcoded creds":    r'(?:password|passwd|secret)\s*[=:]\s*["\'][^"\']{4,}["\']',
    }

    print()
    found_any = False
    for name, pattern in api_patterns.items():
        matches = re.findall(pattern, content, re.I)
        if matches:
            found_any = True
            print(f"  {NEON_GRN}[{name}]{RST}  ({len(matches)} found)")
            for m in matches[:5]:
                print(f"    {NEON_CYN}{m[:80]}{RST}")

    if not found_any:
        info("No obvious sensitive patterns in this JS file")


def run():
    print_banner("WEB CRAWLER & ENDPOINT DISCOVERY", "tmrswrr")
    while True:
        url = SESSION.get("target_url", "-")
        crawl_count = len(SESSION.get("endpoints", []))
        print(f"""
  {NEON_GRN}Target:{RST}    {PURE_WHITE}{url}{RST}
  {NEON_GRN}Crawled:{RST}   {PURE_WHITE}{crawl_count} endpoints in session{RST}

  {NEON_CYN}[1]{RST} Full Site Crawl           {SOFT_WHITE}(links, forms, API endpoints, JS){RST}
  {NEON_CYN}[2]{RST} JavaScript Analysis       {SOFT_WHITE}(hidden endpoints, API keys, secrets){RST}
  {NEON_GRN}[0]{RST} Back to main menu
""")
        c = prompt("Choice")
        if c == "0": break
        elif c == "1": run_crawl()
        elif c == "2": show_js_analysis()
        save_session()
