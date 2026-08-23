"""
utils/browser.py
YeepForge - optional headless-browser crawling for JavaScript applications.

The regex crawler reads the HTML the server sends. On a React, Vue or Angular
target that HTML is a nearly empty shell: the routes, the forms and every API
call are produced by JavaScript after load. Against those applications the
regex crawler finds one endpoint - the index - and every test downstream then
reports the app as clean because there was nothing to test.

This module renders the page and reports what the *browser* saw:

  * XHR/fetch requests the application actually issued, with method and body -
    the API surface, which is where the findings are;
  * links and forms present in the DOM after hydration;
  * same-page route changes pushed through the History API.

Playwright is an optional dependency. When it is missing, `available()` returns
False and callers fall back to the regex crawler rather than failing; the
operator is told which one ran, because "no endpoints found" means something
very different in each case.

    pip install playwright && playwright install chromium
"""
from __future__ import annotations

import functools
import os
import time
from urllib.parse import parse_qs, urlparse

from config.settings import SESSION
from utils.helpers import info, warn
from utils.scope import current_scope
from utils.tools import engagement_rps

__all__ = ["BrowserCrawler", "available", "install_hint"]

#: Resource types worth recording. Images and fonts are traffic, not surface.
INTERESTING_TYPES = {"xhr", "fetch", "document", "websocket"}

#: Extensions that are static assets even when fetched as a document.
STATIC_SUFFIXES = (".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff",
                   ".woff2", ".ttf", ".ico", ".map", ".webp", ".avif")


@functools.lru_cache(maxsize=1)
def available() -> bool:
    """True when Playwright's Python bindings and Node driver are both present.

    Importing playwright is not enough. Distro packages (e.g. Kali's
    ``python3-playwright``) ship the bindings but split out - or omit - the
    Node driver (``cli.js``). Starting Playwright without it does not raise
    cleanly: it spawns ``node cli.js``, which dumps a "Cannot find module"
    stack trace *and* an unretrieved-asyncio-task traceback to the console,
    neither of which can be caught once the driver has been spawned. So we
    check the driver *files* exist before anything is launched - without
    spawning, which would itself leak async tracebacks on failure.

    A missing browser binary is deliberately not probed here: that would
    require starting the driver (and leaks the same way). run() launches the
    browser inside a guarded block and prints install_hint() if it is absent.

    Cached: the check runs at most once per process.
    """
    try:
        from playwright.sync_api import sync_playwright  # noqa: F401
    except Exception:
        return False

    # The Node driver must exist on disk. compute_driver_executable() returns
    # either the cli.js path or a (node, cli.js) tuple depending on version.
    try:
        from playwright._impl._driver import compute_driver_executable
        parts = compute_driver_executable()
        driver_paths = parts if isinstance(parts, (tuple, list)) else (parts,)
        return all(p and os.path.exists(str(p)) for p in driver_paths)
    except Exception:
        # Unknown internal layout: assume usable and let run() surface any real
        # failure through its own guarded launch rather than guessing here.
        return True


def install_hint() -> str:
    return ("Headless crawling needs Playwright:\n"
            "    pip install playwright\n"
            "    playwright install chromium")


class BrowserCrawler:
    """Renders pages in headless Chromium and collects the resulting surface.

    The engagement's cookies, headers, auth token and proxy are applied to the
    browser context, so an authenticated crawl sees what a logged-in user sees.
    Scope is enforced per navigation: the browser will happily follow a link to
    a third party, and doing so on a bounty engagement is a report to the wrong
    programme at best.
    """

    def __init__(self, base_url: str, max_pages: int = 40, max_depth: int = 2,
                 wait_ms: int = 2500, timeout_ms: int = 20000):
        self.base = base_url.rstrip("/")
        self.origin = urlparse(base_url).netloc
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.wait_ms = wait_ms
        self.timeout_ms = timeout_ms

        self.visited: set[str] = set()
        self.endpoints: list[dict] = []
        self.js_files: set[str] = set()
        self._seen_keys: set[str] = set()
        self._scope = current_scope(SESSION)

    # ── recording ────────────────────────────────────────────────────────────
    def _record(self, url: str, method: str = "GET", params: dict | None = None,
                forms: list | None = None, source: str = "") -> None:
        key = f"{method}:{url.split('#')[0]}"
        if key in self._seen_keys:
            return
        self._seen_keys.add(key)
        entry = {"url": url, "method": method.upper(),
                 "params": params or {}, "forms": forms or []}
        if source:
            entry["source"] = source
        self.endpoints.append(entry)

    def _in_scope(self, url: str) -> bool:
        return bool(url) and url.startswith(("http://", "https://")) \
            and self._scope.allows(url)

    def _same_origin(self, url: str) -> bool:
        return urlparse(url).netloc == self.origin

    def _on_request(self, request) -> None:
        """Record an API call the page made."""
        url = request.url
        if request.resource_type not in INTERESTING_TYPES:
            return
        if url.lower().split("?")[0].endswith(STATIC_SUFFIXES):
            return
        if not self._in_scope(url) or not self._same_origin(url):
            return

        params = {k: v[0] for k, v in parse_qs(urlparse(url).query).items()}
        body_params: dict = {}
        if request.method.upper() != "GET":
            try:
                post = request.post_data
            except Exception:
                post = None
            if post:
                if post.strip().startswith("{"):
                    import json
                    try:
                        loaded = json.loads(post)
                        if isinstance(loaded, dict):
                            body_params = {k: str(v) for k, v in loaded.items()}
                    except ValueError:
                        pass
                else:
                    body_params = {k: v[0] for k, v in parse_qs(post).items()}

        self._record(url, request.method, {**params, **body_params},
                     source=f"browser:{request.resource_type}")

    # ── DOM extraction ───────────────────────────────────────────────────────
    _DOM_SCRIPT = """() => {
      const abs = (u) => { try { return new URL(u, location.href).href; } catch (e) { return null; } };
      const links = [...document.querySelectorAll('a[href], area[href]')]
        .map(a => abs(a.getAttribute('href'))).filter(Boolean);
      const scripts = [...document.querySelectorAll('script[src]')]
        .map(s => abs(s.getAttribute('src'))).filter(Boolean);
      const forms = [...document.querySelectorAll('form')].map(f => ({
        action: abs(f.getAttribute('action') || location.href),
        method: (f.getAttribute('method') || 'GET').toUpperCase(),
        inputs: [...f.querySelectorAll('input,select,textarea')]
          .filter(i => i.name)
          .map(i => ({name: i.name, type: i.type || 'text', value: i.value || ''})),
      }));
      return {links, scripts, forms};
    }"""

    def _harvest_dom(self, page, page_url: str) -> list[str]:
        try:
            dom = page.evaluate(self._DOM_SCRIPT)
        except Exception as exc:
            warn(f"DOM extraction failed on {page_url}: {exc}")
            return []

        for form in dom.get("forms", []):
            action = form.get("action") or page_url
            if not self._in_scope(action):
                continue
            inputs = form.get("inputs", [])
            self._record(action, form.get("method", "GET"),
                         {i["name"]: i["value"] for i in inputs},
                         forms=inputs, source="browser:form")

        for script in dom.get("scripts", []):
            if self._in_scope(script) and self._same_origin(script):
                self.js_files.add(script)

        return [link for link in dom.get("links", [])
                if self._in_scope(link) and self._same_origin(link)]

    # ── the crawl ────────────────────────────────────────────────────────────
    def run(self) -> dict:
        # Checked before Playwright is even imported: there is no reason to
        # start a browser for a host the engagement does not cover.
        if not self._in_scope(self.base):
            warn(f"{self.base} is outside the engagement scope - nothing to render. "
                 "Check --target and --scope.")
            return self._result()

        from playwright.sync_api import Error as PlaywrightError
        from playwright.sync_api import sync_playwright

        rps = engagement_rps()
        # The browser fires many requests per page; the pause between
        # navigations is what keeps a rendered crawl inside the engagement's
        # budget, since Playwright does not go through utils.http.
        pause = 0.0 if rps <= 0 else max(1.0 / rps, 0.2)

        info(f"Rendering up to {self.max_pages} pages in headless Chromium "
             f"(depth {self.max_depth})...")

        queue: list[tuple[str, int]] = [(self.base, 0)]
        with sync_playwright() as pw:
            try:
                browser = pw.chromium.launch(headless=True)
            except PlaywrightError as exc:
                warn(f"Could not launch Chromium: {exc}\n{install_hint()}")
                return self._result()

            context = browser.new_context(**self._context_options())
            page = context.new_page()
            page.on("request", self._on_request)

            try:
                while queue and len(self.visited) < self.max_pages:
                    url, depth = queue.pop(0)
                    url = url.split("#")[0]
                    if url in self.visited or not self._in_scope(url):
                        continue
                    self.visited.add(url)

                    try:
                        page.goto(url, timeout=self.timeout_ms, wait_until="domcontentloaded")
                        # Hydration and the first data fetches happen after
                        # DOMContentLoaded; without this wait the API calls that
                        # make up the whole attack surface are never observed.
                        page.wait_for_timeout(self.wait_ms)
                    except PlaywrightError as exc:
                        warn(f"{url}: {str(exc).splitlines()[0][:120]}")
                        continue

                    parsed = urlparse(page.url)
                    self._record(page.url, "GET",
                                 {k: v[0] for k, v in parse_qs(parsed.query).items()},
                                 source="browser:page")

                    if depth < self.max_depth:
                        for link in self._harvest_dom(page, url):
                            if link.split("#")[0] not in self.visited:
                                queue.append((link, depth + 1))
                    else:
                        self._harvest_dom(page, url)

                    time.sleep(pause)
            finally:
                context.close()
                browser.close()

        return self._result()

    def _context_options(self) -> dict:
        """Browser context carrying the engagement's identity and proxy."""
        options: dict = {"ignore_https_errors": True}

        proxy = (SESSION.get("proxy") or "").strip()
        if proxy:
            options["proxy"] = {"server": proxy}

        headers: dict[str, str] = {}
        raw = SESSION.get("headers") or ""
        if isinstance(raw, dict):
            headers.update({str(k): str(v) for k, v in raw.items()})
        elif isinstance(raw, str) and raw.strip():
            from utils.http import _parse_header_string
            headers.update(_parse_header_string(raw))

        token = (SESSION.get("auth_token") or "").strip()
        if token and "Authorization" not in headers:
            headers["Authorization"] = token if " " in token else f"Bearer {token}"

        cookies = (SESSION.get("cookies") or "").strip()
        if cookies:
            # Sent as a header rather than as context cookies: the session value
            # is a raw Cookie string, and splitting it into name/value/domain
            # triples loses attributes the application may depend on.
            headers["Cookie"] = cookies

        if headers:
            options["extra_http_headers"] = headers
        return options

    def _result(self) -> dict:
        return {
            "base": self.base,
            "pages": len(self.visited),
            "endpoints": self.endpoints,
            "js_files": sorted(self.js_files),
            "js_endpoints": [],
            "renderer": "browser",
        }
