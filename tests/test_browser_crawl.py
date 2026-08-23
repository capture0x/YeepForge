"""Tests for the headless-browser crawl.

Playwright is an optional dependency and no test here installs or launches a
browser. What is pinned is everything around it: which requests count as attack
surface, that scope is enforced per navigation, that the engagement's identity
reaches the browser context, and that a missing browser degrades to the regex
crawler instead of losing the crawl.
"""
import pytest

from modules import crawler as crawler_mod
from utils.browser import BrowserCrawler


@pytest.fixture
def bc(monkeypatch):
    # The crawler reads the engagement scope at construction, so the session has
    # to name the target the way a real run does.
    import config.settings as settings
    monkeypatch.setitem(settings.SESSION, "target_url", "https://target.test")
    monkeypatch.setitem(settings.SESSION, "scope", "")
    return BrowserCrawler("https://target.test", max_pages=5, max_depth=1)


class _Request:
    def __init__(self, url, method="GET", resource_type="xhr", post_data=None):
        self.url = url
        self.method = method
        self.resource_type = resource_type
        self.post_data = post_data


# ── what counts as surface ────────────────────────────────────────────────────
def test_xhr_call_is_recorded_with_its_query_parameters(bc):
    bc._on_request(_Request("https://target.test/api/users?role=admin&page=2"))
    assert bc.endpoints == [{
        "url": "https://target.test/api/users?role=admin&page=2",
        "method": "GET",
        "params": {"role": "admin", "page": "2"},
        "forms": [],
        "source": "browser:xhr",
    }]


def test_json_post_body_becomes_testable_parameters(bc):
    """The body of an API call is the parameter set every injection test needs."""
    bc._on_request(_Request("https://target.test/api/login", "POST", "fetch",
                            '{"username":"a","password":"b"}'))
    assert bc.endpoints[0]["params"] == {"username": "a", "password": "b"}
    assert bc.endpoints[0]["method"] == "POST"


def test_urlencoded_post_body_is_parsed_too(bc):
    bc._on_request(_Request("https://target.test/api/login", "POST", "xhr",
                            "username=a&password=b"))
    assert bc.endpoints[0]["params"] == {"username": "a", "password": "b"}


def test_malformed_json_body_does_not_crash_the_crawl(bc):
    bc._on_request(_Request("https://target.test/api/x", "POST", "xhr", "{not json"))
    assert len(bc.endpoints) == 1
    assert bc.endpoints[0]["params"] == {}


@pytest.mark.parametrize("resource_type", ["image", "font", "stylesheet", "media"])
def test_static_assets_are_not_surface(bc, resource_type):
    bc._on_request(_Request("https://target.test/logo.png", resource_type=resource_type))
    assert bc.endpoints == []


@pytest.mark.parametrize("url", [
    "https://target.test/app.css",
    "https://target.test/bundle.js.map",
    "https://target.test/hero.WEBP",
])
def test_asset_extensions_are_skipped_even_as_documents(bc, url):
    bc._on_request(_Request(url, resource_type="document"))
    assert bc.endpoints == []


def test_duplicate_calls_are_recorded_once(bc):
    for _ in range(3):
        bc._on_request(_Request("https://target.test/api/me"))
    assert len(bc.endpoints) == 1


def test_same_url_with_different_method_is_a_separate_endpoint(bc):
    bc._on_request(_Request("https://target.test/api/me"))
    bc._on_request(_Request("https://target.test/api/me", "POST"))
    assert len(bc.endpoints) == 2


# ── scope ─────────────────────────────────────────────────────────────────────
def test_third_party_api_call_is_not_recorded(bc):
    """A rendered page calls analytics and CDNs; those are not the engagement."""
    bc._on_request(_Request("https://analytics.example/collect?id=1"))
    assert bc.endpoints == []


def test_out_of_scope_link_is_not_queued(bc, monkeypatch):
    assert not bc._in_scope("https://elsewhere.example/page")
    assert bc._in_scope("https://target.test/page")


def test_non_http_scheme_is_rejected(bc):
    assert not bc._in_scope("javascript:alert(1)")
    assert not bc._in_scope("mailto:x@y.z")
    assert not bc._in_scope("")


# ── engagement identity reaches the browser ───────────────────────────────────
def test_out_of_scope_base_url_is_refused(monkeypatch):
    """Crawling a host the engagement does not cover is a mis-set target."""
    import config.settings as settings
    monkeypatch.setitem(settings.SESSION, "target_url", "https://target.test")
    monkeypatch.setitem(settings.SESSION, "scope", "target.test")
    other = BrowserCrawler("https://elsewhere.example")
    result = other.run()
    assert result["endpoints"] == []
    assert result["pages"] == 0


def test_context_carries_cookies_auth_and_proxy(monkeypatch):
    import config.settings as settings
    for key, value in {
        "target_url": "https://target.test",
        "cookies": "sid=abc",
        "auth_token": "tok123",
        "proxy": "http://127.0.0.1:8080",
        "headers": "X-Env: staging",
    }.items():
        monkeypatch.setitem(settings.SESSION, key, value)

    options = BrowserCrawler("https://target.test")._context_options()
    headers = options["extra_http_headers"]
    assert headers["Cookie"] == "sid=abc"
    assert headers["Authorization"] == "Bearer tok123"
    assert headers["X-Env"] == "staging"
    assert options["proxy"] == {"server": "http://127.0.0.1:8080"}


def test_context_without_a_session_sets_no_credential_headers(monkeypatch):
    import config.settings as settings
    for key in ("cookies", "auth_token", "proxy", "headers"):
        monkeypatch.setitem(settings.SESSION, key, "")
    options = BrowserCrawler("https://target.test")._context_options()
    assert "extra_http_headers" not in options
    assert "proxy" not in options


def test_full_scheme_auth_token_is_not_double_prefixed(monkeypatch):
    import config.settings as settings
    monkeypatch.setitem(settings.SESSION, "auth_token", "Basic dXNlcjpwYXNz")
    monkeypatch.setitem(settings.SESSION, "cookies", "")
    monkeypatch.setitem(settings.SESSION, "headers", "")
    options = BrowserCrawler("https://target.test")._context_options()
    assert options["extra_http_headers"]["Authorization"] == "Basic dXNlcjpwYXNz"


# ── degradation ───────────────────────────────────────────────────────────────
def test_browser_default_follows_availability(monkeypatch):
    monkeypatch.delenv("YEEPFORGE_BROWSER", raising=False)
    monkeypatch.setattr(crawler_mod, "browser_available", lambda: True)
    assert crawler_mod._browser_default() is True
    monkeypatch.setattr(crawler_mod, "browser_available", lambda: False)
    assert crawler_mod._browser_default() is False


@pytest.mark.parametrize("value,expected", [("0", False), ("1", True),
                                            ("no", False), ("yes", True)])
def test_no_browser_flag_overrides_availability(monkeypatch, value, expected):
    monkeypatch.setenv("YEEPFORGE_BROWSER", value)
    monkeypatch.setattr(crawler_mod, "browser_available", lambda: not expected)
    assert crawler_mod._browser_default() is expected


def test_missing_playwright_keeps_the_html_crawl(monkeypatch):
    """A browser that cannot start must not take the regex results with it."""
    monkeypatch.setattr(crawler_mod, "browser_available", lambda: False)
    c = crawler_mod.Crawler("https://target.test", browser=True)
    c.endpoints = [{"url": "https://target.test/", "method": "GET",
                    "params": {}, "forms": []}]
    c._merge_browser_crawl()
    assert len(c.endpoints) == 1


def test_browser_crash_keeps_the_html_crawl(monkeypatch):
    monkeypatch.setattr(crawler_mod, "browser_available", lambda: True)

    class _Exploding:
        def __init__(self, *a, **kw):
            raise RuntimeError("chromium missing")

    monkeypatch.setattr(crawler_mod, "BrowserCrawler", _Exploding)
    c = crawler_mod.Crawler("https://target.test", browser=True)
    c.endpoints = [{"url": "https://target.test/", "method": "GET",
                    "params": {}, "forms": []}]
    c._merge_browser_crawl()
    assert len(c.endpoints) == 1


def test_browser_results_are_merged_not_substituted(monkeypatch):
    """robots.txt-only pages and runtime API calls both have to survive."""
    monkeypatch.setattr(crawler_mod, "browser_available", lambda: True)

    class _Fake:
        def __init__(self, *a, **kw):
            pass

        def run(self):
            return {"pages": 3, "endpoints": [{"url": "https://target.test/api/me",
                                               "method": "GET", "params": {},
                                               "forms": []}],
                    "js_files": ["https://target.test/app.js"]}

    monkeypatch.setattr(crawler_mod, "BrowserCrawler", _Fake)
    c = crawler_mod.Crawler("https://target.test", browser=True)
    c.endpoints = [{"url": "https://target.test/admin", "method": "GET",
                    "params": {}, "forms": []}]
    c._merge_browser_crawl()

    urls = {e["url"] for e in c.endpoints}
    assert urls == {"https://target.test/admin", "https://target.test/api/me"}
    assert "https://target.test/app.js" in c.js_files
