"""Tests for the HTTP engine, scope enforcement and the evidence pipeline.

No test here touches the network: the Client's underlying requests.Session is
replaced with a stub, so scope/rate-limit/evidence behaviour is verified in
isolation.
"""
import shlex
import time

import pytest
import requests

from config.settings import CONFIDENCE_LEVELS, normalize_evidence
from utils.http import Client, Evidence, RateLimiter, build_curl, curl_flags
from utils.scope import Scope, ScopeViolation, assert_in_scope, host_of


# ── scope ─────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("raw,expected", [
    ("https://example.com/app?a=1", "example.com"),
    ("example.com:8443", "example.com"),
    ("EXAMPLE.com", "example.com"),
    ("", ""),
])
def test_host_of(raw, expected):
    assert host_of(raw) == expected


def test_scope_allows_wildcard_and_apex():
    scope = Scope.parse("*.example.com")
    assert scope.allows("https://api.example.com/x")
    # Bounty scope written as '*.example.com' is understood to include the apex.
    assert scope.allows("https://example.com/")
    assert not scope.allows("https://example.org/")


def test_scope_deny_wins_over_allow():
    scope = Scope.parse("*.example.com, !admin.example.com")
    assert scope.allows("https://shop.example.com")
    ok, reason = scope.check("https://admin.example.com")
    assert not ok and "exclusion" in reason


def test_scope_parses_multiple_separators_and_urls():
    scope = Scope.parse("https://a.com/path\nb.com , c.com;!d.com")
    assert scope.allow == ["a.com", "b.com", "c.com"]
    assert scope.deny == ["d.com"]


def test_scope_derived_from_target_when_unset():
    scope = Scope.from_session({"target_url": "https://target.test/app"})
    assert scope.allows("https://target.test/other")
    assert scope.allows("https://api.target.test/")
    # The whole point: a tool pointed at one host must not wander to another.
    assert not scope.allows("https://evil.test/")


def test_scope_unrestricted_without_target_or_scope():
    scope = Scope.from_session({})
    assert scope.unscoped
    assert scope.allows("https://anything.test/")


def test_assert_in_scope_raises():
    session = {"target_url": "https://target.test"}
    assert_in_scope("https://target.test/a", session)  # no raise
    with pytest.raises(ScopeViolation):
        assert_in_scope("https://elsewhere.test/a", session)


def test_audit_mode_warns_instead_of_blocking(capsys):
    scope = Scope.parse("example.com", enforce=False)
    assert not scope.allows("https://other.com")
    session = {"target_url": "https://target.test", "scope": "example.com"}
    import utils.scope as scope_mod
    original = scope_mod._enforce_default
    scope_mod._enforce_default = lambda: False
    try:
        assert_in_scope("https://other.com", session)  # must not raise
    finally:
        scope_mod._enforce_default = original
    assert "SCOPE (audit)" in capsys.readouterr().out


# ── curl building ─────────────────────────────────────────────────────────────
def test_build_curl_quotes_shell_metacharacters():
    """A payload must reach the target, never the tester's own shell.

    The command is parsed back with shlex, which is exactly how the shell reads
    it: the URL has to survive as one argument, substitutions intact and
    unexpanded.
    """
    url = "http://t.test/ping?host=127.0.0.1$(id)`whoami`"
    argv = shlex.split(build_curl(url))
    assert argv[-1] == url
    assert argv[0] == "curl"


def test_build_curl_includes_method_headers_proxy_body():
    argv = shlex.split(build_curl(
        "http://t.test/", method="post", headers={"X-A": "b"},
        data="a=1", cookies="s=1", proxy="http://127.0.0.1:8080", timeout=7,
    ))
    assert argv[argv.index("-X") + 1] == "POST"
    assert argv[argv.index("-H") + 1] == "X-A: b"
    assert argv[argv.index("--proxy") + 1] == "http://127.0.0.1:8080"
    assert argv[argv.index("-b") + 1] == "s=1"
    assert argv[argv.index("--data-binary") + 1] == "a=1"
    assert argv[argv.index("-m") + 1] == "7"


def test_curl_flags_carries_session_context_quoted():
    session = {
        "cookies": "sid=1; evil='$(id)",
        "proxy": "http://127.0.0.1:8080",
        "auth_token": "abc123",
        "headers": "X-Bug: bounty",
    }
    argv = shlex.split(curl_flags(session))
    assert argv[argv.index("--proxy") + 1] == "http://127.0.0.1:8080"
    headers = [argv[i + 1] for i, a in enumerate(argv) if a == "-H"]
    assert "Authorization: Bearer abc123" in headers
    assert "X-Bug: bounty" in headers
    # A cookie holding shell metacharacters stays one inert argument.
    assert argv[argv.index("-b") + 1] == "sid=1; evil='$(id)"


def test_curl_flags_does_not_duplicate_explicit_authorization():
    argv = shlex.split(curl_flags({"headers": "Authorization: Basic xyz", "auth_token": "abc"}))
    headers = [argv[i + 1] for i, a in enumerate(argv) if a == "-H"]
    assert headers == ["Authorization: Basic xyz"]


# ── rate limiting ─────────────────────────────────────────────────────────────
def test_rate_limiter_spaces_requests():
    limiter = RateLimiter(rps=20)  # 50ms apart
    start = time.monotonic()
    for _ in range(3):
        limiter.acquire()
    elapsed = time.monotonic() - start
    assert elapsed >= 0.09  # two enforced gaps


def test_rate_limiter_unlimited_when_rps_zero():
    limiter = RateLimiter(rps=0)
    assert limiter.acquire() == 0.0
    assert limiter.interval == 0.0


# ── client ────────────────────────────────────────────────────────────────────
class _StubResponse:
    def __init__(self, status=200, body="ok", headers=None):
        self.status_code = status
        self.text = body
        self.headers = headers or {"Content-Type": "text/html", "Set-Cookie": "sid=secret"}


class _StubHTTP:
    """Stands in for requests.Session - records calls, returns canned responses."""

    def __init__(self, responses=None, raise_exc=None):
        self.calls = []
        self.responses = list(responses or [_StubResponse()])
        self.raise_exc = raise_exc

    def request(self, method, url, **kwargs):
        self.calls.append({"method": method, "url": url, **kwargs})
        if self.raise_exc:
            raise self.raise_exc
        return self.responses[min(len(self.calls) - 1, len(self.responses) - 1)]

    def close(self):
        pass

    def mount(self, *_a, **_kw):
        pass


def _client(session=None, **kw):
    c = Client(session=session or {"target_url": "https://target.test"}, rps=0, **kw)
    c._http = _StubHTTP()
    return c


def test_client_blocks_out_of_scope_request():
    c = _client()
    with pytest.raises(ScopeViolation):
        c.get("https://not-the-target.test/")
    assert c._http.calls == []  # nothing left the machine


def test_client_resolves_relative_paths_against_target():
    c = _client()
    c.get("/admin")
    assert c._http.calls[0]["url"] == "https://target.test/admin"


def test_client_injects_session_context():
    c = _client({
        "target_url": "https://target.test",
        "cookies": "sid=1",
        "auth_token": "tok",
        "headers": "X-Bug: bounty",
        "proxy": "http://127.0.0.1:8080",
    })
    c.get("/")
    call = c._http.calls[0]
    assert call["headers"]["Cookie"] == "sid=1"
    assert call["headers"]["Authorization"] == "Bearer tok"
    assert call["headers"]["X-Bug"] == "bounty"
    # Proxy on every request is what makes Burp history complete.
    assert call["proxies"] == {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}


def test_client_attaches_redacted_evidence():
    c = _client({"target_url": "https://target.test", "cookies": "sid=supersecret"})
    r = c.get("/x", params={"q": "1"})
    ev = r.evidence
    assert ev.status == 200
    assert ev.url.endswith("?q=1")
    assert ev.request_headers["Cookie"] == "<redacted>"
    assert ev.response_headers["Set-Cookie"] == "<redacted>"
    assert "supersecret" not in ev.curl
    assert "GET /x?q=1 HTTP/1.1" in ev.request_text()
    assert "HTTP/1.1 200" in ev.response_text()


def test_client_retries_transient_status_then_gives_up():
    c = _client()
    c._http = _StubHTTP(responses=[_StubResponse(status=503)])
    c.retries = 2
    r = c.get("/")
    assert r.status_code == 503
    assert len(c._http.calls) == 3  # initial + 2 retries


def test_client_does_not_retry_application_status():
    c = _client()
    c._http = _StubHTTP(responses=[_StubResponse(status=404)])
    c.retries = 2
    c.get("/")
    assert len(c._http.calls) == 1


def test_safe_get_swallows_transport_errors():
    c = _client()
    c._http = _StubHTTP(raise_exc=requests.ConnectionError("boom"))
    c.retries = 0
    assert c.safe_get("/") is None
    # The failed attempt is still evidence - it explains a gap in the report.
    assert c.history[-1].error == "boom"


def test_client_history_is_capped():
    c = _client()
    c.max_history = 5
    for _ in range(12):
        c.get("/")
    assert len(c.history) == 5


# ── evidence pipeline ─────────────────────────────────────────────────────────
def test_normalize_evidence_accepts_objects_dicts_and_text():
    ev = Evidence(method="GET", url="https://t.test/")
    assert normalize_evidence(ev)["url"] == "https://t.test/"
    assert normalize_evidence({"a": 1}) == {"a": 1}
    assert normalize_evidence("saw it happen") == {"note": "saw it happen"}
    assert normalize_evidence(None) is None


def test_add_vuln_records_evidence_and_confidence():
    from config.settings import SESSION, add_vuln
    SESSION["vulns_found"] = []
    add_vuln("SQL Injection", "Critical", "A03:2021", "detail", "https://t.test/x",
             evidence=Evidence(url="https://t.test/x", status=500), confidence="Confirmed",
             cwe="CWE-89")
    v = SESSION["vulns_found"][-1]
    assert v["confidence"] == "Confirmed"
    assert v["cwe"] == "CWE-89"
    assert v["evidence"]["status"] == 500
    SESSION["vulns_found"] = []


def test_add_vuln_rejects_unknown_confidence():
    from config.settings import SESSION, add_vuln
    SESSION["vulns_found"] = []
    add_vuln("X", "Low", "A01:2021", confidence="totally-sure")
    assert SESSION["vulns_found"][-1]["confidence"] in CONFIDENCE_LEVELS
    SESSION["vulns_found"] = []


def test_add_finding_stores_evidence():
    from utils.helpers import add_finding
    session = {}
    add_finding(session, "Open Redirect", "Medium", evidence=Evidence(url="https://t.test/r"))
    assert session["findings"][0]["evidence"]["url"] == "https://t.test/r"
