"""Tests for the migration off shelled-out curl and onto the HTTP engine.

Three things are pinned here:

  * anonymous requests genuinely carry no identity (the baseline every
    access-control check compares against);
  * external scanners inherit the engagement's rate limit and proxy, because
    utils.http cannot pace a subprocess;
  * the detection rules that replaced keyword matching hold their shape - a
    login page containing the word "welcome" is not a successful login, and a
    200 that matches the app's own 404 page is not an exposed file.

Nothing here touches the network.
"""
import pytest

from modules import auto_scanner, injection
from utils.http import Client, looks_like_notfound
from utils.tools import engagement_rps, pacing_argv, proxy_argv, shell_join, tool_cmd


# ── stubs ─────────────────────────────────────────────────────────────────────
class _Resp:
    def __init__(self, status=200, body="ok", headers=None, cookies=None):
        self.status_code = status
        self.text = body
        self.headers = headers or {"Content-Type": "text/html"}
        self.cookies = cookies or {}


class _StubHTTP:
    def __init__(self, responses=None):
        self.calls = []
        self.responses = list(responses or [_Resp()])
        self.cookies = _Jar()

    def request(self, method, url, **kwargs):
        self.calls.append({"method": method, "url": url, **kwargs})
        return self.responses[min(len(self.calls) - 1, len(self.responses) - 1)]

    def close(self):
        pass

    def mount(self, *_a, **_kw):
        pass


class _Jar(dict):
    def clear(self):
        super().clear()


def _client(responses=None, session=None):
    c = Client(session=session or {"target_url": "https://target.test"}, rps=0)
    c._http = _StubHTTP(responses)
    return c


# ── anonymous requests ────────────────────────────────────────────────────────
def test_anonymous_request_drops_cookies_and_auth():
    session = {
        "target_url": "https://target.test",
        "cookies": "sid=secret",
        "auth_token": "Bearer abc123",
        "headers": "X-Api-Key: k",
    }
    c = _client(session=session)
    anon = _StubHTTP()
    c._anon_http = anon

    c.get("https://target.test/admin", anonymous=True)

    sent = anon.calls[0]["headers"]
    assert "Cookie" not in sent
    assert "Authorization" not in sent
    # Operator-supplied headers can carry credentials too, so they go as well.
    assert "X-Api-Key" not in sent
    assert sent["User-Agent"]


def test_authenticated_request_still_carries_identity():
    session = {"target_url": "https://target.test", "cookies": "sid=secret",
               "auth_token": "abc123"}
    c = _client(session=session)
    c.get("https://target.test/admin")

    sent = c._http.calls[0]["headers"]
    assert sent["Cookie"] == "sid=secret"
    assert sent["Authorization"] == "Bearer abc123"


def test_anonymous_request_uses_a_separate_cookie_jar():
    """The shared session's jar must not ride along on an anonymous request."""
    c = _client()
    c._http.cookies["sid"] = "from-earlier-response"
    anon = c._anon_session()
    assert anon is not c._http
    assert not anon.cookies


# ── external tool pacing ──────────────────────────────────────────────────────
@pytest.fixture
def rps(monkeypatch):
    def _set(value):
        monkeypatch.setenv("YEEPFORGE_RPS", str(value))
    return _set


def test_engagement_rps_reads_the_same_env_var_as_the_engine(rps):
    rps(3)
    assert engagement_rps() == 3.0


def test_engagement_rps_falls_back_when_unset_or_garbage(monkeypatch):
    monkeypatch.delenv("YEEPFORGE_RPS", raising=False)
    assert engagement_rps() == 10.0
    monkeypatch.setenv("YEEPFORGE_RPS", "not-a-number")
    assert engagement_rps() == 10.0


@pytest.mark.parametrize("tool,expected_flag", [
    ("sqlmap", "--delay="),
    ("dalfox", "--worker="),
    ("ffuf", "-rate"),
    ("nuclei", "-rate-limit"),
    ("wpscan", "--throttle"),
])
def test_every_paced_tool_gets_a_throttle_flag(rps, tool, expected_flag):
    rps(2)
    argv = pacing_argv(tool)
    assert any(expected_flag in a for a in argv), f"{tool} not throttled: {argv}"


def test_sqlmap_delay_is_the_inverse_of_the_rate(rps):
    rps(4)                                     # 4 req/s → 0.25s between requests
    assert "--delay=0.25" in pacing_argv("sqlmap")


def test_pacing_never_exceeds_the_worker_ceiling(rps):
    rps(1000)
    workers = [a for a in pacing_argv("dalfox") if a.startswith("--worker=")]
    assert workers == ["--worker=8"]


def test_unlimited_rate_still_bounds_concurrency(rps):
    rps(0)
    assert "--worker=8" in pacing_argv("dalfox")


def test_proxy_reaches_external_tools(monkeypatch):
    import config.settings as settings
    monkeypatch.setitem(settings.SESSION, "proxy", "http://127.0.0.1:8080")
    assert proxy_argv("sqlmap") == ["--proxy=http://127.0.0.1:8080"]
    assert proxy_argv("nuclei") == ["-proxy", "http://127.0.0.1:8080"]
    assert proxy_argv("ffuf") == ["-x", "http://127.0.0.1:8080"]


def test_no_proxy_configured_adds_no_flags(monkeypatch):
    import config.settings as settings
    monkeypatch.setitem(settings.SESSION, "proxy", "")
    assert proxy_argv("sqlmap") == []


# ── shell safety of the tool layer ────────────────────────────────────────────
def test_shell_join_quotes_command_substitution():
    assert shell_join(["curl", "$(id)"]) == "curl '$(id)'"


def test_tool_cmd_quotes_a_hostile_payload(rps):
    rps(0)
    cmd = tool_cmd("sqlmap", ["-u", "https://t.test/?q=`whoami`", "--batch"])
    # Backticks must survive as literal characters inside quotes, never bare.
    assert "'https://t.test/?q=`whoami`'" in cmd
    assert cmd.startswith("sqlmap ")


def test_tool_cmd_can_skip_pacing_for_local_invocations(rps):
    rps(2)
    assert "--delay" not in tool_cmd("sqlmap", ["--version"], pace=False, proxy=False)


# ── detection rules that replaced keyword matching ────────────────────────────
def test_failed_login_baseline_detects_a_status_change():
    baseline = (401, 500)
    assert injection._differs_from_failed_login(_Resp(status=302, body="x" * 500), baseline)


def test_failed_login_baseline_ignores_an_identical_rejection():
    """A login page that says 'Welcome! Please sign in' is not a bypass."""
    body = "Welcome! Please sign in. Invalid credentials."
    baseline = (200, len(body))
    assert not injection._differs_from_failed_login(_Resp(status=200, body=body), baseline)


def test_failed_login_baseline_flags_a_new_session_cookie():
    body = "x" * 500
    baseline = (200, len(body))
    resp = _Resp(status=200, body=body, cookies={"sessionid": "granted"})
    assert injection._differs_from_failed_login(resp, baseline)


def test_soft_404_is_not_reported_as_an_exposed_file():
    signature = (200, 4000)
    spa_index = _Resp(status=200, body="x" * 4010)
    assert looks_like_notfound(spa_index, signature)


def test_cors_wildcard_is_not_critical():
    """`*` cannot be combined with credentials, so it is not a takeover."""
    c = _client([_Resp(headers={"Access-Control-Allow-Origin": "*",
                                "Access-Control-Allow-Credentials": "true"})])
    import utils.http as http_mod
    original, http_mod._client = http_mod._client, c
    try:
        findings = auto_scanner._quick_cors("https://target.test/")
    finally:
        http_mod._client = original
    assert len(findings) == 1
    assert findings[0]["severity"] == "Low"


def test_cors_reflected_origin_with_credentials_is_high():
    c = _client([_Resp(headers={"Access-Control-Allow-Origin": "https://evil.example",
                                "Access-Control-Allow-Credentials": "true"})])
    import utils.http as http_mod
    original, http_mod._client = http_mod._client, c
    try:
        findings = auto_scanner._quick_cors("https://target.test/")
    finally:
        http_mod._client = original
    assert len(findings) == 1
    assert findings[0]["severity"] == "High"
    assert findings[0]["confidence"] == "Confirmed"


def test_sqlmap_result_records_nothing_without_proof(tmp_path, monkeypatch):
    """Running sqlmap is not a finding - only its verdict is."""
    import config.settings as settings
    monkeypatch.setitem(settings.SESSION, "vulns_found", [])
    log = tmp_path / "target.test" / "log"
    log.parent.mkdir(parents=True)
    log.write_text("[INFO] testing connection to the target URL\n")

    injection._record_sqlmap_result(str(tmp_path), "https://target.test/?id=1")
    assert settings.SESSION["vulns_found"] == []


def test_sqlmap_result_records_a_finding_when_proven(tmp_path, monkeypatch):
    import config.settings as settings
    monkeypatch.setitem(settings.SESSION, "vulns_found", [])
    log = tmp_path / "target.test" / "log"
    log.parent.mkdir(parents=True)
    log.write_text("sqlmap identified the following injection point(s):\n"
                   "Parameter: id (GET)\n    Type: boolean-based blind\n")

    injection._record_sqlmap_result(str(tmp_path), "https://target.test/?id=1")
    vulns = settings.SESSION["vulns_found"]
    assert len(vulns) == 1
    assert vulns[0]["confidence"] == "Confirmed"
    assert "boolean-based blind" in vulns[0]["detail"]
