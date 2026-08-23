"""Tests for mid-scan session expiry detection.

The failure this guards against is the quiet one: a cookie dies an hour into a
run, every later request is answered with a login page, nothing is found, and
the report says the application is clean. These tests pin that the loss is
noticed, that it is not claimed spuriously, and that everything recorded
afterwards is marked untrusted rather than silently believed.
"""
import pytest

from config.settings import SESSION, add_vuln
from utils.liveness import SessionMonitor, get_monitor, reset_monitor


class _Resp:
    def __init__(self, status=200, body="", headers=None):
        self.status_code = status
        self.text = body
        self.headers = headers or {}


class _Client:
    """Returns canned responses to safe_get, in order."""

    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    def safe_get(self, url, **kwargs):
        self.calls.append({"url": url, **kwargs})
        return self.responses.pop(0) if self.responses else None


APP = "<html><h1>Dashboard</h1><p>Welcome back, Alice</p><p>3 open tickets</p></html>"
WALL = "<html><h1>Sign in</h1><p>Your session has expired, please log in.</p></html>"


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    reset_monitor()
    monkeypatch.setitem(SESSION, "cookies", "sid=aaa")
    monkeypatch.setitem(SESSION, "target_url", "https://target.test/")
    monkeypatch.setitem(SESSION, "vulns_found", [])
    SESSION.pop("session_degraded", None)
    SESSION.pop("session_degraded_reason", None)
    yield
    reset_monitor()


# ── baseline ──────────────────────────────────────────────────────────────────
def test_baseline_is_established_when_auth_changes_the_response():
    monitor = SessionMonitor()
    client = _Client(_Resp(body=APP), _Resp(status=302, body=""))
    assert monitor.establish(client) is True
    assert monitor.established
    # The second call must be the credential-free one.
    assert client.calls[1]["anonymous"] is True


def test_no_credentials_means_no_monitoring(monkeypatch):
    """There is no session to lose, so nothing should warn about losing it."""
    for key in ("cookies", "auth_token", "headers"):
        monkeypatch.setitem(SESSION, key, "")
    monitor = SessionMonitor()
    assert monitor.establish(_Client(_Resp(body=APP))) is False
    assert not monitor.established


def test_indistinguishable_responses_disable_the_check():
    """If logged-in and logged-out look the same, expiry is undetectable and
    claiming otherwise would produce warnings at random."""
    monitor = SessionMonitor()
    assert monitor.establish(_Client(_Resp(body=APP), _Resp(body=APP))) is False
    assert not monitor.established


def test_unreachable_target_does_not_establish_a_baseline():
    monitor = SessionMonitor()
    assert monitor.establish(_Client(None)) is False


# ── recognising the logged-out state ──────────────────────────────────────────
@pytest.mark.parametrize("status", [401, 403])
def test_unauthorised_status_is_a_lost_session(status):
    monitor = SessionMonitor()
    assert monitor.looks_logged_out(_Resp(status=status))


@pytest.mark.parametrize("phrase", [
    "Your session has expired",
    "Please log in to continue",
    "Authentication required",
    "You must be logged in",
])
def test_login_wall_wording_is_recognised(phrase):
    monitor = SessionMonitor()
    assert monitor.looks_logged_out(_Resp(body=f"<html><p>{phrase}</p></html>"))


def test_the_word_login_in_a_footer_is_not_a_lost_session():
    """Half the internet has 'Login' in its navigation."""
    monitor = SessionMonitor()
    page = APP + "<footer><a href='/login'>Login</a> | <a href='/about'>About</a></footer>"
    assert monitor.looks_logged_out(_Resp(body=page)) == ""


def test_a_wall_phrase_deep_in_a_long_page_is_not_matched():
    """Only the head of the body is inspected; a help article that mentions
    session expiry is not itself a session expiry."""
    monitor = SessionMonitor()
    page = "<html>" + ("<p>Ordinary content. </p>" * 200) + "<p>session expired</p>"
    assert monitor.looks_logged_out(_Resp(body=page)) == ""


def test_response_matching_the_anonymous_baseline_is_a_lost_session():
    monitor = SessionMonitor()
    monitor.establish(_Client(_Resp(body=APP), _Resp(status=302, body="redirect")))
    assert monitor.looks_logged_out(_Resp(status=302, body="redirect"))


def test_a_normal_response_is_not_a_lost_session():
    monitor = SessionMonitor()
    monitor.establish(_Client(_Resp(body=APP), _Resp(status=302, body="")))
    assert monitor.looks_logged_out(_Resp(body=APP)) == ""


# ── sampling cadence ──────────────────────────────────────────────────────────
def test_probe_requests_are_not_sent_on_every_call():
    monitor = SessionMonitor(interval=10)
    monitor.establish(_Client(_Resp(body=APP), _Resp(status=302)))
    assert [monitor.note_request() for _ in range(9)] == [False] * 9
    assert monitor.note_request() is True


def test_no_sampling_before_a_baseline_exists():
    assert SessionMonitor().note_request() is False


def test_no_further_sampling_once_degraded():
    monitor = SessionMonitor(interval=1)
    monitor.establish(_Client(_Resp(body=APP), _Resp(status=302)))
    monitor.mark_degraded("HTTP 401")
    assert monitor.note_request() is False


# ── consequences ──────────────────────────────────────────────────────────────
def test_degrading_sets_the_session_flag():
    monitor = get_monitor()
    monitor.mark_degraded("HTTP 401")
    assert SESSION["session_degraded"] is True
    assert SESSION["session_degraded_reason"] == "HTTP 401"


def test_findings_after_a_lost_session_are_marked_untrusted():
    get_monitor().mark_degraded("the response says 'session expired'")
    add_vuln("Missing HSTS", "Medium", "A05:2021", "No HSTS header.",
             "https://target.test/", confidence="Confirmed")

    finding = SESSION["vulns_found"][-1]
    assert finding["untrusted"] is True
    assert "[UNTRUSTED]" in finding["detail"]
    # A finding produced by an anonymous request cannot stay "Confirmed".
    assert finding["confidence"] == "Tentative"


def test_findings_before_the_loss_are_untouched():
    add_vuln("Missing HSTS", "Medium", "A05:2021", "No HSTS header.",
             "https://target.test/", confidence="Confirmed")
    finding = SESSION["vulns_found"][-1]
    assert finding["untrusted"] is False
    assert finding["confidence"] == "Confirmed"
    assert "[UNTRUSTED]" not in finding["detail"]


def test_degrading_twice_keeps_the_first_reason():
    monitor = get_monitor()
    monitor.mark_degraded("HTTP 401")
    monitor.mark_degraded("something else")
    assert SESSION["session_degraded_reason"] == "HTTP 401"


def test_report_carries_the_caveat_when_the_session_was_lost():
    import modules.reporting as reporting
    get_monitor().mark_degraded("HTTP 401")
    assert "INCOMPLETE ASSESSMENT" in reporting.generate_html()
    assert "INCOMPLETE ASSESSMENT" in reporting.generate_markdown()


def test_report_has_no_caveat_on_a_healthy_run():
    import modules.reporting as reporting
    assert "INCOMPLETE ASSESSMENT" not in reporting.generate_html()
