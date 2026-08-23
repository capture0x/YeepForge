"""Session, CORS and cookie logic - the parts that decide severity and truth."""
import pytest

from modules import security_misconfig as smc
from modules import session_security as ss
from utils.http import set_cookie_headers


class _Raw:
    def __init__(self, values):
        self.headers = self  # urllib3 exposes .headers.getlist
        self._values = values

    def getlist(self, _name):
        return self._values


class _Resp:
    def __init__(self, set_cookies=None, joined=None, text="", status=200, headers=None):
        self.status_code = status
        self.text = text
        self.headers = dict(headers or {})
        if joined is not None:
            self.headers["Set-Cookie"] = joined
        self.raw = _Raw(set_cookies) if set_cookies is not None else None


# ── Set-Cookie parsing ────────────────────────────────────────────────────────
def test_set_cookie_headers_prefers_the_raw_list():
    resp = _Resp(set_cookies=["a=1; HttpOnly", "b=2; Secure"])
    assert set_cookie_headers(resp) == ["a=1; HttpOnly", "b=2; Secure"]


def test_set_cookie_headers_splits_joined_header_without_breaking_expires():
    """requests joins repeated headers with ', ' - and Expires contains commas."""
    joined = "sid=abc; Expires=Mon, 01 Jan 2027 00:00:00 GMT; HttpOnly, theme=dark; Path=/"
    resp = _Resp(joined=joined)
    cookies = set_cookie_headers(resp)
    assert len(cookies) == 2
    assert cookies[0].startswith("sid=abc")
    assert "Expires=Mon, 01 Jan 2027" in cookies[0]
    assert cookies[1].startswith("theme=dark")


def test_set_cookie_headers_empty():
    assert set_cookie_headers(_Resp(joined="")) == []


# ── cookie severity ───────────────────────────────────────────────────────────
def test_session_cookie_detection():
    assert ss.is_session_cookie("PHPSESSID")
    assert ss.is_session_cookie("auth_token")
    assert not ss.is_session_cookie("theme")


def test_missing_httponly_is_graded_by_cookie_purpose():
    """A locale cookie readable from JS is not a session cookie readable from JS."""
    assert ss._cookie_severity("PHPSESSID", "httponly", True) == "Medium"
    assert ss._cookie_severity("theme", "httponly", True) == "Low"


def test_secure_flag_on_plain_http_is_not_the_headline():
    assert ss._cookie_severity("PHPSESSID", "secure", False) == "Low"
    assert ss._cookie_severity("PHPSESSID", "secure", True) == "Medium"


# ── session fixation preconditions ────────────────────────────────────────────
def test_cookie_value_reads_the_named_cookie():
    resp = _Resp(set_cookies=["PHPSESSID=abc123; Path=/", "other=1"])
    assert ss._cookie_value(resp, "PHPSESSID") == "abc123"
    assert ss._cookie_value(resp, "missing") == ""
    assert ss._cookie_value(None, "PHPSESSID") == ""


@pytest.mark.parametrize("body,failed", [
    ("Invalid username or password", True),
    ("Login failed, try again", True),
    ("<h1>Welcome back, admin</h1>", False),
])
def test_failed_login_detection(body, failed):
    """An unchanged session ID after a *rejected* login proves nothing."""
    assert ss._looks_like_failed_login(_Resp(text=body)) is failed


# ── debug endpoint severity ───────────────────────────────────────────────────
def test_debug_endpoint_severity_is_graded():
    assert smc._endpoint_severity("/actuator/heapdump") == "Critical"
    assert smc._endpoint_severity("/actuator/env") == "Critical"
    assert smc._endpoint_severity("/swagger") == "Medium"
    # /health being reachable is normal operations, not a High finding.
    assert smc._endpoint_severity("/health") == "Info"
    assert smc._endpoint_severity("/version") == "Info"


def test_cors_canary_is_not_a_third_party_domain():
    """Probing with a domain someone else owns puts target traffic in their logs."""
    assert smc.CORS_CANARY.endswith(".example.net")
    assert "evil.com" not in smc.CORS_CANARY
    assert ss.LOGOUT_CSRF_CANARY.endswith(".example.net")
