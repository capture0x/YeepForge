"""Open-redirect detection: only a Location header that really navigates counts."""
from modules import open_redirect as orx

CANARY = orx.CANARY_HOST


class _Resp:
    def __init__(self, status=302, location=None):
        self.status_code = status
        self.headers = {"Location": location} if location else {}


def test_redirects_to_matches_host_and_subdomains():
    assert orx._redirects_to(f"https://{CANARY}/x", CANARY)
    assert orx._redirects_to(f"https://sub.{CANARY}/x", CANARY)
    assert orx._redirects_to(f"//{CANARY}/x", CANARY)          # protocol-relative
    assert orx._redirects_to(f"https:\\\\{CANARY}", CANARY)     # backslash variant


def test_redirects_to_rejects_substring_lookalikes():
    """The old substring check called all of these open redirects."""
    assert not orx._redirects_to(f"/login?next=https://{CANARY}", CANARY)
    assert not orx._redirects_to(f"https://trusted.test/{CANARY}/path", CANARY)
    assert not orx._redirects_to(f"https://not{CANARY}.attacker.test", CANARY)
    assert not orx._redirects_to("", CANARY)


def test_redirect_target_only_reads_redirect_responses():
    assert orx._redirect_target(_Resp(302, "https://x.test")) == "https://x.test"
    # A 200 with a Location header is not a redirect.
    assert orx._redirect_target(_Resp(200, "https://x.test")) == ""
    assert orx._redirect_target(_Resp(302)) == ""
    assert orx._redirect_target(None) == ""


def test_dangerous_scheme_detects_browser_executable_targets():
    assert orx._dangerous_scheme("javascript:alert(1)") == "javascript"
    assert orx._dangerous_scheme("  JAVASCRIPT:alert(1)") == "javascript"
    assert orx._dangerous_scheme("\x00javascript:alert(1)") == "javascript"
    assert orx._dangerous_scheme("data:text/html,<script>") == "data"
    assert orx._dangerous_scheme("vbscript:msgbox(1)") == "vbscript"


def test_dangerous_scheme_ignores_ordinary_urls():
    assert orx._dangerous_scheme("https://trusted.test/next") == ""
    assert orx._dangerous_scheme("/relative/path") == ""
    assert orx._dangerous_scheme("") == ""
