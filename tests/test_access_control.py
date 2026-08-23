"""Access-control detection logic: soft-404 handling and IDOR evidence rules.

These guard the false-positive fixes - a scanner that reports every path as
exposed, or records an IDOR because a scan ran, is worse than no scanner.
"""
import pytest

from config.settings import SESSION
from modules import broken_access_control as bac


class _Resp:
    def __init__(self, status=200, text="body", url="https://t.test/x"):
        self.status_code = status
        self.text = text
        self.headers = {"Content-Type": "text/html"}
        self.evidence = type("E", (), {"url": url, "to_dict": lambda self: {"url": url}})()


class _FakeClient:
    """Serves canned responses keyed by substring of the requested URL."""

    def __init__(self, routes, default=None):
        self.routes = routes
        self.default = default or _Resp(status=404, text="not found")
        self.requested = []

    def safe_get(self, url, **kw):
        self.requested.append(url)
        for needle, resp in self.routes.items():
            if needle in url:
                return resp
        return self.default


@pytest.fixture(autouse=True)
def clean_vulns():
    SESSION["vulns_found"] = []
    yield
    SESSION["vulns_found"] = []


# ── soft-404 baseline ─────────────────────────────────────────────────────────
def test_notfound_signature_probes_a_random_path():
    client = _FakeClient({}, default=_Resp(status=200, text="Page not found"))
    sig = bac._notfound_signature(client, "https://t.test")
    assert sig == (200, len("Page not found"))
    assert "yeepforge-" in client.requested[0]


def test_looks_like_notfound_matches_similar_body():
    sig = (200, 1000)
    assert bac._looks_like_notfound(_Resp(200, "x" * 1010), sig)
    assert not bac._looks_like_notfound(_Resp(200, "x" * 3000), sig)
    assert not bac._looks_like_notfound(_Resp(403, "x" * 1000), sig)


def test_looks_like_notfound_without_baseline_never_filters():
    assert not bac._looks_like_notfound(_Resp(200, "anything"), None)


# ── IDOR ──────────────────────────────────────────────────────────────────────
def test_idor_not_reported_when_every_id_returns_the_same_page(capsys):
    """A page identical for every ID ignores the ID - that is not an IDOR."""
    same = _Resp(200, "<html>Generic dashboard</html>")
    client = _FakeClient({"/api/user/": same},
                         default=_Resp(404, "nope"))
    _run_idor(client, count=5)
    assert SESSION["vulns_found"] == []
    assert "no IDOR evidence" in capsys.readouterr().out


def test_idor_reported_with_evidence_when_objects_differ():
    routes = {f"/api/user/{i}": _Resp(200, f"<html>user {i} private data</html>")
              for i in range(1, 6)}
    client = _FakeClient(routes, default=_Resp(404, "nope"))
    _run_idor(client, count=5)
    assert len(SESSION["vulns_found"]) == 1
    finding = SESSION["vulns_found"][0]
    assert finding["cwe"] == "CWE-639"
    # Distinct content is a lead, not proof of cross-account access.
    assert finding["confidence"] == "Tentative"
    assert finding["evidence"] is not None


def test_idor_skips_endpoint_without_a_numeric_id(capsys):
    _run_idor(_FakeClient({}), endpoint="/api/user/me", count=3)
    assert SESSION["vulns_found"] == []
    assert "No numeric ID" in capsys.readouterr().out


def _run_idor(client, endpoint="/api/user/1", count=5):
    """Call _numeric_idor with the module's client replaced by a stub."""
    original = bac.get_client
    bac.get_client = lambda: client
    try:
        bac._numeric_idor("https://t.test", endpoint, count=count)
    finally:
        bac.get_client = original
