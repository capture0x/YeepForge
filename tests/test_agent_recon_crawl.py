"""Crawl results must be real locations, and a fingerprint must reach the report."""
import pytest

from config.settings import SESSION
from modules.agent import _core


@pytest.fixture
def clean_session():
    saved = {k: SESSION.get(k) for k in ("tech_stack",)}
    SESSION["tech_stack"] = []
    yield SESSION
    SESSION.update(saved)


# ── Pseudo-URL filtering ──────────────────────────────────────────────────────

@pytest.mark.parametrize("raw", [
    "javascript:__doPostBack(",
    "JavaScript:void(0)",
    "  javascript:foo()",
    "mailto:security@target.test",
    "tel:+15550100",
    "data:text/html,<h1>x</h1>",
    "about:blank",
    "#section",
])
def test_pseudo_urls_are_not_locations(raw):
    assert _core._is_pseudo_url(raw)


@pytest.mark.parametrize("raw", [
    "/login.aspx",
    "ReadNews.aspx?id=2",
    "https://target.test/api/v1/users",
    "../about.aspx",
])
def test_real_paths_survive(raw):
    assert not _core._is_pseudo_url(raw)


# ── Tech fingerprint ──────────────────────────────────────────────────────────

def test_stack_headers_are_recorded(clean_session):
    _core._record_tech(
        "HTTP/1.1 200 OK\r\n"
        "Server: Microsoft-IIS/8.5\r\n"
        "X-AspNet-Version: 2.0.50727\r\n"
        "X-Powered-By: ASP.NET\r\n"
        "Content-Type: text/html\r\n"
    )
    stack = SESSION["tech_stack"]
    assert "Server: Microsoft-IIS/8.5" in stack
    assert "X-AspNet-Version: 2.0.50727" in stack
    # Headers that say nothing about the stack stay out of it.
    assert not any("Content-Type" in s for s in stack)


def test_empty_header_values_are_skipped(clean_session):
    _core._record_tech("Server: \r\nX-Powered-By: PHP/8.2\r\n")
    assert SESSION["tech_stack"] == ["X-Powered-By: PHP/8.2"]


def test_recording_twice_does_not_duplicate(clean_session):
    for _ in range(2):
        _core._record_tech("Server: nginx/1.24\r\n")
    assert SESSION["tech_stack"] == ["Server: nginx/1.24"]


# ── dalfox pacing ─────────────────────────────────────────────────────────────
# dalfox issues its own HTTP, so --rps cannot reach it through utils.http. If
# the cap is not translated here, one tool floods a target the rest of the run
# is carefully pacing - and a flooded host stops answering entirely.

def test_rate_cap_bounds_workers_and_sets_delay(monkeypatch):
    monkeypatch.setenv("YEEPFORGE_RPS", "4")
    workers, delay = _core._dalfox_pacing()
    assert workers == 4
    assert delay == 250


def test_worker_count_is_capped_well_below_dalfox_default(monkeypatch):
    monkeypatch.setenv("YEEPFORGE_RPS", "500")
    workers, _ = _core._dalfox_pacing()
    assert workers <= 8


def test_slow_cap_still_leaves_one_worker(monkeypatch):
    monkeypatch.setenv("YEEPFORGE_RPS", "0.5")
    workers, delay = _core._dalfox_pacing()
    assert workers == 1
    assert delay == 2000


def test_unlimited_is_still_paced(monkeypatch):
    """0 means 'no cap', not 'flood' - dalfox's own default is 100 workers."""
    monkeypatch.setenv("YEEPFORGE_RPS", "0")
    workers, delay = _core._dalfox_pacing()
    assert workers <= 8
    assert delay > 0


def test_unparseable_cap_falls_back_to_the_default(monkeypatch):
    monkeypatch.setenv("YEEPFORGE_RPS", "fast")
    assert _core._dalfox_pacing() == _core._dalfox_pacing()
    monkeypatch.setenv("YEEPFORGE_RPS", "10")
    assert _core._dalfox_pacing()[0] <= 8
