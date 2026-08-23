"""A finding must appear once, keep its own remediation, and land in a file.

These cover the defects a live run against a public test target surfaced: the
report double-counted every finding recorded through the agent, discarded the
remediation the tester wrote, and handed the caller 40 KB of HTML where a path
was expected.
"""
import pytest

from config.settings import SESSION, add_vuln
from modules import reporting


@pytest.fixture
def clean_session(tmp_path):
    saved = {k: SESSION.get(k) for k in
             ("findings", "vulns_found", "target_url", "engagement", "tech_stack")}
    SESSION["findings"] = []
    SESSION["vulns_found"] = []
    SESSION["target_url"] = "https://target.test"
    SESSION["engagement"] = "unit-test"
    yield SESSION
    SESSION.update(saved)


# ── Deduplication ─────────────────────────────────────────────────────────────

def test_same_finding_in_both_stores_collapses(clean_session):
    """The historic dual-write: one copy located, one bare."""
    SESSION["vulns_found"] = [{
        "title": "SQL Injection in id", "severity": "Critical",
        "url": "https://target.test/news?id=2", "detail": "proven",
    }]
    SESSION["findings"] = [{
        "title": "SQL Injection in id", "severity": "Critical",
        "url": "", "detail": "proven",
    }]
    out = reporting._sorted_findings()
    assert len(out) == 1
    assert out[0]["url"] == "https://target.test/news?id=2"


def test_bare_copy_donates_fields_it_alone_carries(clean_session):
    SESSION["vulns_found"] = [{
        "title": "XSS", "severity": "High", "url": "https://target.test/q",
    }]
    SESSION["findings"] = [{
        "title": "XSS", "severity": "High", "url": "",
        "evidence": {"note": "reflected in <script>"},
    }]
    out = reporting._sorted_findings()
    assert len(out) == 1
    assert out[0]["evidence"] == {"note": "reflected in <script>"}


def test_same_title_on_different_urls_stays_separate(clean_session):
    """Two endpoints with one bug class are two findings, not one."""
    SESSION["vulns_found"] = [
        {"title": "IDOR", "severity": "High", "url": "https://target.test/a"},
        {"title": "IDOR", "severity": "High", "url": "https://target.test/b"},
    ]
    assert len(reporting._sorted_findings()) == 2


def test_placeless_copy_dropped_when_title_spans_several_urls(clean_session):
    """It cannot say which endpoint it meant, so it must not become a row."""
    SESSION["vulns_found"] = [
        {"title": "IDOR", "severity": "High", "url": "https://target.test/a"},
        {"title": "IDOR", "severity": "High", "url": "https://target.test/b"},
    ]
    SESSION["findings"] = [{"title": "IDOR", "severity": "High", "url": ""}]
    out = reporting._sorted_findings()
    assert len(out) == 2
    assert all(f["url"] for f in out)


def test_report_body_count_matches_dedup(clean_session):
    SESSION["vulns_found"] = [{"title": "SSRF", "severity": "Critical",
                              "url": "https://target.test/fetch"}]
    SESSION["findings"] = [{"title": "SSRF", "severity": "Critical", "url": ""}]
    html = reporting.generate_html()
    assert html.count('class="finding-card"') == 1


# ── Remediation ───────────────────────────────────────────────────────────────

def test_supplied_remediation_survives_into_the_report(clean_session):
    add_vuln("SQL Injection in id", "Critical", "A03:2021", "detail",
             "https://target.test/news?id=2",
             remediation="Parameterise the id lookup and drop db_owner.")
    html = reporting.generate_html()
    assert "Parameterise the id lookup and drop db_owner." in html
    # The generic per-class hint must not also appear for the same finding.
    assert "Never concatenate user input into SQL strings." not in html


def test_generic_hint_still_fills_the_gap(clean_session):
    add_vuln("SQL Injection in id", "Critical", "A03:2021", "detail",
             "https://target.test/news?id=2")
    assert "Never concatenate user input into SQL strings." in reporting.generate_html()


# ── CVSS coverage ─────────────────────────────────────────────────────────────

def test_unmapped_title_still_scores_from_severity(clean_session):
    """A blank CVSS column reads as 'not assessed', which is not what we mean."""
    score, vector = reporting._get_cvss("Missing security headers", "Medium")
    assert score == "5.3"
    assert vector.startswith("CVSS:3.1/")


def test_known_title_keeps_its_specific_score(clean_session):
    assert reporting._get_cvss("SQL Injection in id", "Medium")[0] == "9.8"


# ── Writing the file ──────────────────────────────────────────────────────────

def test_save_html_returns_a_path_that_exists(clean_session, tmp_path):
    add_vuln("SSRF", "Critical", "A10:2021", "d", "https://target.test/fetch")
    out = reporting.save_html(tmp_path / "report.html")
    assert out.exists()
    assert out.read_text(encoding="utf-8").startswith("<!DOCTYPE html>")


def test_save_html_creates_missing_directories(clean_session, tmp_path):
    out = reporting.save_html(tmp_path / "nested" / "deep" / "r.html")
    assert out.exists()
