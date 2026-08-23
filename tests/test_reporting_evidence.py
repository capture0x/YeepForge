"""The report must carry the proof, and must not leak or execute what it shows."""
import pytest

from config.settings import SESSION
from modules import reporting
from utils.http import Evidence


@pytest.fixture
def clean_session():
    saved = {k: SESSION.get(k) for k in ("findings", "vulns_found", "target_url", "engagement")}
    SESSION["findings"] = []
    SESSION["vulns_found"] = []
    SESSION["target_url"] = "https://target.test"
    SESSION["engagement"] = "unit-test"
    yield SESSION
    SESSION.update(saved)


def _evidence(**kw) -> dict:
    base = Evidence(
        method="GET",
        url="https://target.test/item?id=1'",
        request_headers={"User-Agent": "YeepForge", "Cookie": "<redacted>"},
        status=500,
        response_headers={"Content-Type": "text/html"},
        response_body="You have an error in your SQL syntax",
        elapsed_ms=142,
        curl="curl -s -k 'https://target.test/item?id=1%27'",
    ).to_dict()
    base.update(kw)
    return base


def test_html_report_renders_request_response_and_repro(clean_session):
    SESSION["vulns_found"] = [{
        "title": "SQL Injection", "severity": "Critical", "owasp": "A03:2021",
        "detail": "error-based", "url": "https://target.test/item",
        "confidence": "Confirmed", "cwe": "CWE-89", "evidence": _evidence(),
        "time": "2026-07-25T10:00:00",
    }]
    html = reporting.generate_html()
    assert "GET /item?id=1&#x27; HTTP/1.1" in html
    assert "You have an error in your SQL syntax" in html
    assert "curl -s -k" in html
    assert "Confirmed" in html
    assert "CWE-89" in html
    assert "142 ms" in html


def test_html_report_escapes_evidence(clean_session):
    """Evidence is attacker-influenced text - it must never become live markup."""
    SESSION["vulns_found"] = [{
        "title": "Reflected XSS", "severity": "High", "owasp": "A03:2021",
        "url": "https://target.test/s",
        "evidence": _evidence(response_body="<script>alert(document.domain)</script>"),
        "time": "2026-07-25T10:00:00",
    }]
    html = reporting.generate_html()
    assert "<script>alert(document.domain)</script>" not in html
    assert "&lt;script&gt;alert(document.domain)&lt;/script&gt;" in html


def test_markdown_report_fences_evidence(clean_session):
    SESSION["vulns_found"] = [{
        "title": "SQL Injection", "severity": "Critical", "owasp": "A03:2021",
        "url": "https://target.test/item", "confidence": "Confirmed",
        "evidence": _evidence(), "time": "2026-07-25T10:00:00",
    }]
    md = reporting.generate_markdown()
    assert "**Request**" in md and "**Response**" in md and "**Reproduce**" in md
    assert "```http" in md and "```bash" in md
    assert "| Confidence | Confirmed |" in md


def test_findings_without_evidence_still_render(clean_session):
    SESSION["vulns_found"] = [{
        "title": "Missing HSTS", "severity": "Low", "owasp": "A05:2021",
        "url": "https://target.test/", "time": "2026-07-25T10:00:00",
    }]
    html = reporting.generate_html()
    assert "Missing HSTS" in html
    assert "Evidence" not in html
    assert "**Request**" not in reporting.generate_markdown()


def test_dedup_keeps_the_copy_with_evidence(clean_session):
    common = {"title": "SQL Injection", "severity": "Critical",
              "owasp": "A03:2021", "url": "https://target.test/item"}
    SESSION["vulns_found"] = [
        {**common, "evidence": _evidence()},
        {**common},  # a later evidence-less duplicate must not win
    ]
    findings = reporting._sorted_findings()
    assert len(findings) == 1
    assert findings[0]["evidence"]


def test_free_text_evidence_renders_as_note(clean_session):
    SESSION["vulns_found"] = [{
        "title": "Business Logic Flaw", "severity": "High", "owasp": "A04:2021",
        "url": "https://target.test/checkout",
        "evidence": {"note": "Coupon reused 5 times, total went negative"},
        "time": "2026-07-25T10:00:00",
    }]
    html = reporting.generate_html()
    assert "Coupon reused 5 times" in html
