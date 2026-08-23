"""Tests for two-identity access-control comparison.

Access control is the most-paid bug class and the easiest to report wrongly.
Every case below is one of the ways a single-session check produces a false
positive: a public page, an empty list, a login page served with HTTP 200, a
body that differs only by its CSRF token.
"""
import pytest

from utils.differential import (
    SAME_CONTENT,
    Verdict,
    compare_access,
    normalise,
    similarity,
)
from utils.identity import Identity, request_as


class _Resp:
    def __init__(self, status=200, body="", headers=None):
        self.status_code = status
        self.text = body
        self.headers = headers or {}


PRIVATE = ("<h1>Order 1001</h1><p>Customer: Alice Andersson</p>"
           "<p>Card ending 4242</p><p>Total 249.90 EUR</p><p>Ship to Malmo</p>")
OTHER = ("<h1>Order 2002</h1><p>Customer: Bob Bergstrom</p>"
         "<p>Card ending 1111</p><p>Total 12.50 EUR</p><p>Ship to Uppsala</p>")
LOGIN = "<h1>Sign in</h1><form method=post><input name=user><input name=pass></form>"


# ── normalisation ─────────────────────────────────────────────────────────────
def test_csrf_token_does_not_make_a_page_differ_from_itself():
    a = '<form><input name="csrf_token" value="aaaaaaaa"></form><p>Order 1001</p>'
    b = '<form><input name="csrf_token" value="bbbbbbbb"></form><p>Order 1001</p>'
    assert similarity(a, b) >= SAME_CONTENT


def test_timestamps_are_normalised_away():
    a = "<p>Generated 2026-01-01 10:00:00</p><p>Balance 42</p>"
    b = "<p>Generated 2026-08-09 22:31:07</p><p>Balance 42</p>"
    assert similarity(a, b) >= SAME_CONTENT


def test_whitespace_differences_are_ignored():
    assert normalise("<p>a</p>\n\n   <p>b</p>") == normalise("<p>a</p> <p>b</p>")


def test_genuinely_different_content_is_not_similar():
    assert similarity(PRIVATE, OTHER) < SAME_CONTENT


# ── the false positives a naive check produces ────────────────────────────────
def test_public_page_is_not_an_access_control_finding():
    """The single biggest source of bogus IDOR reports."""
    page = "<h1>About us</h1>" + "Our company has been trading since 1994. " * 5
    verdict = compare_access(_Resp(body=page), _Resp(body=page), _Resp(body=page))
    assert verdict.kind == Verdict.NOT_PRIVATE
    assert not verdict.is_finding


def test_empty_response_to_everyone_is_inconclusive_not_idor():
    """An endpoint that returns [] to all callers proves nothing."""
    verdict = compare_access(_Resp(body="[]"), _Resp(body="[]"), _Resp(body="[]"))
    assert verdict.kind == Verdict.INCONCLUSIVE
    assert not verdict.is_finding


def test_login_page_served_with_200_to_both_users_is_not_idor():
    """A 200-with-login-form is a refusal, and it is identical for both users -
    which is exactly what a similarity check alone would call a finding."""
    verdict = compare_access(_Resp(body=LOGIN), _Resp(body=LOGIN), _Resp(body=LOGIN))
    assert verdict.kind == Verdict.NOT_PRIVATE


def test_owner_refused_is_inconclusive_not_a_clean_bill():
    """If the owner cannot read it either, the test setup is wrong."""
    verdict = compare_access(_Resp(status=403, body="denied"),
                             _Resp(status=403, body="denied"),
                             _Resp(status=401))
    assert verdict.kind == Verdict.INCONCLUSIVE
    assert "owner" in verdict.detail.lower()


# ── the true positives ────────────────────────────────────────────────────────
def test_second_user_reading_the_owners_resource_is_idor():
    verdict = compare_access(
        owner=_Resp(body=PRIVATE),
        attacker=_Resp(body=PRIVATE),
        anonymous=_Resp(status=401, body="Unauthorized"),
    )
    assert verdict.kind == Verdict.IDOR
    assert verdict.is_finding
    assert verdict.attacker_similarity >= SAME_CONTENT


def test_idor_survives_a_per_render_token_difference():
    owner = PRIVATE + '<input name="csrf" value="1111111111111111">'
    attacker = PRIVATE + '<input name="csrf" value="9999999999999999">'
    verdict = compare_access(_Resp(body=owner), _Resp(body=attacker),
                             _Resp(status=302))
    assert verdict.kind == Verdict.IDOR


def test_anonymous_access_to_a_named_private_resource_is_missing_auth():
    """Worse than IDOR, and reported as its own class - but only when the
    operator has asserted the path belongs to a specific user. On the wire, a
    public page and an unauthenticated endpoint are the same bytes."""
    verdict = compare_access(
        owner=_Resp(body=PRIVATE),
        attacker=_Resp(body=PRIVATE),
        anonymous=_Resp(body=PRIVATE),
        resource_is_private=True,
    )
    assert verdict.kind == Verdict.MISSING_AUTH
    assert verdict.is_finding


def test_the_same_responses_without_that_assertion_are_not_a_finding():
    verdict = compare_access(
        owner=_Resp(body=PRIVATE),
        attacker=_Resp(body=PRIVATE),
        anonymous=_Resp(body=PRIVATE),
    )
    assert verdict.kind == Verdict.NOT_PRIVATE
    assert not verdict.is_finding


def test_second_user_getting_their_own_data_is_not_a_finding():
    verdict = compare_access(_Resp(body=PRIVATE), _Resp(body=OTHER),
                             _Resp(status=401))
    assert verdict.kind == Verdict.OWNER_ONLY
    assert not verdict.is_finding


@pytest.mark.parametrize("status", [401, 403, 404, 302])
def test_refusing_the_second_user_is_not_a_finding(status):
    verdict = compare_access(_Resp(body=PRIVATE), _Resp(status=status, body=""),
                             _Resp(status=401))
    assert verdict.kind == Verdict.OWNER_ONLY


def test_missing_attacker_response_is_handled():
    verdict = compare_access(_Resp(body=PRIVATE), None, _Resp(status=401))
    assert verdict.kind == Verdict.OWNER_ONLY
    assert not verdict.is_finding


def test_comparison_without_an_anonymous_probe_still_reports_idor():
    """Callers may not have an anonymous baseline; the check still works, it
    just cannot rule out a public resource."""
    verdict = compare_access(_Resp(body=PRIVATE), _Resp(body=PRIVATE))
    assert verdict.kind == Verdict.IDOR


# ── identities ────────────────────────────────────────────────────────────────
def test_identity_headers_carry_cookie_and_bearer():
    identity = Identity("user-b", cookies="sid=bbb", auth_token="tok")
    headers = identity.request_headers()
    assert headers["Cookie"] == "sid=bbb"
    assert headers["Authorization"] == "Bearer tok"


def test_identity_does_not_double_prefix_a_full_scheme():
    identity = Identity("x", auth_token="Basic dXNlcg==")
    assert identity.request_headers()["Authorization"] == "Basic dXNlcg=="


def test_anonymous_identity_sends_nothing():
    assert Identity.anonymous().request_headers() == {}
    assert Identity.anonymous().is_anonymous


def test_explicit_header_beats_the_derived_one():
    identity = Identity("x", cookies="sid=aaa", headers={"Cookie": "sid=override"})
    assert identity.request_headers()["Cookie"] == "sid=override"


def test_request_as_replaces_rather_than_merges_the_session():
    """The owner's cookie must not ride along on the attacker's request."""
    captured = {}

    class _Client:
        def request(self, method, url, **kwargs):
            captured.update(kwargs)
            captured["method"] = method
            return _Resp()

    request_as(_Client(), Identity("user-b", cookies="sid=bbb"), "GET", "https://t/x")
    assert captured["anonymous"] is True          # engagement creds stripped first
    assert captured["headers"]["Cookie"] == "sid=bbb"


def test_identity_from_session_reads_configured_credentials():
    identity = Identity.from_session({
        "cookies": "sid=aaa", "auth_token": "tok", "headers": "X-Team: red",
    })
    headers = identity.request_headers()
    assert headers["Cookie"] == "sid=aaa"
    assert headers["X-Team"] == "red"
    assert not identity.is_anonymous
