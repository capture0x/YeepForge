"""
utils/differential.py
YeepForge - deciding whether two users got the same answer.

This is the whole of access-control testing, and the reason it is a module of
its own is that the naive version produces nothing but false positives. HTTP
200 for the attacker is not a finding: the endpoint may be public, it may
return an empty list to everyone, it may render a login page with status 200.
Byte-equal responses are not a finding either, because a page containing a CSRF
token or a timestamp is never byte-equal to itself.

Three responses decide it:

    owner      the resource's owner - what the private data looks like
    attacker   a different authenticated user asking for the same thing
    anonymous  no credentials at all

and the rule is:

  * if `anonymous` already sees what `owner` sees, the content is not private
    and nothing here is an access-control finding - this is the check that
    keeps a public marketing page out of the report;
  * otherwise, if `attacker` sees what `owner` sees, the attacker is reading
    another user's data;
  * if `anonymous` sees it and `owner` does too, authentication is missing
    outright, which is worse and reported as such.

Similarity is measured after normalising away the parts of a page that change
on every render.
"""
from __future__ import annotations

import difflib
import re

__all__ = ["Verdict", "compare_access", "normalise", "similarity"]

#: Values that differ between two renders of the same page and say nothing
#: about who is authorised to see it.
_VOLATILE = [
    (re.compile(r'name=["\'][^"\']*(?:csrf|xsrf|_token|authenticity)[^"\']*["\']'
                r'[^>]*value=["\'][^"\']*["\']', re.I), "CSRF"),
    (re.compile(r'\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2})?\b'), "TIMESTAMP"),
    (re.compile(r'\b\d{10,13}\b'), "EPOCH"),
    (re.compile(r'\b[0-9a-f]{32,64}\b', re.I), "HEX"),
    (re.compile(r'nonce=["\'][^"\']+["\']', re.I), "NONCE"),
    (re.compile(r'\s+'), " "),
]

#: A body this short carries no evidence either way - an empty list, a bare
#: "null", a 1-byte response. Treating two of them as "the same private data"
#: is how an endpoint that tells everyone nothing becomes a Critical finding.
MIN_MEANINGFUL_BODY = 32

#: Above this, two normalised bodies are the same content.
SAME_CONTENT = 0.95


def normalise(body: str) -> str:
    """Strip the per-render noise so two views of one page compare equal."""
    text = body or ""
    for pattern, label in _VOLATILE:
        text = pattern.sub(label, text)
    return text.strip()


def similarity(a: str, b: str) -> float:
    """0.0-1.0 similarity of two response bodies after normalisation."""
    left, right = normalise(a), normalise(b)
    if not left and not right:
        return 1.0
    if not left or not right:
        return 0.0
    # Long pages make difflib expensive and the extra precision is not useful.
    return difflib.SequenceMatcher(None, left[:20000], right[:20000]).ratio()


class Verdict:
    """The outcome of one access-control comparison."""

    NOT_PRIVATE = "not-private"
    OWNER_ONLY = "owner-only"
    IDOR = "idor"
    MISSING_AUTH = "missing-auth"
    INCONCLUSIVE = "inconclusive"

    def __init__(self, kind: str, detail: str, attacker_similarity: float = 0.0,
                 anon_similarity: float = 0.0):
        self.kind = kind
        self.detail = detail
        self.attacker_similarity = attacker_similarity
        self.anon_similarity = anon_similarity

    @property
    def is_finding(self) -> bool:
        return self.kind in (self.IDOR, self.MISSING_AUTH)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Verdict {self.kind}: {self.detail}>"


def _ok(response) -> bool:
    return response is not None and 200 <= response.status_code < 300


def compare_access(owner, attacker, anonymous=None,
                   resource_is_private: bool = False) -> Verdict:
    """Decide what the attacker's access to the owner's resource means.

    `owner`, `attacker` and `anonymous` are responses to the same request made
    under different identities. `anonymous` is optional but strongly advised:
    without it, a public endpoint is indistinguishable from a broken one.

    `resource_is_private` is the one thing the comparison cannot derive. When
    an unauthenticated caller receives the same bytes as the owner, that is
    either a public page or an endpoint with no authentication, and the two are
    identical on the wire. Only the operator knows which: they named this path
    as belonging to a specific user. Left False, the ambiguous case is reported
    as "not private" - the conservative reading, since inventing a Critical out
    of a marketing page is the worse error.
    """
    if not _ok(owner):
        status = "no response" if owner is None else f"HTTP {owner.status_code}"
        return Verdict(Verdict.INCONCLUSIVE,
                       f"The owner could not read the resource either ({status}); "
                       "the request or the session is wrong, so nothing can be "
                       "concluded about the attacker's access.")

    owner_body = owner.text or ""
    if len(normalise(owner_body)) < MIN_MEANINGFUL_BODY:
        return Verdict(Verdict.INCONCLUSIVE,
                       f"The owner's response carries only {len(owner_body)} bytes - "
                       "too little to tell private data from an empty result.")

    anon_sim = 0.0
    if anonymous is not None and _ok(anonymous):
        anon_sim = similarity(owner_body, anonymous.text or "")
        if anon_sim >= SAME_CONTENT:
            # Checked first and on purpose: everything below would otherwise
            # report a public page as an access-control failure.
            if resource_is_private:
                return Verdict(
                    Verdict.MISSING_AUTH,
                    f"An unauthenticated request returns the owner's content "
                    f"({anon_sim:.0%} similar). The path was identified as belonging "
                    "to a specific user, so the endpoint enforces no authentication "
                    "at all - a stronger finding than a broken ownership check.",
                    anon_similarity=anon_sim)
            return Verdict(
                Verdict.NOT_PRIVATE,
                f"An unauthenticated request returns the same content as the owner "
                f"({anon_sim:.0%} similar), so this resource is public and access "
                "control is not being bypassed.",
                anon_similarity=anon_sim)

    if not _ok(attacker):
        status = "no response" if attacker is None else f"HTTP {attacker.status_code}"
        return Verdict(Verdict.OWNER_ONLY,
                       f"The second user is refused ({status}) while the owner is "
                       "served - access control holds for this resource.",
                       anon_similarity=anon_sim)

    attacker_sim = similarity(owner_body, attacker.text or "")
    if attacker_sim >= SAME_CONTENT:
        # An anonymous caller seeing the same content was already handled above;
        # reaching here means they did not, so authentication is enforced and
        # only the ownership check is missing.
        return Verdict(
            Verdict.IDOR,
            f"A second authenticated user receives the owner's resource "
            f"({attacker_sim:.0%} identical after normalising per-render values), "
            "while an unauthenticated caller does not - the object is protected by "
            "authentication but not by authorisation.",
            attacker_similarity=attacker_sim, anon_similarity=anon_sim)

    return Verdict(
        Verdict.OWNER_ONLY,
        f"The second user is served a different response ({attacker_sim:.0%} similar "
        "to the owner's) - most likely their own data, not the owner's.",
        attacker_similarity=attacker_sim, anon_similarity=anon_sim)
