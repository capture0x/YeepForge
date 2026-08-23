"""
utils/identity.py
YeepForge - replaying one request as several users.

Access-control bugs are the most commonly paid class in bug bounty, and none of
them can be found with a single session. The question is always comparative:
*this* response is what the owner sees - does a different user get it too? Does
someone with no session at all?

YeepForge could only ask the first half. Its IDOR check sent one request with
one cookie jar and reported a finding when the answer was HTTP 200 - which it
also is when the endpoint is public, when it returns an empty list, and when it
renders a login page with status 200.

An Identity is one set of credentials. `request_as` sends a request carrying
exactly that identity and nothing else: the engagement's own session is not
merged in, because a test that accidentally sends the owner's cookie alongside
the attacker's proves nothing.

    victim   = Identity("victim",   cookies="sid=aaa")
    attacker = Identity("attacker", cookies="sid=bbb")
    anon     = Identity.anonymous()

    a = request_as(client, victim,   "GET", url)
    b = request_as(client, attacker, "GET", url)
"""
from __future__ import annotations

from dataclasses import dataclass, field

__all__ = ["Identity", "request_as"]


@dataclass
class Identity:
    """One user's credentials, as they go on the wire."""

    name: str
    cookies: str = ""
    auth_token: str = ""
    headers: dict[str, str] = field(default_factory=dict)

    @classmethod
    def anonymous(cls) -> "Identity":
        """A caller with no credentials at all."""
        return cls(name="anonymous")

    @classmethod
    def from_session(cls, session: dict, name: str = "session") -> "Identity":
        """The engagement's own configured identity."""
        raw = session.get("headers") or ""
        headers: dict[str, str] = {}
        if isinstance(raw, dict):
            headers = {str(k): str(v) for k, v in raw.items()}
        elif isinstance(raw, str) and raw.strip():
            from utils.http import _parse_header_string
            headers = _parse_header_string(raw)
        return cls(
            name=name,
            cookies=(session.get("cookies") or "").strip(),
            auth_token=(session.get("auth_token") or "").strip(),
            headers=headers,
        )

    @property
    def is_anonymous(self) -> bool:
        return not (self.cookies or self.auth_token or self.headers)

    def request_headers(self) -> dict[str, str]:
        """Exactly the headers this identity sends."""
        out = dict(self.headers)
        if self.auth_token and "Authorization" not in out:
            out["Authorization"] = (self.auth_token if " " in self.auth_token
                                    else f"Bearer {self.auth_token}")
        if self.cookies and "Cookie" not in out:
            out["Cookie"] = self.cookies
        return out

    def describe(self) -> str:
        if self.is_anonymous:
            return f"{self.name} (no credentials)"
        carried = []
        if self.cookies:
            carried.append("cookie")
        if self.auth_token:
            carried.append("token")
        if self.headers:
            carried.append(f"{len(self.headers)} header(s)")
        return f"{self.name} ({', '.join(carried)})"


def request_as(client, identity: Identity, method: str, url: str, **kwargs):
    """Send one request carrying `identity` and no other credentials.

    anonymous=True strips the engagement's own cookies, token and headers; the
    identity's headers are then layered on. Without that first step the shared
    session's cookie rides along and every identity looks like the operator.
    """
    headers = dict(kwargs.pop("headers", None) or {})
    headers.update(identity.request_headers())
    return client.request(method, url, headers=headers, anonymous=True, **kwargs)
