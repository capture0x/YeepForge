"""
utils/scope.py
YeepForge - engagement scope enforcement.

A pentest tool that wanders outside the authorised scope is a liability: on a
bug bounty program it gets the researcher banned, on a client engagement it is
unauthorised access. Every request YeepForge makes through `utils.http` is
checked here first.

Scope is written the way bounty programs publish it - one pattern per line (or
comma separated), `*` wildcards allowed, `!` prefix marks an explicit exclusion:

    *.example.com
    api.example.com
    203.0.113.10
    !admin.example.com
    !*.internal.example.com

Rules:
  * A URL is in scope when it matches at least one allow pattern AND no deny
    pattern. Deny always wins.
  * With no patterns configured, scope is *derived from the target* - the
    target host plus its subdomains. That is the conservative default: a tool
    pointed at one host should not silently start scanning another.
  * With neither scope nor target set, nothing is enforced (nothing to compare
    against) and `check()` reports it as unscoped rather than blocked.
"""
from __future__ import annotations

import fnmatch
import ipaddress
import os
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

__all__ = ["Scope", "ScopeViolation", "current_scope", "in_scope", "assert_in_scope", "host_of"]

_SPLIT_RE = re.compile(r"[,\s;]+")


class ScopeViolation(Exception):
    """Raised when a request would leave the authorised engagement scope."""

    def __init__(self, url: str, reason: str):
        self.url = url
        self.reason = reason
        super().__init__(f"out of scope: {url} - {reason}")


def host_of(url: str) -> str:
    """Hostname of a URL, lowercased, port and credentials stripped.

    Accepts bare hosts ('example.com', 'example.com:8080') as well as full URLs
    so scope patterns and targets can be written either way.
    """
    if not url:
        return ""
    raw = url.strip()
    if "//" not in raw:
        raw = "//" + raw
    try:
        parts = urlsplit(raw)
        return (parts.hostname or "").lower()
    except ValueError:
        # urlsplit rejects malformed IPv6 literals; treat as no host rather
        # than crashing a scan mid-flight.
        return ""


def _normalise(pattern: str) -> str:
    """Reduce a user-written scope entry to a matchable host pattern."""
    p = pattern.strip().strip('"').strip("'")
    if not p:
        return ""
    # Strip scheme/path/query so 'https://example.com/app?x=1' behaves like
    # 'example.com' - programs publish scope in both shapes.
    if "://" in p:
        p = host_of(p) or p
    else:
        p = p.split("/", 1)[0]
        # Keep '*.example.com' intact: host_of() would drop the wildcard label.
        if not p.startswith("*"):
            p = host_of(p) or p
    return p.lower().rstrip(".")


@dataclass
class Scope:
    allow: list[str] = field(default_factory=list)
    deny: list[str] = field(default_factory=list)
    #: When False, violations are reported but not blocked (audit mode).
    enforce: bool = True
    #: True when no explicit scope and no target were configured.
    unscoped: bool = False

    # ── construction ─────────────────────────────────────────────────────────
    @classmethod
    def parse(cls, raw: str | list | None, *, enforce: bool = True) -> "Scope":
        """Build a Scope from a raw scope string (or list of patterns)."""
        items: list[str] = []
        if isinstance(raw, str):
            items = [i for i in _SPLIT_RE.split(raw) if i]
        elif isinstance(raw, (list, tuple, set)):
            items = [str(i) for i in raw]

        allow, deny = [], []
        for item in items:
            negated = item.startswith("!")
            host = _normalise(item[1:] if negated else item)
            if not host:
                continue
            (deny if negated else allow).append(host)
        return cls(allow=allow, deny=deny, enforce=enforce)

    @classmethod
    def from_session(cls, session: dict) -> "Scope":
        """Derive the active scope from a YeepForge SESSION dict.

        Explicit `scope` wins. Otherwise the target host and its subdomains are
        used, so a plain `--target` run is still fenced in.
        """
        enforce = _enforce_default()
        scope = cls.parse(session.get("scope"), enforce=enforce)
        if scope.allow or scope.deny:
            return scope

        host = host_of(session.get("target_url") or session.get("target_host") or "")
        if host:
            return cls(allow=[host, f"*.{host}"], deny=[], enforce=enforce)

        ip = (session.get("target_ip") or "").strip()
        if ip:
            return cls(allow=[ip.lower()], deny=[], enforce=enforce)

        return cls(allow=[], deny=[], enforce=enforce, unscoped=True)

    # ── matching ─────────────────────────────────────────────────────────────
    def _matches(self, host: str, patterns: list[str]) -> str | None:
        for pat in patterns:
            if fnmatch.fnmatch(host, pat):
                return pat
            # '*.example.com' conventionally covers the apex in bounty scope
            # write-ups; honour that so users don't have to list both.
            if pat.startswith("*.") and host == pat[2:]:
                return pat
        return None

    def check(self, url: str) -> tuple[bool, str]:
        """Return (allowed, reason). `reason` explains a block or a pass."""
        host = host_of(url)
        if not host:
            return False, "no host in URL"

        denied = self._matches(host, self.deny)
        if denied:
            return False, f"host matches exclusion '{denied}'"

        if self.unscoped or (not self.allow and not self.deny):
            return True, "no scope configured (unrestricted)"

        allowed = self._matches(host, self.allow)
        if allowed:
            return True, f"matches '{allowed}'"

        # A bare IP target should still reach itself when scope was written as
        # a hostname that resolves elsewhere - but we do NOT resolve DNS here:
        # resolution is attacker-controlled and would let a rebind slip through.
        if _is_ip(host) and host in self.allow:
            return True, "explicit IP in scope"

        return False, f"host '{host}' not in scope ({', '.join(self.allow) or 'empty'})"

    def allows(self, url: str) -> bool:
        return self.check(url)[0]

    def describe(self) -> str:
        if self.unscoped:
            return "unrestricted (no target or scope set)"
        parts = []
        if self.allow:
            parts.append("allow: " + ", ".join(self.allow))
        if self.deny:
            parts.append("deny: " + ", ".join(self.deny))
        mode = "enforced" if self.enforce else "audit-only"
        return f"{'; '.join(parts) or 'empty'} [{mode}]"


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _enforce_default() -> bool:
    """Scope is enforced unless the operator explicitly opts out.

    `YEEPFORGE_SCOPE=audit` (or `off`) downgrades violations to warnings, for
    the rare case of a legitimately multi-host engagement that hasn't been
    written into the scope yet.
    """
    return os.environ.get("YEEPFORGE_SCOPE", "").strip().lower() not in ("audit", "off", "0", "false")


def current_scope(session: dict | None = None) -> Scope:
    """Active scope for the running engagement."""
    if session is None:
        from config.settings import SESSION as session  # local import: avoids cycle
    return Scope.from_session(session)


def in_scope(url: str, session: dict | None = None) -> bool:
    return current_scope(session).allows(url)


def assert_in_scope(url: str, session: dict | None = None) -> None:
    """Raise ScopeViolation if `url` is outside the engagement scope.

    In audit mode the violation is printed instead of raised.
    """
    scope = current_scope(session)
    ok, reason = scope.check(url)
    if ok:
        return
    if not scope.enforce:
        from utils.helpers import warn
        warn(f"SCOPE (audit): {url} - {reason}")
        return
    raise ScopeViolation(url, reason)
