"""
utils/liveness.py
YeepForge - noticing when the engagement's session has died.

A long scan outlives its cookie. When it does, every remaining request is
answered with a login page, every test finds nothing in it, and the run ends by
reporting the application clean. That is the worst failure mode a scanner has:
it is indistinguishable from a good result, and it gets more likely the longer
and more thorough the scan.

The check is cheap and specific. Once at the start, an authenticated request
establishes what being logged in looks like; from then on the engine samples
periodically and compares. When the samples start looking like a login page -
or like the same URL fetched with no credentials at all - the run is marked
degraded, the operator is told, and every finding recorded afterwards carries
that caveat rather than being quietly trusted.

Nothing here decides to stop the scan. An operator may legitimately continue
unauthenticated; what they must not do is read the results as if the session
had held.
"""
from __future__ import annotations

import threading
import time

from config.settings import SESSION
from utils.helpers import success, warn

__all__ = ["SessionMonitor", "get_monitor", "reset_monitor"]

#: Wording that means the response is an authentication wall rather than the
#: application. Matched only against a *short* prefix of the body: the word
#: "login" appears in the footer of half the internet.
LOGIN_WALL_MARKERS = (
    "please log in", "please sign in", "session expired", "session has expired",
    "your session", "log in to continue", "sign in to continue",
    "authentication required", "you must be logged in", "not authenticated",
    "login required", "re-authenticate",
)

#: Statuses that mean the credentials were not accepted.
UNAUTH_STATUSES = frozenset({401, 403})

#: Requests between liveness samples. Frequent enough to bound how much of a
#: scan can be wasted, rare enough not to add meaningful traffic.
DEFAULT_INTERVAL = 60


class SessionMonitor:
    """Tracks whether the engagement is still authenticated.

    `probe_url` is fetched with the engagement's credentials and, for the
    baseline, without them. The difference between those two responses is what
    "being logged in" means for this application; later samples are judged
    against it.
    """

    def __init__(self, probe_url: str = "", interval: int = DEFAULT_INTERVAL):
        self.probe_url = probe_url
        self.interval = interval
        self.baseline_status: int | None = None
        self.baseline_length: int | None = None
        self.anon_status: int | None = None
        self.anon_length: int | None = None
        self.established = False
        self.degraded = False
        self.degraded_reason = ""
        self.checked_at = 0.0
        self.requests_since_check = 0
        self._lock = threading.Lock()

    # ── baseline ─────────────────────────────────────────────────────────────
    def establish(self, client) -> bool:
        """Learn what an authenticated response looks like. Returns success.

        Returns False when the engagement has no credentials at all - there is
        no session to lose, so the whole check is skipped rather than warning
        about an expiry that cannot happen.
        """
        if not (SESSION.get("cookies") or SESSION.get("auth_token")
                or SESSION.get("headers")):
            return False
        probe = self.probe_url or SESSION.get("target_url", "")
        if not probe:
            return False
        self.probe_url = probe

        authed = client.safe_get(probe, timeout=10)
        if authed is None:
            return False
        anon = client.safe_get(probe, timeout=10, anonymous=True)

        self.baseline_status = authed.status_code
        self.baseline_length = len(authed.text or "")
        if anon is not None:
            self.anon_status = anon.status_code
            self.anon_length = len(anon.text or "")

        if not self._authenticated_differs():
            # The application answers identically with and without credentials,
            # so no later sample can tell the session apart from its absence.
            warn("Authenticated and unauthenticated requests to "
                 f"{probe} are indistinguishable - session expiry cannot be "
                 "detected on this target. Pick a probe URL that requires login.")
            return False

        self.established = True
        self.checked_at = time.monotonic()
        success(f"Session liveness baseline set on {probe} "
                f"(HTTP {self.baseline_status}, {self.baseline_length} bytes)")
        return True

    def _authenticated_differs(self) -> bool:
        if self.anon_status is None:
            return True                      # no anonymous sample; assume usable
        if self.anon_status != self.baseline_status:
            return True
        if self.baseline_length is None or self.anon_length is None:
            return True
        return abs(self.anon_length - self.baseline_length) > max(
            64, (self.baseline_length or 0) * 0.05)

    # ── sampling ─────────────────────────────────────────────────────────────
    def note_request(self) -> bool:
        """Count a request; True when a liveness sample is due."""
        with self._lock:
            if not self.established or self.degraded:
                return False
            self.requests_since_check += 1
            if self.requests_since_check < self.interval:
                return False
            self.requests_since_check = 0
            return True

    def looks_logged_out(self, response) -> str:
        """Why this response looks unauthenticated, or "" if it does not."""
        if response is None:
            return ""
        if response.status_code in UNAUTH_STATUSES:
            return f"HTTP {response.status_code}"
        # Only the head of the body: "login" in a page footer is not a wall.
        head = (response.text or "")[:1500].lower()
        marker = next((m for m in LOGIN_WALL_MARKERS if m in head), "")
        if marker:
            return f"the response says {marker!r}"
        if self.anon_status is not None and response.status_code == self.anon_status:
            if self.anon_length is not None and abs(
                    len(response.text or "") - self.anon_length) <= max(
                        64, self.anon_length * 0.05):
                return "the response matches what an unauthenticated caller receives"
        return ""

    def check(self, client) -> bool:
        """Sample the probe URL. Returns True while the session still holds."""
        if not self.established or self.degraded:
            return not self.degraded
        response = client.safe_get(self.probe_url, timeout=10)
        reason = self.looks_logged_out(response)
        if not reason:
            self.checked_at = time.monotonic()
            return True
        self.mark_degraded(reason)
        return False

    def mark_degraded(self, reason: str) -> None:
        if self.degraded:
            return
        self.degraded = True
        self.degraded_reason = reason
        SESSION["session_degraded"] = True
        SESSION["session_degraded_reason"] = reason
        warn("=" * 68)
        warn(f"SESSION LOST - {reason}.")
        warn("Everything tested from here on is being tested as an anonymous "
             "user. Findings recorded after this point are marked untrusted, and "
             "'nothing found' means nothing was reachable, not that the "
             "application is clean.")
        warn("Refresh the cookie or token and re-run to get a usable result.")
        warn("=" * 68)


# ── shared monitor ────────────────────────────────────────────────────────────
_monitor: SessionMonitor | None = None
_monitor_lock = threading.Lock()


def get_monitor() -> SessionMonitor:
    global _monitor
    if _monitor is None:
        with _monitor_lock:
            if _monitor is None:
                _monitor = SessionMonitor()
    return _monitor


def reset_monitor() -> None:
    global _monitor
    with _monitor_lock:
        _monitor = None
    SESSION.pop("session_degraded", None)
    SESSION.pop("session_degraded_reason", None)
