"""
utils/oob.py
YeepForge - the out-of-band collaborator every blind check shares.

The highest-paying bug classes are the ones with no in-band evidence: blind
SSRF, blind XXE, blind command injection, deserialisation, Log4Shell. Each is
confirmed the same way - put a unique hostname in the payload and see whether
the target contacts it - and none of them can be confirmed by a listener bound
to a machine behind NAT, which is what YeepForge shipped.

This module hands every check one collaborator:

    from utils.oob import get_collaborator

    oob = get_collaborator()
    if oob:
        url = oob.url("ssrf-1")          # http://ssrf-1.abc123.oast.fun
        client.get(target, params={"u": url})
        if oob.wait_for("ssrf-1", timeout=20):
            ...confirmed

interactsh is used when `interactsh-client` is installed: it is publicly
resolvable, it records DNS lookups as well as HTTP requests (so a payload that
only resolves a name still registers), and it needs no port forwarding. When it
is absent, the local listener in modules.oob_server is used instead and the
caller is told the limitation rather than being handed a silent false negative.

Correlation is by subdomain, not by path: a target that resolves the hostname
without fetching it still produces a DNS interaction carrying the tag.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import threading
import time

from config.settings import SESSION
from utils.helpers import info, success, warn

__all__ = ["Collaborator", "get_collaborator", "reset_collaborator", "stop_collaborator"]

#: interactsh hands out a hostname on one of these domains at startup.
_DOMAIN_RE = re.compile(
    r"\b([a-z0-9]{15,40}\.oast\.(?:fun|site|pro|live|online|me|network))\b", re.I)

#: How long to wait for interactsh-client to announce its domain.
_STARTUP_TIMEOUT = 20.0

#: interactsh polls its server on an interval; a callback is not visible the
#: instant the target makes it.
_POLL_INTERVAL = 5.0


class Collaborator:
    """A public (or local) endpoint that records who contacted it.

    `kind` is "interactsh" for the public service and "local" for the built-in
    listener. Callers should treat a local collaborator as best-effort: it only
    sees callbacks from targets that can route back to this host.
    """

    def __init__(self, domain: str, kind: str, process: subprocess.Popen | None = None,
                 log_path: str = ""):
        self.domain = domain
        self.kind = kind
        self._process = process
        self._log_path = log_path
        self._interactions: list[dict] = []
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._reader: threading.Thread | None = None
        if process is not None:
            self._reader = threading.Thread(target=self._drain, daemon=True)
            self._reader.start()

    # ── payload construction ─────────────────────────────────────────────────
    def hostname(self, tag: str) -> str:
        """Hostname carrying `tag`, for payloads that take a bare host."""
        safe = re.sub(r"[^a-z0-9-]", "-", tag.lower()).strip("-") or "probe"
        return f"{safe}.{self.domain}"

    def url(self, tag: str, scheme: str = "http") -> str:
        """Full URL carrying `tag`, for payloads that take a URL."""
        return f"{scheme}://{self.hostname(tag)}/"

    # ── reading callbacks ────────────────────────────────────────────────────
    def _drain(self) -> None:
        """Collect interactions from interactsh-client's JSON output."""
        assert self._process is not None
        stream = self._process.stdout
        if stream is None:
            return
        for line in stream:
            if self._stop.is_set():
                return
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                event = json.loads(line)
            except ValueError:
                continue
            with self._lock:
                self._interactions.append(event)
            proto = event.get("protocol", "?")
            origin = event.get("remote-address", "?")
            host = event.get("full-id") or event.get("unique-id") or ""
            success(f"[OOB HIT] {proto.upper()} from {origin} → {host}")

    def _local_interactions(self) -> list[dict]:
        from modules.oob_server import _HIT_LOG
        return [{"protocol": "http", "full-id": h.get("path", ""),
                 "remote-address": h.get("client", ""), "timestamp": h.get("time", ""),
                 "raw-request": json.dumps(h.get("headers", {}))} for h in _HIT_LOG]

    def hits(self, tag: str | None = None) -> list[dict]:
        """Interactions recorded so far, optionally filtered to one tag."""
        if self.kind == "local":
            events = self._local_interactions()
        else:
            with self._lock:
                events = list(self._interactions)
        if tag is None:
            return events
        needle = self.hostname(tag).split(".")[0]
        return [e for e in events
                if needle in (e.get("full-id") or "")
                or needle in (e.get("raw-request") or "")]

    def wait_for(self, tag: str, timeout: float = 30.0) -> list[dict]:
        """Block until `tag` is contacted, or the timeout expires.

        Returns the matching interactions - an empty list means no callback was
        observed, which is *not* the same as the target being safe: a firewalled
        egress path produces the same silence.
        """
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            found = self.hits(tag)
            if found:
                return found
            time.sleep(1.0)
        return []

    def describe(self) -> str:
        if self.kind == "interactsh":
            return f"interactsh ({self.domain}) - public, records DNS and HTTP"
        return (f"local listener ({self.domain}) - only reachable if the target can "
                "route back to this host")

    def stop(self) -> None:
        self._stop.set()
        if self._process is not None:
            self._process.terminate()
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()
            self._process = None


# ── construction ──────────────────────────────────────────────────────────────
_collaborator: Collaborator | None = None
_collab_lock = threading.Lock()


def _start_interactsh() -> Collaborator | None:
    """Launch interactsh-client and read the domain it is assigned."""
    if not shutil.which("interactsh-client"):
        return None

    # -json puts one interaction per line on stdout; -v keeps the banner that
    # carries the assigned domain.
    argv = ["interactsh-client", "-json", "-v"]
    server = (SESSION.get("interactsh_server") or "").strip()
    if server:
        argv += ["-server", server]
    token = (os.environ.get("INTERACTSH_TOKEN") or "").strip()
    if token:
        argv += ["-token", token]

    try:
        process = subprocess.Popen(
            argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1,
        )
    except OSError as exc:
        warn(f"Could not start interactsh-client: {exc}")
        return None

    # The domain appears in the startup banner. Read until we see it, so the
    # first payload built cannot reference a domain that was never assigned.
    domain = ""
    deadline = time.monotonic() + _STARTUP_TIMEOUT
    banner: list[str] = []
    while time.monotonic() < deadline and process.stdout is not None:
        line = process.stdout.readline()
        if not line:
            break
        banner.append(line)
        match = _DOMAIN_RE.search(line)
        if match:
            domain = match.group(1)
            break

    if not domain:
        warn("interactsh-client started but never announced a domain; "
             + ("".join(banner[-3:]).strip() or "no output"))
        process.terminate()
        return None

    success(f"interactsh collaborator ready: {domain}")
    return Collaborator(domain, "interactsh", process)


def _start_local() -> Collaborator | None:
    from modules.oob_server import _get_local_ip, start_server
    try:
        ip, port = start_server()
    except OSError as exc:
        warn(f"Could not start the local OOB listener: {exc}")
        return None
    if ip in ("127.0.0.1", "::1"):
        warn("The local listener is only bound to loopback - no external target "
             "can reach it, so blind findings cannot be confirmed.")
    else:
        warn(f"Using the local listener on {ip}:{port}. It only sees callbacks from "
             "targets that can route back here, and it records HTTP only - a payload "
             "that merely resolves the name will not register. Install "
             "interactsh-client for reliable results.")
    _ = _get_local_ip
    return Collaborator(f"{ip}:{port}", "local")


def get_collaborator(required: bool = False) -> Collaborator | None:
    """The shared collaborator, starting one on first use.

    With `required`, a failure to start any collaborator is announced loudly -
    the caller is about to run a check whose only possible evidence is a
    callback, and should say so rather than reporting "not vulnerable".
    """
    global _collaborator
    if _collaborator is not None:
        return _collaborator

    with _collab_lock:
        if _collaborator is not None:
            return _collaborator
        collaborator = _start_interactsh()
        if collaborator is None:
            info("interactsh-client not available - falling back to the local listener. "
                 "Install: go install -v "
                 "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest")
            collaborator = _start_local()
        if collaborator is None:
            if required:
                warn("No OOB collaborator could be started. Blind checks cannot be "
                     "confirmed; their results are UNTESTED, not clean.")
            return None
        _collaborator = collaborator

    SESSION["oob_domain"] = _collaborator.domain
    SESSION["oob_kind"] = _collaborator.kind
    info(f"OOB collaborator: {_collaborator.describe()}")
    info(f"Callbacks are polled every ~{int(_POLL_INTERVAL)}s; allow that long "
         "before treating silence as a negative.")
    return _collaborator


def stop_collaborator() -> None:
    global _collaborator
    with _collab_lock:
        if _collaborator is not None:
            _collaborator.stop()
            _collaborator = None
    SESSION.pop("oob_domain", None)
    SESSION.pop("oob_kind", None)


def reset_collaborator() -> None:
    """Drop the shared collaborator without stopping it (for tests)."""
    global _collaborator
    with _collab_lock:
        _collaborator = None
