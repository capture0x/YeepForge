"""Tests for the out-of-band collaborator.

Blind SSRF, blind XXE and blind command injection have no in-band evidence, so
the collaborator is the only thing standing between "confirmed" and "guessed".
These tests pin the parts that decide that: tag correlation, the interactsh
startup handshake, and the rule that silence is never reported as safety.

No test starts interactsh or binds a socket.
"""
import json

import pytest

from utils import oob as oob_mod
from utils.oob import Collaborator


@pytest.fixture(autouse=True)
def _clean_collaborator():
    oob_mod.reset_collaborator()
    yield
    oob_mod.reset_collaborator()


def _collab(interactions=None):
    c = Collaborator("abc123def456ghi.oast.fun", "interactsh")
    c._interactions = list(interactions or [])
    return c


# ── payload construction ──────────────────────────────────────────────────────
def test_tag_becomes_a_subdomain_not_a_path():
    """DNS-only exfiltration never sends a path, so the tag must be in the host."""
    c = _collab()
    assert c.hostname("ssrf-1") == "ssrf-1.abc123def456ghi.oast.fun"
    assert c.url("ssrf-1") == "http://ssrf-1.abc123def456ghi.oast.fun/"


def test_tag_is_sanitised_into_a_legal_hostname_label():
    c = _collab()
    assert c.hostname("XXE Direct/1") == "xxe-direct-1.abc123def456ghi.oast.fun"


def test_empty_tag_still_produces_a_usable_host():
    c = _collab()
    assert c.hostname("!!!").startswith("probe.")


def test_https_url_scheme_is_selectable():
    assert _collab().url("t", scheme="https").startswith("https://")


# ── correlation ───────────────────────────────────────────────────────────────
def test_hits_are_filtered_to_the_requesting_tag():
    c = _collab([
        {"protocol": "dns", "full-id": "ssrf-1.abc123def456ghi"},
        {"protocol": "http", "full-id": "xxe-direct.abc123def456ghi"},
    ])
    assert len(c.hits("ssrf-1")) == 1
    assert c.hits("ssrf-1")[0]["protocol"] == "dns"
    assert len(c.hits("xxe-direct")) == 1
    assert c.hits() == c._interactions


def test_unrelated_callback_does_not_confirm_a_tag():
    """Another researcher's traffic on a shared domain must not become evidence."""
    c = _collab([{"protocol": "http", "full-id": "somethingelse.abc123def456ghi"}])
    assert c.hits("ssrf-1") == []


def test_wait_for_returns_empty_rather_than_blocking_forever():
    c = _collab()
    assert c.wait_for("never", timeout=0.1) == []


def test_wait_for_returns_the_matching_interaction():
    c = _collab([{"protocol": "dns", "full-id": "cmdi-curl-semi.abc123def456ghi"}])
    assert len(c.wait_for("cmdi-curl-semi", timeout=0.1)) == 1


# ── interactsh startup ────────────────────────────────────────────────────────
class _FakeStdout:
    def __init__(self, lines):
        self._lines = list(lines)

    def readline(self):
        return self._lines.pop(0) if self._lines else ""

    def __iter__(self):
        return iter([])


class _FakeProcess:
    def __init__(self, lines):
        self.stdout = _FakeStdout(lines)
        self.terminated = False

    def terminate(self):
        self.terminated = True

    def wait(self, timeout=None):
        return 0

    def kill(self):
        pass


def test_interactsh_domain_is_read_from_the_startup_banner(monkeypatch):
    banner = [
        "[INF] Current interactsh-client version v1.2.0\n",
        "[INF] Listing 1 payload for OOB Testing\n",
        "[INF] c8rj2p9mn4kd7xw1qe5t.oast.fun\n",
    ]
    monkeypatch.setattr(oob_mod.shutil, "which", lambda _: "/usr/bin/interactsh-client")
    monkeypatch.setattr(oob_mod.subprocess, "Popen",
                        lambda *a, **kw: _FakeProcess(banner))

    collaborator = oob_mod._start_interactsh()
    assert collaborator is not None
    assert collaborator.domain == "c8rj2p9mn4kd7xw1qe5t.oast.fun"
    assert collaborator.kind == "interactsh"


def test_interactsh_without_a_domain_is_not_used(monkeypatch):
    """A client that starts but never registers must not silently produce payloads
    pointing at a domain nobody is listening on."""
    monkeypatch.setattr(oob_mod.shutil, "which", lambda _: "/usr/bin/interactsh-client")
    process = _FakeProcess(["[ERR] could not reach the interactsh server\n"])
    monkeypatch.setattr(oob_mod.subprocess, "Popen", lambda *a, **kw: process)
    monkeypatch.setattr(oob_mod, "_STARTUP_TIMEOUT", 0.5)

    assert oob_mod._start_interactsh() is None
    assert process.terminated


def test_missing_interactsh_binary_is_not_an_error(monkeypatch):
    monkeypatch.setattr(oob_mod.shutil, "which", lambda _: None)
    assert oob_mod._start_interactsh() is None


def test_get_collaborator_falls_back_to_the_local_listener(monkeypatch):
    monkeypatch.setattr(oob_mod, "_start_interactsh", lambda: None)
    monkeypatch.setattr(oob_mod, "_start_local",
                        lambda: Collaborator("10.0.0.5:8877", "local"))

    collaborator = oob_mod.get_collaborator()
    assert collaborator.kind == "local"
    # Payload builders read the domain off the session.
    from config.settings import SESSION
    assert SESSION["oob_domain"] == "10.0.0.5:8877"


def test_get_collaborator_is_shared_across_calls(monkeypatch):
    monkeypatch.setattr(oob_mod, "_start_interactsh",
                        lambda: Collaborator("x1y2z3.oast.fun", "interactsh"))
    assert oob_mod.get_collaborator() is oob_mod.get_collaborator()


def test_no_collaborator_available_returns_none(monkeypatch):
    monkeypatch.setattr(oob_mod, "_start_interactsh", lambda: None)
    monkeypatch.setattr(oob_mod, "_start_local", lambda: None)
    assert oob_mod.get_collaborator(required=True) is None


# ── describe() must not oversell a local listener ─────────────────────────────
def test_local_collaborator_describes_its_limitation():
    text = Collaborator("192.168.1.10:8877", "local").describe()
    assert "route back" in text


def test_interactsh_collaborator_mentions_dns():
    assert "DNS" in _collab().describe()


# ── the drain loop ────────────────────────────────────────────────────────────
def test_non_json_banner_lines_are_ignored_by_the_reader():
    c = Collaborator("abc123def456ghi.oast.fun", "interactsh")
    lines = [
        "[INF] some banner text\n",
        json.dumps({"protocol": "dns", "full-id": "ssrf-1.abc123def456ghi"}) + "\n",
        "not json at all\n",
    ]

    class _P:
        stdout = iter(lines)

    c._process = _P()
    c._drain()
    assert len(c._interactions) == 1
    assert c._interactions[0]["protocol"] == "dns"
