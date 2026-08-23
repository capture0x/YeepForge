"""Unit tests for the MCP server's pure logic: URL/host handling, engagement
state, and the input-sanitization layer that injects the session target into
tool calls. No network, no subprocesses.
"""
import pytest

import mcp_server
from config.settings import SESSION


@pytest.fixture(autouse=True)
def _isolate_session(monkeypatch):
    """Snapshot SESSION and stub disk writes so tests don't touch state/files."""
    snapshot = dict(SESSION)
    monkeypatch.setattr(mcp_server, "save_session", lambda *a, **k: None)
    yield
    SESSION.clear()
    SESSION.update(snapshot)


def test_host_of_strips_scheme_and_path():
    assert mcp_server._host_of("https://app.example.com/login?x=1") == "app.example.com"
    assert mcp_server._host_of("http://10.0.0.5:8080/") == "10.0.0.5:8080"
    assert mcp_server._host_of("") == ""


def test_set_engagement_requires_target():
    out = mcp_server._set_engagement({"target_url": ""})
    assert "rejected" in out.lower()


def test_set_engagement_adds_scheme_and_host():
    out = mcp_server._set_engagement({"target_url": "example.com"})
    assert SESSION["target_url"] == "https://example.com"
    assert SESSION["target_host"] == "example.com"
    assert "Engagement set" in out


def test_set_engagement_stores_auth_context():
    mcp_server._set_engagement(
        {"target_url": "https://a.com", "cookies": "sid=1", "proxy": "http://127.0.0.1:8080"}
    )
    assert SESSION["cookies"] == "sid=1"
    assert SESSION["proxy"] == "http://127.0.0.1:8080"


def test_switching_host_clears_previous_findings():
    mcp_server._set_engagement({"target_url": "https://old.com"})
    SESSION["findings"] = [{"title": "stale"}]
    SESSION["endpoints"] = ["/old"]
    out = mcp_server._set_engagement({"target_url": "https://new.com"})
    assert SESSION["findings"] == []
    assert SESSION["endpoints"] == []
    assert "cleared" in out.lower()


def test_same_host_keeps_findings():
    mcp_server._set_engagement({"target_url": "https://keep.com/a"})
    SESSION["findings"] = [{"title": "real"}]
    mcp_server._set_engagement({"target_url": "https://keep.com/b"})
    assert SESSION["findings"] == [{"title": "real"}]


def test_sanitize_injects_session_url():
    mcp_server._set_engagement({"target_url": "https://t.com"})
    # A url-based tool called with no url should inherit the session target.
    name = next(
        (t["name"] for t in mcp_server.TOOLS if "url" in t["input_schema"].get("properties", {})),
        None,
    )
    if name is None:
        pytest.skip("no url-based tool in registry")
    clean = mcp_server._sanitize_tool_inputs(name, {})
    assert clean.get("url") == "https://t.com"


def test_sanitize_drops_undeclared_keys():
    name = mcp_server.TOOLS[0]["name"]
    clean = mcp_server._sanitize_tool_inputs(name, {"totally_bogus_key": "x"})
    assert "totally_bogus_key" not in clean
