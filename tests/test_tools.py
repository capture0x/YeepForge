"""Validate the agent tool registry (TOOLS / TOOL_MAP) - the single source of
truth the standalone agent and the MCP server both consume.

A malformed schema or a name that exists in one table but not the other breaks
tool dispatch silently, so guard the invariants explicitly.
"""
from modules.agent._core import TOOL_MAP, TOOLS


def test_tables_are_nonempty():
    assert TOOLS, "TOOLS registry is empty"
    assert TOOL_MAP, "TOOL_MAP registry is empty"


def test_names_match_between_tables():
    tool_names = {t["name"] for t in TOOLS}
    assert tool_names == set(TOOL_MAP), (
        "TOOLS and TOOL_MAP disagree: "
        f"only in TOOLS={tool_names - set(TOOL_MAP)}, "
        f"only in TOOL_MAP={set(TOOL_MAP) - tool_names}"
    )


def test_tool_names_unique():
    names = [t["name"] for t in TOOLS]
    assert len(names) == len(set(names)), "duplicate tool name in TOOLS"


def test_every_tool_has_required_fields():
    for t in TOOLS:
        assert t.get("name"), f"tool missing name: {t}"
        assert t.get("description"), f"{t['name']} missing description"
        assert "input_schema" in t, f"{t['name']} missing input_schema"


def test_input_schemas_are_valid_json_schema_shape():
    for t in TOOLS:
        schema = t["input_schema"]
        assert schema.get("type") == "object", f"{t['name']} schema not an object"
        assert isinstance(schema.get("properties", {}), dict)
        # Every declared required key must exist in properties.
        props = schema.get("properties", {})
        for req in schema.get("required", []):
            assert req in props, f"{t['name']} requires undeclared prop '{req}'"


def test_handlers_are_callable():
    for name, handler in TOOL_MAP.items():
        assert callable(handler), f"handler for {name} is not callable"
