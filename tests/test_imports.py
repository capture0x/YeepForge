"""Smoke test: every module and entry point imports without error.

Catches syntax errors, broken imports, and top-level exceptions across the whole
codebase - the cheapest regression net for a 13k-line tool.
"""
import importlib
import os

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_MODULES_DIR = os.path.join(_ROOT, "modules")

_MODULE_NAMES = sorted(
    f[:-3]
    for f in os.listdir(_MODULES_DIR)
    if f.endswith(".py") and f != "__init__.py"
)


@pytest.mark.parametrize("name", _MODULE_NAMES)
def test_module_imports(name):
    importlib.import_module(f"modules.{name}")


def test_agent_package_imports():
    for sub in ("_core", "backends", "knowledge", "logger", "constants"):
        importlib.import_module(f"modules.agent.{sub}")


def test_entrypoints_import():
    import main  # noqa: F401
    import mcp_server  # noqa: F401


def test_main_has_callable_entry():
    import main

    assert callable(main.main)


def test_config_imports():
    from config import settings

    assert hasattr(settings, "SESSION")
    assert hasattr(settings, "save_session")
