"""Shared pytest fixtures/paths. Ensures the repo root is importable so tests
run from anywhere (e.g. `pytest` in CI) without installing the package first."""
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
