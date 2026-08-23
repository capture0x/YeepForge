#!/bin/bash
# YeepForge - Quick launcher
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

# Load .env if present
[ -f .env ] && export $(grep -v '^#' .env | xargs) 2>/dev/null

# Prefer the project venv (its Playwright driver + deps are known-good); fall
# back to system python3 only if the venv is missing.
PY="$DIR/venv/bin/python3"
[ -x "$PY" ] || PY="python3"

exec "$PY" "$DIR/main.py" "$@"
