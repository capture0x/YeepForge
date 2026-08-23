"""
config/settings.py
YeepForge - Session, Config & Target Management
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

BASE_DIR     = Path(__file__).parent.parent
ENV_FILE     = BASE_DIR / ".env"
SESSION_FILE = BASE_DIR / "output" / "session.json"
OUTPUT_DIR   = BASE_DIR / "output"
REPORTS_DIR  = BASE_DIR / "reports"
OUTPUT_DIR.mkdir(exist_ok=True)
REPORTS_DIR.mkdir(exist_ok=True)

def load_env(path: Path = ENV_FILE) -> dict:
    env = {}
    if not path.exists():
        return env
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, _, val = line.partition("=")
                env[key.strip()] = val.strip().strip('"').strip("'")
    return env

_ENV = load_env()

SESSION: dict = {
    "target_url":     _ENV.get("TARGET_URL", ""),
    "target_ip":      _ENV.get("TARGET_IP", ""),
    "target_host":    _ENV.get("TARGET_HOST", ""),
    "scope":          _ENV.get("SCOPE", ""),
    "cookies":        _ENV.get("COOKIES", ""),
    "headers":        _ENV.get("HEADERS", ""),
    "auth_token":     _ENV.get("AUTH_TOKEN", ""),
    "username":       _ENV.get("WEB_USERNAME", ""),
    "password":       _ENV.get("WEB_PASSWORD", ""),
    "proxy":          _ENV.get("PROXY", ""),
    "engagement":     _ENV.get("ENGAGEMENT_NAME", ""),
    "output_dir":     _ENV.get("OUTPUT_DIR", str(OUTPUT_DIR)),
    "start_time":     datetime.now().isoformat(),
    "findings":       [],
    "commands_run":   [],
    "vulns_found":    [],
    "endpoints":      [],
    "subdomains":     [],
    "tech_stack":     [],
    "loot":           {},
}

CONFIG: dict = {
    "version": "1.0",
    "author":  "YeepForge",
    "tool":    "YeepForge",
}

SHOW_SECRETS = _ENV.get("YEEPFORGE_SHOW_SECRETS", "false").lower() in ("1", "true", "yes")

SECRET_KEYS = {"password", "auth_token", "cookies", "headers", "api_key"}

def redact_obj(value: Any) -> Any:
    """Strip secret-valued keys from a structure so they are never written to
    disk in the clear. Secrets are *omitted* (not replaced with a placeholder):
    a placeholder like '***' would be reloaded as the real value and then sent
    on every request, corrupting the engagement's real credentials."""
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if str(k).lower() in SECRET_KEYS:
                continue  # omit - do not persist a sentinel that reloads as data
            out[k] = redact_obj(v)
        return out
    if isinstance(value, list):
        return [redact_obj(v) for v in value]
    return value

def save_session(path: Path = SESSION_FILE) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {k: v for k, v in SESSION.items() if k != "commands_run"}
    if not SHOW_SECRETS:
        data = redact_obj(data)
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)

def load_session(path: Path = SESSION_FILE) -> bool:
    if not path.exists():
        return False
    try:
        with open(path) as f:
            data = json.load(f)
        # Defensive: never let a legacy '***' placeholder (written by older
        # builds) become a live secret that gets sent on every request.
        for k in SECRET_KEYS:
            if str(data.get(k, "")).strip() == "***":
                data.pop(k, None)
        SESSION.update(data)
        return True
    except Exception:
        return False

def update_session(**kwargs) -> None:
    SESSION.update(kwargs)

#: How sure we are the finding is real. Drives report presentation and lets a
#: triage pass (or a human) sort verified issues from leads worth checking.
CONFIDENCE_LEVELS = ("Confirmed", "Firm", "Tentative")


def normalize_evidence(evidence: Any) -> dict | None:
    """Coerce an evidence object into the plain dict stored in the session.

    Accepts a `utils.http.Evidence` (anything with `.to_dict()`), a dict, or a
    plain string (treated as free-form proof text). Returns None for nothing.
    """
    if not evidence:
        return None
    to_dict = getattr(evidence, "to_dict", None)
    if callable(to_dict):
        return to_dict()
    if isinstance(evidence, dict):
        return evidence
    return {"note": str(evidence)}


def add_vuln(title: str, severity: str, owasp: str, detail: str = "", url: str = "",
             evidence: Any = None, confidence: str = "Firm", cwe: str = "",
             remediation: str = "") -> None:
    """Record a vulnerability.

    `evidence` should be the request/response pair that proves it (pass
    `response.evidence` from utils.http). A finding without evidence is a lead,
    not a report item - the reporter marks it as such.

    `remediation` is stored rather than regenerated: advice written for this
    specific finding is worth more than the reporter's generic per-class hint.
    """
    if confidence not in CONFIDENCE_LEVELS:
        confidence = "Firm"

    # A finding recorded after the engagement's session expired was produced by
    # an anonymous request, whatever the module thought it was testing. Say so
    # on the finding itself rather than leaving it to be read as authenticated.
    if SESSION.get("session_degraded"):
        reason = SESSION.get("session_degraded_reason", "session lost")
        detail = (f"{detail}\n\n[UNTRUSTED] Recorded after the engagement's session "
                  f"stopped authenticating ({reason}). This was tested as an "
                  "anonymous user; re-run with a fresh session before reporting.")
        confidence = "Tentative"

    SESSION.setdefault("vulns_found", []).append({
        "title":       title,
        "severity":    severity,
        "owasp":       owasp,
        "detail":      detail,
        "url":         url,
        "cwe":         cwe,
        "confidence":  confidence,
        "remediation": remediation,
        "evidence":    normalize_evidence(evidence),
        "untrusted":   bool(SESSION.get("session_degraded")),
        "time":        datetime.now().isoformat(),
    })

def has_target() -> bool:
    return bool(SESSION.get("target_url"))

def get_target() -> str:
    return SESSION.get("target_url", "")

def get_proxy_dict() -> dict | None:
    proxy = SESSION.get("proxy", "")
    if not proxy:
        return None
    return {"http": proxy, "https": proxy}

load_session()
