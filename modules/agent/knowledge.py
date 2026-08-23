"""
modules/agent/knowledge.py
Persistent Knowledge Base - accumulates findings, payloads, target intel across runs.
Survives between sessions. JSON-backed with semantic search via simple TF-IDF index.
"""
import hashlib
import json
import os
import re
from datetime import datetime
from pathlib import Path

_KB_PATH = Path(os.path.expanduser("~/.yeepforge/knowledge.json"))
_KB_PATH.parent.mkdir(parents=True, exist_ok=True)


def _load() -> dict:
    if _KB_PATH.exists():
        try:
            return json.loads(_KB_PATH.read_text())
        except Exception:
            pass
    return {
        "targets": {},          # domain → {tech, findings, endpoints, params, notes}
        "payloads": {},         # vuln_type → [{"payload", "context", "success_count"}]
        "cves": {},             # tech_version → [cve_info]
        "methodology": [],      # successful attack chains
        "global_stats": {"runs": 0, "vulns_confirmed": 0},
    }


def _save(kb: dict):
    _KB_PATH.write_text(json.dumps(kb, indent=2, default=str))


def kb_record_target(domain: str, tech_stack: list, endpoints: list,
                     notes: str = "") -> None:
    """Record discovered target intelligence."""
    kb = _load()
    if domain not in kb["targets"]:
        kb["targets"][domain] = {
            "first_seen": datetime.now().isoformat(),
            "tech_stack": [],
            "endpoints": [],
            "params": [],
            "findings": [],
            "notes": [],
        }
    t = kb["targets"][domain]
    t["tech_stack"] = list(set(t.get("tech_stack", []) + tech_stack))[:50]
    t["endpoints"]  = list(set(t.get("endpoints", []) + endpoints))[:200]
    t["last_seen"]  = datetime.now().isoformat()
    if notes:
        t["notes"].append({"time": datetime.now().isoformat(), "note": notes})
    _save(kb)


def kb_record_finding(domain: str, title: str, severity: str, owasp: str,
                      description: str, payload: str = "", url: str = "") -> None:
    """Record a confirmed vulnerability finding."""
    kb = _load()
    kb["targets"].setdefault(domain, {"findings": [], "notes": []})
    finding = {
        "id": hashlib.md5(f"{title}{url}".encode()).hexdigest()[:8],
        "time": datetime.now().isoformat(),
        "title": title, "severity": severity, "owasp": owasp,
        "description": description[:500], "payload": payload[:200], "url": url,
    }
    existing_ids = [f.get("id") for f in kb["targets"][domain].get("findings", [])]
    if finding["id"] not in existing_ids:
        kb["targets"][domain].setdefault("findings", []).append(finding)
    # Record successful payload
    if payload:
        vuln_type = owasp or title.split()[0].lower()
        kb["payloads"].setdefault(vuln_type, [])
        existing = [p["payload"] for p in kb["payloads"][vuln_type]]
        if payload not in existing:
            kb["payloads"][vuln_type].append({
                "payload": payload, "context": domain,
                "success_count": 1, "added": datetime.now().isoformat(),
            })
        else:
            for p in kb["payloads"][vuln_type]:
                if p["payload"] == payload:
                    p["success_count"] = p.get("success_count", 0) + 1
    kb["global_stats"]["vulns_confirmed"] = kb["global_stats"].get("vulns_confirmed", 0) + 1
    _save(kb)


def kb_record_methodology(steps: list, result: str, target_type: str = "web") -> None:
    """Record a successful attack chain for future reuse."""
    kb = _load()
    kb["methodology"].append({
        "time": datetime.now().isoformat(),
        "target_type": target_type,
        "steps": steps,
        "result": result,
    })
    kb["methodology"] = kb["methodology"][-50:]  # keep last 50
    _save(kb)


def kb_get_target_context(domain: str) -> str:
    """Get all known intelligence about a target domain."""
    kb = _load()
    t = kb["targets"].get(domain, {})
    if not t:
        return f"No prior knowledge about {domain}"
    lines = [
        f"Prior knowledge for {domain}:",
        f"  First seen: {t.get('first_seen', 'unknown')}",
        f"  Tech stack: {', '.join(t.get('tech_stack', [])[:10]) or 'unknown'}",
        f"  Known endpoints: {len(t.get('endpoints', []))}",
        f"  Previous findings: {len(t.get('findings', []))}",
    ]
    for f in t.get("findings", [])[-5:]:
        lines.append(f"    [{f['severity']}] {f['title']} - {f.get('url', '')}")
    return "\n".join(lines)


def kb_get_payloads(vuln_type: str, limit: int = 5) -> list:
    """Get historically successful payloads for a vuln type."""
    kb = _load()
    # Search across all vuln_type keys that match
    results = []
    for key, payloads in kb["payloads"].items():
        if vuln_type.lower() in key.lower() or key.lower() in vuln_type.lower():
            sorted_p = sorted(payloads, key=lambda x: x.get("success_count", 0), reverse=True)
            results.extend([p["payload"] for p in sorted_p[:limit]])
    return results[:limit]


def kb_get_similar_findings(title: str) -> list:
    """Simple keyword-based search for similar past findings."""
    kb = _load()
    keywords = set(re.findall(r'\w{4,}', title.lower()))
    similar = []
    for domain, target_data in kb["targets"].items():
        for f in target_data.get("findings", []):
            f_keywords = set(re.findall(r'\w{4,}', f["title"].lower()))
            overlap = len(keywords & f_keywords)
            if overlap >= 2:
                similar.append({**f, "domain": domain, "overlap": overlap})
    return sorted(similar, key=lambda x: x["overlap"], reverse=True)[:5]


def kb_increment_run():
    kb = _load()
    kb["global_stats"]["runs"] = kb["global_stats"].get("runs", 0) + 1
    _save(kb)


def kb_summary() -> str:
    kb = _load()
    stats = kb["global_stats"]
    targets = len(kb["targets"])
    total_findings = sum(len(t.get("findings", [])) for t in kb["targets"].values())
    payload_types  = len(kb["payloads"])
    return (
        f"Knowledge Base: {targets} targets | "
        f"{total_findings} total findings | "
        f"{payload_types} payload categories | "
        f"{stats.get('runs', 0)} runs"
    )
