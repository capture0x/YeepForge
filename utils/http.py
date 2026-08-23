"""
utils/http.py
YeepForge - the single HTTP engine every module should send requests through.

Why this exists
---------------
YeepForge historically issued requests by shelling out to `curl` with an
f-string per call site. That made four things impossible to guarantee:

  * **Proxy** - an operator who sets a Burp proxy expects *all* traffic in the
    proxy history. Per-call curl strings only honoured it in a couple of spots.
  * **Rate limiting** - bug bounty programs ban researchers who hammer them.
  * **Evidence** - a finding without the raw request/response that produced it
    is not reportable, and cannot be re-verified.
  * **Safety** - values interpolated into a shell string (cookies, URLs) are
    executed by the shell; a `$(...)` in a cookie ran on the tester's machine.

Everything here is synchronous and dependency-light (requests only), so modules
can adopt it incrementally:

    from utils.http import get_client
    r = get_client().get(url, params={"id": 1})
    if "SQL syntax" in r.text:
        add_vuln(..., evidence=r.evidence)

`r.evidence` carries the redacted request/response pair plus a ready-to-paste
`curl` reproduction line.
"""
from __future__ import annotations

import json
import os
import random
import re
import shlex
import threading
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlsplit

import requests
from requests.adapters import HTTPAdapter

from config.settings import SESSION
from utils.scope import ScopeViolation, assert_in_scope

__all__ = [
    "Client",
    "Evidence",
    "RateLimiter",
    "build_curl",
    "curl_flags",
    "get_client",
    "looks_like_notfound",
    "notfound_signature",
    "set_cookie_headers",
    "reset_client",
    "ScopeViolation",
]

# Pentest targets routinely have broken/self-signed TLS; certificate validation
# is off by default (matching the old `curl -sk`), but the warning noise is not
# useful so it is silenced once, here.
try:  # pragma: no cover - depends on urllib3 version
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:  # pragma: no cover
    pass

DEFAULT_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0 Safari/537.36 YeepForge/1.0"
)

#: Header names whose values are stripped before a finding reaches a report.
SENSITIVE_HEADERS = {"authorization", "cookie", "set-cookie", "proxy-authorization",
                     "x-api-key", "x-auth-token", "api-key"}

#: How much of a response body to keep as evidence. Enough to show the proof
#: (an SQL error, a reflected payload) without bloating reports with full pages.
BODY_EVIDENCE_LIMIT = 2000


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, "").strip() or default)
    except ValueError:
        return default


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "").strip() or default)
    except ValueError:
        return default


# ── Rate limiting ─────────────────────────────────────────────────────────────
class RateLimiter:
    """Blocking token bucket: at most `rps` requests per second, with jitter.

    Thread-safe, so a threaded module (crawler, fuzzer) shares one budget for
    the whole engagement rather than one per worker.
    """

    def __init__(self, rps: float = 10.0, jitter: float = 0.0):
        self.rps = max(0.0, float(rps))
        self.jitter = max(0.0, float(jitter))
        self._lock = threading.Lock()
        self._next_at = 0.0

    @property
    def interval(self) -> float:
        return 0.0 if self.rps <= 0 else 1.0 / self.rps

    def acquire(self) -> float:
        """Sleep until the next request is allowed. Returns seconds waited."""
        if self.rps <= 0:
            return 0.0
        with self._lock:
            now = time.monotonic()
            wait = max(0.0, self._next_at - now)
            step = self.interval
            if self.jitter:
                step += random.uniform(0, self.jitter)
            self._next_at = max(now, self._next_at) + step
        if wait:
            time.sleep(wait)
        return wait


# ── Evidence ──────────────────────────────────────────────────────────────────
def _redact_headers(headers: dict, show_secrets: bool) -> dict:
    if show_secrets:
        return dict(headers)
    out = {}
    for k, v in (headers or {}).items():
        out[k] = "<redacted>" if str(k).lower() in SENSITIVE_HEADERS else v
    return out


@dataclass
class Evidence:
    """The request/response pair that proves a finding.

    Secrets are redacted at construction: reports get shared with clients and
    pasted into bounty platforms, and an Authorization header must not ride
    along. Set YEEPFORGE_SHOW_SECRETS=true to keep them.
    """

    method: str = "GET"
    url: str = ""
    request_headers: dict = field(default_factory=dict)
    request_body: str = ""
    status: int | None = None
    response_headers: dict = field(default_factory=dict)
    response_body: str = ""
    elapsed_ms: int = 0
    curl: str = ""
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "method": self.method,
            "url": self.url,
            "request_headers": self.request_headers,
            "request_body": self.request_body,
            "status": self.status,
            "response_headers": self.response_headers,
            "response_body": self.response_body,
            "elapsed_ms": self.elapsed_ms,
            "curl": self.curl,
            "error": self.error,
        }

    def request_text(self) -> str:
        """Raw-ish HTTP request, the shape a report reader expects."""
        parts = urlsplit(self.url)
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        lines = [f"{self.method} {path} HTTP/1.1", f"Host: {parts.netloc}"]
        lines += [f"{k}: {v}" for k, v in self.request_headers.items()]
        if self.request_body:
            lines += ["", self.request_body]
        return "\n".join(lines)

    def response_text(self) -> str:
        if self.error and self.status is None:
            return f"(no response: {self.error})"
        lines = [f"HTTP/1.1 {self.status}"]
        lines += [f"{k}: {v}" for k, v in self.response_headers.items()]
        if self.response_body:
            lines += ["", self.response_body]
        return "\n".join(lines)


# ── curl builder ──────────────────────────────────────────────────────────────
def curl_flags(session: dict | None = None, insecure: bool = True) -> str:
    """Shell-safe curl flags carrying the engagement context.

    Migration shim for modules that still shell out to curl: it puts the
    session's cookies, custom headers, auth token and - critically - the proxy
    onto every command, all shlex-quoted. Prefer `get_client()` for new code;
    this exists so a legacy call site becomes safe with a one-line change.
    """
    sess = SESSION if session is None else session
    flags = ["-s"]
    if insecure:
        flags.append("-k")

    cookies = (sess.get("cookies") or "").strip()
    if cookies:
        flags += ["-b", shlex.quote(cookies)]

    raw_headers = sess.get("headers") or ""
    parsed = raw_headers if isinstance(raw_headers, dict) else _parse_header_string(str(raw_headers))
    for key, val in parsed.items():
        flags += ["-H", shlex.quote(f"{key}: {val}")]

    token = (sess.get("auth_token") or "").strip()
    if token and "authorization" not in {k.lower() for k in parsed}:
        value = token if " " in token else f"Bearer {token}"
        flags += ["-H", shlex.quote(f"Authorization: {value}")]

    proxy = (sess.get("proxy") or "").strip()
    if proxy:
        flags += ["--proxy", shlex.quote(proxy)]

    return " ".join(flags)


def build_curl(
    url: str,
    method: str = "GET",
    headers: dict | None = None,
    data: str | None = None,
    cookies: str = "",
    proxy: str = "",
    timeout: int = 15,
    insecure: bool = True,
    extra: list[str] | None = None,
) -> str:
    """Build a shell-safe `curl` command string.

    Every interpolated value goes through shlex.quote, so a payload containing
    `$(id)`, backticks or quotes is sent to the *target* instead of being
    executed by the tester's own shell. Modules that still shell out to curl
    must build their command with this function.
    """
    cmd = ["curl", "-s"]
    if insecure:
        cmd.append("-k")
    cmd += ["-i", "-m", str(int(timeout))]
    if method.upper() != "GET":
        cmd += ["-X", method.upper()]
    for key, val in (headers or {}).items():
        cmd += ["-H", shlex.quote(f"{key}: {val}")]
    if cookies:
        cmd += ["-b", shlex.quote(cookies)]
    if proxy:
        cmd += ["--proxy", shlex.quote(proxy)]
    if data is not None:
        cmd += ["--data-binary", shlex.quote(data)]
    if extra:
        cmd += [shlex.quote(e) for e in extra]
    cmd.append(shlex.quote(url))
    return " ".join(cmd)


# ── Client ────────────────────────────────────────────────────────────────────
class Client:
    """Session-aware HTTP client: scope-checked, rate-limited, evidence-taking.

    Configuration is read from the YeepForge SESSION (target, cookies, headers,
    auth token, proxy) and from the environment:

        YEEPFORGE_RPS       requests per second (default 10; 0 = unlimited)
        YEEPFORGE_TIMEOUT   per-request timeout in seconds (default 15)
        YEEPFORGE_RETRIES   retries on connection error / 429 / 5xx (default 2)
        YEEPFORGE_JITTER    extra random delay per request, seconds (default 0)
        YEEPFORGE_UA        User-Agent override
        YEEPFORGE_VERIFY_TLS=1  turn certificate validation back on
    """

    #: Statuses worth retrying - transient infrastructure, not app behaviour.
    RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})

    def __init__(
        self,
        session: dict | None = None,
        rps: float | None = None,
        timeout: int | None = None,
        retries: int | None = None,
        verify: bool | None = None,
        user_agent: str | None = None,
        pool_size: int = 20,
    ):
        self.session_data = SESSION if session is None else session
        self.timeout = timeout if timeout is not None else _env_int("YEEPFORGE_TIMEOUT", 15)
        self.retries = retries if retries is not None else _env_int("YEEPFORGE_RETRIES", 2)
        self.verify = (
            verify
            if verify is not None
            else os.environ.get("YEEPFORGE_VERIFY_TLS", "").lower() in ("1", "true", "yes")
        )
        self.user_agent = user_agent or os.environ.get("YEEPFORGE_UA") or DEFAULT_UA
        self.limiter = RateLimiter(
            rps if rps is not None else _env_float("YEEPFORGE_RPS", 10.0),
            _env_float("YEEPFORGE_JITTER", 0.0),
        )
        #: Every exchange made through this client, newest last. Modules use it
        #: to attach evidence after the fact; reporting can dump it as a log.
        self.history: list[Evidence] = []
        self.max_history = 500

        self._http = requests.Session()
        adapter = HTTPAdapter(pool_connections=pool_size, pool_maxsize=pool_size)
        self._http.mount("http://", adapter)
        self._http.mount("https://", adapter)
        self._pool_size = pool_size
        self._anon_http: requests.Session | None = None

    def _anon_session(self) -> requests.Session:
        """A session that holds no cookies, rebuilt empty on every use."""
        if self._anon_http is None:
            self._anon_http = requests.Session()
            adapter = HTTPAdapter(pool_connections=self._pool_size,
                                  pool_maxsize=self._pool_size)
            self._anon_http.mount("http://", adapter)
            self._anon_http.mount("https://", adapter)
        self._anon_http.cookies.clear()
        return self._anon_http

    # ── session-derived context ──────────────────────────────────────────────
    @property
    def proxy(self) -> str:
        return (self.session_data.get("proxy") or "").strip()

    def _proxies(self) -> dict | None:
        p = self.proxy
        return {"http": p, "https": p} if p else None

    def _session_headers(self, anonymous: bool = False) -> dict:
        """Headers implied by the engagement: UA, custom headers, auth, cookies.

        With `anonymous`, the credentials are left off: no cookies, no auth
        token, no operator-supplied Authorization. Tests that ask "can an
        unauthenticated caller do this?" need a request that genuinely carries
        no identity, which merging extra headers on top cannot produce.
        """
        headers = {"User-Agent": self.user_agent}
        if anonymous:
            return headers

        raw = self.session_data.get("headers") or ""
        if isinstance(raw, dict):
            headers.update({str(k): str(v) for k, v in raw.items()})
        elif isinstance(raw, str) and raw.strip():
            headers.update(_parse_header_string(raw))

        token = (self.session_data.get("auth_token") or "").strip()
        if token and "Authorization" not in headers:
            # Accept a bare token or a full scheme ('Bearer x', 'Basic y').
            headers["Authorization"] = token if " " in token else f"Bearer {token}"

        cookies = (self.session_data.get("cookies") or "").strip()
        if cookies and "Cookie" not in headers:
            headers["Cookie"] = cookies

        return headers

    def resolve(self, url: str) -> str:
        """Absolute URL: bare paths are joined onto the engagement target."""
        if not url:
            return self.session_data.get("target_url", "")
        if url.startswith(("http://", "https://")):
            return url
        base = self.session_data.get("target_url", "")
        return urljoin(base if base.endswith("/") else base + "/", url.lstrip("/"))

    # ── the one request path ─────────────────────────────────────────────────
    def request(
        self,
        method: str,
        url: str,
        *,
        params: dict | None = None,
        data: Any = None,
        json_body: Any = None,
        headers: dict | None = None,
        allow_redirects: bool = True,
        timeout: int | None = None,
        check_scope: bool = True,
        anonymous: bool = False,
        **kwargs,
    ) -> requests.Response:
        """Send one request. Returns the requests.Response with `.evidence`.

        Raises ScopeViolation if the URL is outside the engagement scope, and
        requests exceptions only after retries are exhausted.

        `anonymous=True` strips the engagement's cookies and auth token from
        this one request - the baseline an access-control test compares against.
        """
        full_url = self.resolve(url)
        if check_scope:
            assert_in_scope(full_url, self.session_data)

        req_headers = self._session_headers(anonymous=anonymous)
        if headers:
            req_headers.update(headers)

        body_repr = ""
        if json_body is not None:
            req_headers.setdefault("Content-Type", "application/json")
            body_repr = json.dumps(json_body)
        elif isinstance(data, (dict, list)):
            body_repr = "&".join(f"{k}={v}" for k, v in (data.items() if isinstance(data, dict) else data))
        elif data is not None:
            body_repr = str(data)

        timeout = self.timeout if timeout is None else timeout
        show_secrets = _show_secrets()
        attempt, last_exc, response = 0, None, None
        started = time.monotonic()

        # An anonymous request goes out on its own session: requests merges the
        # shared session's cookie jar into every call, so stripping the Cookie
        # header alone would still leak whatever the jar picked up earlier.
        http = self._anon_session() if anonymous else self._http

        while attempt <= self.retries:
            self.limiter.acquire()
            try:
                response = http.request(
                    method.upper(),
                    full_url,
                    params=params,
                    data=data,
                    json=json_body,
                    headers=req_headers,
                    allow_redirects=allow_redirects,
                    timeout=timeout,
                    verify=self.verify,
                    proxies=self._proxies(),
                    **kwargs,
                )
            except requests.RequestException as exc:
                last_exc, response = exc, None
            else:
                if response.status_code not in self.RETRY_STATUSES:
                    break
                # Honour Retry-After when the target tells us how long to wait -
                # ignoring it is how scanners get blocked mid-engagement.
                self._respect_retry_after(response, attempt)
                last_exc = None
            attempt += 1
            if attempt <= self.retries and last_exc is not None:
                time.sleep(min(2 ** attempt * 0.5, 8))

        elapsed_ms = int((time.monotonic() - started) * 1000)
        evidence = Evidence(
            method=method.upper(),
            url=full_url if not params else _with_params(full_url, params),
            request_headers=_redact_headers(req_headers, show_secrets),
            request_body=body_repr[:BODY_EVIDENCE_LIMIT],
            elapsed_ms=elapsed_ms,
            curl=build_curl(
                full_url if not params else _with_params(full_url, params),
                method=method,
                headers=_redact_headers(req_headers, show_secrets),
                data=body_repr or None,
                proxy=self.proxy,
                timeout=timeout,
                insecure=not self.verify,
            ),
        )

        if response is None:
            evidence.error = str(last_exc) if last_exc else "request failed"
            self._record(evidence)
            raise last_exc if last_exc else requests.RequestException("request failed")

        evidence.status = response.status_code
        evidence.response_headers = _redact_headers(dict(response.headers), show_secrets)
        evidence.response_body = _safe_text(response)[:BODY_EVIDENCE_LIMIT]
        self._record(evidence)
        if not anonymous:
            self._watch_session(response)
        # Attached, not returned separately, so call sites can pass `r.evidence`
        # straight into add_vuln() without threading an extra variable around.
        response.evidence = evidence  # type: ignore[attr-defined]
        return response

    def _respect_retry_after(self, response: requests.Response, attempt: int) -> None:
        raw = response.headers.get("Retry-After", "").strip()
        delay = None
        if raw:
            try:
                delay = float(raw)
            except ValueError:
                delay = None  # HTTP-date form: fall back to backoff
        if delay is None:
            delay = min(2 ** attempt * 0.5, 8)
        time.sleep(max(0.0, min(delay, 30.0)))

    def _watch_session(self, response) -> None:
        """Notice a session that has expired mid-scan.

        Sits on the one request path every module now shares, so a cookie that
        dies an hour into a run is caught wherever it happens rather than in the
        one module that remembered to check. A scan that silently continues
        unauthenticated reports the application clean, which is indistinguishable
        from a good result.
        """
        from utils.liveness import get_monitor
        monitor = get_monitor()
        if not monitor.established or monitor.degraded:
            return
        # The response in hand is a free sample; the probe request is only made
        # when it is inconclusive and the interval is up.
        reason = monitor.looks_logged_out(response)
        if reason:
            monitor.mark_degraded(reason)
        elif monitor.note_request():
            monitor.check(self)

    def _record(self, evidence: Evidence) -> None:
        self.history.append(evidence)
        if len(self.history) > self.max_history:
            del self.history[: len(self.history) - self.max_history]

    # ── verbs ────────────────────────────────────────────────────────────────
    def get(self, url: str, **kw) -> requests.Response:
        return self.request("GET", url, **kw)

    def post(self, url: str, **kw) -> requests.Response:
        return self.request("POST", url, **kw)

    def head(self, url: str, **kw) -> requests.Response:
        kw.setdefault("allow_redirects", False)
        return self.request("HEAD", url, **kw)

    def put(self, url: str, **kw) -> requests.Response:
        return self.request("PUT", url, **kw)

    def delete(self, url: str, **kw) -> requests.Response:
        return self.request("DELETE", url, **kw)

    def options(self, url: str, **kw) -> requests.Response:
        return self.request("OPTIONS", url, **kw)

    def safe_get(self, url: str, **kw) -> requests.Response | None:
        """GET that returns None instead of raising - for bulk probing loops."""
        try:
            return self.get(url, **kw)
        except (requests.RequestException, ScopeViolation):
            return None

    def close(self) -> None:
        self._http.close()
        if self._anon_http is not None:
            self._anon_http.close()
            self._anon_http = None


def set_cookie_headers(response) -> list[str]:
    """Every individual Set-Cookie header on a response.

    requests joins repeated headers with ', ' in `response.headers`, which
    corrupts cookie parsing because cookie attributes (Expires) contain commas
    too. urllib3 keeps the originals, so prefer those and only fall back to
    splitting when the raw object is unavailable (or stubbed in a test).
    """
    raw = getattr(response, "raw", None)
    getlist = getattr(getattr(raw, "headers", None), "getlist", None)
    if callable(getlist):
        values = getlist("Set-Cookie")
        if values:
            return list(values)

    joined = (response.headers.get("Set-Cookie") or "").strip()
    if not joined:
        return []
    # Split on commas that start a new `name=` pair, leaving `Expires=Mon, 01 …`
    # intact.
    return [c.strip() for c in re.split(r",(?=[^;=,]+=)", joined) if c.strip()]


def notfound_signature(client: "Client", base_url: str) -> tuple[int, int] | None:
    """Fingerprint (status, body length) of a path that certainly does not exist.

    Many applications answer a missing path with HTTP 200 and a friendly page,
    or with an SPA's index.html. Without this baseline, a path-probing module
    reports every path it tries as exposed. Returns None when the probe fails.
    """
    import uuid
    probe = f"/yeepforge-{uuid.uuid4().hex[:12]}"
    resp = client.safe_get(base_url.rstrip("/") + probe)
    if resp is None:
        return None
    return resp.status_code, len(resp.text)


def looks_like_notfound(response, signature: tuple[int, int] | None) -> bool:
    """True when a response is indistinguishable from the known-missing page."""
    if signature is None or response is None:
        return False
    status, length = signature
    if response.status_code != status:
        return False
    # Same status as the known-missing path and a near-identical body size.
    return abs(len(response.text) - length) <= max(32, length * 0.05)


def _with_params(url: str, params: dict) -> str:
    from urllib.parse import urlencode
    sep = "&" if "?" in url else "?"
    return f"{url}{sep}{urlencode(params)}"


def _safe_text(response: requests.Response) -> str:
    try:
        return response.text
    except Exception:
        return repr(response.content[:BODY_EVIDENCE_LIMIT])


def _parse_header_string(raw: str) -> dict:
    """Parse the SESSION['headers'] free-text form into a dict.

    Accepts JSON, 'K: V' lines, and 'K: V; K2: V2' - operators type all three.
    """
    raw = raw.strip()
    if raw.startswith("{"):
        try:
            loaded = json.loads(raw)
            if isinstance(loaded, dict):
                return {str(k): str(v) for k, v in loaded.items()}
        except ValueError:
            pass
    out = {}
    chunks = raw.replace("\r", "").split("\n")
    if len(chunks) == 1:
        chunks = raw.split(";")
    for chunk in chunks:
        if ":" not in chunk:
            continue
        key, _, val = chunk.partition(":")
        key, val = key.strip(), val.strip()
        if key:
            out[key] = val
    return out


def _show_secrets() -> bool:
    # Read through the module (not a from-import) so a test or the CLI can flip
    # it at runtime and have the change take effect here.
    import config.settings as settings
    return bool(getattr(settings, "SHOW_SECRETS", False))


# ── module-level client ───────────────────────────────────────────────────────
_client: Client | None = None
_client_lock = threading.Lock()


def get_client() -> Client:
    """The shared client - one rate-limit budget and one history per run."""
    global _client
    if _client is None:
        with _client_lock:
            if _client is None:
                _client = Client()
    return _client


def reset_client() -> None:
    """Drop the shared client (config changed, or a test needs a clean one)."""
    global _client
    with _client_lock:
        if _client is not None:
            _client.close()
        _client = None
