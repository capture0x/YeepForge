"""backends.py - YeepForge Agent AI backend helpers
Supports: Ollama · Claude (Anthropic) · OpenAI · Groq · Gemini · DeepSeek
"""
import json
from types import SimpleNamespace

try:
    import requests as _requests
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False

OLLAMA_BASE = "http://127.0.0.1:11434"


# ── Ollama ────────────────────────────────────────────────────────────────────

def _get_ollama_models() -> list:
    try:
        if _HAS_REQUESTS:
            resp = _requests.get(f"{OLLAMA_BASE}/api/tags", timeout=4)
            data = resp.json()
        else:
            import urllib.request
            with urllib.request.urlopen(f"{OLLAMA_BASE}/api/tags", timeout=4) as r:
                data = json.loads(r.read())
        return [m["name"] for m in data.get("models", [])]
    except Exception:
        return []


def _best_model(models: list) -> str:
    override = __import__("sys").modules.get("config.settings")
    if override:
        sess = getattr(override, "SESSION", {})
        ov = sess.get("_ollama_model", "")
        if ov and ov in models:
            return ov
    preferences = [
        "mistral", "qwen2.5-coder", "qwen2.5", "qwen",
        "llama3.1:8b", "llama3.1", "llama3.2",
        "phi3", "phi", "gemma2", "gemma", "deepseek",
    ]
    for pref in preferences:
        for m in models:
            if pref in m.lower():
                return m
    return models[0] if models else "mistral"


def _ollama_generate(model: str, prompt: str, timeout: int = 120,
                     num_predict: int = 256) -> str:
    payload = {
        "model": model, "prompt": prompt, "stream": False,
        "options": {"temperature": 0.05, "num_predict": num_predict,
                    "top_p": 0.9, "repeat_penalty": 1.1},
    }
    try:
        if _HAS_REQUESTS:
            resp = _requests.post(f"{OLLAMA_BASE}/api/generate", json=payload, timeout=timeout)
            return resp.json().get("response", "")
        else:
            import urllib.request
            req = urllib.request.Request(
                f"{OLLAMA_BASE}/api/generate",
                data=json.dumps(payload).encode(),
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read()).get("response", "")
    except Exception as e:
        return f"[Ollama error: {e}]"


def _ollama_chat(model: str, messages: list, timeout: int = 120) -> str:
    payload = {
        "model": model, "messages": messages, "stream": False,
        "options": {"temperature": 0.1, "num_predict": 1024},
    }
    try:
        if _HAS_REQUESTS:
            resp = _requests.post(f"{OLLAMA_BASE}/api/chat", json=payload, timeout=timeout)
            return resp.json().get("message", {}).get("content", "")
        else:
            import urllib.request
            req = urllib.request.Request(
                f"{OLLAMA_BASE}/api/chat",
                data=json.dumps(payload).encode(),
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read()).get("message", {}).get("content", "")
    except Exception as e:
        return f"[Ollama error: {e}]"


def _ollama_chat_stream(model: str, messages: list, timeout: int = 300):
    payload = {
        "model": model, "messages": messages, "stream": True,
        "options": {"temperature": 0.2, "num_predict": 2048},
    }
    try:
        if _HAS_REQUESTS:
            with _requests.post(f"{OLLAMA_BASE}/api/chat", json=payload,
                                stream=True, timeout=timeout) as resp:
                for line in resp.iter_lines():
                    if not line:
                        continue
                    try:
                        chunk = json.loads(line)
                        token = chunk.get("message", {}).get("content", "")
                        if token:
                            yield token
                        if chunk.get("done"):
                            break
                    except json.JSONDecodeError:
                        continue
        else:
            import urllib.request
            req = urllib.request.Request(
                f"{OLLAMA_BASE}/api/chat",
                data=json.dumps(payload).encode(),
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as r:
                for raw_line in r:
                    line = raw_line.decode("utf-8").strip()
                    if not line:
                        continue
                    try:
                        chunk = json.loads(line)
                        token = chunk.get("message", {}).get("content", "")
                        if token:
                            yield token
                        if chunk.get("done"):
                            break
                    except json.JSONDecodeError:
                        continue
    except Exception as e:
        yield f"[Stream error: {e}]"


# ── OpenAI-compatible backend (OpenAI · Groq · DeepSeek · any OpenAI-compat) ──

def _openai_chat(api_key: str, model: str, messages: list,
                  base_url: str = "https://api.openai.com/v1",
                  timeout: int = 120, tools: list = None) -> str:
    """Generic OpenAI-compatible /chat/completions endpoint."""
    if not _HAS_REQUESTS:
        return "[OpenAI backend requires requests library]"
    payload = {
        "model": model,
        "messages": messages,
        "temperature": 0.1,
        "max_tokens": 4096,
    }
    if tools:
        payload["tools"] = tools
        payload["tool_choice"] = "auto"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    try:
        resp = _requests.post(
            f"{base_url}/chat/completions",
            json=payload, headers=headers, timeout=timeout,
        )
        data = resp.json()
        choices = data.get("choices", [])
        if not choices:
            return f"[API error: {data}]"
        msg = choices[0].get("message", {})
        # If tool_calls present, return JSON representation
        if msg.get("tool_calls"):
            tc = msg["tool_calls"][0]
            return json.dumps({
                "tool": tc["function"]["name"],
                "args": json.loads(tc["function"].get("arguments", "{}")),
            })
        return msg.get("content", "")
    except Exception as e:
        return f"[OpenAI-compat error: {e}]"


def _openai_chat_stream(api_key: str, model: str, messages: list,
                         base_url: str = "https://api.openai.com/v1",
                         timeout: int = 300):
    """Stream from OpenAI-compatible endpoint."""
    if not _HAS_REQUESTS:
        yield "[requests library required]"; return
    payload = {"model": model, "messages": messages, "stream": True,
               "temperature": 0.2, "max_tokens": 4096}
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    try:
        with _requests.post(f"{base_url}/chat/completions", json=payload,
                             headers=headers, stream=True, timeout=timeout) as resp:
            for line in resp.iter_lines():
                if not line or line == b"data: [DONE]":
                    continue
                line_str = line.decode("utf-8")
                if line_str.startswith("data: "):
                    try:
                        chunk = json.loads(line_str[6:])
                        token = chunk["choices"][0].get("delta", {}).get("content", "")
                        if token:
                            yield token
                    except Exception:
                        continue
    except Exception as e:
        yield f"[Stream error: {e}]"


# ── Gemini ────────────────────────────────────────────────────────────────────

def _gemini_chat(api_key: str, model: str, messages: list, timeout: int = 120) -> str:
    if not _HAS_REQUESTS:
        return "[requests required for Gemini]"
    # Convert OpenAI format to Gemini format
    contents = []
    for m in messages:
        role = "user" if m["role"] in ("user", "tool") else "model"
        contents.append({"role": role, "parts": [{"text": str(m.get("content", ""))}]})
    payload = {
        "contents": contents,
        "generationConfig": {"temperature": 0.1, "maxOutputTokens": 4096},
    }
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
    try:
        resp = _requests.post(url, json=payload, timeout=timeout)
        data = resp.json()
        candidates = data.get("candidates", [])
        if candidates:
            return candidates[0]["content"]["parts"][0].get("text", "")
        return f"[Gemini error: {data}]"
    except Exception as e:
        return f"[Gemini error: {e}]"


# ── Web search (no API key needed) ───────────────────────────────────────────

def web_search_ddg(query: str, max_results: int = 5) -> str:
    """DuckDuckGo instant answer search - no API key required."""
    import urllib.parse
    import urllib.request
    encoded = urllib.parse.quote(query)
    url = f"https://api.duckduckgo.com/?q={encoded}&format=json&no_html=1&skip_disambig=1"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "YeepForge/2.0"})
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.loads(r.read())
        results = []
        # Abstract
        if data.get("AbstractText"):
            results.append(data["AbstractText"][:300])
        # Related topics
        for topic in data.get("RelatedTopics", [])[:max_results]:
            if isinstance(topic, dict) and topic.get("Text"):
                results.append(topic["Text"][:200])
        return "\n".join(results) if results else f"No results for: {query}"
    except Exception as e:
        return f"[Search error: {e}]"


def web_search_cve(tech: str, version: str = "") -> str:
    """Search CVE/NVD for a technology + version."""
    import urllib.parse
    import urllib.request
    query = f"{tech} {version}".strip()
    encoded = urllib.parse.quote(query)
    # NVD API (free, no key)
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={encoded}&resultsPerPage=5"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "YeepForge"})
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.loads(r.read())
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return f"No CVEs found for: {query}"
        lines = [f"CVEs for {query}:"]
        for v in vulns[:5]:
            cve = v.get("cve", {})
            cve_id = cve.get("id", "")
            descs = cve.get("descriptions", [])
            desc = next((d["value"] for d in descs if d.get("lang") == "en"), "")[:200]
            metrics = cve.get("metrics", {})
            cvss = ""
            for k in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if k in metrics:
                    score = metrics[k][0].get("cvssData", {}).get("baseScore", "")
                    if score:
                        cvss = f"CVSS:{score}"
                        break
            lines.append(f"  {cve_id} {cvss} - {desc[:180]}")
        return "\n".join(lines)
    except Exception as e:
        return f"[CVE lookup error: {e}]"


# ── Backward compat ───────────────────────────────────────────────────────────

def _ollama_chat_completion(model: str, messages: list, tools: list = None,
                             timeout: int = 60) -> SimpleNamespace:
    text = _ollama_chat(model, messages, timeout=timeout)
    msg = SimpleNamespace(content=text, tool_calls=None)
    return SimpleNamespace(choices=[SimpleNamespace(message=msg)])
