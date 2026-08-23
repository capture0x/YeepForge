"""SSRF and sensitive-file detection: markers must prove a fetch, not a mention."""
from modules import crypto_failures as cf
from modules import ssrf


class _Resp:
    def __init__(self, text="", ctype="text/plain", status=200):
        self.text = text
        self.status_code = status
        self.headers = {"Content-Type": ctype}


# ── SSRF markers ──────────────────────────────────────────────────────────────
def test_internal_hit_recognises_real_service_output():
    assert ssrf._internal_hit('{"AccessKeyId": "ASIA..."}', "http://169.254.169.254/")[0] == "AccessKeyId"
    assert ssrf._internal_hit("SSH-2.0-OpenSSH_9.6", "http://127.0.0.1:22")[1] == "SSH banner"
    assert ssrf._internal_hit("redis_version:7.2.4", "http://127.0.0.1:6379")[1] == "Redis"


def test_internal_hit_ignores_pages_that_merely_mention_services():
    """The old word list made these Critical SSRF findings."""
    page = "<html><body>Powered by MySQL and Redis. SSH access is disabled.</body></html>"
    assert ssrf._internal_hit(page, "http://127.0.0.1:3306") is None


def test_internal_hit_ignores_the_reflected_payload():
    """An app echoing the payload back contains 'meta-data' without fetching it."""
    payload = "http://169.254.169.254/latest/meta-data/local-ipv4"
    body = f"<p>Could not fetch {payload}</p>"
    assert ssrf._internal_hit(body, payload) is None


def test_internal_hit_ignores_url_encoded_reflection():
    payload = "http://169.254.169.254/latest/meta-data/local-ipv4"
    import urllib.parse
    body = f"error: {urllib.parse.quote(payload, safe='')}"
    assert ssrf._internal_hit(body, payload) is None


def test_matches_baseline_compares_status_and_size():
    assert ssrf._matches_baseline(_Resp("x" * 1000), (200, 1000))
    assert not ssrf._matches_baseline(_Resp("x" * 5000), (200, 1000))
    assert not ssrf._matches_baseline(_Resp("x" * 1000), None)


# ── sensitive file detection ──────────────────────────────────────────────────
def test_real_env_file_is_recognised():
    body = "DB_PASSWORD=hunter2\nAPI_KEY=abc\n"
    assert cf._looks_like_the_real_file("/.env", body, _Resp(body))


def test_spa_index_html_is_not_an_exposed_env_file():
    """An SPA answers every unknown path with index.html and HTTP 200."""
    body = "<!DOCTYPE html><html><head><title>App</title></head><body></body></html>"
    assert not cf._looks_like_the_real_file("/.env", body, _Resp(body, ctype="text/html"))
    assert not cf._looks_like_the_real_file("/private.key", body, _Resp(body, ctype="text/html"))
    assert not cf._looks_like_the_real_file("/package.json", body, _Resp(body, ctype="text/html"))


def test_html_detected_from_body_when_content_type_lies():
    body = "<html><body>Not found</body></html>"
    assert not cf._looks_like_the_real_file("/.env", body, _Resp(body, ctype="application/json"))


def test_git_config_needs_git_markers():
    assert cf._looks_like_the_real_file("/.git/config", "[core]\n\trepositoryformatversion = 0",
                                        _Resp(ctype="text/plain"))
    assert not cf._looks_like_the_real_file("/.git/config", "nothing to see",
                                            _Resp(ctype="text/plain"))


def test_private_key_requires_a_pem_header():
    assert cf._looks_like_the_real_file("/private.key", "-----BEGIN RSA PRIVATE KEY-----",
                                        _Resp(ctype="text/plain"))
    assert not cf._looks_like_the_real_file("/private.key", "access denied",
                                            _Resp(ctype="text/plain"))


def test_empty_body_is_never_a_file():
    assert not cf._looks_like_the_real_file("/.env", "   ", _Resp())


# ── JS secret patterns ────────────────────────────────────────────────────────
def test_aws_secret_pattern_needs_context():
    """A bare 40-char quoted string is a hash in a bundle, not an AWS secret."""
    import re
    pattern = cf.JS_SECRET_PATTERNS["AWS Secret Key"][0]
    minified = 'var h="a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0";'
    assert not re.search(pattern, minified)
    real = 'aws_secret_access_key: "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"'
    assert re.search(pattern, real)


def test_js_secret_severities_are_graded():
    """A live cloud key and a 'password:' assignment are not the same finding."""
    severities = {name: sev for name, (_re, sev) in cf.JS_SECRET_PATTERNS.items()}
    assert severities["AWS Access Key"] == "Critical"
    assert severities["Password in JS"] == "Medium"
    assert set(severities.values()) <= {"Critical", "High", "Medium", "Low", "Info"}


def test_high_signal_patterns_match_real_tokens():
    import re
    cases = {
        "AWS Access Key": "AKIAIOSFODNN7EXAMPLE",
        "GitHub Token":   "ghp_" + "a" * 36,
        "Stripe Key":     "sk_live_" + "b" * 24,
        "Slack Token":    "xoxb-1234567890-abcdefghij",
    }
    for name, sample in cases.items():
        assert re.search(cf.JS_SECRET_PATTERNS[name][0], sample), name
