"""Ratchet for the shell-quoting debt.

YeepForge still builds many commands as shell strings. Each unquoted
interpolation is a spot where an operator-supplied or target-derived value is
parsed by the tester's own shell. The migration to utils/http.py is incremental,
so rather than blocking on a 500-site rewrite this test freezes the count: new
code must use the HTTP client (or build_curl/curl_flags), and every migrated
call site lowers the baseline.

If this fails with a *lower* number: well done - lower BASELINE to match.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from audit_shell_safety import scan_file, total_unsafe  # noqa: E402

#: Measured 2026-07-25 after migrating injection, broken_access_control,
#: open_redirect, ssrf, crypto_failures, security_misconfig, csrf and
#: session_security. Lower this as further modules move to the HTTP client.
BASELINE = 225


def test_unsafe_shell_interpolations_do_not_grow():
    total = total_unsafe()
    assert total <= BASELINE, (
        f"{total - BASELINE} new unquoted shell interpolation(s). "
        "Use utils.http.get_client(), or build_curl()/curl_flags() if the call "
        "must stay a shell command. Run: python3 scripts/audit_shell_safety.py --list"
    )


def test_audit_flags_an_unquoted_command(tmp_path):
    sample = tmp_path / "sample.py"
    sample.write_text('run_cmd(f\'curl -sk "{url}" -H "Cookie: {cookies}"\')\n')
    hits = scan_file(sample)
    assert len(hits) == 2


def test_audit_accepts_quoted_and_client_based_code(tmp_path):
    sample = tmp_path / "sample.py"
    sample.write_text(
        "import shlex\n"
        "run_cmd(f'curl -sk {shlex.quote(url)}')\n"
        "run_cmd(f'curl {curl_flags()} {build_curl(url)}')\n"
        "get_client().get(url)\n"
    )
    assert scan_file(sample) == []


def test_audit_ignores_menu_text_and_labels(tmp_path):
    sample = tmp_path / "sample.py"
    sample.write_text(
        'print(f"{NEON_CYN}[1]{RST} sqlmap (automated, full scan)")\n'
        'lines = [f"=== curl -I {url} ==="]\n'
    )
    assert scan_file(sample) == []
