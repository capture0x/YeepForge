"""logger.py - YeepForge Agent Markdown report logger"""
import re
from datetime import datetime
from pathlib import Path

from config.settings import SESSION

_ANSI_RE = re.compile(r'\x1b\[[0-9;]*[mABCDEFGHJKSTfhilmnprsu]')


def _strip_ansi(text: str) -> str:
    return _ANSI_RE.sub('', str(text))


_SEV_EMOJI = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🟢",
    "info":     "🔵",
}


class AgentMarkdownLog:
    """Append-only markdown log for a YeepForge agent run."""

    def __init__(self, path: Path, target_url: str, model: str) -> None:
        self.path = Path(path)
        self._lines: list[str] = []
        engagement = SESSION.get("engagement", "Web Pentest")
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        self._lines += [
            "# tmrswrr Agent Report\n\n",
            "| Field       | Value |\n",
            "|-------------|-------|\n",
            f"| **Target**  | `{target_url}` |\n",
            f"| **Date**    | {now} |\n",
            f"| **Model**   | {model} |\n",
            f"| **Engagement** | {engagement} |\n",
            "\n---\n\n",
        ]
        self._flush()

    # ------------------------------------------------------------------
    def add_round(self, round_num: int, tool_name: str, args: dict,
                  result: str, commands: list = None) -> None:
        """Append a tool-call section."""
        safe_result = _strip_ansi(result or "")
        if len(safe_result) > 4000:
            safe_result = safe_result[:4000] + "\n... (truncated)"

        block = [
            f"\n## Round {round_num} - `{tool_name}`\n\n",
            "**Arguments:**\n\n",
            "```json\n",
            f"{_strip_ansi(str(args))}\n",
            "```\n\n",
        ]
        if commands:
            block += [
                "**Commands run:**\n\n",
                "```\n",
            ]
            for cmd in commands:
                block.append(f"{_strip_ansi(cmd)}\n")
            block.append("```\n\n")

        block += [
            "**Result:**\n\n",
            "```\n",
            f"{safe_result}\n",
            "```\n\n",
        ]
        self._lines.extend(block)
        self._flush()

    # ------------------------------------------------------------------
    def add_finding(self, title: str, severity: str, description: str,
                    owasp: str = "") -> None:
        """Append a confirmed vulnerability finding."""
        sev_lower = severity.lower()
        emoji = _SEV_EMOJI.get(sev_lower, "⚪")
        block = [
            f"\n### {emoji} {_strip_ansi(title)}\n\n",
            f"- **Severity:** {severity}\n",
        ]
        if owasp:
            block.append(f"- **OWASP:** {owasp}\n")
        block += [
            f"\n{_strip_ansi(description)}\n\n",
        ]
        self._lines.extend(block)
        self._flush()

    # ------------------------------------------------------------------
    def add_summary(self, round_num: int, status: str, findings: list) -> None:
        """Write final summary table grouped by severity."""
        sev_order = ["Critical", "High", "Medium", "Low", "Info"]

        grouped: dict[str, list] = {s: [] for s in sev_order}
        for f in findings:
            sev = f.get("severity", "Info")
            bucket = sev if sev in grouped else "Info"
            grouped[bucket].append(f)

        block = [
            "\n---\n\n",
            "## Assessment Summary\n\n",
            f"- **Total rounds:** {round_num}\n",
            f"- **Status:** {status}\n",
            f"- **Total findings:** {len(findings)}\n\n",
            "### Findings by Severity\n\n",
            "| Severity | Count | Titles |\n",
            "|----------|-------|--------|\n",
        ]
        for sev in sev_order:
            items = grouped[sev]
            if not items:
                continue
            emoji = _SEV_EMOJI.get(sev.lower(), "⚪")
            titles = "; ".join(_strip_ansi(f.get("title", "?")) for f in items)
            block.append(f"| {emoji} {sev} | {len(items)} | {titles} |\n")

        block.append("\n")
        self._lines.extend(block)
        self._flush()

    # ------------------------------------------------------------------
    def _flush(self) -> None:
        """Write accumulated lines to disk (strips ANSI)."""
        text = "".join(self._lines)
        text = _strip_ansi(text)
        self.path.write_text(text, encoding="utf-8")
