"""constants.py - YeepForge Agent configuration"""
import os
from pathlib import Path

from config.settings import OUTPUT_DIR
from utils.helpers import NEON_CYN, NEON_GRN, PURE_WHITE, SOFT_WHITE

MODEL      = "claude-opus-4-7"
MAX_TOKENS = 4096
MAX_ROUNDS = 30

LOG_DIR           = Path(OUTPUT_DIR) / "agent_logs"
AGENT_RUNTIME_DIR = Path(OUTPUT_DIR) / "agent_runtime"
LOG_DIR.mkdir(exist_ok=True)
AGENT_RUNTIME_DIR.mkdir(exist_ok=True)

AGENT_LIVE_COMMANDS = os.environ.get("YEEPFORGE_AGENT_LIVE_COMMANDS", "true").lower() in ("1", "true", "yes")
OLLAMA_API_TIMEOUT  = int(os.environ.get("YEEPFORGE_OLLAMA_TIMEOUT", "60"))
OPSEC_MODE          = os.environ.get("YEEPFORGE_OPSEC", "normal").lower()  # loud/normal/stealth

AGENT_GREEN = NEON_GRN
AGENT_CYAN  = NEON_CYN
AGENT_TEXT  = SOFT_WHITE
AGENT_WHITE = PURE_WHITE
