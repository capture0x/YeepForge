#!/bin/bash
# YeepForge - Installation Script
set -e

GREEN='\033[38;2;0;255;65m'
CYAN='\033[38;2;0;230;255m'
RED='\033[38;2;255;60;60m'
BOLD='\033[1m'
RST='\033[0m'

echo -e "\n${GREEN}${BOLD}╔══════════════════════════════════════════════╗"
echo -e "║  YeepForge - Web Pentest Framework Install   ║"
echo -e "╚══════════════════════════════════════════════╝${RST}\n"

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Python dependencies
echo -e "${CYAN}[*] Installing Python dependencies...${RST}"
pip install -r "$DIR/requirements.txt" --quiet

# APT tools
echo -e "${CYAN}[*] Installing APT security tools...${RST}"
apt-get update -qq 2>/dev/null || true
TOOLS="nmap nikto sqlmap gobuster ffuf dirb feroxbuster hydra hashcat john \
       wpscan wafw00f whatweb masscan netcat-openbsd curl jq python3-pip"

for tool in $TOOLS; do
    if ! command -v "$tool" &>/dev/null; then
        echo -e "  ${CYAN}Installing ${tool}...${RST}"
        apt-get install -y "$tool" -qq 2>/dev/null || echo -e "  ${RED}Failed: $tool${RST}"
    else
        echo -e "  ${GREEN}[✓] $tool${RST}"
    fi
done

# Python tools via pip
echo -e "\n${CYAN}[*] Installing Python security tools...${RST}"
PIP_TOOLS="xsstrike droopescan subfinder wafw00f"
for t in $PIP_TOOLS; do
    pip install "$t" --quiet 2>/dev/null && echo -e "  ${GREEN}[✓] $t${RST}" || echo -e "  ${RED}[✗] $t${RST}"
done

# Go tools (if Go is installed)
if command -v go &>/dev/null; then
    echo -e "\n${CYAN}[*] Installing Go security tools...${RST}"
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null && \
        echo -e "  ${GREEN}[✓] subfinder${RST}" || echo -e "  ${RED}[✗] subfinder${RST}"
    go install github.com/hahwul/dalfox/v2@latest 2>/dev/null && \
        echo -e "  ${GREEN}[✓] dalfox${RST}" || echo -e "  ${RED}[✗] dalfox${RST}"
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null && \
        echo -e "  ${GREEN}[✓] nuclei${RST}" || echo -e "  ${RED}[✗] nuclei${RST}"
fi

# Headless browser crawling (optional - pulls a ~150MB Chromium build).
# Opt in with:  INSTALL_BROWSER=1 ./install.sh
if [ "${INSTALL_BROWSER:-0}" = "1" ]; then
    echo -e "\n${CYAN}[*] Installing headless browser support (Playwright + Chromium)...${RST}"
    pip install "playwright>=1.40" --quiet \
        && python3 -m playwright install chromium \
        && echo -e "  ${GREEN}[✓] Playwright + Chromium${RST}" \
        || echo -e "  ${RED}[✗] Playwright browser setup failed${RST}"
else
    echo -e "\n${CYAN}[i] Headless browser crawling is optional (needed only for JS apps).${RST}"
    echo -e "    ${CYAN}Enable it with:  INSTALL_BROWSER=1 ./install.sh${RST}"
    echo -e "    ${CYAN}or manually:     pip install 'playwright>=1.40' && playwright install chromium${RST}"
fi

# Create .env if missing
if [ ! -f "$DIR/.env" ]; then
    cp "$DIR/.env.example" "$DIR/.env"
    echo -e "\n${CYAN}[*] Created .env from template - edit it to configure your engagement${RST}"
fi

# Permissions
chmod +x "$DIR/run.sh"
mkdir -p "$DIR/output" "$DIR/reports" "$DIR/wordlists"

echo -e "\n${GREEN}${BOLD}[✓] YeepForge installed successfully!${RST}"
echo -e "${CYAN}Run: ./run.sh  (uses the project venv; falls back to system python3)${RST}\n"
