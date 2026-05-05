#!/bin/bash
# ==============================================================================
#  fitijoe Tools Installer
#  Author : fitijoe (MohamedSuleiman)
#  GitHub : https://github.com/fitijoe
# ==============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'

echo -e "${CYAN}${BOLD}"
echo "  _____ _____ _____ _     _     ___  _____ "
echo " |  ___|_   _|_   _| |   | |   / _ \|  ___|"
echo " | |_    | |   | | | |   | |  | | | | |_   "
echo " |  _|   | |   | | | |___| |__| |_| |  _|  "
echo " |_|     |_|   |_| |_____|_____\___/|_|    "
echo -e "${NC}"
echo -e "  ${CYAN}fitijoe Tools Installer${NC}"
echo -e "  ${CYAN}Author: fitijoe (MohamedSuleiman)${NC}"
echo -e "  ${CYAN}GitHub: https://github.com/fitijoe${NC}"
echo ""
echo -e "  ─────────────────────────────────────────"
echo ""

# Check if running on Kali Linux
if ! grep -q "kali" /etc/os-release 2>/dev/null; then
    echo -e "  ${YELLOW}[!] Warning: This tool is optimized for Kali Linux${NC}"
    echo -e "  ${YELLOW}    It may work on other Debian-based systems${NC}"
    echo ""
fi

# Check if running as root or with sudo
if [ "$EUID" -ne 0 ]; then
    echo -e "  ${YELLOW}[!] Some installations require sudo privileges${NC}"
    echo ""
fi

install_tool() {
    local tool=$1
    local package=$2
    if ! command -v "$tool" &>/dev/null; then
        echo -e "  ${YELLOW}[*]${NC} Installing $tool..."
        sudo apt install -y "$package" -qq 2>/dev/null
        if command -v "$tool" &>/dev/null; then
            echo -e "  ${GREEN}[+]${NC} $tool installed successfully"
        else
            echo -e "  ${RED}[-]${NC} Failed to install $tool — install manually"
        fi
    else
        echo -e "  ${GREEN}[+]${NC} $tool already installed ✓"
    fi
}

install_go_tool() {
    local tool=$1
    local pkg=$2
    if ! command -v "$tool" &>/dev/null; then
        echo -e "  ${YELLOW}[*]${NC} Installing $tool (Go)..."
        go install "$pkg" 2>/dev/null
        if command -v "$tool" &>/dev/null; then
            echo -e "  ${GREEN}[+]${NC} $tool installed successfully"
        else
            echo -e "  ${YELLOW}[!]${NC} $tool — add ~/go/bin to PATH:"
            echo -e "      export PATH=\$PATH:~/go/bin"
        fi
    else
        echo -e "  ${GREEN}[+]${NC} $tool already installed ✓"
    fi
}

# Update package list
echo -e "  ${CYAN}[*] Updating package list...${NC}"
sudo apt update -qq 2>/dev/null
echo ""

# Required tools
echo -e "  ${BOLD}Installing required tools...${NC}"
install_tool "nmap"      "nmap"
install_tool "nikto"     "nikto"
install_tool "whatweb"   "whatweb"
install_tool "curl"      "curl"
install_tool "dig"       "dnsutils"
install_tool "whois"     "whois"
echo ""

# Optional tools
echo -e "  ${BOLD}Installing optional tools...${NC}"
install_tool "gobuster"  "gobuster"
install_tool "ffuf"      "ffuf"
install_tool "sqlmap"    "sqlmap"
install_tool "sslscan"   "sslscan"
install_tool "wafw00f"   "wafw00f"
install_tool "wpscan"    "wpscan"
install_tool "hydra"     "hydra"
install_tool "dirb"      "dirb"
install_tool "exiftool"  "libimage-exiftool-perl"
install_tool "smbclient" "smbclient"
echo ""

# Go tools
if command -v go &>/dev/null; then
    echo -e "  ${BOLD}Installing Go-based tools...${NC}"
    install_go_tool "subfinder" "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    install_go_tool "httpx"     "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    install_go_tool "nuclei"    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    install_go_tool "dnsx"      "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    echo ""
else
    echo -e "  ${YELLOW}[!] Go not installed — skipping Go tools${NC}"
    echo -e "  ${YELLOW}    Install Go: sudo apt install golang -y${NC}"
    echo ""
fi

# Python tools
echo -e "  ${BOLD}Installing Python tools...${NC}"
if command -v pip3 &>/dev/null; then
    pip3 install arjun --break-system-packages -q 2>/dev/null && \
        echo -e "  ${GREEN}[+]${NC} arjun installed ✓" || \
        echo -e "  ${RED}[-]${NC} arjun failed"
    pip3 install jwt_tool --break-system-packages -q 2>/dev/null && \
        echo -e "  ${GREEN}[+]${NC} jwt_tool installed ✓" || \
        echo -e "  ${RED}[-]${NC} jwt_tool failed"
else
    echo -e "  ${YELLOW}[!] pip3 not found — skipping Python tools${NC}"
fi
echo ""

# Make all tools executable
echo -e "  ${BOLD}Making tools executable...${NC}"
chmod +x *.py 2>/dev/null && echo -e "  ${GREEN}[+]${NC} All .py files made executable ✓"
echo ""

# Done
echo -e "  ${GREEN}${BOLD}✓ Installation complete!${NC}"
echo ""
echo -e "  ${CYAN}How to use your tools:${NC}"
echo -e "  ${CYAN}─────────────────────────────────────────${NC}"
echo -e "  python3 fitijoe-pentest-tool.py     -t http://target.com"
echo -e "  python3 fitijoe-api-tester.py       -t https://api.target.com"
echo -e "  python3 fitijoe-osint.py            -d target.com"
echo -e "  python3 fitijoe-cms-scanner.py      -t http://wordpress-site.com"
echo ""
echo -e "  ${YELLOW}⚠  For authorized testing only!${NC}"
echo -e "  ${YELLOW}   Always get permission before scanning any target.${NC}"
echo ""
