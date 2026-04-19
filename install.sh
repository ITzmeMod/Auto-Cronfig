#!/usr/bin/env bash
# ============================================================
# Auto-Cronfig Universal Installer
# Supports: Linux · macOS · Termux (Android) · WSL
# No root required on Android
# ============================================================

set -e

REPO_URL="https://github.com/ITzmeMod/Auto-Cronfig.git"
INSTALL_DIR="$HOME/Auto-Cronfig"
BOLD="\033[1m"
GREEN="\033[0;32m"
CYAN="\033[0;36m"
YELLOW="\033[0;33m"
RED="\033[0;31m"
DIM="\033[2m"
RESET="\033[0m"

echo ""
echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════╗${RESET}"
echo -e "${CYAN}${BOLD}║   🔍  Auto-Cronfig  —  Universal Installer   ║${RESET}"
echo -e "${CYAN}${BOLD}║   GitHub Secret Scanner  ·  v3.0.0           ║${RESET}"
echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════╝${RESET}"
echo ""

# ── Detect platform ──────────────────────────────────────────
detect_platform() {
    if [ -n "$TERMUX_VERSION" ] || [ -d "/data/data/com.termux" ]; then
        echo "termux"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macos"
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        echo "linux"
    elif [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" ]]; then
        echo "windows"
    else
        echo "unknown"
    fi
}

PLATFORM=$(detect_platform)
echo -e "  ${BOLD}Platform detected:${RESET} ${CYAN}$PLATFORM${RESET}"
echo ""

# ── Install system dependencies ──────────────────────────────
install_system_deps() {
    case "$PLATFORM" in
        termux)
            echo -e "  ${CYAN}📦 Installing packages via pkg (Termux)…${RESET}"
            pkg update -y 2>/dev/null || true
            pkg install -y python git nodejs curl 2>/dev/null || true
            echo -e "  ${GREEN}✓ System packages installed${RESET}"
            ;;
        macos)
            echo -e "  ${CYAN}📦 Checking macOS dependencies…${RESET}"
            if ! command -v python3 &>/dev/null; then
                if command -v brew &>/dev/null; then
                    brew install python git node
                else
                    echo -e "  ${RED}✗ Python 3 not found. Install from: https://python.org${RESET}"
                    exit 1
                fi
            fi
            if ! command -v node &>/dev/null; then
                command -v brew &>/dev/null && brew install node || true
            fi
            ;;
        linux)
            echo -e "  ${CYAN}📦 Checking Linux dependencies…${RESET}"
            if ! command -v python3 &>/dev/null; then
                if command -v apt-get &>/dev/null; then
                    sudo apt-get install -y python3 python3-pip git curl
                elif command -v dnf &>/dev/null; then
                    sudo dnf install -y python3 python3-pip git curl
                elif command -v pacman &>/dev/null; then
                    sudo pacman -S --noconfirm python python-pip git curl
                else
                    echo -e "  ${RED}✗ Please install Python 3 manually.${RESET}"
                    exit 1
                fi
            fi
            if ! command -v node &>/dev/null; then
                command -v apt-get &>/dev/null && sudo apt-get install -y nodejs || true
                command -v dnf &>/dev/null && sudo dnf install -y nodejs || true
            fi
            ;;
        windows)
            echo -e "  ${YELLOW}⚠  Windows detected. Make sure Python 3 and Node.js are installed.${RESET}"
            echo -e "  ${DIM}  Python: https://python.org/downloads${RESET}"
            echo -e "  ${DIM}  Node.js: https://nodejs.org${RESET}"
            ;;
    esac
}

install_system_deps

# ── Check Python ──────────────────────────────────────────────
PYTHON=""
for cmd in python3 python; do
    if command -v "$cmd" &>/dev/null; then
        PYTHON="$cmd"
        break
    fi
done

if [ -z "$PYTHON" ]; then
    echo -e "  ${RED}✗ Python not found. Please install Python 3.8+${RESET}"
    exit 1
fi

PYVER=$($PYTHON --version 2>&1)
echo -e "  ${GREEN}✓ Found: $PYVER${RESET}"

# ── Check Node.js ─────────────────────────────────────────────
if command -v node &>/dev/null; then
    NODEVER=$(node --version 2>&1)
    echo -e "  ${GREEN}✓ Found: Node.js $NODEVER${RESET}"
    HAS_NODE=true
else
    echo -e "  ${YELLOW}⚠  Node.js not found — paste/web scraping will be disabled${RESET}"
    echo -e "  ${DIM}  Install later: pkg install nodejs (Termux) / apt install nodejs (Linux)${RESET}"
    HAS_NODE=false
fi

echo ""

# ── Clone or update repo ──────────────────────────────────────
if [ -d "$INSTALL_DIR/.git" ]; then
    echo -e "  ${CYAN}🔄 Updating existing installation…${RESET}"
    cd "$INSTALL_DIR"
    git pull --quiet
    echo -e "  ${GREEN}✓ Updated to latest version${RESET}"
else
    echo -e "  ${CYAN}📥 Cloning Auto-Cronfig…${RESET}"
    git clone --quiet "$REPO_URL" "$INSTALL_DIR"
    cd "$INSTALL_DIR"
    echo -e "  ${GREEN}✓ Cloned to $INSTALL_DIR${RESET}"
fi

cd "$INSTALL_DIR"

# ── Install Python packages ───────────────────────────────────
echo ""
echo -e "  ${CYAN}📦 Installing Python dependencies…${RESET}"
$PYTHON -m pip install --upgrade pip --quiet 2>/dev/null || true
$PYTHON -m pip install -r requirements.txt --quiet
echo -e "  ${GREEN}✓ Python packages installed (includes interactive menu)${RESET}"

# ── Install Node.js packages ──────────────────────────────────
if [ "$HAS_NODE" = true ] && [ -f "package.json" ]; then
    echo ""
    echo -e "  ${CYAN}📦 Installing Node.js dependencies (axios, cheerio)…${RESET}"
    npm install --quiet 2>/dev/null
    echo -e "  ${GREEN}✓ Node.js packages installed${RESET}"
fi

# ── Run test suite ────────────────────────────────────────────
echo ""
echo -e "  ${CYAN}🧪 Running tests to verify installation…${RESET}"
if $PYTHON -m pytest tests/ -q 2>&1 | tail -1 | grep -q "passed"; then
    RESULT=$($PYTHON -m pytest tests/ -q 2>&1 | tail -1)
    echo -e "  ${GREEN}✓ Tests: $RESULT${RESET}"
else
    echo -e "  ${YELLOW}⚠  Some tests may have failed. The tool should still work.${RESET}"
fi

# ── Create shortcuts ──────────────────────────────────────────
echo ""
MENU_SHORTCUT=""
CLI_SHORTCUT=""

if [ "$PLATFORM" = "termux" ]; then
    mkdir -p "$PREFIX/bin"
    MENU_SHORTCUT="$PREFIX/bin/auto-cronfig"
    CLI_SHORTCUT="$PREFIX/bin/auto-cronfig-cli"
elif [ -d "$HOME/.local/bin" ]; then
    mkdir -p "$HOME/.local/bin"
    MENU_SHORTCUT="$HOME/.local/bin/auto-cronfig"
    CLI_SHORTCUT="$HOME/.local/bin/auto-cronfig-cli"
elif [ -d "/usr/local/bin" ] && [ -w "/usr/local/bin" ]; then
    MENU_SHORTCUT="/usr/local/bin/auto-cronfig"
    CLI_SHORTCUT="/usr/local/bin/auto-cronfig-cli"
fi

if [ -n "$MENU_SHORTCUT" ]; then
    # Interactive menu shortcut
    cat > "$MENU_SHORTCUT" << EOF
#!/usr/bin/env bash
# Auto-Cronfig interactive menu
cd "$INSTALL_DIR" && $PYTHON menu.py "\$@"
EOF
    chmod +x "$MENU_SHORTCUT"

    # CLI shortcut
    cat > "$CLI_SHORTCUT" << EOF
#!/usr/bin/env bash
# Auto-Cronfig CLI scanner
cd "$INSTALL_DIR" && $PYTHON scanner.py "\$@"
EOF
    chmod +x "$CLI_SHORTCUT"

    echo -e "  ${GREEN}✓ Shortcuts created:${RESET}"
    echo -e "     ${CYAN}auto-cronfig${RESET}      — interactive menu"
    echo -e "     ${CYAN}auto-cronfig-cli${RESET}  — direct CLI scanner"
fi

# ── Print completion message ──────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════╗${RESET}"
echo -e "${GREEN}${BOLD}║   ✅  Auto-Cronfig installed successfully!   ║${RESET}"
echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════╝${RESET}"
echo ""
echo -e "  ${BOLD}🚀 Launch interactive menu:${RESET}"
echo ""
if [ -n "$MENU_SHORTCUT" ]; then
echo -e "     ${CYAN}auto-cronfig${RESET}                         (from anywhere)"
fi
echo -e "     ${CYAN}cd $INSTALL_DIR && $PYTHON menu.py${RESET}"
echo ""
echo -e "  ${BOLD}📋 CLI commands:${RESET}"
echo ""
echo -e "     ${DIM}# Scan a repo or user${RESET}"
echo -e "     ${CYAN}$PYTHON scanner.py scan --repo owner/repo --token ghp_xxx${RESET}"
echo -e "     ${CYAN}$PYTHON scanner.py scan --user username   --token ghp_xxx${RESET}"
echo ""
echo -e "     ${DIM}# VibeScan — NEW AI repos (highest hit rate)${RESET}"
echo -e "     ${CYAN}$PYTHON scanner.py vibe --token ghp_xxx${RESET}"
echo -e "     ${CYAN}$PYTHON scanner.py vibe --platform lovable --token ghp_xxx${RESET}"
echo -e "     ${CYAN}$PYTHON scanner.py vibe --days 1 --token ghp_xxx${RESET}"
echo ""
echo -e "     ${DIM}# Global scan — all 200+ queries across GitHub${RESET}"
echo -e "     ${CYAN}$PYTHON scanner.py global --token ghp_xxx${RESET}"
echo ""
echo -e "     ${DIM}# Deep scan (commits + PRs + issues + gists)${RESET}"
echo -e "     ${CYAN}$PYTHON scanner.py deep --repo owner/repo --token ghp_xxx${RESET}"
echo ""
echo -e "     ${DIM}# Export HTML/JSON report${RESET}"
echo -e "     ${CYAN}$PYTHON scanner.py vibe --token ghp_xxx --output report.html${RESET}"
echo ""
echo -e "  ${BOLD}🔑 Get a GitHub token (recommended):${RESET}"
echo -e "     ${DIM}https://github.com/settings/tokens → repo scope${RESET}"
echo ""
echo -e "  ${BOLD}📱 Android/Termux guide:${RESET}  TERMUX.md"
echo -e "  ${BOLD}📖 Full documentation:${RESET}    README.md"
echo -e "  ${BOLD}🔒 Security policy:${RESET}       SECURITY.md"
echo ""
if [ "$PLATFORM" = "termux" ]; then
echo -e "  ${YELLOW}💡 Tip: Run ${CYAN}termux-setup-storage${YELLOW} to access phone storage${RESET}"
echo -e "  ${YELLOW}💡 Tip: Install ${CYAN}Termux:API${YELLOW} from F-Droid for push notifications${RESET}"
echo ""
fi
