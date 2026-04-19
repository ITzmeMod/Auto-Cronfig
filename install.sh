#!/usr/bin/env bash
# ============================================================
# Auto-Cronfig Universal Installer
# Works on: Linux, macOS, Termux (Android), WSL
# No root required on Android (Termux)
# ============================================================

set -e

REPO_URL="https://github.com/ITzmeMod/Auto-Cronfig.git"
INSTALL_DIR="$HOME/Auto-Cronfig"
BOLD="\033[1m"
GREEN="\033[0;32m"
CYAN="\033[0;36m"
RED="\033[0;31m"
RESET="\033[0m"

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════╗${RESET}"
echo -e "${CYAN}║  🔍 Auto-Cronfig Universal Installer     ║${RESET}"
echo -e "${CYAN}║  GitHub Secret & Vulnerability Scanner   ║${RESET}"
echo -e "${CYAN}╚══════════════════════════════════════════╝${RESET}"
echo ""

# ── Detect platform ─────────────────────────────────────────
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
echo -e "${BOLD}Platform detected:${RESET} $PLATFORM"
echo ""

# ── Install dependencies ─────────────────────────────────────
install_deps() {
    case "$PLATFORM" in
        termux)
            echo -e "${CYAN}📦 Installing via pkg (Termux)...${RESET}"
            pkg update -y 2>/dev/null || true
            pkg install -y python git 2>/dev/null || true
            ;;
        macos)
            echo -e "${CYAN}📦 Checking brew/python...${RESET}"
            if ! command -v python3 &>/dev/null; then
                if command -v brew &>/dev/null; then
                    brew install python git
                else
                    echo -e "${RED}Please install Python 3: https://python.org${RESET}"
                    exit 1
                fi
            fi
            ;;
        linux)
            echo -e "${CYAN}📦 Checking system Python...${RESET}"
            if ! command -v python3 &>/dev/null; then
                if command -v apt-get &>/dev/null; then
                    sudo apt-get install -y python3 python3-pip git
                elif command -v dnf &>/dev/null; then
                    sudo dnf install -y python3 python3-pip git
                elif command -v pacman &>/dev/null; then
                    sudo pacman -S --noconfirm python python-pip git
                else
                    echo -e "${RED}Please install Python 3 manually.${RESET}"
                    exit 1
                fi
            fi
            ;;
    esac
}

install_deps

# ── Check python ─────────────────────────────────────────────
PYTHON=""
for cmd in python3 python; do
    if command -v "$cmd" &>/dev/null; then
        PYTHON="$cmd"
        break
    fi
done

if [ -z "$PYTHON" ]; then
    echo -e "${RED}❌ Python not found. Please install Python 3.8+${RESET}"
    exit 1
fi

PYVER=$($PYTHON --version 2>&1)
echo -e "${GREEN}✓ Found: $PYVER${RESET}"

# ── Clone or update repo ─────────────────────────────────────
if [ -d "$INSTALL_DIR/.git" ]; then
    echo -e "${CYAN}🔄 Updating existing installation...${RESET}"
    cd "$INSTALL_DIR" && git pull
else
    echo -e "${CYAN}📥 Cloning Auto-Cronfig...${RESET}"
    git clone "$REPO_URL" "$INSTALL_DIR"
    cd "$INSTALL_DIR"
fi

# ── Install Python packages ──────────────────────────────────
echo -e "${CYAN}📦 Installing Python dependencies...${RESET}"
$PYTHON -m pip install --upgrade pip --quiet
$PYTHON -m pip install -r requirements.txt --quiet
echo -e "${GREEN}✓ Dependencies installed${RESET}"

# ── Verify install ───────────────────────────────────────────
echo ""
echo -e "${CYAN}🧪 Running tests...${RESET}"
cd "$INSTALL_DIR"
$PYTHON -m pytest tests/ -q 2>&1 | tail -3

# ── Create shortcut ──────────────────────────────────────────
SHORTCUT=""
if [ "$PLATFORM" = "termux" ]; then
    mkdir -p "$PREFIX/bin"
    SHORTCUT="$PREFIX/bin/auto-cronfig"
elif [ -d "$HOME/.local/bin" ]; then
    SHORTCUT="$HOME/.local/bin/auto-cronfig"
elif [ -d "/usr/local/bin" ] && [ -w "/usr/local/bin" ]; then
    SHORTCUT="/usr/local/bin/auto-cronfig"
fi

if [ -n "$SHORTCUT" ]; then
    cat > "$SHORTCUT" << EOF
#!/usr/bin/env bash
cd "$INSTALL_DIR" && $PYTHON scanner.py "\$@"
EOF
    chmod +x "$SHORTCUT"
    echo -e "${GREEN}✓ Shortcut created: auto-cronfig${RESET}"
fi

# ── Done ─────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════╗${RESET}"
echo -e "${GREEN}${BOLD}║  ✅ Auto-Cronfig installed successfully! ║${RESET}"
echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════╝${RESET}"
echo ""
echo -e "${BOLD}Quick start:${RESET}"
echo "  cd $INSTALL_DIR"
echo "  $PYTHON scanner.py --repo owner/repo"
echo "  $PYTHON scanner.py --user someusername --token ghp_xxx"
echo ""
if [ -n "$SHORTCUT" ]; then
    echo -e "  ${CYAN}Or from anywhere:${RESET} auto-cronfig --user someusername"
    echo ""
fi
echo -e "${CYAN}📱 Android/Termux guide: TERMUX.md${RESET}"
echo -e "${CYAN}📖 Full docs: README.md${RESET}"
echo ""
