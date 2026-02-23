#!/usr/bin/env bash
# AEON Universal Installer
# Usage: curl -fsSL https://raw.githubusercontent.com/aeon-lang/aeon/main/install.sh | bash
#
# Supports: macOS, Ubuntu/Debian, Fedora/RHEL, Arch Linux, Alpine
# Installs: Python 3.11+, AEON, z3-solver, llvmlite

set -euo pipefail

AEON_VERSION="${AEON_VERSION:-latest}"
AEON_REPO="https://github.com/aeon-lang/aeon.git"
AEON_INSTALL_DIR="${AEON_INSTALL_DIR:-$HOME/.aeon}"

# ── Colors ──────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

info()  { echo -e "${BLUE}[INFO]${NC} $1"; }
ok()    { echo -e "${GREEN}[OK]${NC} $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
err()   { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# ── Detect OS ───────────────────────────────────────
detect_os() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
    elif [[ -f /etc/os-release ]]; then
        . /etc/os-release
        case "$ID" in
            ubuntu|debian|pop|linuxmint|elementary) OS="debian" ;;
            fedora|rhel|centos|rocky|almalinux)     OS="fedora" ;;
            arch|manjaro|endeavouros)                OS="arch" ;;
            alpine)                                  OS="alpine" ;;
            *)                                       OS="linux-generic" ;;
        esac
    else
        OS="linux-generic"
    fi
    info "Detected OS: $OS"
}

# ── Check Python ────────────────────────────────────
check_python() {
    if command -v python3 &>/dev/null; then
        PY_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
        PY_MAJOR=$(echo "$PY_VERSION" | cut -d. -f1)
        PY_MINOR=$(echo "$PY_VERSION" | cut -d. -f2)
        if [[ "$PY_MAJOR" -ge 3 && "$PY_MINOR" -ge 10 ]]; then
            ok "Python $PY_VERSION found"
            return 0
        fi
    fi
    return 1
}

# ── Install Python ──────────────────────────────────
install_python() {
    info "Installing Python 3.11..."
    case "$OS" in
        macos)
            if command -v brew &>/dev/null; then
                brew install python@3.11
            else
                err "Homebrew not found. Install it first: https://brew.sh"
            fi
            ;;
        debian)
            sudo apt-get update -qq
            sudo apt-get install -y python3 python3-pip python3-venv
            ;;
        fedora)
            sudo dnf install -y python3 python3-pip
            ;;
        arch)
            sudo pacman -Sy --noconfirm python python-pip
            ;;
        alpine)
            sudo apk add python3 py3-pip
            ;;
        *)
            err "Cannot auto-install Python on this OS. Please install Python 3.10+ manually."
            ;;
    esac
}

# ── Install Git ─────────────────────────────────────
ensure_git() {
    if command -v git &>/dev/null; then
        return 0
    fi
    info "Installing git..."
    case "$OS" in
        macos)   brew install git ;;
        debian)  sudo apt-get install -y git ;;
        fedora)  sudo dnf install -y git ;;
        arch)    sudo pacman -Sy --noconfirm git ;;
        alpine)  sudo apk add git ;;
        *)       err "Please install git manually." ;;
    esac
}

# ── Install AEON ────────────────────────────────────
install_aeon() {
    info "Installing AEON to $AEON_INSTALL_DIR..."

    # Clone or update
    if [[ -d "$AEON_INSTALL_DIR" ]]; then
        info "Updating existing installation..."
        cd "$AEON_INSTALL_DIR"
        git pull --quiet
    else
        git clone --quiet "$AEON_REPO" "$AEON_INSTALL_DIR"
        cd "$AEON_INSTALL_DIR"
    fi

    # Checkout specific version if not latest
    if [[ "$AEON_VERSION" != "latest" ]]; then
        git checkout "v$AEON_VERSION" 2>/dev/null || git checkout "$AEON_VERSION"
    fi

    # Create virtual environment
    info "Creating virtual environment..."
    python3 -m venv "$AEON_INSTALL_DIR/.venv"
    source "$AEON_INSTALL_DIR/.venv/bin/activate"

    # Install dependencies
    info "Installing dependencies..."
    pip install --quiet --upgrade pip
    pip install --quiet -e "$AEON_INSTALL_DIR"
    pip install --quiet z3-solver llvmlite 2>/dev/null || warn "Some optional deps failed (z3/llvmlite); core features still work"

    deactivate
}

# ── Set up PATH ─────────────────────────────────────
setup_path() {
    # Create wrapper script
    mkdir -p "$HOME/.local/bin"
    cat > "$HOME/.local/bin/aeon" <<EOF
#!/usr/bin/env bash
source "$AEON_INSTALL_DIR/.venv/bin/activate"
python3 -m aeon.cli "\$@"
EOF
    chmod +x "$HOME/.local/bin/aeon"

    # Add to PATH if needed
    SHELL_RC=""
    if [[ -f "$HOME/.zshrc" ]]; then
        SHELL_RC="$HOME/.zshrc"
    elif [[ -f "$HOME/.bashrc" ]]; then
        SHELL_RC="$HOME/.bashrc"
    elif [[ -f "$HOME/.profile" ]]; then
        SHELL_RC="$HOME/.profile"
    fi

    if [[ -n "$SHELL_RC" ]]; then
        if ! grep -q '.local/bin' "$SHELL_RC" 2>/dev/null; then
            echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$SHELL_RC"
            info "Added ~/.local/bin to PATH in $SHELL_RC"
        fi
    fi

    export PATH="$HOME/.local/bin:$PATH"
}

# ── Main ────────────────────────────────────────────
main() {
    echo ""
    echo -e "${PURPLE}╔══════════════════════════════════════════╗${NC}"
    echo -e "${PURPLE}║         AEON Installer v0.3.0            ║${NC}"
    echo -e "${PURPLE}║   AI-Native Formal Verification          ║${NC}"
    echo -e "${PURPLE}╚══════════════════════════════════════════╝${NC}"
    echo ""

    detect_os
    ensure_git

    if ! check_python; then
        install_python
        check_python || err "Python installation failed"
    fi

    install_aeon
    setup_path

    echo ""
    echo -e "${GREEN}══════════════════════════════════════════${NC}"
    echo -e "${GREEN} AEON installed successfully!${NC}"
    echo -e "${GREEN}══════════════════════════════════════════${NC}"
    echo ""
    echo "  Verify a file:  aeon check your_code.py --deep-verify"
    echo "  Start API:      aeon-api --port 8000"
    echo "  Run tests:      aeon test --all"
    echo ""
    echo "  Supported languages: Python, Java, JavaScript, TypeScript,"
    echo "                       Go, Rust, C/C++, Ruby"
    echo ""
    echo -e "  ${YELLOW}Restart your shell or run:${NC} source $SHELL_RC"
    echo ""
}

main "$@"
