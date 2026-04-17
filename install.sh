#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════════╗
# ║   HackLens — Web Recon & Vulnerability Scanner                       ║
# ║   Installer Script                                                    ║
# ║                                                                       ║
# ║   Created by  : Yogesh Bhandage                                       ║
# ║   Website     : yogeshbhandage.com                                    ║
# ║   Built with AI using original ideas by the author                   ║
# ║                                                                       ║
# ║   ⚠  For Authorized Security Testing Only                            ║
# ╚══════════════════════════════════════════════════════════════════════╝

set -e

# ── Colors ────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; MAGENTA='\033[0;35m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}[*]${RESET} $1"; }
success() { echo -e "${GREEN}[+]${RESET} $1"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $1"; }
error()   { echo -e "${RED}[-]${RESET} $1"; exit 1; }
section() {
    echo ""
    echo -e "${MAGENTA}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo -e "${MAGENTA}${BOLD}  $1${RESET}"
    echo -e "${MAGENTA}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
}

# ── Banner ─────────────────────────────────────────────────────────────────
echo -e "${GREEN}${BOLD}"
cat << 'BANNER'
  ██╗  ██╗ █████╗  ██████╗██╗  ██╗██╗     ███████╗███╗   ██╗███████╗
  ██║  ██║██╔══██╗██╔════╝██║ ██╔╝██║     ██╔════╝████╗  ██║██╔════╝
  ███████║███████║██║     █████╔╝ ██║     █████╗  ██╔██╗ ██║███████╗
  ██╔══██║██╔══██║██║     ██╔═██╗ ██║     ██╔══╝  ██║╚██╗██║╚════██║
  ██║  ██║██║  ██║╚██████╗██║  ██╗███████╗███████╗██║ ╚████║███████║
  ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═══╝╚══════╝
BANNER
echo -e "${RESET}${CYAN}  Web Recon & Vulnerability Scanner${RESET}"
echo -e "${CYAN}  Created by Yogesh Bhandage | yogeshbhandage.com${RESET}"
echo -e "${CYAN}  Installer v1.0${RESET}"
echo ""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Detect OS ─────────────────────────────────────────────────────────────
detect_os() {
    section "Detecting Operating System"
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if   command -v apt-get &>/dev/null; then OS="debian"
        elif command -v yum     &>/dev/null; then OS="rhel"
        elif command -v pacman  &>/dev/null; then OS="arch"
        else OS="linux"; fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
    else
        OS="unknown"
    fi
    success "OS detected: $OS"
}

# ── System Packages ───────────────────────────────────────────────────────
install_system_deps() {
    section "Installing System Packages"
    case $OS in
        debian)
            sudo apt-get update -qq
            sudo apt-get install -y -qq \
                python3 python3-pip python3-venv python3-dev \
                golang-go git curl wget unzip \
                build-essential libssl-dev libpcap-dev \
                2>/dev/null || warn "Some packages failed — continuing"
            ;;
        rhel)
            sudo yum install -y -q \
                python3 python3-pip golang git curl wget \
                libpcap-devel 2>/dev/null || warn "Some packages failed"
            ;;
        arch)
            sudo pacman -Sy --noconfirm \
                python python-pip go git curl wget libpcap \
                2>/dev/null || warn "Some packages failed"
            ;;
        macos)
            command -v brew &>/dev/null || {
                info "Installing Homebrew..."
                /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
            }
            brew install python3 go git curl wget libpcap 2>/dev/null || warn "Some brew packages failed"
            ;;
        *)
            warn "Unknown OS — please install python3, go, git, libpcap manually"
            ;;
    esac
    success "System packages done"
}

# ── Python Virtual Environment ────────────────────────────────────────────
setup_python() {
    section "Setting Up Python Virtual Environment"
    VENV_DIR="$SCRIPT_DIR/venv"

    if [ ! -d "$VENV_DIR" ]; then
        info "Creating virtual environment at $VENV_DIR ..."
        python3 -m venv "$VENV_DIR"
    else
        info "Virtual environment already exists — upgrading packages"
    fi

    source "$VENV_DIR/bin/activate"

    info "Upgrading pip..."
    "$VENV_DIR/bin/pip3" install --upgrade pip setuptools wheel -q

    info "Installing Python dependencies..."
    "$VENV_DIR/bin/pip3" install -q \
        requests \
        jsbeautifier \
        beautifulsoup4 \
        colorama \
        lxml \
        urllib3 \
        certifi \
        charset-normalizer

    success "Python environment ready at $VENV_DIR"
}

# ── Go Environment ────────────────────────────────────────────────────────
setup_go() {
    section "Setting Up Go Environment"

    if command -v go &>/dev/null; then
        success "Go already installed: $(go version)"
    else
        warn "Go not found — attempting install..."
        case $OS in
            debian|rhel|linux)
                GO_VER="1.22.0"
                ARCH=$(uname -m)
                [[ "$ARCH" == "x86_64" ]] && GOARCH="amd64" || GOARCH="arm64"
                info "Downloading Go $GO_VER ($GOARCH)..."
                wget -q "https://go.dev/dl/go${GO_VER}.linux-${GOARCH}.tar.gz" -O /tmp/go.tar.gz
                sudo rm -rf /usr/local/go
                sudo tar -C /usr/local -xzf /tmp/go.tar.gz
                rm -f /tmp/go.tar.gz
                ;;
            macos)
                brew install go
                ;;
            *)
                warn "Please install Go manually: https://go.dev/dl/"
                return 0
                ;;
        esac
    fi

    # Set GOPATH permanently
    export GOPATH="$HOME/go"
    export PATH="$PATH:$GOPATH/bin:/usr/local/go/bin"

    for shell_rc in ~/.bashrc ~/.zshrc ~/.bash_profile; do
        [ -f "$shell_rc" ] || continue
        grep -q "GOPATH" "$shell_rc" 2>/dev/null || echo 'export GOPATH=$HOME/go' >> "$shell_rc"
        grep -q "\$GOPATH/bin" "$shell_rc" 2>/dev/null || echo 'export PATH=$PATH:$GOPATH/bin:/usr/local/go/bin' >> "$shell_rc"
    done

    success "Go environment configured: GOPATH=$HOME/go"
}

# ── Install a Go Tool ─────────────────────────────────────────────────────
install_go_tool() {
    local name="$1"
    local pkg="$2"
    local check="${3:-$name}"

    export GOPATH="$HOME/go"
    export PATH="$PATH:$GOPATH/bin:/usr/local/go/bin"

    if command -v "$check" &>/dev/null; then
        success "$name — already installed"
        return 0
    fi

    info "Installing $name..."
    if GOPATH="$HOME/go" go install "$pkg" 2>/dev/null; then
        # Copy to /usr/local/bin for global access
        [[ -f "$HOME/go/bin/$name" ]] && sudo cp -f "$HOME/go/bin/$name" /usr/local/bin/ 2>/dev/null || true
        command -v "$name" &>/dev/null && success "$name — installed ✓" || warn "$name — installed but not in PATH (run: source ~/.bashrc)"
    else
        warn "$name — install failed (non-critical, tool will gracefully skip)"
    fi
}

# ── Go-Based Recon Tools ──────────────────────────────────────────────────
install_go_tools() {
    section "Installing Go-Based Recon Tools"

    export GOPATH="$HOME/go"
    export PATH="$PATH:$GOPATH/bin:/usr/local/go/bin"

    # ── JS & URL Collectors ──
    install_go_tool "katana"      "github.com/projectdiscovery/katana/cmd/katana@latest"
    install_go_tool "gau"         "github.com/lc/gau/v2/cmd/gau@latest"
    install_go_tool "hakrawler"   "github.com/hakluke/hakrawler@latest"
    install_go_tool "subjs"       "github.com/lc/subjs@latest"
    install_go_tool "waybackurls" "github.com/tomnomnom/waybackurls@latest"

    # ── Subdomain Enumeration ──
    install_go_tool "subfinder"   "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    install_go_tool "assetfinder" "github.com/tomnomnom/assetfinder@latest"
    install_go_tool "httpx"       "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    install_go_tool "httprobe"    "github.com/tomnomnom/httprobe@latest"

    # ── Vulnerability Scanning ──
    install_go_tool "nuclei"      "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"

    success "Go tools installation complete"
}

# ── TruffleHog ────────────────────────────────────────────────────────────
install_trufflehog() {
    section "Installing TruffleHog"
    if command -v trufflehog &>/dev/null; then
        success "TruffleHog already installed"
        return
    fi
    info "Installing TruffleHog via official script..."
    if curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
        | sh -s -- -b /usr/local/bin 2>/dev/null; then
        success "TruffleHog installed"
    else
        warn "TruffleHog auto-install failed"
        echo -e "  Manual install: ${CYAN}curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin${RESET}"
    fi
}

# ── Amass ─────────────────────────────────────────────────────────────────
install_amass() {
    section "Installing Amass"
    if command -v amass &>/dev/null; then
        success "Amass already installed"
        return
    fi
    if command -v apt-get &>/dev/null; then
        sudo apt-get install -y amass 2>/dev/null && success "Amass installed via apt" && return
    fi
    if command -v snap &>/dev/null; then
        sudo snap install amass 2>/dev/null && success "Amass installed via snap" && return
    fi
    install_go_tool "amass" "github.com/owasp-amass/amass/v4/...@master"
}

# ── Copy all Go bins to /usr/local/bin ───────────────────────────────────
copy_go_bins() {
    section "Making Go Tools Globally Accessible"
    local copied=0
    for bin in "$HOME/go/bin/"*; do
        [[ -f "$bin" ]] || continue
        name=$(basename "$bin")
        if sudo cp -f "$bin" /usr/local/bin/ 2>/dev/null; then
            echo -e "  ${GREEN}✓${RESET} $name"
            ((copied++)) || true
        fi
    done
    success "$copied binaries copied to /usr/local/bin"
}

# ── Create run.sh wrapper ─────────────────────────────────────────────────
create_runner() {
    section "Creating run.sh Launcher"

    cat > "$SCRIPT_DIR/run.sh" << 'RUNEOF'
#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════════╗
# ║  HackLens — Run Launcher                                             ║
# ║  Created by Yogesh Bhandage | yogeshbhandage.com                     ║
# ╚══════════════════════════════════════════════════════════════════════╝

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="$SCRIPT_DIR/venv/bin/python3"

# Ensure Go tools are in PATH
export GOPATH="$HOME/go"
export PATH="$PATH:$GOPATH/bin:/usr/local/go/bin:/usr/local/bin"

if [[ ! -f "$PYTHON" ]]; then
    echo "[!] Python virtual environment not found."
    echo "[!] Please run: bash install.sh"
    exit 1
fi

exec "$PYTHON" "$SCRIPT_DIR/hacklens.py" "$@"
RUNEOF

    chmod +x "$SCRIPT_DIR/run.sh"
    success "run.sh created"
}

# ── Verification ──────────────────────────────────────────────────────────
verify() {
    section "Verification"
    echo ""
    echo -e "  ${BOLD}Python Environment:${RESET}"
    VENV="$SCRIPT_DIR/venv"
    if [[ -f "$VENV/bin/python3" ]]; then
        py_ok=$("$VENV/bin/python3" -c "import requests,jsbeautifier,bs4,colorama; print('OK')" 2>/dev/null || echo "FAIL")
        [[ "$py_ok" == "OK" ]] \
            && echo -e "  ${GREEN}✓${RESET} Python packages (requests, jsbeautifier, bs4, colorama)" \
            || echo -e "  ${RED}✗${RESET} Python packages — run: cd venv && pip install -r requirements.txt"
    else
        echo -e "  ${RED}✗${RESET} Virtual environment missing"
    fi

    echo ""
    echo -e "  ${BOLD}Recon Tools:${RESET}"
    declare -A tool_desc=(
        ["katana"]="Deep JS crawler"
        ["gau"]="Historical URL collector"
        ["hakrawler"]="Fast web crawler"
        ["subjs"]="JS file extractor"
        ["waybackurls"]="Wayback Machine URLs"
        ["subfinder"]="Subdomain enumeration"
        ["assetfinder"]="Subdomain discovery"
        ["httpx"]="HTTP probe"
        ["nuclei"]="Vulnerability scanner"
        ["trufflehog"]="Secret scanning"
        ["amass"]="Subdomain enumeration"
    )

    all_ok=true
    for tool in katana gau hakrawler subjs waybackurls subfinder assetfinder httpx nuclei trufflehog amass; do
        if command -v "$tool" &>/dev/null; then
            echo -e "  ${GREEN}✓${RESET} $tool — ${tool_desc[$tool]}"
        else
            echo -e "  ${YELLOW}✗${RESET} $tool — not in PATH (try: source ~/.bashrc)"
            all_ok=false
        fi
    done
}

# ── Usage ─────────────────────────────────────────────────────────────────
print_usage() {
    echo ""
    echo -e "${GREEN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo -e "${GREEN}${BOLD}  ✓ HackLens installed successfully!${RESET}"
    echo ""
    echo -e "  ${YELLOW}Apply PATH changes:${RESET}"
    echo -e "  ${BOLD}source ~/.bashrc${RESET}"
    echo ""
    echo -e "  ${CYAN}Quick start:${RESET}"
    echo -e "  ${BOLD}bash run.sh -d target.com${RESET}"
    echo ""
    echo -e "  ${CYAN}Deep scan + subdomains:${RESET}"
    echo -e "  ${BOLD}bash run.sh -d target.com --deep --subs${RESET}"
    echo ""
    echo -e "  ${CYAN}Authenticated scan:${RESET}"
    echo -e "  ${BOLD}bash run.sh -d target.com -c 'session=abc123'${RESET}"
    echo ""
    echo -e "  ${CYAN}Through Burp Suite:${RESET}"
    echo -e "  ${BOLD}bash run.sh -d target.com -p http://127.0.0.1:8080${RESET}"
    echo ""
    echo -e "  ${RED}⚠  Only use on targets you have permission to test!${RESET}"
    echo -e "  ${CYAN}  yogeshbhandage.com${RESET}"
    echo -e "${GREEN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo ""
}

# ── Fix missing tools helper ──────────────────────────────────────────────
# Called automatically if some tools failed
fix_path() {
    echo ""
    info "If tools show ✗, run these commands to fix:"
    echo -e "  ${BOLD}source ~/.bashrc${RESET}"
    echo -e "  ${BOLD}bash install.sh${RESET}  # re-run is safe"
}

# ── Main ──────────────────────────────────────────────────────────────────
main() {
    detect_os
    install_system_deps
    setup_python
    setup_go
    install_go_tools
    install_trufflehog
    install_amass
    copy_go_bins
    create_runner
    verify
    fix_path
    print_usage
}

main "$@"
