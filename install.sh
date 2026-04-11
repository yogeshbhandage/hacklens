#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║          HACKLENS - Installer Script                         ║
# ║          Created by Yogesh Bhandage                          ║
# ║          yogeshbhandage.com                                  ║
# ╚══════════════════════════════════════════════════════════════╝

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
RESET='\033[0m'

info()    { echo -e "${CYAN}[*]${RESET} $1"; }
success() { echo -e "${GREEN}[+]${RESET} $1"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $1"; }
error()   { echo -e "${RED}[-]${RESET} $1"; }
section() {
    echo -e "\n${MAGENTA}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo -e "${MAGENTA}${BOLD}  $1${RESET}"
    echo -e "${MAGENTA}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
}

# ── Banner ────────────────────────────────────────────────────
echo -e "${GREEN}${BOLD}"
cat << 'BANNER'
  ██╗  ██╗ █████╗  ██████╗██╗  ██╗██╗     ███████╗███╗   ██╗███████╗
  ██║  ██║██╔══██╗██╔════╝██║ ██╔╝██║     ██╔════╝████╗  ██║██╔════╝
  ███████║███████║██║     █████╔╝ ██║     █████╗  ██╔██╗ ██║███████╗
  ██╔══██║██╔══██║██║     ██╔═██╗ ██║     ██╔══╝  ██║╚██╗██║╚════██║
  ██║  ██║██║  ██║╚██████╗██║  ██╗███████╗███████╗██║ ╚████║███████║
  ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═══╝╚══════╝
BANNER
echo -e "${CYAN}              Installer  |  Created by Yogesh Bhandage${RESET}"
echo -e "${CYAN}              yogeshbhandage.com${RESET}"
echo -e "${RESET}"

# ── Detect OS ─────────────────────────────────────────────────
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if command -v apt-get &>/dev/null; then OS="debian"
        elif command -v yum &>/dev/null;     then OS="rhel"
        elif command -v pacman &>/dev/null;   then OS="arch"
        else OS="linux"; fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
    else
        OS="unknown"
    fi
    info "Detected OS: $OS"
}

# ── System Dependencies ───────────────────────────────────────
install_system_deps() {
    section "Installing System Dependencies"
    case $OS in
        debian)
            sudo apt-get update -qq
            sudo apt-get install -y -qq \
                python3 python3-pip python3-venv \
                golang-go git curl wget \
                build-essential libssl-dev libpcap-dev \
                2>/dev/null || warn "Some apt packages failed"
            ;;
        rhel)
            sudo yum install -y -q python3 python3-pip golang git curl wget libpcap-devel \
                2>/dev/null || warn "Some yum packages failed"
            ;;
        arch)
            sudo pacman -Sy --noconfirm python python-pip go git curl wget libpcap \
                2>/dev/null || warn "Some pacman packages failed"
            ;;
        macos)
            command -v brew &>/dev/null || /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
            brew install python3 go git curl wget libpcap 2>/dev/null || true
            ;;
        *)
            warn "Unknown OS. Please install python3, go, git manually."
            ;;
    esac
    success "System dependencies done"
}

# ── Python Virtual Environment ────────────────────────────────
setup_python_env() {
    section "Setting Up Python Environment"
    VENV_DIR="$(dirname "$0")/venv"

    if [ ! -d "$VENV_DIR" ]; then
        info "Creating virtual environment..."
        python3 -m venv "$VENV_DIR"
        success "Virtual environment created: $VENV_DIR"
    else
        info "Virtual environment already exists"
    fi

    source "$VENV_DIR/bin/activate"
    PIP="$VENV_DIR/bin/pip3"

    info "Upgrading pip..."
    $PIP install --upgrade pip -q

    info "Installing Python packages..."
    $PIP install -q \
        requests \
        jsbeautifier \
        beautifulsoup4 \
        colorama \
        lxml \
        urllib3 \
        tqdm \
        certifi \
        charset-normalizer \
        fake-useragent

    success "Python packages installed"
}

# ── Go Setup ──────────────────────────────────────────────────
setup_go() {
    section "Setting Up Go Environment"
    if ! command -v go &>/dev/null; then
        warn "Go not found. Attempting to install..."
        case $OS in
            debian|rhel)
                GO_VER="1.22.0"
                ARCH=$(uname -m)
                [ "$ARCH" = "x86_64" ] && GOARCH="amd64" || GOARCH="arm64"
                wget -q "https://go.dev/dl/go${GO_VER}.linux-${GOARCH}.tar.gz" -O /tmp/go.tar.gz
                sudo tar -C /usr/local -xzf /tmp/go.tar.gz
                export PATH=$PATH:/usr/local/go/bin
                echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
                echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.zshrc 2>/dev/null || true
                success "Go installed"
                ;;
            macos) brew install go ;;
            *) warn "Please install Go manually: https://go.dev/dl/" ; return 1 ;;
        esac
    else
        success "Go already installed: $(go version)"
    fi

    export GOPATH=$HOME/go
    export PATH=$PATH:$GOPATH/bin
    echo 'export GOPATH=$HOME/go'        >> ~/.bashrc
    echo 'export PATH=$PATH:$GOPATH/bin' >> ~/.bashrc
    echo 'export GOPATH=$HOME/go'        >> ~/.zshrc 2>/dev/null || true
    echo 'export PATH=$PATH:$GOPATH/bin' >> ~/.zshrc 2>/dev/null || true
}

# ── Install a Go Tool ─────────────────────────────────────────
install_go_tool() {
    local name=$1
    local pkg=$2

    if command -v "$name" &>/dev/null; then
        success "$name already installed"
        return 0
    fi

    info "Installing $name..."
    if GOPATH=$HOME/go go install "$pkg" 2>/dev/null; then
        sudo cp -f "$HOME/go/bin/$name" /usr/local/bin/ 2>/dev/null || true
        success "$name installed"
    else
        warn "$name failed to install"
    fi
}

# ── Go Tools ──────────────────────────────────────────────────
install_go_tools() {
    section "Installing Go-Based Recon Tools"

    export GOPATH=$HOME/go
    export PATH=$PATH:$GOPATH/bin:/usr/local/go/bin

    # JS & URL collectors
    install_go_tool "katana"      "github.com/projectdiscovery/katana/cmd/katana@latest"
    install_go_tool "gau"         "github.com/lc/gau/v2/cmd/gau@latest"
    install_go_tool "hakrawler"   "github.com/hakluke/hakrawler@latest"
    install_go_tool "subjs"       "github.com/lc/subjs@latest"
    install_go_tool "waybackurls" "github.com/tomnomnom/waybackurls@latest"

    # Subdomain enumeration
    install_go_tool "subfinder"   "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    install_go_tool "assetfinder" "github.com/tomnomnom/assetfinder@latest"
    install_go_tool "httprobe"    "github.com/tomnomnom/httprobe@latest"
    install_go_tool "httpx"       "github.com/projectdiscovery/httpx/cmd/httpx@latest"

    # Secret scanning
    install_go_tool "nuclei"      "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"

    success "Go tools installation complete"
}

# ── TruffleHog ────────────────────────────────────────────────
install_trufflehog() {
    section "Installing TruffleHog"
    if command -v trufflehog &>/dev/null; then
        success "TruffleHog already installed: $(trufflehog --version 2>/dev/null | head -1)"
        return
    fi
    info "Installing TruffleHog via official script..."
    curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
        | sh -s -- -b /usr/local/bin 2>/dev/null && success "TruffleHog installed" \
        || warn "TruffleHog install failed — run manually: curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin"
}

# ── Amass ─────────────────────────────────────────────────────
install_amass() {
    section "Installing Amass"
    if command -v amass &>/dev/null; then
        success "Amass already installed"
        return
    fi
    if command -v snap &>/dev/null; then
        sudo snap install amass 2>/dev/null && success "Amass installed via snap" \
            || install_go_tool "amass" "github.com/owasp-amass/amass/v4/...@master"
    else
        install_go_tool "amass" "github.com/owasp-amass/amass/v4/...@master"
    fi
}

# ── Copy all Go bins to /usr/local/bin ────────────────────────
copy_go_bins() {
    section "Copying Go Binaries to /usr/local/bin"
    for bin in "$HOME/go/bin/"*; do
        name=$(basename "$bin")
        sudo cp -f "$bin" /usr/local/bin/ 2>/dev/null && echo -e "  ${GREEN}✓${RESET} $name" || true
    done
    success "All Go binaries copied"
}

# ── Create run.sh wrapper ─────────────────────────────────────
create_runner() {
    section "Creating run.sh Wrapper"
    SCRIPT_DIR="$(dirname "$0")"

    cat > "$SCRIPT_DIR/run.sh" << 'RUNEOF'
#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  HACKLENS - Run Wrapper                                      ║
# ║  Created by Yogesh Bhandage | yogeshbhandage.com             ║
# ╚══════════════════════════════════════════════════════════════╝

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$SCRIPT_DIR/venv/bin/python3"

export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin:/usr/local/go/bin

if [ ! -f "$VENV" ]; then
    echo "[!] Virtual environment not found. Run: bash install.sh"
    exit 1
fi

"$VENV" "$SCRIPT_DIR/hacklens.py" "$@"
RUNEOF

    chmod +x "$SCRIPT_DIR/run.sh"
    success "run.sh created"
}

# ── Verify Installation ───────────────────────────────────────
verify() {
    section "Verification"
    echo ""
    echo -e "  ${BOLD}Recon Tools:${RESET}"
    tools=("katana" "gau" "hakrawler" "subjs" "waybackurls" "subfinder" "assetfinder" "httpx" "trufflehog" "amass" "nuclei")
    for tool in "${tools[@]}"; do
        if command -v "$tool" &>/dev/null; then
            echo -e "  ${GREEN}✓${RESET} $tool"
        else
            echo -e "  ${YELLOW}✗${RESET} $tool ${YELLOW}(not found — try: source ~/.bashrc)${RESET}"
        fi
    done

    echo ""
    echo -e "  ${BOLD}Python Environment:${RESET}"
    VENV_DIR="$(dirname "$0")/venv"
    if [ -f "$VENV_DIR/bin/python3" ]; then
        py_check=$("$VENV_DIR/bin/python3" -c "import requests,jsbeautifier,bs4,colorama; print('OK')" 2>/dev/null || echo "FAIL")
        [ "$py_check" = "OK" ] \
            && echo -e "  ${GREEN}✓${RESET} Python packages ready" \
            || echo -e "  ${RED}✗${RESET} Python packages missing"
    else
        echo -e "  ${RED}✗${RESET} Virtual environment not found"
    fi
}

# ── Print Usage ───────────────────────────────────────────────
print_usage() {
    echo ""
    echo -e "${GREEN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo -e "${GREEN}${BOLD}  ✓ HackLens installed successfully!${RESET}"
    echo ""
    echo -e "  ${CYAN}Apply PATH changes:${RESET}"
    echo -e "  ${BOLD}source ~/.bashrc${RESET}"
    echo ""
    echo -e "  ${CYAN}Basic scan:${RESET}"
    echo -e "  ${BOLD}bash run.sh -d target.com${RESET}"
    echo ""
    echo -e "  ${CYAN}Deep scan + subdomains:${RESET}"
    echo -e "  ${BOLD}bash run.sh -d target.com --deep --subs${RESET}"
    echo ""
    echo -e "  ${CYAN}Authenticated scan:${RESET}"
    echo -e "  ${BOLD}bash run.sh -d target.com -c 'session=abc123'${RESET}"
    echo ""
    echo -e "  ${CYAN}Through Burp proxy:${RESET}"
    echo -e "  ${BOLD}bash run.sh -d target.com -p http://127.0.0.1:8080${RESET}"
    echo ""
    echo -e "  ${YELLOW}⚠  Only use on targets you have permission to test!${RESET}"
    echo -e "  ${CYAN}  yogeshbhandage.com${RESET}"
    echo -e "${GREEN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo ""
}

# ── Main ──────────────────────────────────────────────────────
main() {
    detect_os
    install_system_deps
    setup_python_env
    setup_go
    install_go_tools
    install_trufflehog
    install_amass
    copy_go_bins
    create_runner
    verify
    print_usage
}

main
