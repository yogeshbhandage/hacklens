#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════════╗
# ║   HackLens v2.0 — Web Recon & Vulnerability Scanner                  ║
# ║   Created by Yogesh Bhandage | yogeshbhandage.com                    ║
# ║   ⚠  For Authorized Security Testing Only                            ║
# ╚══════════════════════════════════════════════════════════════════════╝
set -e
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; MAGENTA='\033[0;35m'; BOLD='\033[1m'; RESET='\033[0m'
info()    { echo -e "${CYAN}[*]${RESET} $1"; }
success() { echo -e "${GREEN}[+]${RESET} $1"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $1"; }
section() {
    echo -e "\n${MAGENTA}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo -e "${MAGENTA}${BOLD}  $1${RESET}"
    echo -e "${MAGENTA}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
}

echo -e "${GREEN}${BOLD}"
cat << 'BANNER'
  ██╗  ██╗ █████╗  ██████╗██╗  ██╗██╗     ███████╗███╗   ██╗███████╗
  ██║  ██║██╔══██╗██╔════╝██║ ██╔╝██║     ██╔════╝████╗  ██║██╔════╝
  ███████║███████║██║     █████╔╝ ██║     █████╗  ██╔██╗ ██║███████╗
  ██╔══██║██╔══██║██║     ██╔═██╗ ██║     ██╔══╝  ██║╚██╗██║╚════██║
  ██║  ██║██║  ██║╚██████╗██║  ██╗███████╗███████╗██║ ╚████║███████║
  ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═══╝╚══════╝
BANNER
echo -e "${RESET}${CYAN}  v2.0 Installer | Created by Yogesh Bhandage | yogeshbhandage.com${RESET}\n"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

detect_os() {
    section "Detecting OS"
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        command -v apt-get &>/dev/null && OS="debian" || \
        command -v yum     &>/dev/null && OS="rhel"   || \
        command -v pacman  &>/dev/null && OS="arch"   || OS="linux"
    elif [[ "$OSTYPE" == "darwin"* ]]; then OS="macos"
    else OS="unknown"; fi
    success "OS: $OS"
}

install_system_deps() {
    section "System Packages"
    case $OS in
        debian)
            sudo apt-get update -qq
            sudo apt-get install -y -qq python3 python3-pip python3-venv python3-dev \
                golang-go git curl wget unzip jq build-essential \
                libssl-dev libpcap-dev dnsutils 2>/dev/null || warn "Some packages failed"
            ;;
        rhel)
            sudo yum install -y -q python3 python3-pip golang git curl wget \
                libpcap-devel bind-utils 2>/dev/null || warn "Some failed"
            ;;
        arch)
            sudo pacman -Sy --noconfirm python python-pip go git curl wget libpcap bind 2>/dev/null || warn "Some failed"
            ;;
        macos)
            command -v brew &>/dev/null || /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
            brew install python3 go git curl wget libpcap jq 2>/dev/null || warn "Some failed"
            ;;
    esac
    success "System packages done"
}

setup_python() {
    section "Python Virtual Environment"
    VENV_DIR="$SCRIPT_DIR/venv"
    [ ! -d "$VENV_DIR" ] && python3 -m venv "$VENV_DIR" && info "venv created"
    source "$VENV_DIR/bin/activate"
    "$VENV_DIR/bin/pip3" install --upgrade pip -q
    info "Installing Python packages..."
    "$VENV_DIR/bin/pip3" install -q \
        requests jsbeautifier beautifulsoup4 colorama lxml urllib3 certifi charset-normalizer
    success "Python environment ready"
}

setup_go() {
    section "Go Environment"
    if ! command -v go &>/dev/null; then
        warn "Go not found — installing..."
        case $OS in
            debian|rhel|linux)
                GO_VER="1.22.0"
                GOARCH="amd64"; [[ "$(uname -m)" == "aarch64" ]] && GOARCH="arm64"
                wget -q "https://go.dev/dl/go${GO_VER}.linux-${GOARCH}.tar.gz" -O /tmp/go.tar.gz
                sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf /tmp/go.tar.gz
                rm -f /tmp/go.tar.gz ;;
            macos) brew install go ;;
            *) warn "Install Go manually: https://go.dev/dl/" ; return 0 ;;
        esac
    else
        success "Go: $(go version)"
    fi
    export GOPATH="$HOME/go"; export PATH="$PATH:$GOPATH/bin:/usr/local/go/bin"
    for rc in ~/.bashrc ~/.zshrc ~/.bash_profile; do
        [ -f "$rc" ] || continue
        grep -q "GOPATH"       "$rc" 2>/dev/null || echo 'export GOPATH=$HOME/go'                     >> "$rc"
        grep -q "\$GOPATH/bin" "$rc" 2>/dev/null || echo 'export PATH=$PATH:$GOPATH/bin:/usr/local/go/bin' >> "$rc"
    done
    success "Go GOPATH=$HOME/go"
}

install_go_tool() {
    local name="$1" pkg="$2"
    export GOPATH="$HOME/go"; export PATH="$PATH:$GOPATH/bin:/usr/local/go/bin"
    command -v "$name" &>/dev/null && { success "$name — already installed"; return 0; }
    info "Installing $name..."
    GOPATH="$HOME/go" go install "$pkg" 2>/dev/null \
        && { sudo cp -f "$HOME/go/bin/$name" /usr/local/bin/ 2>/dev/null || true
             command -v "$name" &>/dev/null && success "$name ✓" || warn "$name — needs: source ~/.bashrc"; } \
        || warn "$name — failed (tool will be gracefully skipped)"
}

install_subdomain_api_check() {
    # ── Subdomain Sources Summary ─────────────────────────────────────────
    # HackLens uses 10+ subdomain sources. Here's what needs installation:
    #
    # NO INSTALL REQUIRED (pure HTTP API calls inside hacklens.py):
    #   ✓ crt.sh         — certificate transparency logs
    #   ✓ HackerTarget   — passive DNS API
    #   ✓ RapidDNS       — DNS search
    #   ✓ AlienVault OTX — threat intelligence
    #   ✓ URLScan.io     — web scan history
    #   ✓ ThreatCrowd    — threat intelligence
    #   ✓ DNSDumpster    — DNS recon (scraped)
    #
    # REQUIRES TOOL INSTALL (handled below):
    #   → Subfinder      — go install
    #   → Assetfinder    — go install
    #   → Amass          — apt / snap / go install
    #   → Chaos          — go install + API key needed
    #   → MassDNS        — compiled from source (optional, for bruteforce)
    #   → httpx          — go install (alive check after enumeration)
    # ─────────────────────────────────────────────────────────────────────
    section "Subdomain Sources"
    echo -e "  ${GREEN}API sources (no install needed):${RESET}"
    echo -e "  ${CYAN}✓${RESET} crt.sh, HackerTarget, RapidDNS, AlienVault OTX,"
    echo -e "  ${CYAN}✓${RESET} URLScan.io, ThreatCrowd, DNSDumpster"
    echo -e ""
    echo -e "  ${GREEN}Tool-based sources (installing below):${RESET}"
    echo -e "  ${CYAN}→${RESET} Subfinder, Assetfinder, Amass, Chaos, MassDNS, httpx"
}

install_go_tools() {
    section "Go Recon Tools"
    export GOPATH="$HOME/go"; export PATH="$PATH:$GOPATH/bin:/usr/local/go/bin"
    # JS & URL collection
    install_go_tool "katana"      "github.com/projectdiscovery/katana/cmd/katana@latest"
    install_go_tool "gau"         "github.com/lc/gau/v2/cmd/gau@latest"
    install_go_tool "hakrawler"   "github.com/hakluke/hakrawler@latest"
    install_go_tool "subjs"       "github.com/lc/subjs@latest"
    install_go_tool "waybackurls" "github.com/tomnomnom/waybackurls@latest"
    # Subdomain
    install_go_tool "subfinder"   "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    install_go_tool "assetfinder" "github.com/tomnomnom/assetfinder@latest"
    install_go_tool "httpx"       "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    install_go_tool "httprobe"    "github.com/tomnomnom/httprobe@latest"
    # Vuln
    install_go_tool "nuclei"      "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    success "Go tools done"
}

install_chaos() {
    section "Chaos (ProjectDiscovery)"
    command -v chaos &>/dev/null && { success "Chaos already installed"; return; }
    export GOPATH="$HOME/go"; export PATH="$PATH:$GOPATH/bin:/usr/local/go/bin"
    GOPATH="$HOME/go" go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest 2>/dev/null \
        && { sudo cp -f "$HOME/go/bin/chaos" /usr/local/bin/ 2>/dev/null || true
             success "Chaos ✓ (set API key: export CHAOS_KEY=your_key)"; } \
        || warn "Chaos install failed"
}

install_amass() {
    section "Amass"
    command -v amass &>/dev/null && { success "Amass already installed"; return; }
    command -v apt-get &>/dev/null && sudo apt-get install -y amass 2>/dev/null && success "Amass via apt ✓" && return
    command -v snap    &>/dev/null && sudo snap install amass 2>/dev/null && success "Amass via snap ✓" && return
    install_go_tool "amass" "github.com/owasp-amass/amass/v4/...@master"
}

install_trufflehog() {
    section "TruffleHog"
    command -v trufflehog &>/dev/null && { success "TruffleHog already installed"; return; }
    curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
        | sh -s -- -b /usr/local/bin 2>/dev/null \
        && success "TruffleHog ✓" \
        || warn "TruffleHog failed — manual install: https://github.com/trufflesecurity/trufflehog"
}

install_massdns() {
    section "MassDNS (Optional)"
    command -v massdns &>/dev/null && { success "MassDNS already installed"; return; }
    if command -v make &>/dev/null && command -v gcc &>/dev/null; then
        cd /tmp
        git clone https://github.com/blechschmidt/massdns.git massdns_build 2>/dev/null
        cd massdns_build && make 2>/dev/null
        sudo cp -f bin/massdns /usr/local/bin/ 2>/dev/null || true
        cd / && rm -rf /tmp/massdns_build
        command -v massdns &>/dev/null && success "MassDNS ✓" || warn "MassDNS build failed"
    else
        warn "MassDNS skipped — needs gcc & make (apt install build-essential)"
    fi
}

install_seclists() {
    section "SecLists Wordlists"
    [ -d "/usr/share/seclists" ] && { success "SecLists already installed"; return; }
    command -v apt-get &>/dev/null \
        && sudo apt-get install -y seclists 2>/dev/null && success "SecLists ✓" && return
    info "Downloading DNS wordlist..."
    sudo mkdir -p /usr/share/seclists/Discovery/DNS/
    sudo curl -sL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt" \
        -o /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt 2>/dev/null \
        && success "DNS wordlist ✓" || warn "Wordlist download failed"
}

copy_go_bins() {
    section "Global PATH Fix"
    local n=0
    for bin in "$HOME/go/bin/"*; do
        [[ -f "$bin" ]] || continue
        sudo cp -f "$bin" /usr/local/bin/ 2>/dev/null && ((n++)) || true
    done
    success "$n Go binaries → /usr/local/bin"
}

create_runner() {
    section "Creating run.sh"
    cat > "$SCRIPT_DIR/run.sh" << 'EOF'
#!/usr/bin/env bash
# HackLens v2.0 | yogeshbhandage.com
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="$SCRIPT_DIR/venv/bin/python3"
export GOPATH="$HOME/go"
export PATH="$PATH:$GOPATH/bin:/usr/local/go/bin:/usr/local/bin"
[[ ! -f "$PYTHON" ]] && echo "[!] Run: bash install.sh" && exit 1
exec "$PYTHON" "$SCRIPT_DIR/hacklens.py" "$@"
EOF
    chmod +x "$SCRIPT_DIR/run.sh"
    success "run.sh created"
}

verify() {
    section "Verification"
    echo ""
    VENV="$SCRIPT_DIR/venv"
    [[ -f "$VENV/bin/python3" ]] && {
        "$VENV/bin/python3" -c "import requests,jsbeautifier,bs4,colorama; print('[+] Python packages OK')" 2>/dev/null \
            || echo "[-] Python packages — re-run install.sh"
        "$VENV/bin/python3" "$SCRIPT_DIR/hacklens.py" --version 2>/dev/null || true
    }
    echo ""
    declare -A DESC=(
        [katana]="JS crawler" [gau]="URL history" [hakrawler]="Web crawler"
        [subjs]="JS extractor" [waybackurls]="Wayback URLs"
        [subfinder]="Subdomain" [assetfinder]="Subdomain" [httpx]="Alive check"
        [nuclei]="Vuln scan" [trufflehog]="Secrets" [amass]="Subdomain"
        [chaos]="Subdomain (optional)" [massdns]="DNS bruteforce (optional)"
    )
    for t in katana gau hakrawler subjs waybackurls subfinder assetfinder httpx nuclei trufflehog amass chaos massdns; do
        command -v "$t" &>/dev/null \
            && echo -e "  ${GREEN}✓${RESET} $t — ${DESC[$t]}" \
            || { [[ "$t" =~ ^(chaos|massdns)$ ]] \
                 && echo -e "  ${CYAN}○${RESET} $t — ${DESC[$t]}" \
                 || echo -e "  ${YELLOW}✗${RESET} $t — try: source ~/.bashrc"; }
    done
}

print_usage() {
    echo ""
    echo -e "${GREEN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo -e "${GREEN}${BOLD}  HackLens v2.0 ready!${RESET}"
    echo ""
    echo -e "  ${YELLOW}source ~/.bashrc${RESET}"
    echo ""
    echo -e "  ${CYAN}# Auto-crawl + scan:${RESET}"
    echo -e "  bash run.sh -d target.com --deep --subs"
    echo ""
    echo -e "  ${CYAN}# Pre-crawled URL list (skip recon):${RESET}"
    echo -e "  bash run.sh -d target.com -l urls.txt"
    echo ""
    echo -e "  ${CYAN}# Check version:${RESET}"
    echo -e "  bash run.sh --version"
    echo ""
    echo -e "  ${RED}⚠  Authorized testing only! | yogeshbhandage.com${RESET}"
    echo -e "${GREEN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}\n"
}

main() {
    detect_os; install_system_deps; setup_python; setup_go
    install_subdomain_api_check
    install_go_tools; install_chaos; install_amass; install_trufflehog
    install_massdns; install_seclists; copy_go_bins; create_runner
    verify; print_usage
}
main "$@"
