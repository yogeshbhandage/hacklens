#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════════╗
# ║  HackLens — Fix Tools Script                                         ║
# ║  Run this if tools show ✗ after install.sh                           ║
# ║  Created by Yogesh Bhandage | yogeshbhandage.com                     ║
# ╚══════════════════════════════════════════════════════════════════════╝

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}[*]${RESET} $1"; }
success() { echo -e "${GREEN}[+]${RESET} $1"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $1"; }

echo -e "${GREEN}${BOLD}HackLens — Fix Tools${RESET}"
echo -e "${CYAN}yogeshbhandage.com${RESET}"
echo ""

# Set Go environment
export GOPATH="$HOME/go"
export PATH="$PATH:$GOPATH/bin:/usr/local/go/bin:/usr/local/bin"

info "Go path: $GOPATH/bin"
info "Go version: $(go version 2>/dev/null || echo 'not found')"
echo ""

install_tool() {
    local name="$1"
    local pkg="$2"

    if command -v "$name" &>/dev/null; then
        success "$name — already in PATH"
        return 0
    fi

    info "Installing $name..."
    if GOPATH="$HOME/go" go install "$pkg" 2>&1; then
        sudo cp -f "$HOME/go/bin/$name" /usr/local/bin/ 2>/dev/null || true
        command -v "$name" &>/dev/null && success "$name — installed" || warn "$name — needs: source ~/.bashrc"
    else
        warn "$name — failed"
    fi
}

# Re-install any missing tools
install_tool "katana"      "github.com/projectdiscovery/katana/cmd/katana@latest"
install_tool "gau"         "github.com/lc/gau/v2/cmd/gau@latest"
install_tool "hakrawler"   "github.com/hakluke/hakrawler@latest"
install_tool "subjs"       "github.com/lc/subjs@latest"
install_tool "waybackurls" "github.com/tomnomnom/waybackurls@latest"
install_tool "subfinder"   "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
install_tool "assetfinder" "github.com/tomnomnom/assetfinder@latest"
install_tool "httpx"       "github.com/projectdiscovery/httpx/cmd/httpx@latest"
install_tool "nuclei"      "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"

# TruffleHog
if ! command -v trufflehog &>/dev/null; then
    info "Installing TruffleHog..."
    curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
        | sh -s -- -b /usr/local/bin 2>/dev/null && success "TruffleHog installed" || warn "TruffleHog failed"
else
    success "trufflehog — already in PATH"
fi

# Amass
if ! command -v amass &>/dev/null; then
    info "Installing Amass..."
    sudo apt-get install -y amass 2>/dev/null \
    || sudo snap install amass 2>/dev/null \
    || GOPATH="$HOME/go" go install "github.com/owasp-amass/amass/v4/...@master" 2>/dev/null
    command -v amass &>/dev/null && success "amass — installed" || warn "amass — failed"
else
    success "amass — already in PATH"
fi

# Copy all Go bins to /usr/local/bin
info "Copying Go binaries to /usr/local/bin..."
for bin in "$HOME/go/bin/"*; do
    [[ -f "$bin" ]] && sudo cp -f "$bin" /usr/local/bin/ 2>/dev/null || true
done

# Fix PATH in shell configs
info "Adding GOPATH to shell configs..."
for rc in ~/.bashrc ~/.zshrc ~/.bash_profile; do
    [[ -f "$rc" ]] || continue
    grep -q "GOPATH" "$rc" 2>/dev/null || echo 'export GOPATH=$HOME/go' >> "$rc"
    grep -q "\$GOPATH/bin" "$rc" 2>/dev/null || echo 'export PATH=$PATH:$GOPATH/bin:/usr/local/go/bin' >> "$rc"
done

# Verify
echo ""
echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${CYAN}${BOLD}  Tool Status${RESET}"
echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
for t in katana gau hakrawler subjs waybackurls subfinder assetfinder httpx nuclei trufflehog amass; do
    if command -v "$t" &>/dev/null; then
        echo -e "  ${GREEN}✓${RESET} $t"
    else
        echo -e "  ${YELLOW}✗${RESET} $t"
    fi
done

echo ""
echo -e "${GREEN}Done! Apply changes:${RESET}"
echo -e "  ${BOLD}source ~/.bashrc${RESET}"
echo -e "  ${BOLD}bash run.sh -d target.com${RESET}"
echo ""
