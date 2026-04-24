#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════════╗
# ║  HackLens — Update Script                                            ║
# ║  Updates tool to latest version from GitHub                          ║
# ║  Created by Yogesh Bhandage | yogeshbhandage.com                     ║
# ╚══════════════════════════════════════════════════════════════════════╝

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'
RED='\033[0;31m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}[*]${RESET} $1"; }
success() { echo -e "${GREEN}[+]${RESET} $1"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $1"; }
error()   { echo -e "${RED}[-]${RESET} $1"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_URL="https://github.com/yogeshbhandage/hacklens"

echo -e "${GREEN}${BOLD}"
cat << 'BANNER'
  ██╗  ██╗ █████╗  ██████╗██╗  ██╗██╗     ███████╗███╗   ██╗███████╗
  ██║  ██║██╔══██╗██╔════╝██║ ██╔╝██║     ██╔════╝████╗  ██║██╔════╝
  ███████║███████║██║     █████╔╝ ██║     █████╗  ██╔██╗ ██║███████╗
  ██╔══██║██╔══██║██║     ██╔═██╗ ██║     ██╔══╝  ██║╚██╗██║╚════██║
  ██║  ██║██║  ██║╚██████╗██║  ██╗███████╗███████╗██║ ╚████║███████║
  ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═══╝╚══════╝
BANNER
echo -e "${RESET}${CYAN}  Updater | yogeshbhandage.com${RESET}\n"

# ── Show current version ──────────────────────────────────────────────────
PYTHON="$SCRIPT_DIR/venv/bin/python3"
if [[ -f "$PYTHON" ]]; then
    CURRENT_VER=$("$PYTHON" "$SCRIPT_DIR/hacklens.py" --version 2>/dev/null || echo "unknown")
    info "Current version: $CURRENT_VER"
else
    info "Current version: unknown (venv not found)"
fi

# ── Pull latest from GitHub ───────────────────────────────────────────────
if [ -d "$SCRIPT_DIR/.git" ]; then
    # Repo was cloned — use git pull
    info "Pulling latest changes from GitHub..."
    cd "$SCRIPT_DIR"

    # Stash any local changes so pull doesn't fail
    git stash 2>/dev/null || true

    if git pull origin main 2>&1; then
        success "Code updated from GitHub"
    else
        warn "git pull failed — trying force update..."
        git fetch origin
        git reset --hard origin/main
        success "Force updated to latest"
    fi

else
    # No .git folder — download fresh hacklens.py directly
    warn "No .git folder found — downloading latest hacklens.py directly..."
    RAW_URL="https://raw.githubusercontent.com/yogeshbhandage/hacklens/main/hacklens.py"

    if command -v wget &>/dev/null; then
        wget -q "$RAW_URL" -O "$SCRIPT_DIR/hacklens.py.new" \
            && mv "$SCRIPT_DIR/hacklens.py.new" "$SCRIPT_DIR/hacklens.py" \
            && success "hacklens.py updated"
    elif command -v curl &>/dev/null; then
        curl -sSL "$RAW_URL" -o "$SCRIPT_DIR/hacklens.py.new" \
            && mv "$SCRIPT_DIR/hacklens.py.new" "$SCRIPT_DIR/hacklens.py" \
            && success "hacklens.py updated"
    else
        error "Neither wget nor curl found — install one and retry"
    fi
fi

# ── Re-run installer for any new dependencies ─────────────────────────────
info "Checking for new dependencies..."
if [[ -f "$SCRIPT_DIR/install.sh" ]]; then
    bash "$SCRIPT_DIR/install.sh"
else
    # install.sh missing — download it too
    warn "install.sh not found — downloading..."
    curl -sSL "https://raw.githubusercontent.com/yogeshbhandage/hacklens/main/install.sh" \
        -o "$SCRIPT_DIR/install.sh" 2>/dev/null \
        && chmod +x "$SCRIPT_DIR/install.sh" \
        && bash "$SCRIPT_DIR/install.sh"
fi

# ── Show new version ──────────────────────────────────────────────────────
echo ""
if [[ -f "$PYTHON" ]]; then
    NEW_VER=$("$PYTHON" "$SCRIPT_DIR/hacklens.py" --version 2>/dev/null || echo "unknown")
    success "Updated to: $NEW_VER"
fi

echo ""
echo -e "${GREEN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${GREEN}${BOLD}  ✓ HackLens update complete!${RESET}"
echo ""
echo -e "  ${YELLOW}Apply PATH changes:${RESET}"
echo -e "  ${BOLD}source ~/.bashrc${RESET}"
echo ""
echo -e "  ${CYAN}Run HackLens:${RESET}"
echo -e "  ${BOLD}bash run.sh -d target.com --deep --subs${RESET}"
echo -e "${GREEN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""
