#!/usr/bin/env bash
# Ghost-Scan Installer
# By Gh0st-Bx1 | github.com/Ghost-Bx1

G="\033[92m"; Y="\033[93m"; R="\033[91m"; C="\033[96m"
W="\033[97m"; D="\033[2m"; N="\033[1m"; X="\033[0m"
EQ="════════════════════════════════════════════════════════════════════"
HL="────────────────────────────────────────────────────────────────────"

banner() {
    echo -e "${G}╔${EQ}╗${X}"
    echo -e "${G}║${X}                                                                    ${G}║${X}"
    echo -e "${G}║${X}       ${G}⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠛⠛⠛⠿⠟⠉⠛⠻⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿${X}       ${G}║${X}"
    echo -e "${G}║${X}       ${G}⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠉⢀⣠⣤⣶⣶⣶⣶⣶⣶⣤⣀⠢⢝⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿${X}       ${G}║${X}"
    echo -e "${G}║${X}       ${G}⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⡡⢀⣴⡿⢋⡴⢿⣿⣿⣿⣿⣿⣿⣿⢷⣦⡑⠈⡛⠿⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿${X}       ${G}║${X}"
    echo -e "${G}║${X}       ${G}⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡏⡜⢠⣾⣿⣤⣋⣴⣿⣿⣿⣿⣿⣿⣿⣿⣷⣌⠻⣶⣦⣤⣤⣀⠉⠻⣿⣿⣿⡿⠿⢛⢛⡻⠿⣿⣿⣿⣿${X}       ${G}║${X}"
    echo -e "${G}║${X}       ${G}⣿⠿⠟⠟⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⠀⢀⣿⣿⣿⡿⠛⠛⠻⣿⣿⣿⡿⠛⠛⢿⣿⣿⣧⠉⠉⣁⣈⣉⣁⢀⣿⣿⢋⠄⣁⣴⣶⣄⠐⢌⢻⣿⣿${X}       ${G}║${X}"
    echo -e "${G}║${X}       ${G}⡏⠀⣴⣦⣄⠢⡙⢿⣿⣿⣿⣿⣿⣿⡇⠀⣼⣿⣿⣿⠅⠀⠀  ⢹⣿⡿⠁⠀⠀⠀⢹⣿⣿⡆⠀⣿⣿⣿⣿⣿⡟⠁⢀⣴⣿⣿⣿⣿⣷⡈⠎⢿⣿${X}       ${G}║${X}"
    echo -e "${G}║${X}       ${G}⡇⠀⣿⣿⣿⣷⣌⠀⠙⢿⣿⣿⣿⣿⠀⢀⣿⣿⣿⣿⠀⠀⠀  ⠀⠈⣿⡇⠀⠀⠀⠀⠈⢿⣿⡇⠁⢻⣿⣿⣿⡿⠁⢠⣾⣿⣿⣿⡿⢿⣿⣷⠀⠘⣿${X}       ${G}║${X}"
    echo -e "${G}║${X}       ${G}⣇⠀⢿⣿⣿⡟⣿⣷⣄⠀⠙⢿⣿⡇⠀⣸⣿⣿⡿⣿⡀⠀⠀⠀  ⢸⣿⣧⠀⠀⠀⠀⣸⡈⣿⣷⠀⡈⣿⣿⡿⠁⢀⣾⣿⣿⢩⣿⠁⣾⣿⣿⡆⠀⢿${X}       ${G}║${X}"
    echo -e "${G}║${X}       ${G}⣿⡀⠘⣿⣿⣿⡘⣿⣿⣷⣌⠂⠉⠁⢠⣿⣿⡟⣰⢿⣷⣤⣤⣴⣿⣿⣿⣷⣄⣠⣴⣿⣧⠸⣿⣧⡐⠢⠉⠁⢀⣾⣿⣿⡇⣼⣿⢸⣿⣿⣿⣇⠀⢸${X}       ${G}║${X}"
    echo -e "${G}║${X}       ${G}⣿⣷⡀⠸⣿⣿⣧⠸⣿⣿⣿⣿⣶⣶⣿⣿⠏⡰⢃⣾⣿⣿⣿⣿⡏⠀⠈⣿⣿⣿⣿⣿⣏⠳⣘⣿⣿⣷⣶⣾⣿⣿⣿⣿⢠⣿⣿⣿⣿⣿⣿⣿⠀⢸${X}       ${G}║${X}"
    echo -e "${G}║${X}       ${G}⣿⣿⡇⠀⣿⣿⣿⡄⡿⢿⣿⣿⣿⣿⣿⣷⣾⣷⣿⣿⣿⣿⣿⣿⣧⣀⣠⣿⣿⣿⣿⣿⣿⣷⣾⣿⣿⣿⣿⣿⣿⣿⣿⡇⠸⠋⢉⠉⡉⠛⠿⣿⠀⢸${X}       ${G}║${X}"
    echo -e "${G}║${X}       ${G}⣿⣿⡇⢀⣿⣿⣿⣧⢸⡘⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠁⢠⣾⣿⡄⠈⠀⠀⠀⠀ ⣾${X}       ${G}║${X}"
    echo -e "${G}║${X}       ${G}⣿⡟⠀⣸⣿⣿⣿⣿⣜⡇⢿⣧⠹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣄⡉⠻⠇⠀⠰⠀⠀ ⣀⣾${X}       ${G}║${X}"
    echo -e "${G}║${X}       ${G}⣿⠃⢠⣿⣿⠿⠿⠿⢿⣿⠸⣿⣀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢻⣿⣿⣿⣿⣿⣿⣿⣷⣄⠀⢣⢸⣿⣿⣿${X}       ${G}║${X}"
    echo -e "${G}║${X}       ${G}⣿⢰⠜⠋⠀⢀⡄⢰⣤⡀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⠀⠃⢻⣿⣿${X}       ${G}║${X}"
    echo -e "${G}║${X}       ${G}⣿⣆⠠⠀⡀⠀⠁⣿⣿⠟⠀⣽⣿⣿⣿⣿⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⢻⣿⣿⣿⣿⣿⢃⣿⣿⣿⡟⣸⣿⣿⣿⣿⡿⠋⢠⢃⣾⣿⣿${X}       ${G}║${X}"
    echo -e "${G}║${X}       ${G}⣿⣿⣷⣶⠆⡄⠈⢉⣠⣴⣾⣿⢿⣿⣿⣿⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⢋⣴⣿⣿⣿⣿⣿⣿⢸⣿⣿⣿⠇⠛⢏⠉⠉⠁⠤⢊⣥⣾⣿⣿⣿${X}       ${G}║${X}"
    echo -e "${G}║${X}       ${G}⣿⣿⣿⣿⢄⠀⢾⣿⣿⣿⣿⡇⢸⣿⣿⣿⢸⣿⣿⣿⣿⣿⣿⣿⣶⣬⣭⣶⣾⣿⣿⠏⣼⣿⣿⣿⡇⣸⣿⣿⣿⠀⣰⣿⡁⢠⣿⣿⣿⣿⣿⣿⣿⣿${X}       ${G}║${X}"
    echo -e "${G}║${X}       ${G}⣿⣿⣿⣿⣤⣀⡀⠀⠀⠉⠉⠁⢸⣿⣿⣿⢸⣿⣿⣿⣿⡹⣿⣿⣿⣿⣿⣿⣿⣿⠋⣼⣿⣿⣿⣿⠇⣿⣿⣿⣿⡀⠹⢿⡇⠀⢿⣿⣿⣿⣿⣿⣿⣿${X}       ${G}║${X}"
    echo -e "${G}║${X}       ${G}⣿⣿⣿⣿⣿⣿⣿⣿⠃⠀⠛⠀⣼⣿⣿⣿⢸⣿⣿⢻⣿⣷⣌⠻⣿⣿⣿⣿⠟⣡⣾⣿⡟⣼⣿⣿⠀⣿⣿⣿⣿⣿⣶⣤⡀⠀⢸⣿⣿⣿⣿⣿⣿⣿${X}       ${G}║${X}"
    echo -e "${G}║${X}       ${G}⣿⣿⣿⣿⣿⣿⣿⣿⠈⠀⣴⣾⣿⣿⣿⡇⢸⣿⣿⣇⢻⣿⣿⣷⣦⣭⣭⣴⣾⣿⣿⣿⢡⣿⣿⣿⠀⣿⣿⣿⣿⣿⠿⠟⠃⡀⢸⣿⣿⣿⣿⣿⣿⣿${X}       ${G}║${X}"
    echo -e "${G}║${X}       ${G}⣿⣿⣿⣿⣿⣿⣿⣿⡐⠠⢈⡉⠛⠛⠿⡇⢸⣿⣿⣿⡜⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡏⣼⣿⣿⣿⠀⣁⣤⡄⠀⣀⣒⣀⣤⣶⣿⣿⣿⣿⣿⣿⣿⣿${X}       ${G}║${X}"
    echo -e "${G}║${X}       ${G}⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣦⡌⠀⣦⠀⣼⣿⣿⣿⣇⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⢁⣿⣿⣿⣿⣄⡈⠛⠃⠐⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿${X}       ${G}║${X}"
    echo -e "${G}║${X}       ${G}⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠁⠀⢁⣤⣿⣿⣿⣿⣿⠘⣿⣿⣿⣿⣿⣿⣿⣿⡟⢸⣿⣿⣿⣿⣿⣿⣦⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿${X}       ${G}║${X}"
    echo -e "${G}║${X}       ${G}⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⠀⠠⣿⣿⣿⣿⣿⣿⣿⠀⣿⣿⣿⣿⣿⣿⣿⣿⡇⢼⠿⠿⣿⣿⣿⣿⠟⠀⢀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿${X}       ${G}║${X}"
    echo -e "${G}║${X}       ${G}⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣄⠀⠈⣙⠛⠛⣛⣛⠛⠀⠻⢿⣿⣿⣿⣿⣿⣿⡃⢠⣤⠀⠀⣀⣉⣁⣀⣠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿${X}       ${G}║${X}"
    echo -e "${G}║${X}       ${G}⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣶⣶⣶⣶⣶⣶⣤⡀⢀⠈⢿⣿⣿⣿⣿⣷⣄⠁⠀⣹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿${X}       ${G}║${X}"
    echo -e "${G}║${X}       ${G}⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⠁⠈⣿⣿⣿⣿⣿⣿⡆⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿${X}       ${G}║${X}"
    echo -e "${G}║${X}       ${G}⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠠⢠⣿⣿⣿⣿⣿⠟⢀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿${X}       ${G}║${X}"
    echo -e "${G}║${X}       ${G}⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡗⠀⢸⣿⣿⣿⡿⢁⡄⣡⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿${X}       ${G}║${X}"
    echo -e "${G}║${X}       ${G}⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⠰⠘⣿⣿⣿⠁⠎⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿${X}       ${G}║${X}"
    echo -e "${G}║${X}       ${G}⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⡑⠈⠻⠇⠈⣸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿${X}       ${G}║${X}"
    echo -e "${G}║${X}       ${G}⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣤⣀⣠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿${X}       ${G}║${X}"
    echo -e "${G}║${X}                                                                    ${G}║${X}"
    echo -e "${G}║${X}  ${G}${N}GHOST-SCAN INSTALLER${X}                                              ${G}║${X}"
    echo -e "${G}║${X}  ${C}v2.0.0  ${D}Vulnerability & Port Scanner${X}                              ${G}║${X}"
    echo -e "${G}║${X}  ${D}${HL:0:44}${X}                      ${G}║${X}"
    echo -e "${G}║${X}  ${W}By Gh0st-Bx1  ${D}│  github.com/Ghost-Bx1${X}                             ${G}║${X}"
    echo -e "${G}║${X}  ${D}${HL:0:44}${X}                      ${G}║${X}"
    echo -e "${G}║${X}                                                                    ${G}║${X}"
    echo -e "${G}╚${EQ}╝${X}"
    echo
}

info()  { echo -e "  ${C}[*]${X} $*"; }
ok()    { echo -e "  ${G}[+]${X} $*"; }
warn()  { echo -e "  ${Y}[~]${X} $*"; }
err()   { echo -e "  ${R}[!]${X} $*"; }
step()  { echo -e "\n${G}  >${X} ${W}$*${X}"; }

banner

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/opt/ghost-scan"
INSTALL_BIN="/usr/local/bin/ghost-scan"

if [[ $EUID -ne 0 ]]; then
    warn "Not running as root - installing to ~/.local"
    INSTALL_DIR="$HOME/.local/share/ghost-scan"
    INSTALL_BIN="$HOME/.local/bin/ghost-scan"
    mkdir -p "$HOME/.local/bin"
fi

step "Detecting system..."
PYTHON=$(command -v python3 || command -v python)
if [[ -z "$PYTHON" ]]; then
    err "Python 3 not found. Install python3 first."
    exit 1
fi
ok "Python: $($PYTHON --version 2>&1)"

if [[ $EUID -eq 0 ]]; then
    ok "Running as root - SYN scan available"
else
    warn "Not root - only TCP connect scan available (no raw SYN)"
    warn "For SYN scan: sudo ghost-scan"
fi

step "Checking optional Python packages..."
if $PYTHON -c "import scapy" 2>/dev/null; then
    ok "scapy available (SYN scan enabled)"
else
    warn "scapy not found - install with: pip install scapy"
    info "scapy enables raw SYN packet scan (requires root)"
fi

step "Installing ghost-scan..."

mkdir -p "$INSTALL_DIR"
cp "$SCRIPT_DIR/ghost-scan.py" "$INSTALL_DIR/ghost-scan.py"
chmod +x "$INSTALL_DIR/ghost-scan.py"
ok "Copied ghost-scan.py -> $INSTALL_DIR/"

[[ -f "$SCRIPT_DIR/README.md" ]] && cp "$SCRIPT_DIR/README.md" "$INSTALL_DIR/"

mkdir -p "$(dirname "$INSTALL_BIN")"
cat > "$INSTALL_BIN" << WRAPPER
#!/usr/bin/env bash
exec python3 $INSTALL_DIR/ghost-scan.py "\$@"
WRAPPER
chmod +x "$INSTALL_BIN"
ok "Wrapper created: $INSTALL_BIN"

if [[ $EUID -ne 0 ]]; then
    if ! echo "$PATH" | grep -q "$HOME/.local/bin"; then
        warn "Add to PATH: export PATH=\"\$HOME/.local/bin:\$PATH\""
    fi
fi

step "Verifying installation..."
echo
if "$PYTHON" "$INSTALL_DIR/ghost-scan.py" --no-banner --help &>/dev/null; then
    ok "ghost-scan.py runs correctly"
else
    warn "ghost-scan.py check returned non-zero (may be normal)"
fi

echo
echo -e "${G}  ╔══════════════════════════════════════╗${X}"
echo -e "${G}  ║${X}  ${G}${N}Installation complete!${X}              ${G}║${X}"
echo -e "${G}  ║${X}  ${D}Run:${X} ${W}ghost-scan --help${X}                ${G}║${X}"
echo -e "${G}  ║${X}  ${D}Or:${X}  ${W}ghost-scan port --help${X}           ${G}║${X}"
echo -e "${G}  ╚══════════════════════════════════════╝${X}"
echo
