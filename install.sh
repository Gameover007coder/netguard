#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────
#  NetGuard Installer
#  Sets up the firewall + live traffic dashboard on Ubuntu/Debian.
#
#  Usage:  sudo bash install.sh
# ─────────────────────────────────────────────────────────────────
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

INSTALL_DIR="/opt/netguard"
SERVICE_NAME="netguard"
VENV_DIR="${INSTALL_DIR}/venv"

banner() {
    echo -e "${CYAN}"
    echo "  ╔═══════════════════════════════════════╗"
    echo "  ║        NetGuard Installer             ║"
    echo "  ║  Firewall + Live Traffic Dashboard    ║"
    echo "  ╚═══════════════════════════════════════╝"
    echo -e "${NC}"
}

info()  { echo -e "${GREEN}[✓]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
fail()  { echo -e "${RED}[✗]${NC} $*"; exit 1; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        fail "This script must be run as root (use sudo)."
    fi
}

install_system_deps() {
    info "Updating package lists…"
    apt-get update -qq

    info "Installing system dependencies…"
    apt-get install -y -qq \
        nftables \
        conntrack \
        python3 \
        python3-venv \
        python3-pip \
        python3-dev \
        libnetfilter-conntrack3 \
        > /dev/null 2>&1

    info "System packages installed."
}

enable_conntrack_accounting() {
    info "Enabling conntrack accounting…"
    sysctl -w net.netfilter.nf_conntrack_acct=1 > /dev/null 2>&1 || true

    # Make persistent
    if ! grep -q "nf_conntrack_acct" /etc/sysctl.conf 2>/dev/null; then
        echo "net.netfilter.nf_conntrack_acct=1" >> /etc/sysctl.conf
    fi
    info "Conntrack accounting enabled."
}

copy_files() {
    info "Installing NetGuard to ${INSTALL_DIR}…"
    mkdir -p "${INSTALL_DIR}"

    # Copy everything from the source directory
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    cp -r "${SCRIPT_DIR}/app.py"       "${INSTALL_DIR}/"
    cp -r "${SCRIPT_DIR}/requirements.txt" "${INSTALL_DIR}/"
    cp -r "${SCRIPT_DIR}/collectors"   "${INSTALL_DIR}/"
    cp -r "${SCRIPT_DIR}/firewall"     "${INSTALL_DIR}/"
    cp -r "${SCRIPT_DIR}/templates"    "${INSTALL_DIR}/"
    cp -r "${SCRIPT_DIR}/static"       "${INSTALL_DIR}/"

    info "Files copied."
}

setup_venv() {
    info "Creating Python virtual environment…"
    python3 -m venv "${VENV_DIR}"

    info "Installing Python dependencies…"
    "${VENV_DIR}/bin/pip" install --upgrade pip > /dev/null 2>&1
    "${VENV_DIR}/bin/pip" install -r "${INSTALL_DIR}/requirements.txt" > /dev/null 2>&1

    info "Python environment ready."
}

load_firewall() {
    info "Loading nftables firewall rules…"

    # Safety: check if nftables service is active
    systemctl enable nftables > /dev/null 2>&1 || true
    systemctl start nftables > /dev/null 2>&1 || true

    # Load our rules
    nft -f "${INSTALL_DIR}/firewall/firewall.nft"

    info "Firewall rules loaded. Inspect with: sudo nft list ruleset"
}

install_service() {
    info "Installing systemd service…"

    cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=NetGuard – Firewall & Live Traffic Dashboard
After=network.target nftables.service
Wants=nftables.service

[Service]
Type=simple
ExecStart=${VENV_DIR}/bin/python ${INSTALL_DIR}/app.py
WorkingDirectory=${INSTALL_DIR}
Environment=NETGUARD_HOST=127.0.0.1
Environment=NETGUARD_PORT=5000

# Security hardening
NoNewPrivileges=false
ProtectSystem=strict
ReadWritePaths=${INSTALL_DIR}
PrivateTmp=true

# Needs root for nft, conntrack, and raw sockets
User=root

Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable "${SERVICE_NAME}" > /dev/null 2>&1
    systemctl start "${SERVICE_NAME}"

    info "Service installed and started."
}

print_summary() {
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}  NetGuard is installed and running!${NC}"
    echo ""
    echo -e "  Dashboard:  ${CYAN}http://127.0.0.1:5000${NC}"
    echo -e "  Service:    ${CYAN}systemctl status netguard${NC}"
    echo -e "  Logs:       ${CYAN}journalctl -u netguard -f${NC}"
    echo -e "  Firewall:   ${CYAN}sudo nft list ruleset${NC}"
    echo ""
    echo -e "  ${YELLOW}Stop:${NC}     sudo systemctl stop netguard"
    echo -e "  ${YELLOW}Restart:${NC}  sudo systemctl restart netguard"
    echo -e "  ${YELLOW}Uninstall:${NC} sudo systemctl stop netguard && \\"
    echo -e "              sudo systemctl disable netguard && \\"
    echo -e "              sudo rm -rf /opt/netguard /etc/systemd/system/netguard.service && \\"
    echo -e "              sudo nft flush ruleset"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    warn "The dashboard is bound to 127.0.0.1 only (not exposed to the network)."
    warn "If using SSH, ensure port 22 is allowed before rebooting!"
    echo ""
}

# ── Main ─────────────────────────────────────────────────────────
main() {
    banner
    check_root
    install_system_deps
    enable_conntrack_accounting
    copy_files
    setup_venv
    load_firewall
    install_service
    print_summary
}

main "$@"

