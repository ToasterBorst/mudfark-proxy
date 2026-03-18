#!/bin/bash
# Graceful restart for mudlark-proxy
# Sends SIGUSR1 to trigger countdown warnings to all connected clients,
# then the server shuts down and systemd restarts it.
#
# Usage:
#   sudo ./scripts/graceful-restart.sh              # 15 minute countdown (default)
#   sudo RESTART_DELAY=5m ./scripts/graceful-restart.sh  # 5 minute countdown
#   sudo RESTART_DELAY=30s ./scripts/graceful-restart.sh # 30 second countdown
#
# The RESTART_DELAY env var must be set BEFORE the service receives the signal,
# so this script stops the service, sets the env override, and restarts it with
# the signal approach. Alternatively, set it in the systemd unit.
#
# Simplest approach: just signal the running process.

set -e

SERVICE="mudlark-proxy"

# Find the main PID of the service
PID=$(systemctl show -p MainPID --value "$SERVICE" 2>/dev/null)

if [ -z "$PID" ] || [ "$PID" = "0" ]; then
    echo "Error: $SERVICE is not running"
    exit 1
fi

# Build the new binary first
echo "Building new binary..."
cd "$(dirname "$0")/.."
go build -o mudlark-proxy ./cmd/server

DELAY="${RESTART_DELAY:-15m}"
echo "Sending graceful restart signal to $SERVICE (PID $PID)"
echo "Clients will receive countdown warnings over the next $DELAY"

# Write delay to a temp file so the server process can read it
# (environment variables can't be injected into a running process)
echo -n "$DELAY" > /run/mudlark-restart-delay

kill -USR1 "$PID"

echo "Signal sent. The server will shut down after the countdown."
echo "systemd will then restart it with the new binary."
echo ""
echo "Monitor with: sudo journalctl -u $SERVICE -f"
