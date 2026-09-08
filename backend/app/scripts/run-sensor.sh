#!/usr/bin/env bash
#
# run-sensor.sh  (run on LAPTOP 2, inside the uni-shield sensor VM)
#
# Sniffs the tap/SPAN interface for mirrored lab traffic and POSTs the
# resulting flow records to the UniShield backend on Laptop 1 over the
# WireGuard tunnel.
#
# Usage:
#   ./scripts/run-sensor.sh -i <tap-nic> -u <laptop1-backend-url>
#   ./scripts/run-sensor.sh -i enp0s8 -u http://172.16.250.1:8000
#
set -euo pipefail

IFACE=""
URL="http://172.16.250.1:8000"

usage() {
  echo "usage: $0 -i <tap-nic> [-u <laptop1-backend-url>]"
  exit 1
}
while getopts "i:u:h" o; do
  case "$o" in
    i) IFACE="$OPTARG" ;;
    u) URL="$OPTARG" ;;
    *) usage ;;
  esac
done
[ -n "$IFACE" ] || usage

echo "Putting $IFACE in promiscuous mode (needs root):"
sudo ip link set "$IFACE" promisc on 2>/dev/null || true

# Wrapper lives at backend/app/scripts/: repo root is 3 levels up.
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
BACKEND="$REPO_ROOT/backend"
PYTHON="$BACKEND/.venv/bin/python"
[ -x "$PYTHON" ] || PYTHON=/tmp/opencode/ush_venv/bin/python
[ -x "$PYTHON" ] || PYTHON=$(command -v python3)
PYTHONPATH="$BACKEND:$BACKEND/sensor" \
  "$PYTHON" \
  "$BACKEND/scripts/run_sensor.py" -i "$IFACE" -u "$URL"