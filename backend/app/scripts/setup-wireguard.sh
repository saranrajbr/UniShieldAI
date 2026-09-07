#!/usr/bin/env bash
#
# setup-wireguard.sh
#
# Configures the encrypted tunnel that carries the lab away from Laptop 2.
#
#   * Laptop 1 (backend) = WireGuard SERVER (needs a reachable public IP/DDNS
#     or a port-forward on the router; default UDP 51820).
#   * Laptop 2 (VMs)     = WireGuard CLIENT(s) that dial the server.
#
# The sensor VM on Laptop 2 POSTs flow records to the backend on Laptop 1
# over this tunnel (202.202.10.0/24 private tunnel net).
#
# Run the matching role on each laptop:
#   Laptop 1:  ./scripts/setup-wireguard.sh server
#   Laptop 2:  ./scripts/setup-wireguard.sh client CLIENT_NAME SERVER_ENDPOINT
#
# Example (Laptop 2):
#   ./scripts/setup-wireguard.sh client sensor-vm vpn.example.com:51820
#
set -euo pipefail

TUN_NET="${TUN_NET:-172.16.250.0/24}"
SVR_IP="${SVR_IP:-172.16.250.1}"
PORT="${WG_PORT:-51820}"
CONFDIR="${WG_CONFDIR:-/etc/wireguard}"

need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing: $1"; exit 1; }; }

gen_keys() {
  local priv pub
  priv=$(wg genkey); pub=$(echo "$priv" | wg pubkey)
  echo "$priv|$pub"
}

write_conf() {
  local path="$1" content="$2"
  if [ -e "$path" ]; then
    echo "$path already exists; leaving untouched (edit to regenerate)."
  else
    printf '%s\n' "$content" | sudo tee "$path" >/dev/null
    sudo chmod 600 "$path"
    echo "wrote $path"
  fi
}

server() {
  need wg
  local k; k=$(gen_keys); local priv="${k%%|*}" pub="${k##*|}"
  echo "SERVER public key: $pub   (give this to Laptop 2 clients)"
  echo "SERVER endpoint:   $(hostname -I | awk '{print $1}'):$PORT  (or your public IP/DDNS)"
  write_conf "$CONFDIR/wg0.conf" \
" [Interface]
Address = $SVR_IP/24
ListenPort = $PORT
PrivateKey = $priv

# --- Client '[Sensor-vm]' ---
# Append each client here. Replace ClientPublicKey with the client's own key.
[Peer]
# PublicKey = <client-public-key>
# AllowedIPs = 172.16.250.2/32
"
  echo "Now add each Laptop 2 client [Peer] block above with its real key."
}

client() {
  [ $# -ge 3 ] || { echo "usage: $0 client NAME SERVER_ENDPOINT[ :port]"; exit 1; }
  need wg
  local name="$1" endpoint="$2" ip="${3:-172.16.250.2}"
  local k; k=$(gen_keys); local priv="${k%%|*}" pub="${k##|*}"
  echo "CLIENT '$name' public key: $pub   (give this to Laptop 1 server)"
  echo "Server public key: (paste the SERVER's public key into the next line)"
  read -r -p "ServerPublicKey> " srvpub
  write_conf "$CONFDIR/wg0.conf" \
" [Interface]
Address = $ip/32
PrivateKey = $priv
[Peer]
PublicKey = $srvpub
Endpoint = $endpoint
AllowedIPs = 172.16.250.0/24
PersistentKeepalive = 25
"
  echo "After both configs are in place: sudo wg-quick up wg0  (on both laptops)"
}

usage() { echo "usage: $0 {server | client NAME SERVER_ENDPOINT [IP]}"; exit 1; }

case "${1:-}" in
  server) server;;
  client) shift; client "$@";;
  *) usage;;
esac