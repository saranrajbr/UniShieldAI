#!/usr/bin/env bash
#
# setup-vm-lab.sh
#
# Creates the two-VM SPAN/tap lab for UniShield using Oracle VirtualBox.
#
#   * Laptop 1  = runs the UniShield backend (engine + API).        (this script is run THERE)
#   * Laptop 2  = runs TWO VMs:  uni-shield (sensor) + attacker.    (virtualized lab)
#
# Networking (inside VirtualBox on Laptop 2):
#   NIC1  -> intnet "lablan"      : the isolated lab LAN (attacker <-> sensor)
#   NIC2  -> intnet "tapbridge"   : mirror/SPAN port (promiscuous allow-all)
#   NIC3  -> nat                  : only for package installs inside the VMs
#
# The sensor VM captures mirrored traffic on NIC2 and forwards FLOWS to the
# backend on Laptop 1 over a WireGuard tunnel (see docs/vm-testing.md).
#
# Usage:
#   ./scripts/setup-vm-lab.sh [uni-shield|attacker]   # create one VM
#   ./scripts/setup-vm-lab.sh                          # create both
#
set -euo pipefail

VM1="${VM1:-uni-shield}"
VM2="${VM2:-attacker}"
OSTYPE="${OSTYPE_:-Ubuntu_64}"
DISK_GB="${DISK_GB:-20}"
MEM_MB="${MEM_MB:-2048}"
CPU="${CPU:-2}"

# internal networks used by the lab
LABLAN="${LABLAN:-lablan}"
TAPBRIDGE="${TAPBRIDGE:-tapbridge}"

need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing: $1"; exit 1; }; }

create_vm() {
  local name="$1"
  if VBoxManage showvminfo "$name" >/dev/null 2>&1; then
    echo "VM '$name' already exists; skipping creation."
    return 0
  fi
  echo "== Creating VM: $name =="
  VBoxManage createvm --name "$name" --ostype "$OSTYPE" --register

  VBoxManage modifyvm "$name" \
    --memory "$MEM_MB" --cpus "$CPU" \
    --nic1 intnet --intnet1 "$LABLAN"    --nicpromisc1 allow-all \
    --nic2 intnet --intnet2 "$TAPBRIDGE" --nicpromisc2 allow-all \
    --nic3 nat   --cableconnected3 on

  local vdi="$HOME/VirtualBox VMs/$name/$name.vdi"
  VBoxManage createmedium disk --filename "$vdi" --size "$((DISK_GB * 1024))" --format VDI
  VBoxManage storagectl "$name" --name SATA --add sata --controller IntelAhci
  VBoxManage storageattach "$name" --storagectl SATA --port 0 --device 0 \
    --type hdd --medium "$vdi"
}

main() {
  need VBoxManage
  if [ $# -eq 0 ]; then
    create_vm "$VM1"
    create_vm "$VM2"
  else
    create_vm "$1"
  fi
  echo
  echo "Done. Inside VirtualBox, attach the OS ISO to the SATA controller of each VM"
  echo "and install the OS. Then apply docs/vm-testing.md section 'VM networking'."
}

main "$@"