# UniShield VM Testing — Laptop 2 on Windows (Kali VMs)

This document is for the case where **Laptop 2 runs Windows** and hosts the
two lab VMs with **VirtualBox** and **Kali Linux** guests.

- **Laptop 1** (Linux, this repo): runs the UniShield **backend**.
- **Laptop 2** (Windows): runs **two Kali VMs** — `uni-shield` (sensor) and
  `attacker` — on an isolated virtual LAN with a tap/SPAN mirror.

Cross-laptop transport and overall design are identical to
[docs/vm-testing.md](vm-testing.md): the sensor VM forwards flow records over
a WireGuard tunnel to the backend. This doc is Windows-specific setup +
Kali guest configuration.

```
Laptop 1 (backend engine)                 Laptop 2 (Windows + VirtualBox)
+------------------------------+          +--------------------------------+
|  uvicorn app.main:app :8000  | WireGuard|  Kali VM "attacker"           |
|  REST :8000  WS /ws /ws/alerts|<========>|   iperf3/hping3/slowloris/    |
|                              |172.16.250|   dnscat2/iodine (lablan)     |
|                              | .0/24    |      │ tc-mirred mirror       |
|                              |          |      ▼                       |
|                              |          |  Kali VM "uni-shield" (sensor)|
+------------------------------+          |   sniff tap -> POST flows    |
                                          +--------------------------------+
```

---

## 1. Install VirtualBox on Windows (Laptop 2)

1. Download VirtualBox from <https://www.virtualbox.org> (Windows hosts
   installer, `.exe`).
2. Install with default options. A redistributable open-source edition
   (`virtualbox-7.1-win-amd64` / older Oracle builds) both work.
3. Start VirtualBox and disable the default "Oracle Cloud Infrastructure"
   extras if prompted (not needed).

The scripts in the repo (`scripts/setup-vm-lab.sh`) call `VBoxManage` from
bash. On Windows run them from **Git Bash** or **WSL2** so `VBoxManage` is on
`PATH`. Alternatively run the equivalent PowerShell below directly.

## 2. Create the two Kali VMs (PowerShell / Git Bash on Windows)

From an admin PowerShell, create the VMs and virtual networks:

```powershell
# --- virtual networks (internal + tap/SPAN) ---
VBoxManage hostonlyif create                 # or use GUI: Host Network Manager
VBoxManage internalnetwork create --name lablan
VBoxManage internalnetwork create --name tapbridge

# --- uni-shield (sensor) ---
VBoxManage createvm --name uni-shield --ostype Debian_64 --register
VBoxManage modifyvm uni-shield --memory 2048 --cpus 2 `
  --nic1 intnet --intnet1 lablan    --nicpromisc1 allow-all `
  --nic2 intnet --intnet2 tapbridge --nicpromisc2 allow-all `
  --nic3 nat
VBoxManage createmedium disk --filename "$env:USERPROFILE\VirtualBox VMs\uni-shield\uni-shield.vdi" --size 20480
VBoxManage storagectl uni-shield --name SATA --add sata
VBoxManage storageattach uni-shield --storagectl SATA --port 0 --device 0 --type hdd --medium "$env:USERPROFILE\VirtualBox VMs\uni-shield\uni-shield.vdi"

# --- attacker ---
VBoxManage createvm --name attacker --ostype Debian_64 --register
VBoxManage modifyvm attacker --memory 2048 --cpus 2 `
  --nic1 intnet --intnet1 lablan    --nicpromisc1 allow-all `
  --nic2 intnet --intnet2 tapbridge --nicpromisc2 allow-all `
  --nic3 nat
VBoxManage createmedium disk --filename "$env:USERPROFILE\VirtualBox VMs\attacker\attacker.vdi" --size 20480
VBoxManage storagectl attacker --name SATA --add sata
VBoxManage storageattach attacker --storagectl SATA --port 0 --device 0 --type hdd --medium "$env:USERPROFILE\VirtualBox VMs\attacker\attacker.vdi"
```

Behavior notes:
- `--nicpromisc allow-all` on both NICs of both VMs so the tap mirror sees all
  frames.
- `--nic3 nat` is only for downloading/installing packages inside Kali.

## 3. Install Kali in each VM

1. Download the **Kali Linux** ISO (amd64) from <https://www.kali.org>.
2. In VirtualBox: select the VM → **Settings → Storage → add Optical Drive** →
   choose the Kali ISO.
3. Boot the VM, install Kali (default recommended partitioning).
4. When prompted to install `tcpdump`/`wireshark` tools, allow them (the
   sensor VM uses Scapy + tcpdump; the attacker VM uses hping3, iperf3).

Repeat for both VMs.

## 4. Kali networking (inside each VM)

Kali uses **NetworkManager**, not netplan. On each VM, set static IPs on the
isolated `lablan` NIC.

Using `nmcli` (replace `enp0s3` with the actual lablan NIC from `ip -br a`):

```bash
# uni-shield sensor VM
sudo nmcli con mod "Wired connection 1" ipv4.method manual ipv4.addresses 10.0.10.10/24
sudo nmcli con up "Wired connection 1"

# attacker VM
sudo nmcli con mod "Wired connection 1" ipv4.method manual ipv4.addresses 10.0.10.20/24
sudo nmcli con up "Wired connection 1"
```

Or edit `/etc/network/interfaces` and disable the UI for that NIC under
NetworkManager. Leave NAT (nic3) on DHCP for package installs.

Verify:
```bash
ip -br a                 # confirm label + tap IPs
ping -c1 10.0.10.10      # from attacker -> sensor over lablan
```

## 5. Mirror the lab traffic onto the tap (both Kali VMs)

On **both** VMs, use `tc` (Kali ships with `iproute2`):

```bash
# on lablan NIC (enp0s3); mirror a copy out to tap NIC (enp0s8)
sudo tc qdisc add dev enp0s3 handle ffff: ingress
sudo tc filter add dev enp0s3 parent ffff: flower ip_proto tcp \
  action mirred egress mirror dev enp0s8
sudo tc filter add dev enp0s3 parent ffff: flower ip_proto udp \
  action mirred egress mirror dev enp0s8
```

The sensor VM's tap NIC now carries mirrored lab traffic to sniff.

## 6. WireGuard tunnel (Laptop 2 Windows → Laptop 1 Linux)

Install WireGuard client on Windows: <https://www.wireguard.com/install/>

1. In the Windows WireGuard app: **Add Tunnel → New Tunnel**, generate keys.
2. Put the Windows client's public key in **Laptop 1's** server
   `[Peer]` block (see `scripts/setup-wireguard.sh server` on Laptop 1).
3. In the client config, use Laptop 1's public IP / DDNS as the endpoint and
   Laptop 1's server public key:

```
[Interface]
PrivateKey = <laptop2-client-private>
Address = 172.16.250.2/32

[Peer]
PublicKey = <laptop1-server-public>
Endpoint = 203.0.113.5:51820
AllowedIPs = 172.16.250.0/24
PersistentKeepalive = 25
```

4. Activate the tunnel in the WireGuard app. Confirm handshake with
   **Laptop 1**: `sudo wg show`.

> The tunnel must route from the **sensor VM**, so on Windows either (a)
> bridge the tunnel from Windows into the sensor VM via a host-only/virtual
> adapter, or (b) simplest: run the sensor VM's POST over the host NAT by
> setting the sensor's default route through the Windows WireGuard interface.
> A common workable layout: put the sensor VM on a **host-only** adapter and
> enable Windows Internet Connection Sharing (ICS) across the WireGuard
> adapter — the sensor still POSTs to `172.16.250.1`.

## 7. Start the backend (Laptop 1, Linux)

```bash
cd UniShieldAI/backend
PYTHONPATH=$PWD /tmp/opencode/ush_venv/bin/python \
  -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

From the sensor VM: `curl -s http://172.16.250.1:8000/api/v1/health`.

## 8. Run the sensor (inside the Kali sensor VM)

Run WiShield's scapy live source against the tap NIC:

```bash
cd UniShieldAI
./scripts/run-sensor.sh -i enp0s8 -u http://172.16.250.1:8000
```

Kali prerequisite: the Python backend deps. Install inside the sensor VM:

```bash
sudo apt update
sudo apt install -y python3-pip python3-venv
cd UniShieldAI/backend
python3 -m venv /tmp/ush_venv
/tmp/ush_venv/bin/pip install -r requirements.txt
```

Then run `run-sensor.sh` with `PYTHONPATH` pointing at the backend + sensor
directories.

## 9. Generate lab traffic (attacker VM)

Kali has the tools installed. Targeting the sensor on the lab LAN
(`10.0.10.10`), traffic is mirrored to the tap and forwarded to Laptop 1.

| Scenario            | Command (attacker Kali VM)                                      | Expected alert |
|---------------------|------------------------------------------------------------------|----------------|
| Benign (iperf3)     | `iperf3 -c 10.0.10.10`                                          | none           |
| SYN flood (hping3)  | `sudo hping3 -S -p 80 --flood 10.0.10.10`                        | `ddos`         |
| UDP flood (hping3)  | `sudo hping3 -U -p 1234 --flood 10.0.10.10`                      | `dos`          |
| Slowloris           | `slowloris -p 80 -n 200 10.0.10.10`                              | `suspicious`   |
| DNS tunnel (dnscat2)| `python3 dnscat2-client.py 10.0.10.20`                          | `dns_tunneling`|
| DNS tunnel (iodine) | iodine client against DNS server on `10.0.10.20`                 | `dns_tunneling`|
| C2 beacon           | small, timing-regular outbound conns to `10.0.10.20`             | `c2_communication`|

Kali installs most tools; if missing:
```bash
sudo apt install -y hping3 iperf3 iodine dnsutils
# slowloris
pip3 install slowloris
# dnscat2 client
git clone https://github.com/iagox86/dnscat2.git
```

## 10. Watch alerts (Laptop 1)

```bash
curl -s http://127.0.0.1:8000/api/v1/alerts
# or live WebSocket:
python -c "
import asyncio, websockets, json
async def go():
    async with websockets.connect('ws://127.0.0.1:8000/ws/alerts') as ws:
        while True: print(json.loads(await ws.recv()))
asyncio.run(go())"
```

---

## Troubleshooting (Windows / Kali)

- **No handshake in WireGuard on Windows**: open UDP/51820 inbound on Laptop 1's
  router/firewall for Laptop 1's public IP; check `sudo wg show` on both.
- **Sensor can't reach `172.16.250.1`**: ensure the Kali sensor VM routes via
  a host-only adapter with Windows ICS, and that WireGuard is up on Windows.
- **Only NAT traffic seen**: mirrors on the `lablan` NIC only; flows over the
  NAT adapter don't cross the tap.
- **`VBoxManage` not found in Git Bash**: add `C:\Program Files\Oracle\VirtualBox`
  to `PATH`.
- **Kali `tc: unknown level`**: run with `sudo` and confirm the NIC exists
  (`ip -br a`).