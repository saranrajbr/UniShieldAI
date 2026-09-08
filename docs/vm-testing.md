# UniShield VM Testing Guide (two laptops)

This guide shows how to test UniShield using a two-VM SPAN/tap lab across
**two laptops** connected over the internet. Laptop 2 here runs a **Linux**
host with VirtualBox; for a **Windows** Laptop 2 (Kali VMs) see
[docs/windows-setup.md](windows-setup.md).

## Roles

| Machine     | Role                                                        |
|-------------|-------------------------------------------------------------|
| **Laptop 1**| Runs the UniShield **backend** (FastAPI engine, REST + WS, DB). |
| **Laptop 2**| Runs **two Linux VMs** that generate and sense lab traffic. |

```
Laptop 1 (backend engine)                 Laptop 2 (virtualized lab)
+----------------------------+            +-----------------------------+
|  uvicorn app.main:app      |            |  VM "attacker"              |
|  REST :8000  WS /ws        | WireGuard  |   iperf3 / hping3 / slowloris
|  /ws/alerts                |<==========>|   dnscat2 / iodine          |
|                            |172.16.250  |      |   lablan (10.0.10/24)
|                            | .0/24      |      v  mirror (tc-mirred)  |
|                            |            |  VM "uni-shield" (sensor)   |
|                            |            |   sniff tap NIC -> POST     |
+----------------------------+            |   /api/v1/traffic/flows     |
                                          +-----------------------------+
```

Key idea: **Laptop 2 hosts the lab** (attacker VM + sensor VM) on an
isolated virtual LAN with a mirror/SPAN port. The sensor VM captures
mirrored traffic and forwards **flow records** (not raw packets) over the
encrypted tunnel to the backend on **Laptop 1**.

Using flow records over WireGuard (not raw pcap) reuses the exact
`POST /api/v1/traffic/flows` ingest path and stays robust over the internet,
while per-flow timestamps preserve the timing/periodicity features.

---

## 1. Install VirtualBox (Laptop 2, Linux)

```bash
sudo apt update
sudo apt install -y virtualbox virtualbox-dkms
sudo modprobe vboxdrv
```

> `scripts/setup-vm-lab.sh` shells out to `VBoxManage`.

## 2. Create the two VMs (Laptop 2)

```bash
cd UniShieldAI
./scripts/setup-vm-lab.sh            # creates BOTH "uni-shield" and "attacker"
```

Creates on each VM:
- NIC1 `intnet lablan`     — isolated lab LAN (promiscuous)
- NIC2 `intnet tapbridge`  — mirror/SPAN port (promiscuous allow-all)
- NIC3 `nat`               — package installs inside the VM

Attach a Linux ISO (Ubuntu for `uni-shield`; Ubuntu or Kali for `attacker`)
to each VM's SATA controller and install the OS.

## 3. VM networking (Laptop 2, inside each VM)

| NIC   | Network     | uni-shield (sensor) | attacker        |
|-------|-------------|---------------------|-----------------|
| NIC1  | `lablan`    | `10.0.10.10/24`     | `10.0.10.20/24` |
| NIC2  | `tapbridge` | `10.0.9.10/24`      | `10.0.9.20/24`  |
| NIC3  | `nat`       | DHCP                | DHCP            |

Ubuntu 20.04+ netplan (`/etc/netplan/99-lab.yaml`), on both VMs:

```yaml
network:
  version: 2
  ethernets:
    enp0s3: {dhcp4: no, addresses: [10.0.10.10/24]}   # lablan (adjust per host)
    enp0s8: {dhcp4: no, addresses: [10.0.9.10/24]}    # tapbridge
    enp0s9: {dhcp4: true}                             # nat
```

```bash
sudo netplan apply
```

> Interface names vary; verify with `ip -br a`.

## 4. Mirror the lab traffic onto the tap (both VMs)

```bash
sudo tc qdisc add dev enp0s3 handle ffff: ingress
sudo tc filter add dev enp0s3 parent ffff: flower ip_proto tcp \
  action mirred egress mirror dev enp0s8
sudo tc filter add dev enp0s3 parent ffff: flower ip_proto udp \
  action mirred egress mirror dev enp0s8
```

## 5. WireGuard tunnel between the laptops

Install WireGuard on both laptops:
```bash
sudo apt install -y wireguard
```
On **Laptop 1** (server):
```bash
./scripts/setup-wireguard.sh server
```
On **Laptop 2** (client, endpoint = Laptop 1's public IP/DDNS):
```bash
./scripts/setup-wireguard.sh client sensor-vm 203.0.113.5:51820
```
Exchange public keys (server `[Peer]` gets the client key; client config gets
the server key), then on both:
```bash
sudo wg-quick up wg0
sudo wg show
```
Tunnel: `172.16.250.0/24`; Laptop 1 = `172.16.250.1`, sensor = `172.16.250.2`.

## 6. Start the backend (Laptop 1)

```bash
cd UniShieldAI/backend
PYTHONPATH=$PWD /tmp/opencode/ush_venv/bin/python \
  -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```
From the sensor VM: `curl -s http://172.16.250.1:8000/api/v1/health`.

## 7. Run the sensor (Laptop 2, uni-shield VM)

Install backend deps first (Kali/Ubuntu):
```bash
cd UniShieldAI/backend
python3 -m venv /tmp/ush_venv
/tmp/ush_venv/bin/pip install -r requirements.txt
```
Then sniff the tap NIC and POST flows to Laptop 1:
```bash
cd UniShieldAI
./scripts/run-sensor.sh -i enp0s8 -u http://172.16.250.1:8000
```
Alternate — offline replay of a pcap captured on the tap:
```bash
PYTHONPATH=$PWD python scripts/replay_pcap.py dump.pcap --url http://172.16.250.1:8000
```

## 8. Generate lab traffic (Laptop 2, attacker VM)

| Scenario             | Tool / command                                        | Expected alert |
|----------------------|-------------------------------------------------------|----------------|
| Benign bulk (iperf3) | `iperf3 -c 10.0.10.10`                                | none           |
| SYN flood (hping3)   | `sudo hping3 -S -p 80 --flood 10.0.10.10`             | `ddos`         |
| UDP flood (hping3)   | `sudo hping3 -U -p 1234 --flood 10.0.10.10`           | `dos`          |
| Slowloris            | `slowloris -p 80 -n 200 10.0.10.10`                   | `suspicious`   |
| DNS tunnel (dnscat2) | `python3 dnscat2-client.py 10.0.10.20`                | `dns_tunneling`|
| DNS tunnel (iodine)  | iodine client against DNS on `10.0.10.20`             | `dns_tunneling`|
| C2 beacon (DGA)      | small, timing-regular outbound conns to `10.0.10.20`  | `c2_communication` |

Install tools on attacker: `sudo apt install -y iperf3 hping3 iodine dnsutils`
(`pip3 install slowloris`; clone dnscat2 client from
<https://github.com/iagox86/dnscat2>).

Watch alerts on **Laptop 1**:
```bash
curl -s http://127.0.0.1:8000/api/v1/alerts
# live:  python -c "import asyncio,websockets,json; \
#   async def g():\n    async with websockets.connect('ws://127.0.0.1:8000/ws/alerts') as ws:\n        while 1: print(json.loads(await ws.recv()))\n asyncio.run(g())"
```

## 9. Quick smoke test without cross-laptop setup

On Laptop 1 alone:
```bash
python /tmp/opencode/test_full_backend.py
cat /tmp/opencode/frontend_output.json
```

## Troubleshooting

- **No traffic reaches backend**: `sudo wg show` handshake on both; `curl`
  from sensor VM to `http://172.16.250.1:8000/api/v1/health`; `tc filter show
  dev enp0s3 ingress`.
- **Only NAT traffic seen**: mirrors are on `enp0s3` (lablan) only.
- **`suspicious_traffic` for slowloris/brute-force**: these need repeated /
  low-frequency connections; the attacker client produces them naturally.
- **`VBoxManage` not found**: install VirtualBox (section 1).