# UniShield VM Testing Guide (two laptops)

This guide shows how to test UniShield using a two-VM SPAN/tap lab across
**two laptops** connected over the internet.

## Roles

| Machine              | Role                                              |
|----------------------|---------------------------------------------------|
| **Laptop 1**         | Runs the UniShield **backend** (FastAPI engine, REST + WebSocket, DB). |
| **Laptop 2**         | Runs **two VMs** that generate and sense lab traffic.      |

```
Laptop 1 (backend engine)                Laptop 2 (virtualized lab)
+----------------------------+           +-----------------------------+
|  uvicorn app.main:app      |           |  VM "attacker"              |
|  REST :8000  WS /ws        |           |   iperf3 / hping3 / tr.rex/  |
|  /ws/alerts                |  WireGuard|   slowloris / dnscat2       |
|                            |<=========>|      |   lablan (10.0.10/24)
|                            | 172.16.250 |      v  mirror tc-mirred   |
|                            | .0/24      |  VM "uni-shield" (sensor)  |
|                            |           |   sniff tap NIC -> POST     |
+----------------------------+           |   /api/v1/traffic/flows     |
                                         +-----------------------------+
```

Key idea: **Laptop 2 hosts the lab** (attacker VM + sensor VM on an
isolated virtual LAN with a mirror/SPAN port). The sensor VM captures the
mirrored traffic and forwards **flow records** (not raw packets) over the
encrypted tunnel to the backend on **Laptop 1**.

Using flow records over WireGuard, not raw pcap mirroring, is deliberate:
it reuses the exact `POST /api/v1/traffic/flows` ingest path (same one the
e2e harness and training use), stays robust over the internet, and keeps
per-flow timestamps so the timing/periodicity features still work.

---

## 1. Install VirtualBox (Laptop 2)

VirtualBox is what hosts the two VMs. Install it on **Laptop 2** (Ubuntu):

```bash
sudo apt update
sudo apt install -y virtualbox virtualbox-dkms
sudo modprobe vboxdrv
```

> The `scripts/setup-vm-lab.sh` below shells out to `VBoxManage`, so
> VirtualBox must be installed before running it.

## 2. Create the two VMs (Laptop 2)

Everything you need is in the repo script. Clone/copy the repo to Laptop 2,
then run:

```bash
cd UniShieldAI
./scripts/setup-vm-lab.sh            # creates BOTH "uni-shield" and "attacker"
```

The script creates:
- **`uni-shield`** (sensor VM) with:
  - NIC1 `intnet lablan`      — the isolated lab LAN (promiscuous)
  - NIC2 `intnet tapbridge`   — the mirror/SPAN port (promiscuous allow-all)
  - NIC3 `nat`                — only for installing packages inside the VM
- **`attacker`** with the same three NICs.

Inside VirtualBox (GUI), attach the OS ISO to each VM's SATA controller and
install a Linux distro (Ubuntu for `uni-shield`; Ubuntu **or** Kali for
`attacker`).

## 3. VM networking (Laptop 2, inside each VM)

Static IPs on the isolated `lablan` (no gateway — intentionally LAN-only):

| NIC   | Network    | uni-shield (sensor) | attacker        |
|-------|-----------|---------------------|-----------------|
| NIC1  | `lablan`  | `10.0.10.10/24`     | `10.0.10.20/24` |
| NIC2  | `tapbridge`| `10.0.9.10/24`      | `10.0.9.20/24`  |
| NIC3  | `nat`     | DHCP (internet)     | DHCP (internet) |

Ubuntu 20.04+ uses netplan (`/etc/netplan/99-lab.yaml`), same on both VMs
(replace the `.xx` for each host):

```yaml
network:
  version: 2
  ethernets:
    enp0s3:                       # lablan (isolated lab LAN)
      dhcp4: no
      addresses: [10.0.10.10/24]
    enp0s8:                       # tapbridge (mirror port)
      dhcp4: no
      addresses: [10.0.9.10/24]
    enp0s9:                       # nat (internet for installs)
      dhcp4: true
```

Apply:

```bash
sudo netplan apply
```

> The exact interface names (`enp0s3`/`enp0s8`/`enp0s9`) depend on how
> VirtualBox assigns NICs; verify with `ip -br a` after install.

## 4. Mirror the lab traffic onto the tap (Laptop 2)

Both VMs send traffic into `lablan`. Each VM mirrors a copy of its own
`lablan` traffic to `tapbridge` with Linux `tc-mirred`. Do this on **both**
VMs (this is the software equivalent of a SPAN port):

```bash
# on enp0s3 = lablan; send a copy out enp0s8 = tapbridge
sudo tc qdisc add dev enp0s3 handle ffff: ingress
sudo tc filter add dev enp0s3 parent ffff: flower ip_proto tcp \
  action mirred egress mirror dev enp0s8
sudo tc filter add dev enp0s3 parent ffff: flower ip_proto udp \
  action mirred egress mirror dev enp0s8
```

The sensor VM's NIC2 now carries mirrored copies of lab traffic, which it
sniffs and forwards.

## 5. WireGuard tunnel between the laptops

The tunnel carries flow records from the sensor VM (Laptop 2) to the
backend (Laptop 1). **Laptop 1 needs a reachable endpoint** — a public IP /
DDNS, or a port-forward on its router (`UDP 51820`).

On **Laptop 1** (server):

```bash
sudo apt install -y wireguard          # Laptop 1 and Laptop 2
./scripts/setup-wireguard.sh server
```

On **Laptop 2** (client, replace the endpoint with Laptop 1's public
address):

```bash
./scripts/setup-wireguard.sh client sensor-vm 203.0.113.5:51820
```

The scripts print each side's public key. Put the client's key in the
server's `[Peer]` block (and the server's key in the client config), then
bring the tunnel up on both:

```bash
sudo wg-quick up wg0
# verify on both:  sudo wg show
```

The tunnel is `172.16.250.0/24`, with Laptop 1 at `172.16.250.1` and the
sensor VM reachable at `172.16.250.2`.

> **Portable note:** you can run `setup-wireguard.sh` on either laptop; it
> only generates key material and a `wg0.conf` skeleton. The final
> `[Peer]` exchange must happen manually (copy/paste the printed keys).

## 6. Start the backend (Laptop 1)

On **Laptop 1** (this repo), start the engine bound to all tunnel-reachable
interfaces so the sensor VM can POST to it:

```bash
cd UniShieldAI/backend
PYTHONPATH=$PWD /tmp/opencode/ush_venv/bin/python \
  -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Verify it is reachable over the tunnel:

```bash
# from the sensor VM (Laptop 2), once wg0 is up:
curl -s http://172.16.250.1:8000/api/v1/health
```

## 7. Run the sensor on Laptop 2

Inside the **uni-shield sensor VM**, sniff the tap NIC and POST flows to
Laptop 1:

```bash
cd UniShieldAI
./scripts/run-sensor.sh -i enp0s8 -u http://172.16.250.1:8000
```

This uses `app/ingestion/scapy_live.py` (`ScapyLiveSource`) +
`LiveCapture`, aggregating mirrored packets into flow records and sending
them over the tunnel exactly like the e2e harness.

> **Alternative — offline replay:** if you instead capture a pcap on the
> tap and want to push it when convenient, use the existing replay script:
> `PYTHONPATH=$PWD /tmp/opencode/ush_venv/bin/python scripts/replay_pcap.py dump.pcap --url http://172.16.250.1:8000`

## 8. Generate lab traffic (Laptop 2, attacker VM)

From the **attacker VM**, drive the same scenarios the model and rules were
trained/verified on. Their traffic is mirrored to the tap, so the sensor
forwards it and the engine on Laptop 1 alerts:

| Scenario            | Tool / command (on attacker VM)                                  | Expected alert (Laptop 1) |
|---------------------|------------------------------------------------------------------|---------------------------|
| Benign bulk (iperf3)| `iperf3 -c 10.0.10.10`                                          | no alert (risk < 0.6)     |
| SYN flood (hping3)  | `sudo hping3 -S -p 80 --flood 10.0.10.10`                        | `ddos`                    |
| UDP flood (hping3)  | `sudo hping3 -U -p 1234 --flood 10.0.10.10`                      | `dos`                     |
| Slowloris           | `slowloris -p 80 -n 200 10.0.10.10` (or slowloris.py)            | `suspicious_traffic`      |
| DNS tunnel (dnscat2)| `python3 dnscat2-client.py 10.0.10.20` (tunnel to attacker VM)   | `dns_tunneling`           |
| DNS tunnel (iodine) | run an `iodine` tunnel against a DNS server on `10.0.10.20`      | `dns_tunneling`           |
| C2 beacon (DGA)     | a script opening small, timing-regular outbound conns to `attacker`| `c2_communication`       |

The engine alerts in real time. Watch them on **Laptop 1**:

```bash
# REST (persisted alerts):
curl -s http://127.0.0.1:8000/api/v1/alerts
# WebSocket live stream:
python -c "
import asyncio, websockets, json
async def go():
    async with websockets.connect('ws://127.0.0.1:8000/ws/alerts') as ws:
        while True: print(json.loads(await ws.recv()))
asyncio.run(go())"
```

## 9. Quick smoke test without cross-laptop setup

If you just want to confirm the engine end-to-end before wiring the tunnel,
run the included harness on **Laptop 1** alone (backend already running):

```bash
python /tmp/opencode/test_full_backend.py
cat /tmp/opencode/frontend_output.json
```

---

## Troubleshooting

- **No traffic arrives at the backend**: verify `sudo wg show` on both
  laptops shows a handshake; confirm `curl` from sensor VM to
  `http://172.16.250.1:8000/api/v1/health`; make sure `tc-mirred` rules
  exist (`tc filter show dev enp0s3 ingress`).
- **Only NAT traffic seen, not lab traffic**: mirrors are configured on
  `enp0s3` (lablan) only; a `nat`-only flow won't cross the tap.
- **Alerts show but as `suspicious_traffic` for slowloris/brute-force**:
  these are single-flow/low-frequency; feed them as repeated connections
  (the Slowloris client does this naturally) so behavioral rules and the
  timing features fire.
- **`VBoxManage` not found**: install VirtualBox (section 1) and ensure
  `VBoxManage` is on `PATH`.