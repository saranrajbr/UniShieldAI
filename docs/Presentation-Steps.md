# UniShield AI — Live Demo Runbook (Presentation)

Two laptops, one tunnel, live traffic -> alerts. Everything is **pre-staged**;
the only 4 actions during the demo are the commands below.

```
Laptop 1 (Linux)                 Laptop 2 (Windows + WireGuard app)
+----------------------------+   +---------------------------------+
| backend  :8000             |   | WireGuard tunnel  172.16.250.2  |
| frontend :5173        wg0  |<=>| Kali VM "attacker"              |
| 172.16.250.1               |   |    (syn flood, slowloris, ...)  |
|                            |   | Kali VM "uni-shield" (sensor)   |
+----------------------------+   +---------------------------------+
```

---

## LAPTOP 1 — Linux (backend + frontend + tunnel server)

1) Start the backend:
```bash
cd ~/UniShieldAI/backend
PYTHONPATH=$PWD /tmp/opencode/ush_venv/bin/python app/main.py
```

2) Start the frontend (new terminal):
```bash
cd ~/UniShieldAI/frontend
npm run dev -- --host 0.0.0.0
```

3) Bring up the tunnel server (needed once; stays up while laptop is on):
```bash
sudo wg-quick up wg0     # config already at /etc/wireguard/wg0.conf
sudo wg show             # expect "peer … gGC6ZzA… last handshake: X seconds ago"
```

4) Sanity check:
```bash
curl -s http://localhost:8000/api/v1/health
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:5173/        # expect 200
```

`http://localhost:5173` is the presentation screen; full-screen it.

---

## LAPTOP 2 — Windows (WireGuard client + Kali lab VMs)

Pre-staged earlier — copy `docs/wireguard/laptop2-windows.conf` into the
WireGuard app once (File -> Import tunnel(s) -> choose the file -> Activate).
No key exchange is needed at the event.

Prepare (before demo):
- Install WireGuard for Windows: https://www.wireguard.com/install/
- Import `laptop2-windows.conf` (private key is already inside; keep the file
  private).
- Start VirtualBox; ensure both Kali VMs (`uni-shield`, `attacker`) are up.

During demo:
1. Open the **WireGuard app** -> select `laptop2-windows` -> **Connect**
   (icon turns green, "Handshake: X s ago" appears).
2. Check the tunnel: `ping 172.16.250.1` (PowerShell).
3. In the **attacker** Kali VM, fire the traffic you want to show:
   ```bash
   # benign
   iperf3 -c 10.0.10.10
   # SYN flood
   sudo hping3 -S -p 80 --flood 10.0.10.10
   # UDP flood / DNS flood
   sudo hping3 -U -p 1234 --flood 10.0.10.10
   # slowloris
   slowloris -p 80 -n 200 10.0.10.10
   ```
4. The Kali **uni-shield sensor VM** sniffs the tap and POSTs flows to
   `172.16.250.1:8000` (start it before the event on the sensor VM):
   ```bash
   cd UniShieldAI && sudo ./scripts/run-sensor.sh -i enp0s8 -u http://172.16.250.1:8000
   ```

---

## Watch the result (Laptop 1 screen)

- Alerts live: `http://localhost:5173/alerts` (or Overview at `/`)
- Open /alerts, click an alert row -> `/investigation/<id>` shows features +
  score breakdown + recommended (advisory-only) actions.

---

## Numbers to mention

- Tunnel: `172.16.250.1` <-> `172.16.250.2`, UDP 51820, WireGuard.
- Backend pipeline: ingest (NetFlow/Scapy) -> features (20) -> rules + ML
  (XGBoost + Isolation Forest) -> decision fusion -> alerts.
- Read-only SOC: no Block/Isolate, only recommendations (PS 26145).

## Troubleshooting

| Symptom | Fix |
|---|---|
| WireGuard app no "Handshake" | Both laptops same Wi-Fi; check `sudo wg show` on L1; try endpoint `171.79.55.84:51820` (needs UDP 51820 forwarded on router) |
| `172.16.250.1` unreachable from Kali | Route RM: sensor VM must reach L1 via a host-only adapter + Windows ICS across the WireGuard adapter |
| No alerts after attack | Check sensor `run-sensor.sh` running; `/api/v1/traffic/stats` flow counter rising |