# Deployment

Run the UniShield backend locally, in Docker, or on a VM. The backend is a
Python 3.12+ FastAPI application; ML artifacts (`models/`) must be present.

Default config lives in `backend/app/core/config.py` and can be overridden
with a `.env` file (`backend/.env`, see `backend/.env.example`).

## Quick start (local)

```bash
cd backend
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python app/main.py
# or directly:
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

The engine auto-creates `unishield.db` on first run. On startup it also opens
the UDP flow-export listener on `NETFLOW_UDP_PORT` (default `2055`), so the
same pipeline serves router-sourced NetFlow / IPFIX / sFlow exports and
direct sensor recording. Throughput is observable live via `GET
/api/v1/metrics` (`flow_rate_fps`) and per-listener counters in
`GET /api/v1/metrics/engine` (`flow_export.datagrams_received`,
`records_parsed`, `records_rejected`).

## Configuration (`.env`)

| Variable | Default | Purpose |
|----------|---------|---------|
| `HOST` / `PORT` | `0.0.0.0` / `8000` | bind address / port |
| `DEBUG` | `false` | uvicorn reload |
| `MAIN-DATABASE__URL` | `sqlite+aiosqlite:///./unishield.db` | async DB URL |
| `DETECTION_THRESHOLD` | `0.6` | `is_threat` risk cutoff |
| `HIGH_RISK_THRESHOLD`/`CRITICAL_RISK_THRESHOLD` | `0.85` / `0.95` | severity bands |
| `RULE_WEIGHT_SIGNATURE` | `0.30` | risk fusion: signature |
| `RULE_WEIGHT_STATISTICAL` | `0.25` | risk fusion: statistical |
| `RULE_WEIGHT_BEHAVIORAL` | `0.25` | risk fusion: behavioral |
| `ML_WEIGHT_SUPERVISED` / `ML_WEIGHT_ANOMALY` | `0.12` / `0.08` | reserved (ML fused via `ml_blended`) |
| `XGBOOST_MODEL_PATH` | `models/xgboost/model.json` | supervised model |
| `ISOLATION_FOREST_MODEL_PATH` | `models/isolation_forest/model.pkl` | anomaly model |
| `SCALER_PATH` / `FEATURE_COLUMNS_PATH` | `models/preprocessing/...` | preprocessing artifacts |
| `PCAP_ACTIVE_PATH` / `PCAP_INCIDENTS_PATH` / `PCAP_ARCHIVE_PATH` | `captures/...` | pcap rotation paths |
| `FLOW_TIMEOUT_SEC` / `CONNECTION_EXPIRY_SEC` / `ROLLING_WINDOW_SEC` | `120` / `300` / `60` | state windows |
| `MAX_CONCURRENT_FLOWS` / `PIPELINE_QUEUE_SIZE` | `10000` / `50000` | capacity |
| `NETFLOW_UDP_HOST` / `NETFLOW_UDP_PORT` | `0.0.0.0` / `2055` | UDP flow-export listener (NetFlow v5/v9, IPFIX v10, sFlow) |
| `CORS_ORIGINS` | `http://localhost:3000,http://localhost:5173` | comma-separated allowed origins |

> `ml_blended` (weight `0.20`) is the label used by `RiskFusion.fuse` for
> the ML component. The `ml_weight_supervised` / `ml_weight_anomaly` values
> are not summed directly in fusion; the blended score is computed upstream in
> `MLInferenceEngine`.

## Docker / docker-compose

`backend/docker-compose.yml`:
```bash
cd backend
docker compose up --build
```
- Publishes `8000:8000`.
- Mounts `./captures`, `./models`, `./logs` as volumes.
- Loads `./.env.example` as the environment.

`Dockerfile` copies the whole `backend/` into `/app` and runs
`uvicorn app.main:app`.

## Running the sensor / capturing traffic

- **pcap replay:** push an existing capture into the engine:
  ```bash
  cd backend
  PYTHONPATH=$PWD python scripts/replay_pcap.py dump.pcap --url http://localhost:8000
  ```
- **flow-export replay (NetFlow/IPFIX/sFlow):** route exports to the UDP
  listener or POST datagram bytes:
  ```bash
  PYTHONPATH=$PWD python scripts/generate_test_traffic.py --url http://localhost:8000
  # or send raw bytes directly:
  curl -X POST http://localhost:8000/api/v1/traffic/netflow --data-binary @export.dat
  ```
- **live tap sniff (Laptop 2 sensor VM):**
  ```bash
  backend/app/scripts/run-sensor.sh -i <tap-nic> -u http://<laptop1>:8000
  ```
  Wires `ScapyLiveSource` + `LiveCapture` (see `docs/vm-testing.md`,
  `docs/windows-setup.md`).
- **WireGuard tunnel (Laptop 1 ↔ sensor VM):**
  ```bash
  backend/app/scripts/setup-wireguard.sh
  ```
  Server listens on `172.16.250.1:51820`; the sensor VM dials in on
  `172.16.250.2`.
- **synthetic smoke test / test suite:**
  ```bash
  cd backend
  PYTHONPATH=$PWD python -m pytest tests/ -q
  ```

## Model artifacts

Training produces:
- `models/xgboost/model.json`
- `models/preprocessing/scaler.pkl`
- `models/preprocessing/feature_columns.json`
- `models/class_names.json`
- `models/isolation_forest/model.pkl`

Retrain on demand:
```bash
cd backend
PYTHONPATH=$PWD python scripts/train_models.py
```

## Persistence

SQLite via SQLAlchemy async (`sqlite+aiosqlite`). Tables created at startup
(`Base.metadata.create_all`):
- `alerts` — alert rows (evidence JSON, detection sources, pcap path).
- `detections` — per-flow detection records.
- `traffic_metrics` — 30-second metric snapshots.

Swap persistence by changing `MAIN-DATABASE__URL` (Postgres/MySQL use the
SQLAlchemy async dialect + driver).

## Realtime

- `WS /ws` — hello/ping-pong + `metrics` / `engine_state` streams.
- `WS /ws/alerts` — alert events.

## Health checks

- `GET /api/v1/health` — overall status + engine detail.
- `GET /api/v1/health/live` — liveness.
- `GET /api/v1/health/ready` — readiness (pipeline worker + rules).

## Deploying behind a reverse proxy

Run uvicorn on `127.0.0.1` and proxy:
```nginx
location /api/ { proxy_pass http://127.0.0.1:8000; proxy_set_header Host $host; }
location /ws/   { proxy_pass http://127.0.0.1:8000; proxy_http_version 1.1;
                  proxy_set_header Upgrade $http_upgrade; proxy_set_header Connection "upgrade"; }
```
For Docker, remove `ports` and join the proxy's network so only the proxy is
exposed.