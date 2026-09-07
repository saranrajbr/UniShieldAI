# Architecture

UniShield AI is a Python-only, near-real-time network threat detection
engine. It ingests network flows, extracts 20 flow features, runs rule-based
and ML-based detection, fuses them into a risk score, and exposes the results
over REST and WebSockets.

## High-level data flow

```
 Flow sources (Zeek / Scapy / test / synthetic replay)
        │  POST  /api/v1/traffic/flows  (FlowRecord JSON)
        ▼
 ┌─────────────────  Detection Pipeline (app/engine/pipeline.py)  ─────────────┐
 │  flow_hash → FlowState.aggregate → ConnectionTracker.touch                  │
 │        │                                                                   │
 │        ▼                                                                   │
 │  FeatureExtractor.extract_from_entry(entry)  → FlowFeatures (20 features)  │
 │        │                                                                   │
 │        ├─────────────► RuleEngine.result_assessment(features)              │
 │        │                   statistical + behavioral rules                  │
 │        ├─────────────► MLInferenceEngine.run(features)                     │
 │        │                   supervised XGBoost + IsolationForest anomaly    │
 │        ▼                                                                   │
 │  DecisionEngine.decide(flow_id, rules, ml)                                 │
 │       RiskFusion → ScoreBreakdown → RiskScore                              │
 │       ThreatClassifier → threat_type                                       │
 │       SeverityClassifier → severity                                        │
 │       ConfidenceEstimator → confidence                                      │
 └─────────────────────────────────────────────────────────────────────────────┘
        │ decision.is_threat
        ▼
 AlertManager.create_alert(decision, features)
        ├─► WebSocket broadcast  /ws/alerts   (via connection_manager)
        ├─► Persist              AlertRecord / DetectionRecord (SQLite)
        └─► EvidenceCollector    preserve pcap for the incident
```

## Components

### Application bootstrap — `app/main.py`
- `lifespan`: initializes the DB, starts the pipeline worker, the expiry
  manager, the realtime event publisher, wires alert publishers/persisters,
  and boots the ML engine.
- Mounts the 7 routers (`health`, `traffic`, `alerts`, `detection`,
  `metrics`, `models`, `websocket`).
- A 30-second background loop persists `traffic_metrics` snapshots.

### Ingest
- `POST /api/v1/traffic/flow` — single `FlowRecord`.
- `POST /api/v1/traffic/flows` — batch (`{sensor_id, flows[]}`); this is the
  primary ingest used by the sensor, the e2e harness, and training replay.
- Sources:
  - `app/ingestion/scapy.py` — parse a pcap into `FlowRecord`s.
  - `app/ingestion/scapy_live.py` — sniff a live tap/SPAN NIC into flows.
  - `app/ingestion/flow_export_listener.py` — UDP listener (port 2055)
    parsing NetFlow v5/v9, IPFIX v10, sFlow (`app/ingestion/netflow.py`);
    also reusable via `POST /api/v1/traffic/netflow`.
  - `app/ingestion/tls.py` — JA3 fingerprint extraction from raw TLS
    ClientHello bytes (port-443 flows).
  - `app/ingestion/test_source.py` — deterministic synthetic lab traffic.
  - `app/ingestion/zeek.py` — Zeek `conn.log` adapter.
- Flows are identified by `flow_hash(src_ip, dst_ip, src_port, dst_port,
  protocol)`.

### State
- `app/state/flow_state.py` — `FlowState` / `FlowEntry`: aggregates repeated
  reports of the same flow. `merge_stats` accumulates packet/byte/flag counts
  **and per-report timestamps**, which feed the timing features.
- `app/state/connection_tracker.py` — remembers recent connections per
  src→dst, used for `connection_frequency` and port/ip fan-out.
- `app/state/expiry.py` — periodic eviction of stale flows/connections.

### Feature extraction — `app/features/extractor.py`
Produces `FlowFeatures` with the `FEATURE_COLUMNS` vector (20 features):

| Feature | Meaning |
|---------|---------|
| `packet_count`, `byte_count` | aggregate volume for the flow |
| `packets_per_sec`, `bytes_per_sec` | rate (windowed) |
| `syn_ratio`, `ack_ratio`, `rst_ratio`, `fin_ratio` | TCP flag composition |
| `unique_dst_ports`, `unique_dst_ips` | destination fan-out |
| `connection_frequency` | distinct recent connections / 60s from this src |
| `inter_arrival_time_mean`, `inter_arrival_time_std` | packet-gap stats from stored timestamps |
| `periodicity` | cadence regularity `= 1 − min(1, CV(gaps))` ∈ [0,1] |
| `dns_entropy` | natural-log char entropy of DDNS qname |
| `outbound_inbound_ratio` | directional bias |
| `avg_packet_size` | bytes / packets |
| `flow_duration` | last_seen − first_seen |
| `payload_bytes_ratio`, `small_packet_ratio` | payload / small-packet fraction |

In addition to the 20-feature vector, `FlowFeatures` carries forensic fields
that stay **outside** the ML vector (rules/evidence only): `source_entropy`
(Shannon over per-destination source-IP distribution), `udp_amp_ratio`
(UDP response amplification, avg size / 1400 capped at 1), and the `tls_ja3` /
`tls_ja3s` fingerprints — plus optional `dns_qname` metadata on the record.

### Rules — `app/rules/`
- `RuleRegistry.load_defaults()` registers 18 statistical + behavioral rules.
- `statistical.py` — threshold rules using `STATISTICAL_THRESHOLDS`; a `gte`
  score is `min(1.0, 0.5 + (actual − threshold)/threshold)`.
- `behavioral.py` — pattern rules (periodic beacon, SYN flood, port sweep,
  small-packet reconnaissance, brute force, lateral movement, JA3 blocklist).
- `engine.result_assessment()` returns matches and per-category scores.

### ML — `app/ml/`
- `model_loader.py` loads XGBoost (`model.json`) and IsolationForest
  (`model.pkl`) plus the scaler and feature columns.
- `model_registry.py` — `ModelRegistry` with a supervised registry and an
  anomaly registry (each with loaded/fallback semantics).
- `inference.py` — combines supervised probability and anomaly score into a
  single `blended_ml_score`. The supervised model is trusted when confident
  (`|p−0.5|·2 ≥ 0.6`); the anomaly signal only nudges the blend while the
  classifier is uncertain (to avoid the noisy isolation-forest raw decision
  overriding a decisive prediction).
- `feature_schema.py` — `FeatureSchema.vectorize` maps `FlowFeatures` to the
  fixed-order model vector.

### Decision — `app/decision/`
- `risk_fusion.py` — weighted fusion; default weights:
  signature `0.30`, statistical `0.25`, behavioral `0.25`, ML `0.20`,
  normalized by the sum of weights actually present.
- `classifier.py` — picks a `ThreatType` from the highest-scoring evidence;
  `risk < 0.4` → `benign`.
- `severity.py` — `effective = risk·(0.7 + 0.3·confidence)` → CRITICAL
  ≥0.95 / HIGH ≥0.8 / MEDIUM ≥0.6 / LOW ≥0.4 / INFO.
- `confidence.py` — evidence-weighted confidence estimate.
- `engine.py` — `DecisionResult`; `is_threat = risk ≥ 0.6 and
  threat_type != "benign"`.

### Realtime — `app/realtime/`
- `connection_manager` — connected WebSocket clients.
- `publisher.py` — streams (`metrics`, `engine_state`) and alert dispatch.
- `events.py` — `AlertEvent` payload construction.

### Persistence — `app/db/`
- SQLite via SQLAlchemy async (`sqlite+aiosqlite`). Tables: `alerts`,
  `detections`, `traffic_metrics`.
- `persist.py` — `persist_alert`, `persist_metrics_snapshot`.
- `alert_repository.py`, `metrics_repository.py` — read/query helpers.

## Model training — `backend/scripts/train_models.py`
Builds a flow-level dataset by replaying synthetic lab `FlowRecord`s through
the exact live extraction path (FlowState aggregation + ConnectionTracker +
`FeatureExtractor.extract_from_entry` + `FeatureSchema.vectorize`), so the
training distribution matches live features. Trains:
- XGBoost binary classifier (`benign` / `threat`)
- IsolationForest anomaly detector (fit on the benign region)

Run:
```bash
cd backend
PYTHONPATH=$PWD python scripts/train_models.py
```

## Threat-type classification
`ThreatType` values: `port_scan`, `dos`, `ddos`, `brute_force`,
`data_exfiltration`, `c2_communication`, `dns_tunneling`,
`lateral_movement`, `reconnaissance`, `malware_communication`,
`suspicious_traffic`, `benign`. Rule matches and ML each contribute
candidate threat types; the classifier selects the highest-scoring one.