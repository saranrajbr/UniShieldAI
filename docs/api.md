# API Reference

Base URL: `http://<host>:8000` (default port 8000). OpenAPI docs at
`/docs` (Swagger UI) or `/openapi.json`.

All paths are under `/api/v1` except the WebSocket routes.

---

## Health

### `GET /api/v1/health`
Engine liveness + readiness summary.
```json
{
  "status": "ok",
  "app": "UniShield AI",
  "version": "0.1.0",
  "uptime_sec": 1277.3,
  "engine": {
    "rules_loaded": 15,
    "ml": {"supervised_loaded": true, "anomaly_loaded": true},
    "pipeline_queue": 0,
    "pipeline_active": true
  }
}
```

### `GET /api/v1/health/live`
`{"alive": true, "timestamp": "..."}` — process is up.

### `GET /api/v1/health/ready`
`{"ready": bool, "checks": {...}}` — pipeline worker + rules loaded.

---

## Traffic ingest

### `POST /api/v1/traffic/flow`
Ingest a single flow.

Request body — `FlowRecord`:
```json
{
  "ts": "2026-09-02T08:28:05Z",
  "src_ip": "142.75.220.33",
  "dst_ip": "10.0.5.50",
  "src_port": 51234,
  "dst_port": 80,
  "protocol": "tcp",
  "direction": "inbound",
  "packet_count": 450,
  "byte_count": 32614,
  "syn_count": 421,
  "ack_count": 29,
  "rst_count": 0,
  "fin_count": 0,
  "dns_query": null
}
```

Response — `FlowIngestResponse`:
```json
{"received": 1, "accepted": 1, "rejected": 0, "flow_ids": ["<flow_hash>"]}
```

### `POST /api/v1/traffic/flows`
Batch ingest — the primary path used by the sensor, e2e harness, and pcap
replay.

Request body — `FlowBatchIn`:
```json
{
  "sensor_id": "test-sensor",
  "flows": [ { ...FlowRecord... }, { ... } ]
}
```

Response:
```json
{"received": 204, "accepted": 204, "rejected": 0, "flow_ids": ["...", "..."]}
```

> `sensor_id` is required. Posting a bare flow object (no `sensor_id`)
> returns `received: 0`.

### `POST /api/v1/traffic/netflow`
Ingest a raw **flow-export datagram** (NetFlow v5/v9, IPFIX v10, or sFlow)
as opaque bytes. Version detection + protocol parsing are done server-side
(`backend/app/ingestion/netflow.py`); parsed records enter the same pipeline
as live captures.
```sh
curl -X POST http://localhost:8000/api/v1/traffic/netflow \
  --data-binary @flow_export.dat
```
```json
{"received": 9, "accepted": 9, "rejected": 0}
```

### `GET /api/v1/traffic/flows?limit=200`
Snapshot of the active traffic flows for the monitoring UI:
```json
{
  "count": 6,
  "limit": 200,
  "window": "60s",
  "flows": [
    {
      "flow_id": "<flow_hash>", "src_ip": "10.24.18.42", "dst_ip": "185.45.8.3",
      "src_port": 443, "dst_port": 51234, "protocol": "tcp",
      "packet_count": 12492, "byte_count": 8811520,
      "syn_count": 421, "ack_count": 12071, "rst_count": 0, "fin_count": 0,
      "first_seen": 1725300000, "last_seen": 1725300083, "age_sec": 83.2,
      "periodicity": 0.92
    }
  ]
}
```
`periodicity` is estimated from the inter-arrival gaps of a flow's timestamp
history (CV-based; `0` for one-shot flows).

### `GET /api/v1/traffic/stats`
Live engine counters:
```json
{
  "flows_queued": 0,
  "active_flows": 2,
  "connections": 0,
  "processed": 204,
  "window": "60s"
}
```

### `POST /api/v1/traffic/replay?pcap_path=...`
Parse a pcap on the server into flows and submit them.
```json
{"replayed": 45, "accepted": 45}
```

---

## Alerts

### `GET /api/v1/alerts?limit=50`
Persisted + recent live alerts, newest first.
```json
{
  "total": 14,
  "alerts": [
    {
      "id": "1A912E2BABC76D61",
      "alert_id": "1A912E2BABC76D61",
      "timestamp": "2026-09-02T08:28:05.247137",
      "src_ip": "142.75.220.33",
      "dst_ip": "10.0.5.50",
      "protocol": "tcp",
      "threat_type": "ddos",
      "severity": "medium",
      "confidence": 0.7183,
      "risk_score": 0.8462,
      "evidence": {
        "features": {"packet_count": 450, "syn_ratio": 0.9356},
        "score_breakdown": {"statistical": 0.6694, "ml_blended": 0.9999}
      },
      "detection_sources": ["statistical", "behavioral", "supervised_ml", "anomaly_detection"]
    }
  ]
}
```

### `GET /api/v1/alerts/live?limit=100`
Only the in-memory recent alerts (no DB query).

### `GET /api/v1/alerts/{alert_id}`
Single alert by id. `404` if not found.

### `POST /api/v1/alerts/{alert_id}/resolve`
Mark an alert resolved.
```json
{"ok": true, "status": "resolved", "alert_id": "..."}
```

---

## Detection

### `GET /api/v1/detection/engines`
Loaded rule + ML + decision info:
```json
{
  "rules": {
    "loaded": 15,
    "categories": {"statistical": 9, "behavioral": 6}
  },
  "ml": {"registry": {...}, "stats": {"inferences": 0, "errors": 0}},
  "decision": {"threshold": null, "is_threat_gt": 0.6}
}
```

### `POST /api/v1/detection/analyze`
Re-run detection for a previously ingested flow id. If the flow is no longer
cached, returns an empty (benign) decision.
```json
{"flow_id": "..."}
```
Response — `DecisionResult` with `risk_score`, `confidence`, `threat_type`,
`severity`, `is_threat`, `detection_sources`, `score_breakdown`.

---

## Metrics

### `GET /api/v1/metrics`
Runtime snapshot (uptime, flows, alerts, rate, cpu/memory, queue):
```json
{
  "uptime_sec": 92.48,
  "flows_processed": 2,
  "alerts_raised": 0,
  "rules_fired": 0,
  "ml_inferences": 1,
  "flow_rate_fps": 0.39,
  "cpu_percent": 13.3,
  "memory_mb": 185.6,
  "queue_high_watermark": 1,
  "processing_errors": 0
}
```

### `GET /api/v1/metrics/traffic`
Windowed feature statistics (packet/byte rates, flow counts).

### `GET /api/v1/metrics/engine`
Engine internals: queue depth, active flows, recent alerts,
alert stats, ML inference stats, per-rule match counts, and the
flow-export listener state:
```json
{
  "flows_queued": 0, "active_flows": 6, "alerts_recent": 4,
  "flow_export": {"udp_host": "0.0.0.0", "udp_port": 2055,
                  "datagrams_received": 1204, "records_parsed": 1187,
                  "records_rejected": 17}
}
```

---

## Models

### `GET /api/v1/models`
Loaded ML model status + file paths.

### `POST /api/v1/models/reload`
Reload XGBoost + IsolationForest artifacts from disk.
```json
{"ok": true, "status": {"supervised_loaded": true, "anomaly_loaded": true}}
```

### `GET /api/v1/models/rules`
All rule ids + match counters:
```json
{"count": 15, "rules": [{"rule_id": "stat_syn_ratio_high", "category": "statistical", "match_count": 3}, ...]}
```

---

## WebSocket

### `WS /ws`
Realtime feed. On connect:
```json
{"type": "hello", "data": {"message": "UniShield AI realtime feed active"}}
```
Sending `ping` (or empty) returns a `pong`. Streams carry `metrics` and
`engine_state` envelope frames:
```json
{"type": "engine_state", "data": {"flows_queued": 0, "active_flows": 2, "alerts_recent": 0}}
```

### `WS /ws/alerts`
Streams alert events (and, depending on configuration, the same
metrics/engine_state envelopes). Distinguish real alerts by the presence of
a `threat_type` key:
```json
{
  "alert_id": "...",
  "timestamp": "...",
  "src_ip": "...", "dst_ip": "...", "protocol": "tcp",
  "threat_type": "ddos", "severity": "medium",
  "confidence": 0.7183, "risk_score": 0.8462,
  "detection_sources": ["statistical", "behavioral", "supervised_ml", "anomaly_detection"],
  "evidence": {"features": {...}, "score_breakdown": {...}},
  "pcap_path": null
}
```

---

## Threat types
`port_scan`, `dos`, `ddos`, `brute_force`, `data_exfiltration`,
`c2_communication`, `dns_tunneling`, `lateral_movement`, `reconnaissance`,
`malware_communication`, `malicious_ips`, `suspicious_traffic`, `benign`.

## Severity labels
`info`, `low`, `medium`, `high`, `critical` — derived from
`risk·(0.7 + 0.3·confidence)` (CRITICAL ≥0.95 / HIGH ≥0.8 / MEDIUM ≥0.6 /
LOW ≥0.4 / else INFO).