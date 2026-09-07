# Detection Pipeline

This document explains how UniShield turns a flow into a decision: the
rule-based and ML layers, the risk fusion, and how a `ThreatType` and
`severity` are chosen.

## Pipeline stages (`app/engine/pipeline.py`)

For each `FlowRecord`:

1. **Identify** the flow with `flow_hash(src_ip, dst_ip, src_port, dst_port,
   protocol)`.
2. **Aggregate** — `FlowState.get_or_create` + `update` merges repeated
   reports of the same flow into a `FlowEntry` (counts + timestamps).
3. **Touch** the connection tracker (`connection_tracker.touch`) for
   connection-frequency context.
4. **Extract** — `FeatureExtractor.extract_from_entry(entry, dns_query)`
   produces the 20-feature `FlowFeatures` (fixed `FEATURE_COLUMNS`, consumed
   by the ML models). Cyber-forensic fields live **outside** the numeric
   vector and feed rules/evidence: `dns_qname`, `tls_ja3`, `tls_ja3s`,
   `source_entropy`, `udp_amp_ratio`.
5. **Rules** — `RuleEngine.result_assessment(features)`.
6. **ML** — `MLInferenceEngine.run(features)`.
7. **Decide** — `DecisionEngine.decide(flow_id, rules, ml)`.
8. If `is_threat`, create an alert, broadcast on `/ws/alerts`, persist, and
   preserve pcap evidence.

## Detection threshold

```text
is_threat = (risk_score >= settings.detection_threshold) and (threat_type != "benign")
```

`detection_threshold = 0.6` by default. Risk < 0.4 is always classified
`benign` by the threat classifier.

## Rule layer

Default rules (`load_defaults`) are 18 statistical + behavioral rules
(11 statistical, 7 behavioral).

### Statistical rules (`app/rules/statistical.py`)
Threshold checks over the features (`STATISTICAL_THRESHOLDS`):

| Rule | Field | ThreatType |
|------|-------|-----------|
| `stat_syn_ratio_high` | `syn_ratio` ≥ 0.8 | `dos` |
| `stat_conn_freq_high` | `connection_frequency` ≥ 100 | `lateral_movement` |
| `stat_pps_high` | `packets_per_sec` ≥ 2000 | `dos` |
| `stat_bps_high` | `bytes_per_sec` ≥ 2M | `data_exfiltration` |
| `stat_dns_entropy_high` | `dns_entropy` ≥ 3.5 | `dns_tunneling` |
| `stat_unique_ports_high` | `unique_dst_ports` ≥ 50 | `port_scan` |
| `stat_unique_ips_high` | `unique_dst_ips` ≥ 30 | `lateral_movement` |
| `stat_outbound_ratio_high` | `outbound_inbound_ratio` ≥ 10 | `data_exfiltration` |
| `stat_small_packet_high` | `small_packet_ratio` ≥ 0.8 | `reconnaissance` |
| `stat_source_entropy_high` | `source_entropy` ≥ 2.5 | `ddos` (single src fanning to many dsts) |
| `stat_udp_amp_high` | `udp_amp_ratio` ≥ 0.85 | `ddos` (amplified UDP responses ≥ ~1400 B/pkt) |

`source_entropy` is the Shannon entropy of the source-IP distribution seen
toward a destination (log2; `0` for one or two unique sources);
`udp_amp_ratio` = average UDP packet size / 1400, capped at `1.0`.
Threshold bands (`THRESHOLDS.source_entropy` / `udp_amp_ratio`): baseline 0.5
/ 0.3, medium 1.5 / 0.6, high 2.5 / 0.85.

Scoring: `gte` uses `min(1.0, 0.5 + (actual − threshold)/threshold)`.

### Behavioral rules (`app/rules/behavioral.py`)
Pattern-driven:

| Rule | Trigger | ThreatType |
|------|---------|-----------|
| `behav_periodic_conn` | `periodicity > 0.7` | `c2_communication` |
| `behav_syn_flood` | `syn_ratio > 0.9` | `ddos` |
| `behav_port_sweep` | `unique_dst_ports ≥ 10` | `port_scan` |
| `behav_brute_force` | auth port + `connection_frequency ≥ 1.0` | `brute_force` |
| `behav_small_pkt_many_conn` | `small_packet_ratio > 0.6`, `unique_dst_ips ≥ 5` | `reconnaissance` |
| `behav_lateral_move` | inbound-ish + `connection_frequency > 2.0` | `lateral_movement` |
| `behav_tls_ja3_blocklist` | `tls_ja3` in `KNOWN_MALICIOUS_JA3` | `malware_communication` |

`tls_ja3` / `tls_ja3s` are extracted by a pure-bytes TLS ClientHello parser
(`app/ingestion/tls.py` → JA3 fingerprint hash) for flows toward port 443;
the blocklist lives in `app/core/constants.py` and scores `0.95` when hit.

`result_assessment` returns matched rules and a per-category max score.

## ML layer

- **Supervised** — XGBoost binary (`benign` / `threat`), standardized with
  the saved scaler. `probability` is the threat probability; the predicted
  label dictates the candidate threat type.
- **Anomaly** — IsolationForest over scaled features. Produces
  `anomaly_score` (sigmoid of raw decision) and `is_anomaly`.

`MLInferenceEngine.run` blends them:

```text
confidence = |probability - 0.5| * 2
if confidence >= 0.6:
    blended = probability                 # trust the supervised model
elif anomaly_score > 0.5 and is_anomaly:
    blended = probability + 0.15*(anomaly_score - 0.5)
else:
    blended = probability
```

The supervised classifier is trusted when confident; the anomaly signal only
shifts the blend while the classifier is uncertain (avoids the noisy
isolation-forest raw decision overriding a decisive prediction).

## Risk fusion (`app/decision/risk_fusion.py`)

```text
risk = Σ source_score * source_weight           (sources present)
       + blended_ml_score * ml_blended_weight
risk_score = risk / Σ(present weights)          (normalized to [0,1])
```

Default weights: signature `0.30`, statistical `0.25`, behavioral `0.25`,
`ml_blended` `0.20`.

## Threat classification (`app/decision/classifier.py`)

Collect candidate `(score, threat_type)` pairs from rule matches + supervised
ML (+ anomaly when `anomaly_score > 0.6` → `suspicious_traffic`). Pick the
maximum-scoring candidate; `risk < 0.4` → `benign`. `THREAT_PRIORITY`
ranks types for display (e.g. `ddos`, `c2_communication`,
`data_exfiltration` are level 4).

## Severity (`app/decision/severity.py`)

```text
effective = risk * (0.7 + 0.3 * confidence)
CRITICAL >= 0.95
HIGH     >= 0.8
MEDIUM   >= 0.6
LOW      >= 0.4
else INFO
```

## Confidence (`app/decision/confidence.py`)

Weighted evidence, detection-source multiplicity, rule count, and anomaly
signature:
```text
confidence = evidence_strength*0.6 + multiplicity*0.2 + rule_weight*0.1 + anomaly_weight*0.1
```

## Decision result (`DecisionResult`)

`flow_id`, `risk_score`, `confidence`, `threat_type`, `severity`,
`is_threat`, `detection_sources`, `score_breakdown`.

## Scenario → detection mapping (lab)

| Lab scenario | Tool | Detected via | ThreatType |
|--------------|------|--------------|-----------|
| Benign bulk | iperf3 | low features / low risk | `benign` |
| TCP SYN flood | hping3 `-S --flood` | `stat_syn_ratio_high` + `behav_syn_flood` + ML | `ddos` |
| UDP flood | hping3 `-U --flood` | `stat_pps_high` + ML | `dos` |
| Slowloris | slowloris | ML (+ sustained tiny conns) | `suspicious_traffic` |
| DNS tunnel | dnscat2 / iodine | `stat_dns_entropy_high` | `dns_tunneling` |
| C2 beacon (DGA) | periodic small outpout | `behav_periodic_conn` (timing) | `c2_communication` |
| Port scan | nmap / SYN sweep | `stat_unique_ports_high` / `behav_port_sweep` | `port_scan` |
| Brute force | hydra SSH | `behav_brute_force` (conn frequency) | `brute_force` |
| Exfiltration | large outbound | `stat_bps_high` / `stat_outbound_ratio_high` | `data_exfiltration` |
| UDP amplification | large UDP repl. to victim | `stat_udp_amp_high` (avg pkt ≥ ~1.4 KB) | `ddos` |
| Malware TLS fingerprint | known malicious JA3 | `behav_tls_ja3_blocklist` | `malware_communication` |
| Fan-out scan | single src to many dsts | `stat_source_entropy_high` | `ddos` / `port_scan` |

## Notes on timing features

`periodicity`, `inter_arrival_time_mean`, `inter_arrival_time_std` are
computed from per-report timestamps accumulated by `FlowEntry.merge_stats`.
A beacon that **reuses the same flow** on a regular cadence scores
`periodicity ≈ 1` (detected by `behav_periodic_conn`); a bursty page load
scores ≈ 0. Repeated same-flow reports are required for these features to
register — a single one-shot flow yields `periodicity = 0`.