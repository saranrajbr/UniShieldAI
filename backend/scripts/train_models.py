"""Train ML models (XGBoost supervised + IsolationForest) for UniShield AI.

Produces artifacts under models/ used at inference time:
  - models/xgboost/model.json
  - models/preprocessing/scaler.pkl
  - models/preprocessing/feature_columns.json
  - models/class_names.json
  - models/isolation_forest/model.pkl

The dataset is built the SAME way the live engine produces features:
synthetic lab-style FlowRecords (iperf3 / hping3 / Slowloris / dnscat2 /
DGA-C2) are replayed through the real FeatureExtractor with live state
(FlowEntry aggregation + ConnectionTracker), and the resulting 20 flow
features are vectorized with the exact FeatureSchema used at inference.

This guarantees the training distribution matches what the running pipeline
sees, which hand-assembled feature arrays cannot do.
"""

import argparse
import json
import logging
import pickle
import random
import time
from pathlib import Path
from datetime import datetime, timedelta, timezone

import numpy as np

from app.core.constants import FEATURE_COLUMNS
from app.features.extractor import FeatureExtractor
from app.ingestion.test_source import TestTrafficSource
from app.ml.feature_schema import FeatureSchema
from app.schemas.traffic import FlowRecord
from app.state.connection_tracker import connection_tracker
from app.state.flow_state import FlowState
from app.utils.hashing import flow_hash

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("train")

OUT_ROOT = Path("models")
RNG_DEFAULT_SEED = 42

_BASE_CHARSET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
_BENIGN_NAMES = ("www", "mail", "api", "cdn", "app")
_BENIGN_DOMAINS = ("google", "github", "amazon", "example", "cloudflare")
_BENIGN_TLDS = ("com", "net", "org", "io")


def _record(src: str, dst: str, dst_port: int, proto: str,
            packets: int, bytes_: int, syn: int, ack: int, rst: int,
            fin: int, dns_query: str | None = None, src_port: int | None = None,
            ts: datetime | None = None) -> FlowRecord:
    return FlowRecord(
        ts=ts or datetime.now(timezone.utc),
        sensor_id="train",
        src_ip=src,
        dst_ip=dst,
        src_port=src_port if src_port is not None else random.randint(1024, 65535),
        dst_port=dst_port,
        protocol=proto,
        direction="outbound" if src.startswith("10.0") else "unknown",
        packet_count=int(packets),
        byte_count=int(bytes_),
        syn_count=int(syn),
        ack_count=int(ack),
        rst_count=int(rst),
        fin_count=int(fin),
        dns_query=dns_query,
    )


def _tunnel_qname() -> str:
    return ".".join(
        "".join(random.choice(_BASE_CHARSET) for _ in range(random.randint(18, 30)))
        for _ in range(random.randint(4, 6))
    ) + ".t"


def _benign_qname() -> str:
    return (f"{random.choice(_BENIGN_NAMES)}.{random.choice(_BENIGN_DOMAINS)}."
            f"{random.choice(_BENIGN_TLDS)}")


def _internal_ip() -> str:
    return f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}"


def _external_ip() -> str:
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def generate_benign_flow() -> FlowRecord:
    """One isolated benign flow — DNS query, HTTPS session, or bulk transfer."""
    kind = random.random()
    if kind < 0.12:
        return _record(_internal_ip(), _external_ip(), 53, "udp",
                       random.randint(1, 4), random.randint(60, 300),
                       0, 0, 0, 0, dns_query=_benign_qname())
    outbound = random.random() > 0.35
    src, dst = (_internal_ip(), _external_ip()) if outbound else (_external_ip(), _internal_ip())
    dst_port = random.choice([443, 443, 443, 80, 8080])
    if random.random() < 0.6:
        packets = random.randint(3, 250)          # typical short web session
        pkt_size = random.uniform(150, 1200)
    else:
        packets = random.randint(300, 6000)       # bulk / large downloads
        pkt_size = random.uniform(400, 1400)
    return _record(src, dst, dst_port, "tcp",
                   packets, int(packets * pkt_size),
                   syn=1, ack=max(0, packets - random.randint(1, 3)),
                   rst=0 if random.random() > 0.05 else 1,
                   fin=1 if random.random() > 0.7 else 0)


def generate_benign_page_load() -> list[FlowRecord]:
    """A short webpage-load burst: several small flows from one client to one host."""
    client = _internal_ip()
    host = _external_ip()
    flows: list[FlowRecord] = []
    for _ in range(random.randint(2, 6)):
        packets = random.randint(2, 40)
        flows.append(_record(client, host, random.choice([80, 443]),
                             "tcp", packets, packets * random.uniform(150, 1000),
                             syn=1, ack=max(0, packets - 1), rst=0, fin=1))
    return flows


def _syn_flood(attacker: str, victim: str) -> FlowRecord:
    syn = random.randint(400, 2500)
    ack = random.randint(5, 60)
    return _record(attacker, victim, 80, "tcp", syn + ack,
                   random.randint(30000, 80000), syn=syn, ack=ack, rst=0, fin=0)


def _udp_flood(attacker: str, victim: str) -> FlowRecord:
    packets = random.randint(600, 4000)
    return _record(attacker, victim, random.randint(5000, 65000), "udp",
                   packets, packets * random.randint(64, 300), 0, 0, 0, 0)


def _slowloris(attacker: str, victim: str) -> FlowRecord:
    packets = random.randint(1, 40)
    return _record(attacker, victim, 80, "tcp",
                   packets, packets * random.randint(40, 200),
                   syn=1, ack=max(0, packets - 1), rst=0, fin=0)


def _dns_tunnel(src: str) -> FlowRecord:
    packets = random.randint(50, 400)
    return _record(src, _external_ip(), 53, "udp",
                   packets, packets * random.randint(40, 120),
                   0, 0, 0, 0, dns_query=_tunnel_qname())


def _c2_beacon(src: str) -> FlowRecord:
    packets = random.randint(8, 60)
    return _record(src, _external_ip(), 443, "tcp",
                   packets, packets * random.randint(60, 400),
                   syn=1, ack=max(0, packets - 1), rst=0, fin=0)


def _brute_force(attacker: str, victim: str) -> FlowRecord:
    packets = random.randint(2, 12)
    return _record(attacker, victim, random.choice([22, 23, 3389, 445]),
                   "tcp", packets, packets * random.randint(40, 200),
                   syn=random.randint(1, max(1, packets // 2)),
                   ack=max(0, packets - random.randint(1, 4)), rst=0, fin=0)


def _stamp(base: datetime, offset: float) -> datetime:
    return base + timedelta(seconds=offset)


def _c2_beacon_cadence(src: str) -> list[FlowRecord]:
    """C2 beaconing: repeated outbound connections to ONE c2 endpoint on a
    regular cadence (small packets, ~1 connection / 1-3s). The shared flow
    id accumulates timestamps so inter_arrival/periodicity surface the
    repeat cadence — which is what separates beaconing from a one-off web
    page load (bursty, irregular)."""
    base = datetime.now(timezone.utc)
    c2 = _external_ip()
    src_port = random.randint(1024, 65535)
    flow: list[FlowRecord] = []
    interval = random.uniform(1.0, 3.0)
    for i in range(random.randint(12, 30)):
        packets = random.randint(8, 60)
        flow.append(_record(
            src, c2, 443, "tcp",
            packets, packets * random.randint(60, 400),
            1, max(0, packets - 1), 0, 0,
            src_port=src_port,
            ts=_stamp(base, i * interval + random.uniform(0.0, 0.15)),
        ))
    return flow


def generate_episode(scenario: str, rng: random.Random) -> list[FlowRecord]:
    """Generate an episode of lab flows for a scenario."""
    attacker = _external_ip()
    victim = f"10.0.{rng.randint(0, 5)}.{rng.randint(1, 254)}"

    if scenario == "benign":
        return [generate_benign_flow() for _ in range(1)]

    if scenario == "syn_flood":
        return [_syn_flood(attacker, victim) for _ in range(rng.randint(8, 16))]
    if scenario == "udp_flood":
        return [_udp_flood(attacker, victim) for _ in range(rng.randint(8, 20))]
    if scenario == "slowloris":
        # Many long-lived tiny HTTP connections held open; repeated reports
        # share flow identity so the extractor sees a sustained dwell-time.
        base = datetime.now(timezone.utc)
        src_port = random.randint(1024, 65535)
        out = []
        for i in range(rng.randint(15, 40)):
            packets = random.randint(1, 40)
            out.append(_record(attacker, victim, 80, "tcp",
                               packets, packets * random.randint(40, 200),
                               1, max(0, packets - 1), 0, 0,
                               src_port=src_port,
                               ts=_stamp(base, i * random.uniform(0.4, 1.2))))
        return out
    if scenario == "dns_tunnel":
        return [_dns_tunnel(_internal_ip()) for _ in range(rng.randint(10, 25))]
    if scenario == "c2_beacon":
        return _c2_beacon_cadence(_internal_ip())
    if scenario == "brute_force":
        return [_brute_force(attacker, victim) for _ in range(rng.randint(40, 120))]
    if scenario == "port_scan":
        victim_ps = f"10.0.{rng.randint(0, 5)}.{rng.randint(1, 254)}"
        return [_record(attacker, victim_ps, rng.randint(1, 1024), "tcp",
                        random.randint(1, 3), random.randint(40, 120),
                        1, 0, 0, 0) for _ in range(rng.randint(40, 90))]
    raise ValueError(f"unknown scenario: {scenario}")


def extract_row(record: FlowRecord, flow_state: FlowState, extractor: FeatureExtractor) -> dict:
    """Mirror pipeline.process() feature extraction: aggregate flow then extract."""
    flow_id = flow_hash(
        record.src_ip, record.dst_ip, record.src_port, record.dst_port, record.protocol
    )
    entry = flow_state.get_or_create(
        flow_id, record.src_ip, record.dst_ip, record.src_port,
        record.dst_port, record.protocol,
    )
    flow_state.update(
        entry,
        packet_count=record.packet_count,
        byte_count=record.byte_count,
        syn_count=record.syn_count,
        ack_count=record.ack_count,
        rst_count=record.rst_count,
        fin_count=record.fin_count,
        ts=record.ts.timestamp() if record.ts else None,
    )
    connection_tracker.touch(
        record.src_ip, record.dst_ip, record.src_port, record.dst_port,
        record.protocol, packet_size=record.byte_count,
    )
    features = extractor.extract_from_entry(entry, dns_query=record.dns_query)
    return features.model_dump()


def build_dataset(benign_rows: int, attacks_rows: int,
                  seed: int = RNG_DEFAULT_SEED) -> tuple[np.ndarray, np.ndarray, list[str]]:
    """Generate the flow-level dataset through the live extraction path.

    Benign and attack rows are balanced (1:1) so the classifier sees a dense,
    representative benign region instead of being drowned by attack samples.
    """
    rng = random.Random(seed)
    schema = FeatureSchema(columns=FEATURE_COLUMNS)
    extractor = FeatureExtractor()
    flow_state = FlowState()

    attack_scenarios = [
        "syn_flood", "udp_flood", "slowloris", "dns_tunnel", "c2_beacon",
        "brute_force", "port_scan",
    ]

    rows: list[list[float]] = []
    labels: list[int] = []

    def push(scenario: str, records: list[FlowRecord]) -> None:
        label = 0 if scenario == "benign" else 1
        connection_tracker.clear()
        for record in records:
            feature_dict = extract_row(record, flow_state, extractor)
            rows.append(schema.vectorize(feature_dict))
            labels.append(label)

    def make_episode_records(scenario: str) -> list[FlowRecord]:
        if scenario == "benign":
            # ~25% of benign rows come as short webpage-load bursts.
            if rng.random() < 0.25:
                return generate_benign_page_load()
            return [generate_benign_flow()]
        return generate_episode(scenario, rng)

    while sum(1 for lbl in labels if lbl == 0) < benign_rows:
        push("benign", make_episode_records("benign"))

    target_attack = attacks_rows
    produced = 0
    while produced < target_attack:
        scenario = rng.choice(attack_scenarios)
        before = sum(1 for lbl in labels if lbl == 1)
        push(scenario, generate_episode(scenario, rng))
        produced += sum(1 for lbl in labels if lbl == 1) - before

    X = np.asarray(rows, dtype=np.float64)
    y = np.asarray(labels, dtype=np.int64)

    perm = rng.sample(range(X.shape[0]), X.shape[0])
    return X[perm], y[perm], ["benign", "threat"]


def train(args) -> None:
    from sklearn.ensemble import IsolationForest
    from sklearn.metrics import classification_report

    from xgboost import XGBClassifier

    from app.ml.preprocessing import Preprocessor

    Path("data").mkdir(exist_ok=True)
    (OUT_ROOT / "xgboost").mkdir(parents=True, exist_ok=True)
    (OUT_ROOT / "preprocessing").mkdir(parents=True, exist_ok=True)
    (OUT_ROOT / "isolation_forest").mkdir(parents=True, exist_ok=True)

    t_start = time.time()
    X, y, scenario_names = build_dataset(args.benign, args.attacks, seed=args.seed)
    logger.info(
        "Generated %d flow rows (%d benign / %d attack) in %.1fs",
        len(y), int(np.sum(y == 0)), int(np.sum(y == 1)), time.time() - t_start,
    )

    preprocessor = Preprocessor().fit(X)
    X_scaled = np.asarray(
        [(X[i] - preprocessor._mean) / preprocessor._std for i in range(X.shape[0])],
        dtype=np.float64,
    )

    model = XGBClassifier(
        n_estimators=args.estimators,
        max_depth=5,
        learning_rate=0.1,
        subsample=0.85,
        colsample_bytree=0.85,
        min_child_weight=5,
        reg_lambda=2.0,
        eval_metric="logloss",
    )
    model.fit(X_scaled, y)

    predictions = model.predict(X_scaled)
    logger.info("\n%s", classification_report(y, predictions, target_names=["benign", "threat"]))
    logger.info("AUC=%.4f", _auc(y, model, X_scaled))

    anomaly_model = IsolationForest(
        n_estimators=args.estimators,
        max_samples="auto",
        contamination=min(0.5, max(0.05, float(np.sum(y == 1)) / len(y))),
        random_state=args.seed,
    )
    anomaly_model.fit(X_scaled)

    model.save_model(str(OUT_ROOT / "xgboost" / "model.json"))
    preprocessor.save(str(OUT_ROOT / "preprocessing" / "scaler.pkl"))
    with open(OUT_ROOT / "isolation_forest" / "model.pkl", "wb") as fh:
        pickle.dump(anomaly_model, fh)

    (OUT_ROOT / "preprocessing" / "feature_columns.json").write_text(
        json.dumps({"columns": FEATURE_COLUMNS}, indent=2), encoding="utf-8"
    )
    (OUT_ROOT / "class_names.json").write_text(
        json.dumps(["benign", "threat"]), encoding="utf-8"
    )

    logger.info("Artifacts written under %s/", OUT_ROOT)
    logger.info(
        "Feature columns (%d): %s", len(FEATURE_COLUMNS), ", ".join(FEATURE_COLUMNS)
    )


def _auc(y: np.ndarray, model, X_scaled: np.ndarray) -> float:
    from sklearn.metrics import roc_auc_score

    try:
        proba = model.predict_proba(X_scaled)[:, 1]
        return float(roc_auc_score(y, proba))
    except Exception:
        return float("nan")


def main() -> None:
    parser = argparse.ArgumentParser(description="Train UniShield AI models")
    parser.add_argument("--benign", type=int, default=12000)
    parser.add_argument("--attacks", type=int, default=12000)
    parser.add_argument("--estimators", type=int, default=250)
    parser.add_argument("--max-depth", type=int, default=6)
    parser.add_argument("--seed", type=int, default=RNG_DEFAULT_SEED)
    args = parser.parse_args()
    train(args)


if __name__ == "__main__":
    main()