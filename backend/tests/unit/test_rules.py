from app.ingestion.test_source import TestTrafficSource
from app.rules.engine import build_engine


class TestRuleEngine:
    def test_defaults_load(self):
        engine = build_engine(load_defaults=True)
        assert engine.registry.count() > 0

    def test_burst_flow_fires(self):
        engine = build_engine(load_defaults=True)
        features = {
            "syn_ratio": 0.95,
            "connection_frequency": 200.0,
            "unique_dst_ports": 60,
            "packets_per_sec": 5000.0,
            "bytes_per_sec": 5_000_000.0,
            "dns_entropy": 0.0,
            "outbound_inbound_ratio": 0.9,
            "unique_dst_ips": 3,
            "small_packet_ratio": 0.2,
        }
        result = engine.result_assessment(features)
        assert result["source_scores"] != {}
        assert result["aggregate_score"] > 0.0


class TestTestTraffic:
    def test_generates_flow_record(self):
        source = TestTrafficSource(flows_per_second=10, seed=1)
        records = source.generate_batch(10)
        assert len(records) == 10
        assert all(r.src_ip and r.dst_ip for r in records)