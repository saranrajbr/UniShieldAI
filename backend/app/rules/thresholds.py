STATISTICAL_THRESHOLDS: dict[str, dict[str, float]] = {
    "packets_per_sec": {"baseline": 100.0, "medium": 500.0, "high": 2000.0},
    "bytes_per_sec": {"baseline": 100_000.0, "medium": 500_000.0, "high": 2_000_000.0},
    "connection_frequency": {"baseline": 1.0, "medium": 10.0, "high": 100.0},
    "unique_dst_ports": {"baseline": 5.0, "medium": 20.0, "high": 50.0},
    "unique_dst_ips": {"baseline": 3.0, "medium": 10.0, "high": 30.0},
    "syn_ratio": {"baseline": 0.1, "medium": 0.5, "high": 0.8},
    "dns_entropy": {"baseline": 1.0, "medium": 2.5, "high": 3.5},
    "outbound_inbound_ratio": {"baseline": 1.0, "medium": 3.0, "high": 10.0},
    "small_packet_ratio": {"baseline": 0.2, "medium": 0.5, "high": 0.8},
    "packet_count": {"baseline": 100.0, "medium": 1000.0, "high": 10000.0},
    "byte_count": {"baseline": 100_000.0, "medium": 1_000_000.0, "high": 10_000_000.0},
    "source_entropy": {"baseline": 0.5, "medium": 1.5, "high": 2.5},
    "udp_amp_ratio": {"baseline": 0.3, "medium": 0.6, "high": 0.85},
}

SEVERITY_BANDS = {
    "low": 0.3,
    "medium": 0.5,
    "high": 0.8,
    "critical": 0.95,
}


def threshold_for(field: str, level: str = "high") -> float:
    band = STATISTICAL_THRESHOLDS.get(field, {})
    return band.get(level, band.get("high", 0.5))