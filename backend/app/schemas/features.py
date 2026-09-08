from typing import Optional

from pydantic import BaseModel


class FlowFeatures(BaseModel):
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str
    packet_count: int
    byte_count: int
    packets_per_sec: float = 0.0
    bytes_per_sec: float = 0.0
    syn_ratio: float = 0.0
    ack_ratio: float = 0.0
    rst_ratio: float = 0.0
    fin_ratio: float = 0.0
    unique_dst_ports: int = 0
    unique_dst_ips: int = 0
    connection_frequency: float = 0.0
    inter_arrival_time_mean: float = 0.0
    inter_arrival_time_std: float = 0.0
    periodicity: float = 0.0
    dns_entropy: float = 0.0
    outbound_inbound_ratio: float = 0.0
    avg_packet_size: float = 0.0
    flow_duration: float = 0.0
    payload_bytes_ratio: float = 0.0
    small_packet_ratio: float = 0.0

    # Extended / PS-mandated fields. Deliberately NOT part of `as_vector()`
    # so the trained ML feature vector (20 FEATURE_COLUMNS) stays stable —
    # these feed rule detection and alert evidence only.
    source_entropy: float = 0.0
    udp_amp_ratio: float = 0.0
    tls_ja3: Optional[str] = None
    tls_ja3s: Optional[str] = None

    def as_vector(self) -> list[float]:
        return [
            self.packet_count,
            self.byte_count,
            self.packets_per_sec,
            self.bytes_per_sec,
            self.syn_ratio,
            self.ack_ratio,
            self.rst_ratio,
            self.fin_ratio,
            self.unique_dst_ports,
            self.unique_dst_ips,
            self.connection_frequency,
            self.inter_arrival_time_mean,
            self.inter_arrival_time_std,
            self.periodicity,
            self.dns_entropy,
            self.outbound_inbound_ratio,
            self.avg_packet_size,
            self.flow_duration,
            self.payload_bytes_ratio,
            self.small_packet_ratio,
        ]


class FeatureExtractionResult(BaseModel):
    flow_id: str
    features: FlowFeatures
    error: Optional[str] = None
