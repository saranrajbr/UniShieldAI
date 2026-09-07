from enum import IntEnum, StrEnum


class Protocol(StrEnum):
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    DNS = "dns"
    HTTP = "http"
    HTTPS = "https"
    TLS = "tls"
    SSH = "ssh"
    UNKNOWN = "unknown"


class ThreatType(StrEnum):
    PORT_SCAN = "port_scan"
    DOS = "dos"
    DDoS = "ddos"
    BRUTE_FORCE = "brute_force"
    DATA_EXFILTRATION = "data_exfiltration"
    C2_COMMUNICATION = "c2_communication"
    DNS_TUNNELING = "dns_tunneling"
    LATERAL_MOVEMENT = "lateral_movement"
    RECONNAISSANCE = "reconnaissance"
    MALWARE_COMMUNICATION = "malware_communication"
    SUSPICIOUS_TRAFFIC = "suspicious_traffic"
    BENIGN = "benign"


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class DetectionSource(StrEnum):
    SIGNATURE_RULE = "signature_rule"
    STATISTICAL_RULE = "statistical_rule"
    BEHAVIORAL_RULE = "behavioral_rule"
    SUPERVISED_ML = "supervised_ml"
    ANOMALY_DETECTION = "anomaly_detection"
    DECISION_ENGINE = "decision_engine"


class Direction(StrEnum):
    INBOUND = "inbound"
    OUTBOUND = "outbound"
    LATERAL = "lateral"
    UNKNOWN = "unknown"


TCP_FLAGS = {
    "FIN": 0x01,
    "SYN": 0x02,
    "RST": 0x04,
    "PSH": 0x08,
    "ACK": 0x10,
    "URG": 0x20,
    "ECE": 0x40,
    "CWR": 0x80,
}

WELL_KNOWN_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
}

FEATURE_COLUMNS = [
    "packet_count",
    "byte_count",
    "packets_per_sec",
    "bytes_per_sec",
    "syn_ratio",
    "ack_ratio",
    "rst_ratio",
    "fin_ratio",
    "unique_dst_ports",
    "unique_dst_ips",
    "connection_frequency",
    "inter_arrival_time_mean",
    "inter_arrival_time_std",
    "periodicity",
    "dns_entropy",
    "outbound_inbound_ratio",
    "avg_packet_size",
    "flow_duration",
    "payload_bytes_ratio",
    "small_packet_ratio",
]

METRICS_WINDOW_SECONDS = 60
ALERT_BATCH_SIZE = 50
MAX_ALERTS_IN_MEMORY = 10000

# Known-malicious JA3 fingerprints (public threat-intel examples). A TLS
# flow whose fingerprint appears here is flagged as malware_communication.
# Rule-only input — deliberately NOT part of FEATURE_COLUMNS.
KNOWN_MALICIOUS_JA3 = {
    "51c64c77e60f3980eea90869b68c58a8",  # e.g. Tor/obfuscated bundle variant
    "9d2453f9eaa330865d4ecdff5cbbcb39",  # e.g. C2/loader family sample
    "6734f37431670b3ab4292b8f60f29984",  # e.g. RAT family sample
    "73e6a8f4b3b0f7e0d0a3c4e9d4b0c0d0",  # placeholder: add real IOCs from feeds
    "8e6a8f4b3b0f7e0d0a3c4e9d4b0c0d1a",  # placeholder: add real IOCs from feeds
}
