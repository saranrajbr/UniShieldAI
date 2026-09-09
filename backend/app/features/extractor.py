import math
import time

from app.schemas.features import FlowFeatures
from app.schemas.traffic import FlowRecord
from app.state.flow_state import FlowEntry
from app.state.connection_tracker import connection_tracker


def _safe_divide(numerator: float, denominator: float) -> float:
    if denominator <= 0:
        return 0.0
    return numerator / denominator


class FeatureExtractor:
    def __init__(self) -> None:
        self._features: FlowFeatures | None = None

    def extract_from_record(self, record: FlowRecord, flow_id: str) -> FlowFeatures:
        direction = record.direction or "unknown"
        duration = _safe_divide(record.byte_count, max(1.0, record.byte_count))  # placeholder

        conn_key = (
            f"{record.src_ip}:{record.src_port}-"
            f"{record.dst_ip}:{record.dst_port}:{record.protocol}"
        )
        conn = connection_tracker.get(conn_key)
        dst_connections = connection_tracker.connections_for_dst(record.dst_ip)
        dst_ports = {c.dst_port for c in dst_connections if c.dst_port is not None}
        src_ips = {c.src_ip for c in dst_connections}

        syn_ratio = 0.0
        ack_ratio = 0.0
        rst_ratio = 0.0
        fin_ratio = 0.0
        if conn and conn.packet_count > 0:
            flags = conn.flags_seen
            syn_ratio = _safe_divide(flags.count("syn"), conn.packet_count)
            ack_ratio = _safe_divide(flags.count("ack"), conn.packet_count)
            rst_ratio = _safe_divide(flags.count("rst"), conn.packet_count)
            fin_ratio = _safe_divide(flags.count("fin"), conn.packet_count)

        features = FlowFeatures(
            flow_id=flow_id,
            src_ip=record.src_ip,
            dst_ip=record.dst_ip,
            protocol=record.protocol,
            packet_count=record.packet_count,
            byte_count=record.byte_count,
            unique_dst_ports=len(dst_ports),
            unique_dst_ips=len(src_ips),
            connection_frequency=_connection_frequency(record.src_ip, duration),
            outbound_inbound_ratio=_outbound_inbound_ratio(direction),
            small_packet_ratio=_small_packet_ratio(conn),
        )

        features.packets_per_sec = features.packet_count
        features.bytes_per_sec = features.byte_count / max(1e-6, features.flow_duration or 1.0)
        features.avg_packet_size = _safe_divide(features.byte_count, features.packet_count)
        features.dns_entropy = _dns_entropy(record)
        features.inter_arrival_time_mean = _inter_arrival(conn)
        features.inter_arrival_time_std = 0.0
        features.periodicity = 0.0
        features.flow_duration = (conn.last_seen - conn.first_seen) if conn else 0.0

        self._features = features
        return features

    def extract_from_entry(self, entry: FlowEntry, dns_query: str | None = None) -> FlowFeatures:
        duration = entry.duration
        rate_window = max(duration, _MIN_RATE_WINDOW_SEC)
        size_ratio = _safe_divide(entry.byte_count, entry.packet_count)
        between = connection_tracker.connections_between(entry.src_ip, entry.dst_ip)
        dst_ports = {c.dst_port for c in between if c.dst_port is not None}
        src_conns = connection_tracker.connections_for_src(entry.src_ip)
        dst_ips = {c.dst_ip for c in src_conns}
        features = FlowFeatures(
            flow_id=entry.flow_id,
            src_ip=entry.src_ip,
            dst_ip=entry.dst_ip,
            src_port=entry.src_port,
            dst_port=entry.dst_port,
            protocol=entry.protocol,
            packet_count=entry.packet_count,
            byte_count=entry.byte_count,
            packets_per_sec=_safe_divide(entry.packet_count, rate_window),
            bytes_per_sec=_safe_divide(entry.byte_count, rate_window),
            syn_ratio=_safe_divide(entry.syn_count, entry.packet_count),
            ack_ratio=_safe_divide(entry.ack_count, entry.packet_count),
            rst_ratio=_safe_divide(entry.rst_count, entry.packet_count),
            fin_ratio=_safe_divide(entry.fin_count, entry.packet_count),
            connection_frequency=_connection_frequency(entry.src_ip, duration),
            unique_dst_ports=len(dst_ports),
            unique_dst_ips=max(1, len(dst_ips)),
            outbound_inbound_ratio=_outbound_inbound_ratio(entry.src_ip, entry.byte_count, duration),
            dns_entropy=_dns_entropy_record(entry, dns_query),
            inter_arrival_time_mean=_inter_arrival_from_ts(entry.timestamps),
            inter_arrival_time_std=_inter_arrival_std_from_ts(entry.timestamps),
            periodicity=_periodicity_from_ts(entry.timestamps),
            flow_duration=duration,
            avg_packet_size=size_ratio,
            source_entropy=_source_entropy(entry.dst_ip),
            udp_amp_ratio=_udp_amp_ratio(entry),
            small_packet_ratio=_small_packet_ratio_src(entry),
        )
        self._features = features
        return features

    def last_features(self) -> FlowFeatures | None:
        return self._features


def _is_internal(ip: str | None) -> bool:
    if not ip:
        return False
    return (
        ip.startswith("10.")
        or ip.startswith("192.168.")
        or (len(ip) >= 7 and ip[:7] == "172.16." and ip.split(".")[1].isdigit() and 16 <= int(ip.split(".")[1]) <= 31)
    )


def _outbound_inbound_ratio(src_ip: str, byte_count: int, duration: float) -> float:
    """Byte-weighted egress/ingress ratio for this host.

    Previously a hardcoded 1.0/0.0/0.5 ternary, which made the
    data-exfiltration (>=10) and lateral-movement (0<..<0.3) rules
    unreachable. Now uses the connection byte counters: bytes sent by the
    host toward external destinations vs bytes received from external
    sources. Falls back to a direction hint when no history exists yet.
    """
    outbound = float(byte_count) if (_is_internal(src_ip) and not duration) else 0.0
    conns = connection_tracker.connections_for_src(src_ip)
    inbound = 0.0
    if conns:
        for c in conns:
            if not _is_internal(c.dst_ip):
                outbound += float(c.byte_count)
        for c in connection_tracker.connections_for_dst(src_ip):
            if not _is_internal(c.src_ip):
                inbound += float(c.byte_count)
    return _safe_divide(outbound, max(1.0, inbound))


_CONN_FREQ_WINDOW_SEC = 60.0
_MIN_RATE_WINDOW_SEC = 1.0


def _connection_frequency(src_ip: str, duration: float) -> float:
    """Connection establishment rate for a source, in connections/second.

    Counts the distinct connections from this source seen within the recent
    observation window and normalizes by the window length. This is the
    meaningful signal for lateral-movement / connection-flood detection,
    rather than packets-per-second of a single flow.
    """
    recent = connection_tracker.recent_connections_from_src(
        src_ip, within_sec=_CONN_FREQ_WINDOW_SEC
    )
    if recent <= 0:
        return 0.0
    return _safe_divide(recent, _CONN_FREQ_WINDOW_SEC)


def _small_packet_ratio(conn) -> float:
    if conn is None or not conn.events:
        return 0.0
    small = sum(1 for e in conn.events if e.get("size", 0) < 64)
    return _safe_divide(small, len(conn.events))


def _small_packet_ratio_src(entry: FlowEntry) -> float:
    """Fraction of connections from this host that are tiny (recon probes).

    Small SYN-only or zero-payload probes (~40-64 B) indicate port/enumeration
    scanning. Per-source accumulative: the more tiny connections this host
    makes relative to its total, the more it looks like a scanner.
    """
    conns = connection_tracker.connections_for_src(entry.src_ip)
    if not conns:
        return 0.0
    small = 0
    total = 0
    for c in conns:
        if not c.packet_count or c.byte_count <= 0:
            continue
        avg = c.byte_count / float(c.packet_count)
        total += 1
        if avg < 64.0:
            small += 1
    return _safe_divide(small, total)


def _inter_arrival(conn) -> float:
    if conn is None:
        return 0.0
    events = sorted(e.get("ts", 0) for e in conn.events)
    return _inter_arrival_from_ts(events)


def _inter_arrival_from_ts(timestamps: list[float]) -> float:
    if len(timestamps) < 2:
        return 0.0
    diffs = [b - a for a, b in zip(timestamps[:-1], timestamps[1:]) if b > a]
    if not diffs:
        return 0.0
    return math.fsum(diffs) / len(diffs)


def _inter_arrival_std_from_ts(timestamps: list[float]) -> float:
    if len(timestamps) < 3:
        return 0.0
    diffs = [b - a for a, b in zip(timestamps[:-1], timestamps[1:]) if b > a]
    if len(diffs) < 2:
        return 0.0
    mean = math.fsum(diffs) / len(diffs)
    var = math.fsum((d - mean) ** 2 for d in diffs) / (len(diffs) - 1)
    return math.sqrt(var)


def _periodicity_from_ts(timestamps: list[float]) -> float:
    """Cadence regularity score in [0, 1].

    Computed from the coefficient of variation (CV) of inter-packet gaps.
    A low CV means packets arrive on a very regular cadence (beaconing,
    tunneling) -> high periodicity. A high CV means bursty, irregular
    traffic (typical web page loads) -> low periodicity. Requires at least
    3 timestamps; single-shot or near-single-shot flows score 0.
    """
    if len(timestamps) < 3:
        return 0.0
    diffs = [b - a for a, b in zip(timestamps[:-1], timestamps[1:]) if b > a]
    if len(diffs) < 2:
        return 0.0
    mean = math.fsum(diffs) / len(diffs)
    if mean <= 0:
        return 0.0
    var = math.fsum((d - mean) ** 2 for d in diffs) / (len(diffs) - 1)
    std = math.sqrt(var)
    cv = std / mean
    # cv==0 perfectly regular; cv>=1.0 essentially irregular.
    return max(0.0, min(1.0, 1.0 - min(1.0, cv)))


def _dns_entropy(record: FlowRecord) -> float:
    if record.protocol not in ("dns", "udp"):
        return 0.0
    if record.dst_port not in (53, 5353):
        return 0.0
    qname = record.dns_query or record.dst_ip
    if not qname or qname in ("0.0.0.0", ""):
        return 0.0
    counts: dict[str, int] = {}
    for ch in str(qname):
        counts[ch] = counts.get(ch, 0) + 1
    total = sum(counts.values())
    return -sum((c / total) * math.log(c / total) for c in counts.values())


def _dns_entropy_record(entry: FlowEntry, dns_query: str | None) -> float:
    if entry.protocol not in ("dns", "udp"):
        return 0.0
    if entry.dst_port not in (53, 5353):
        return 0.0
    qname = dns_query or entry.dst_ip
    if not qname or qname in ("0.0.0.0", ""):
        return 0.0
    counts: dict[str, int] = {}
    for ch in str(qname):
        counts[ch] = counts.get(ch, 0) + 1
    total = sum(counts.values())
    return -sum((c / total) * math.log(c / total) for c in counts.values())


def _source_entropy(dst_ip: str) -> float:
    """Shannon entropy of the source-IP distribution hitting this destination.

    A widely scattered (spoofed/amplified) flood pushes entropy towards the
    maximum of log2(N); a two-party conversation yields ~0. PS requirement (a).
    """
    conns = connection_tracker.connections_for_dst(dst_ip)
    if len(conns) < 2:
        return 0.0
    counts: dict[str, int] = {}
    for c in conns:
        counts[c.src_ip] = counts.get(c.src_ip, 0) + 1
    total = len(conns)
    return round(
        -sum((c / total) * math.log2(c / total) for c in counts.values()), 4
    )


def _udp_amp_ratio(entry: FlowEntry) -> float:
    """UDP amplification proxy: mean payload size vs a large amp response.

    Reflective flood responses (DNS/NTP/SSDP/memcached, ~500-1400 B) sit near
    the top of this range. 0 for non-UDP flows. PS requirement (a).
    """
    if entry.protocol != "udp" or entry.packet_count < 2:
        return 0.0
    avg = _safe_divide(entry.byte_count, entry.packet_count)
    return round(min(1.0, avg / 1400.0), 4)