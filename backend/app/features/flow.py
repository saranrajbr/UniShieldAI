from app.state.flow_state import FlowEntry
from app.state.connection_tracker import connection_tracker


def flow_level_features(entry: FlowEntry) -> dict:
    packets = entry.packet_count
    bytes_ = entry.byte_count
    duration = entry.duration
    key = f"{entry.src_ip}:{entry.src_port}-{entry.dst_ip}:{entry.dst_port}:{entry.protocol}"
    conn = connection_tracker.get(key)
    dst_conns = connection_tracker.connections_for_dst(entry.dst_ip)

    return {
        "packet_count": packets,
        "byte_count": bytes_,
        "packets_per_sec": packets / duration if duration > 0 else 0.0,
        "bytes_per_sec": bytes_ / duration if duration > 0 else 0.0,
        "avg_packet_size": bytes_ / packets if packets > 0 else 0.0,
        "flow_duration": duration,
        "unique_dst_ports": len({c.dst_port for c in dst_conns if c.dst_port is not None}),
        "unique_dst_ips": len({c.src_ip for c in dst_conns}),
        "connection_frequency": len(dst_conns) / 60.0,
        "syn_count": entry.syn_count,
        "rst_count": entry.rst_count,
        "syn_ratio": entry.syn_count / packets if packets > 0 else 0.0,
        "conn_established": conn.established if conn else False,
    }