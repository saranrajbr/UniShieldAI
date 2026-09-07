from app.state.flow_state import FlowEntry


def tcp_features(entry: FlowEntry) -> dict:
    total = entry.packet_count
    if total <= 0:
        return {
            "syn_ratio": 0.0, "ack_ratio": 0.0, "rst_ratio": 0.0,
            "fin_ratio": 0.0, "syn_ack_ratio": 0.0, "rst_count": 0,
        }
    return {
        "syn_ratio": entry.syn_count / total,
        "ack_ratio": entry.ack_count / total,
        "rst_ratio": entry.rst_count / total,
        "fin_ratio": entry.fin_count / total,
        "syn_ack_ratio": (entry.syn_count / max(1, entry.ack_count)),
        "rst_count": entry.rst_count,
        "half_open": entry.syn_count > (entry.ack_count * 3),
    }


def is_handshake_completed(entry: FlowEntry) -> bool:
    return entry.syn_count >= 1 and entry.ack_count >= 1