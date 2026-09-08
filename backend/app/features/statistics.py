from app.state.rolling_window import RollingWindow, RateWindow

packet_rate = RollingWindow(window_seconds=60.0)
byte_rate = RollingWindow(window_seconds=60.0)
flow_rate = RateWindow(window_seconds=60.0)
connection_rate = RateWindow(window_seconds=60.0)


def record_packet(bytes_: int = 0) -> None:
    packet_rate.add(1)
    byte_rate.add(bytes_)


def record_flow() -> None:
    flow_rate.record()


def record_connection() -> None:
    connection_rate.record()


def snapshot() -> dict:
    return {
        "packets_per_sec": round(packet_rate.rate_per_second(), 2),
        "bytes_per_sec": round(byte_rate.rate_per_second(), 2),
        "flows_per_sec": round(flow_rate.rate(), 2),
        "connections_per_sec": round(connection_rate.rate(), 2),
        "flows_last_60s": int(flow_rate.count()),
        "packets_last_60s": int(packet_rate.total()),
    }