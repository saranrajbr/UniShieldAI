import time

from app.state.connection_tracker import connection_tracker


def connections_over_window(seconds: float = 60.0) -> int:
    cutoff = time.time() - seconds
    total = 0
    for conn in connection_tracker.snapshot_all():
        if conn.last_seen >= cutoff:
            total += 1
    return total


def connection_pattern_features(dst_ip: str) -> dict:
    conns = connection_tracker.connections_for_dst(dst_ip)
    if not conns:
        return {"connection_speed": 0.0, "unique_sources": 0, "spread": 0.0}

    first = min(c.first_seen for c in conns)
    last = max(c.last_seen for c in conns)
    span = last - first if last > first else 1.0
    sources = {c.src_ip for c in conns}

    return {
        "connection_speed": len(conns) / span,
        "unique_sources": len(sources),
        "spread": len(sources) / len(conns),
        "total_connections": len(conns),
    }


def periodicity(timestamps: list[float]) -> float:
    if len(timestamps) < 3:
        return 0.0
    diffs = [b - a for a, b in zip(timestamps[:-1], timestamps[1:]) if b > a]
    if not diffs:
        return 0.0
    import statistics
    try:
        return 1.0 / (1.0 + statistics.pstdev(diffs))
    except statistics.StatisticsError:
        return 0.0