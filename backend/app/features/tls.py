def tls_features(version: str | None = None, cipher_suite: str | None = None,
                 server_name: str | None = None, cert_chain_length: int = 0,
                 handshake_time_ms: float = 0.0) -> dict:
    return {
        "tls_version": version or "unknown",
        "cipher_suite": cipher_suite or "unknown",
        "sni_present": bool(server_name),
        "sni_entropy": _char_entropy(server_name or ""),
        "cert_chain_length": cert_chain_length,
        "handshake_time_ms": handshake_time_ms,
        "suspicious_sni": _suspicious(server_name),
    }


def _char_entropy(sequence: str) -> float:
    import math
    if not sequence:
        return 0.0
    length = float(len(sequence))
    counts: dict[str, int] = {}
    for ch in sequence:
        counts[ch] = counts.get(ch, 0) + 1
    return -sum((c / length) * math.log(c / length) for c in counts.values())


def _suspicious(server_name: str) -> bool:
    if not server_name:
        return False
    first_label = server_name.split(".")[0]
    return len(first_label) > 30 or _char_entropy(first_label) > 3.5