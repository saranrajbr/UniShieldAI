"""TLS/QUIC metadata extraction (PS 26145 requirement d).

Computes a JA3-style fingerprint for a TLS ClientHello **without decrypting
any payload**. JA3 hashes the observable, cleartext handshake parameters —
client version, cipher suites, extensions, supported groups and EC point
formats. It feeds rule detection and alert evidence only; it is never part
of the ML feature vector.

Protocol reference (JA3):
    seed = f"{version},{cipher_suites},{extensions},{groups},{point_formats}"
    ja3  = md5(seed).hexdigest()
"""

import hashlib
import struct
from typing import Optional

TLS_HANDSHAKE = 0x16
TLS_CLIENT_HELLO = 0x01
TLS_EXT_SUPPORTED_GROUPS = 0x000A
TLS_EXT_EC_POINT_FORMATS = 0x000B


def extract_ja3(payload: bytes) -> Optional[str]:
    """Return a JA3 client fingerprint for the first TLS ClientHello in
    `payload`, or None when the payload is not a handshake/ClientHello."""
    if not payload:
        return None
    if payload[0] != TLS_HANDSHAKE:
        return None

    # TLS record: type(1) + version(2) + length(2)
    rec_len = struct.unpack(">H", payload[3:5])[0]
    msg = payload[5 : 5 + rec_len]
    if len(msg) < 4:
        return None
    if msg[0] != TLS_CLIENT_HELLO:
        return None

    h_len = int.from_bytes(msg[1:4], "big")
    body = msg[4 : 4 + h_len]
    return _ja3_from_client_hello(body)


def _ja3_from_client_hello(b: bytes) -> Optional[str]:
    if len(b) < 2:
        return None
    version = struct.unpack(">H", b[0:2])[0]
    if not (0x0300 <= version <= 0x0304):
        return None

    off = 2 + 32  # client_version + random
    if len(b) < off + 1:
        return None
    sid_len = b[off]
    off += 1 + sid_len
    if len(b) < off + 2:
        return None
    suites_len = struct.unpack(">H", b[off : off + 2])[0]
    off += 2
    suites = b[off : off + suites_len]
    if len(suites) < suites_len:
        return None
    cipher_suites = [struct.unpack(">H", suites[i : i + 2])[0] for i in range(0, suites_len, 2)]
    off += suites_len
    if len(b) < off + 1:
        return None
    comp_len = b[off]
    off += 1 + comp_len
    if len(b) < off + 2:
        return None
    ext_len = struct.unpack(">H", b[off : off + 2])[0]
    off += 2
    ext_data = b[off : off + ext_len]

    ext_types: list[int] = []
    groups: list[int] = []
    point_formats: list[int] = []

    e = 0
    while e + 4 <= len(ext_data):
        ext_type = struct.unpack(">H", ext_data[e : e + 2])[0]
        ext_len = struct.unpack(">H", ext_data[e + 2 : e + 4])[0]
        ext_types.append(ext_type)
        body = ext_data[e + 4 : e + 4 + ext_len]
        if ext_type == TLS_EXT_SUPPORTED_GROUPS and len(body) >= 2:
            n = struct.unpack(">H", body[0:2])[0]
            for i in range(2, 2 + n * 2, 2):
                if i + 2 <= len(body):
                    groups.append(struct.unpack(">H", body[i : i + 2])[0])
        elif ext_type == TLS_EXT_EC_POINT_FORMATS and len(body) >= 1:
            n = body[0]
            point_formats = list(body[1 : 1 + n])
        e += 4 + ext_len

    seed = (
        f"{version},"
        f"{','.join(map(str, cipher_suites))},"
        f"{','.join(map(str, ext_types))},"
        f"{','.join(map(str, groups))},"
        f"{','.join(map(str, point_formats))}"
    )
    return hashlib.md5(seed.encode("utf-8")).hexdigest()