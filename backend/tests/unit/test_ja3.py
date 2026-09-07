import struct

from app.ingestion.tls import extract_ja3


def _client_hello_payload(version=0x0303, ciphers=(0x1301, 0x1302, 0xc02f)):
    """Build a minimal TLS record carrying a ClientHello handshake."""
    # body: client_version(2) + random(32) + session_id_len(1) + suites
    body = struct.pack(">H", version)
    body += bytes(range(32))
    body += b"\x00"
    body += struct.pack(">H", len(ciphers) * 2)
    for c in ciphers:
        body += struct.pack(">H", c)
    body += b"\x01\x00"  # compression method + no extension padding start
    body += b"\x00\x00"  # extension block declared len 0
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    rec = bytes([0x16, 0x03, 0x03]) + struct.pack(">H", len(handshake)) + handshake
    return rec


class TestJA3:
    def test_extracts_ja3(self):
        digest = extract_ja3(_client_hello_payload())
        assert digest is not None
        assert len(digest) == 32
        assert digest == extract_ja3(_client_hello_payload())

    def test_different_ciphers_change_ja3(self):
        a = extract_ja3(_client_hello_payload(ciphers=(0x1301, 0x1302)))
        b = extract_ja3(_client_hello_payload(ciphers=(0x1301, 0xc02f)))
        assert a != b

    def test_non_handshake_rejected(self):
        assert extract_ja3(b"\x00\x01\x02\x03") is None
        assert extract_ja3(b"") is None