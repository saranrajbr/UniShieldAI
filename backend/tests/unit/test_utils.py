from app.utils.hashing import flow_hash
from app.utils.ip import get_direction, is_private_ip, is_valid_ip


class TestIpUtils:
    def test_valid_ip(self):
        assert is_valid_ip("8.8.8.8")
        assert not is_valid_ip("not-an-ip")

    def test_private_ip(self):
        assert is_private_ip("10.0.0.1")
        assert not is_private_ip("8.8.8.8")

    def test_direction(self):
        assert get_direction("10.0.0.1", "8.8.8.8") == "outbound"
        assert get_direction("8.8.8.8", "10.0.0.1") == "inbound"
        assert get_direction("10.0.0.1", "10.0.0.2") == "lateral"


class TestHashing:
    def test_flow_hash_deterministic(self):
        a = flow_hash("10.0.0.1", "8.8.8.8", 1234, 443, "tcp")
        b = flow_hash("10.0.0.1", "8.8.8.8", 1234, 443, "tcp")
        assert a == b
        assert len(a) == 32