import hashlib
import json
import random
import time as time_mod
import zlib
from typing import Any


def sha256(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def md5(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.md5(data).hexdigest()


def flow_hash(src_ip: str, dst_ip: str, src_port: int | None,
              dst_port: int | None, protocol: str) -> str:
    canonical = sha256(f"{src_ip}|{dst_ip}|{src_port}|{dst_port}|{protocol}")
    return canonical[:32]


def alert_fingerprint(payload: dict[str, Any]) -> str:
    blob = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def quick_hash(payload: dict[str, Any]) -> str:
    blob = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    return zlib.crc32(blob).to_bytes(4, "big").hex()


def short_id(length: int = 16) -> str:
    return sha256(str(time_mod.time_ns()) + random.random().__str__())[:length]