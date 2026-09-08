import ipaddress
import socket

from app.core.constants import Direction


class InvalidIPError(ValueError):
    pass


def is_valid_ip(address: str) -> bool:
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False


def is_private_ip(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
        return ip.is_private or ip.is_loopback
    except ValueError:
        return False


def is_public_ip(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
        return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved)
    except ValueError:
        return False


def get_direction(src_ip: str, dst_ip: str) -> str:
    try:
        src = ipaddress.ip_address(src_ip)
        dst = ipaddress.ip_address(dst_ip)
    except ValueError:
        return Direction.UNKNOWN

    src_private = src.is_private or src.is_loopback
    dst_private = dst.is_private or dst.is_loopback

    if src_private and dst_private:
        return Direction.LATERAL
    if src_private and not dst_private:
        return Direction.OUTBOUND
    if not src_private and dst_private:
        return Direction.INBOUND
    return Direction.UNKNOWN


def ip_to_int(address: str) -> int:
    return int(ipaddress.ip_address(address))


def resolve_hostname(address: str, timeout: float = 1.0) -> str | None:
    try:
        return socket.gethostbyaddr(address)[0]
    except (socket.herror, socket.timeout, OSError):
        return None


def same_subnet(a: str, b: str, prefix: int = 24) -> bool:
    try:
        net = ipaddress.ip_network(f"{a}/{prefix}", strict=False)
        return ipaddress.ip_address(b) in net
    except ValueError:
        return False


def parse_cidr_list(value: str) -> list[str]:
    return [v.strip() for v in value.split(",") if v.strip()]


def ip_is_in(cidrs: list[str], address: str) -> bool:
    try:
        addr = ipaddress.ip_address(address)
    except ValueError:
        return False
    for cidr in cidrs:
        try:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False