"""Shared network utilities."""
import ipaddress


def is_private(ip: str) -> bool:
    """Return True if ip is an RFC 1918 private IPv4 address."""
    try:
        addr = ipaddress.ip_address(ip)
        if not isinstance(addr, ipaddress.IPv4Address):
            return False
        p = addr.packed
        if p[0] == 10:
            return True
        if p[0] == 172 and 16 <= p[1] <= 31:
            return True
        if p[0] == 192 and p[1] == 168:
            return True
        return False
    except ValueError:
        return False
