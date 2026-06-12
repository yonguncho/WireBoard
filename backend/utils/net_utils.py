"""Shared network utilities."""
import ipaddress


def is_private(ip: str) -> bool:
    """Return True if ip is a non-routable IPv4 address (RFC 1918 + loopback + link-local)."""
    try:
        addr = ipaddress.ip_address(ip)
        if not isinstance(addr, ipaddress.IPv4Address):
            return False
        p = addr.packed
        if p[0] == 10:                        # 10/8
            return True
        if p[0] == 172 and 16 <= p[1] <= 31:  # 172.16/12
            return True
        if p[0] == 192 and p[1] == 168:        # 192.168/16
            return True
        if p[0] == 127:                        # 127/8 loopback
            return True
        if p[0] == 169 and p[1] == 254:        # 169.254/16 link-local
            return True
        return False
    except ValueError:
        return False
