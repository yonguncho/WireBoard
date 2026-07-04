Correctness release — IPv6 support and parser hardening.

**Fixed / New**
- IPv6 is now parsed (dpkt primary + scapy fallback). Dual-stack captures no longer
  silently drop their IPv6 half. TCP/UDP over IPv6 and ICMPv6 are decoded; hop-limit
  maps to the TTL/hop badge.
- Layer fields in the struct fallback: TTL / IP ID / DF / TCP window are populated
  even on the last-resort parser.
- VLAN stack cap (QinQ <= 4 tags) in the struct parser — guards against a
  crafted/looping tag chain.
- FortiGate/tcpdump log timezone is configurable via WIREBOARD_LOG_TZ_OFFSET
  (hours, e.g. 9 or -5); logs carry no TZ, so this normalizes device-local
  timestamps to UTC instead of silently assuming UTC.

**Integrity**
- WireBoard.exe SHA-256: `153e2cdfae663afad6dbc321bb8810c83ea881bc8d3de8ba18e1bcd5095c9cf8`
- 824 tests passed (incl. new IPv6 parse tests).
