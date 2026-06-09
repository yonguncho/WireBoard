"""DNSExtractor — DNS 페이로드 파싱 (minimal binary parser)."""
import socket
import struct
from dataclasses import dataclass, field
from typing import List, Optional

_QTYPE_MAP = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR",
              15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY"}


@dataclass
class DNSResult:
    query_name: Optional[str] = None
    query_type: Optional[str] = None
    response_ips: List[str] = field(default_factory=list)
    is_nxdomain: bool = False


class DNSExtractor:
    def extract(self, payload: bytes) -> Optional[DNSResult]:
        if len(payload) < 12:
            return None
        try:
            return self._parse(payload)
        except Exception:
            return None

    def _parse(self, data: bytes) -> Optional[DNSResult]:
        txid, flags, qdcount, ancount, nscount, arcount = struct.unpack_from("!HHHHHH", data, 0)
        rcode = flags & 0x000F
        is_response = bool(flags & 0x8000)

        result = DNSResult(is_nxdomain=(is_response and rcode == 3))

        offset = 12
        for _ in range(qdcount):
            name, offset = _read_name(data, offset)
            if offset + 4 > len(data):
                break
            qtype, qclass = struct.unpack_from("!HH", data, offset)
            offset += 4
            result.query_name = name
            result.query_type = _QTYPE_MAP.get(qtype, str(qtype))

        for _ in range(ancount):
            if offset >= len(data):
                break
            _name, offset = _read_name(data, offset)
            if offset + 10 > len(data):
                break
            rtype, rclass, ttl, rdlen = struct.unpack_from("!HHIH", data, offset)
            offset += 10
            if offset + rdlen > len(data):
                break
            rdata = data[offset:offset + rdlen]
            offset += rdlen
            if rtype == 1 and rdlen == 4:
                result.response_ips.append(socket.inet_ntoa(rdata))
            elif rtype == 28 and rdlen == 16:
                result.response_ips.append(socket.inet_ntop(socket.AF_INET6, rdata))

        return result


def _read_name(data: bytes, offset: int) -> tuple[str, int]:
    labels = []
    visited = set()
    while offset < len(data):
        if offset in visited:
            break
        visited.add(offset)
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                break
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            offset += 2
            sublabels, _ = _read_name(data, ptr)
            labels.append(sublabels)
            break
        else:
            offset += 1
            end = offset + length
            if end > len(data):
                break
            labels.append(data[offset:end].decode("ascii", errors="replace"))
            offset = end
    return ".".join(labels), offset
