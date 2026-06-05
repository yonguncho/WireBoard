"""IpAnalyzer — Panel 1: Top 20 src/dst IP 분석."""
import ipaddress
from collections import defaultdict
from dataclasses import dataclass, field

from models.session import SessionModel


def _is_private(ip: str) -> bool:
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


@dataclass
class IpAnalysisResult:
    top_src: list = field(default_factory=list)
    top_dst: list = field(default_factory=list)


class IpAnalyzer:
    def analyze(self, sessions: list[SessionModel]) -> IpAnalysisResult:
        src_counts: dict[str, int] = defaultdict(int)
        dst_counts: dict[str, int] = defaultdict(int)

        for s in sessions:
            src_counts[s.src_ip] += 1
            dst_counts[s.dst_ip] += 1

        def _build_top(counts: dict[str, int]) -> list[dict]:
            sorted_items = sorted(counts.items(), key=lambda x: (-x[1], x[0]))
            return [
                {"ip": ip, "count": cnt, "is_private": _is_private(ip)}
                for ip, cnt in sorted_items[:20]
            ]

        return IpAnalysisResult(
            top_src=_build_top(src_counts),
            top_dst=_build_top(dst_counts),
        )
