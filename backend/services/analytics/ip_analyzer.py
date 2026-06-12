"""IpAnalyzer — Panel 1: Top 20 src/dst IP 분석."""
from collections import defaultdict
from dataclasses import dataclass, field

from models.session import SessionModel
from utils.net_utils import is_private as _is_private


@dataclass
class IpAnalysisResult:
    top_src: list = field(default_factory=list)
    top_dst: list = field(default_factory=list)


class IpAnalyzer:
    def analyze(self, sessions: list[SessionModel]) -> IpAnalysisResult:
        src_count: dict[str, int] = defaultdict(int)
        dst_count: dict[str, int] = defaultdict(int)
        src_bytes: dict[str, int] = defaultdict(int)
        dst_bytes: dict[str, int] = defaultdict(int)

        for s in sessions:
            src_count[s.src_ip] += 1
            dst_count[s.dst_ip] += 1
            src_bytes[s.src_ip] += s.bytes_sent
            dst_bytes[s.dst_ip] += s.bytes_recv

        def _build_top(count_map: dict[str, int], byte_map: dict[str, int]) -> list[dict]:
            sorted_items = sorted(count_map.items(), key=lambda x: (-x[1], x[0]))
            return [
                {"ip": ip, "count": c, "bytes": byte_map.get(ip, 0), "is_private": _is_private(ip)}
                for ip, c in sorted_items[:20]
            ]

        return IpAnalysisResult(
            top_src=_build_top(src_count, src_bytes),
            top_dst=_build_top(dst_count, dst_bytes),
        )
