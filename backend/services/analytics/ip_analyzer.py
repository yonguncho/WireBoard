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
        src_bytes: dict[str, int] = defaultdict(int)
        dst_bytes: dict[str, int] = defaultdict(int)

        for s in sessions:
            src_bytes[s.src_ip] += s.bytes_sent
            dst_bytes[s.dst_ip] += s.bytes_recv

        def _build_top(byte_map: dict[str, int]) -> list[dict]:
            sorted_items = sorted(byte_map.items(), key=lambda x: (-x[1], x[0]))
            return [
                {"ip": ip, "bytes": b, "is_private": _is_private(ip)}
                for ip, b in sorted_items[:20]
            ]

        return IpAnalysisResult(
            top_src=_build_top(src_bytes),
            top_dst=_build_top(dst_bytes),
        )
