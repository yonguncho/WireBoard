"""RstAnalyzer — Panel 5: RST/Malformed 패킷 분석."""
from collections import defaultdict
from dataclasses import dataclass, field

from models.session import SessionModel

_HIGH_RST_THRESHOLD = 100


@dataclass
class RstAnalysisResult:
    rst_by_src: dict = field(default_factory=dict)
    high_rst_ips: list = field(default_factory=list)
    malformed_count: int = 0
    suspicious_ips: list = field(default_factory=list)


class RstAnalyzer:
    def analyze(self, sessions: list[SessionModel]) -> RstAnalysisResult:
        rst_by_src: dict[str, int] = defaultdict(int)
        malformed_count = 0
        suspicious_ips: set[str] = set()

        for s in sessions:
            if s.rst:
                rst_by_src[s.src_ip] += 1
            if s.meta and s.meta.get("malformed"):
                malformed_count += 1
                suspicious_ips.add(s.src_ip)

        high_rst_ips = [
            ip for ip, cnt in rst_by_src.items()
            if cnt > _HIGH_RST_THRESHOLD
        ]

        return RstAnalysisResult(
            rst_by_src=dict(rst_by_src),
            high_rst_ips=high_rst_ips,
            malformed_count=malformed_count,
            suspicious_ips=sorted(suspicious_ips),
        )
