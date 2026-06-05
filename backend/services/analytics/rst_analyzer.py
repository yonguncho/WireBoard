"""RstAnalyzer — Panel 5: RST/Malformed/재전송 패킷 분석."""
from collections import defaultdict
from dataclasses import dataclass, field

from models.session import SessionModel

_HIGH_RST_THRESHOLD = 100
_RETRANSMIT_WINDOW_S = 30.0   # 동일 4-tuple이 이 시간 내 재등장하면 재전송으로 간주


@dataclass
class RstAnalysisResult:
    rst_by_src: dict = field(default_factory=dict)
    high_rst_ips: list = field(default_factory=list)
    malformed_count: int = 0
    retransmit_count: int = 0
    suspicious_ips: list = field(default_factory=list)


class RstAnalyzer:
    def analyze(self, sessions: list[SessionModel]) -> RstAnalysisResult:
        rst_by_src: dict[str, int] = defaultdict(int)
        malformed_count = 0
        suspicious_ips: set[str] = set()

        # 재전송 감지: 동일 (src_ip, dst_ip, dst_port, proto) 4-tuple이
        # _RETRANSMIT_WINDOW_S 내에 재등장하면 재전송으로 집계
        four_tuple_last_ts: dict[tuple, float] = {}
        retransmit_count = 0

        for s in sorted(sessions, key=lambda x: x.start_ts):
            if s.rst:
                rst_by_src[s.src_ip] += 1
            if s.meta and s.meta.get("malformed"):
                malformed_count += 1
                suspicious_ips.add(s.src_ip)

            key = (s.src_ip, s.dst_ip, s.dst_port, s.protocol)
            last_ts = four_tuple_last_ts.get(key)
            if last_ts is not None and (s.start_ts - last_ts) < _RETRANSMIT_WINDOW_S:
                retransmit_count += 1
            four_tuple_last_ts[key] = s.start_ts

        high_rst_ips = [
            ip for ip, cnt in rst_by_src.items()
            if cnt > _HIGH_RST_THRESHOLD
        ]

        return RstAnalysisResult(
            rst_by_src=dict(rst_by_src),
            high_rst_ips=high_rst_ips,
            malformed_count=malformed_count,
            retransmit_count=retransmit_count,
            suspicious_ips=sorted(suspicious_ips),
        )
