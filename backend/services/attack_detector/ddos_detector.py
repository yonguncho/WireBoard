"""DDoSDetector — T1498/T1499 분산 서비스 거부 탐지."""
from collections import defaultdict

from models.session import SessionModel
from services.attack_detector.base import AttackResult

_RATE_HIGH = 1000.0   # pps
_RATE_MEDIUM = 300.0
_SRC_HIGH = 50
_SRC_MEDIUM = 10

_SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3}


def _rank(s: str) -> int:
    return _SEVERITY_RANK.get(s, 0)


class DDoSDetector:
    def detect(self, sessions: list[SessionModel]) -> AttackResult | None:
        if not sessions:
            return None

        by_dst: dict[str, list[SessionModel]] = defaultdict(list)
        for s in sessions:
            by_dst[s.dst_ip].append(s)

        best: AttackResult | None = None

        for dst_ip, grp in by_dst.items():
            total_pkts = sum(s.packet_count for s in grp)
            unique_src = len({s.src_ip for s in grp})
            ts_min = min(s.start_ts for s in grp)
            ts_max = max(s.end_ts for s in grp)
            window_s = max(1.0, ts_max - ts_min)
            rate = total_pkts / window_s

            if rate >= _RATE_HIGH or unique_src >= _SRC_HIGH:
                severity = "high"
            elif rate >= _RATE_MEDIUM or unique_src >= _SRC_MEDIUM:
                severity = "medium"
            else:
                continue

            result = AttackResult(
                attack_type="DDoS",
                severity=severity,
                mitre_id="T1498",
                description=f"→ {dst_ip}: {rate:.0f} pps, {unique_src}개 소스",
            )

            if any(s.confidence == "low" for s in grp):
                result = result.downgrade()

            if best is None or _rank(result.severity) > _rank(best.severity):
                best = result

        return best
