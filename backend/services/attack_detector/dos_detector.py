"""DoSDetector — T1499 단일 소스 서비스 거부 탐지."""
from models.session import SessionModel
from services.attack_detector.base import AttackResult

_PKT_HIGH   = 5000
_PKT_MEDIUM = 2000
_RATE_HIGH  = 500.0   # pps
_RATE_MEDIUM = 100.0

_SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3}


def _rank(s: str) -> int:
    return _SEVERITY_RANK.get(s, 0)


class DoSDetector:
    def detect(self, sessions: list[SessionModel]) -> AttackResult | None:
        if not sessions:
            return None

        best: AttackResult | None = None

        for s in sessions:
            window_s = s.end_ts - s.start_ts if s.end_ts > s.start_ts else 0.001
            rate = s.packet_count / window_s

            if s.packet_count >= _PKT_HIGH or rate >= _RATE_HIGH:
                severity = "high"
            elif s.packet_count >= _PKT_MEDIUM or rate >= _RATE_MEDIUM:
                severity = "medium"
            else:
                continue

            result = AttackResult(
                attack_type="DoS",
                severity=severity,
                mitre_id="T1499",
                description=f"{s.src_ip}→{s.dst_ip}: {rate:.0f} pps, {s.packet_count} pkts",
                src_ip=s.src_ip,
            )
            if s.confidence == "low":
                result = result.downgrade()

            if best is None or _rank(result.severity) > _rank(best.severity):
                best = result

        return best
