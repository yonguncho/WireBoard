"""CommFailureDetector — T1499 통신 실패 패턴 탐지 (TCP RST 비율 기반)."""
from models.session import SessionModel
from services.attack_detector.base import AttackResult

_MIN_TCP_SESSIONS = 5
_HIGH_RST_RATIO = 0.8    # RST 비율 >= 80% → high
_MEDIUM_RST_RATIO = 0.4  # RST 비율 >= 40% → medium


class CommFailureDetector:
    def detect(self, sessions: list[SessionModel]) -> AttackResult | None:
        tcp_sessions = [s for s in sessions if s.protocol == "TCP"]
        total = len(tcp_sessions)
        if total < _MIN_TCP_SESSIONS:
            return None

        rst_count = sum(1 for s in tcp_sessions if s.rst)
        ratio = rst_count / total

        if ratio >= _HIGH_RST_RATIO:
            severity = "high"
        elif ratio >= _MEDIUM_RST_RATIO:
            severity = "medium"
        else:
            return None

        return AttackResult(
            attack_type="CommFailure",
            severity=severity,
            mitre_id="T1499",
            description=f"TCP RST 비율 {ratio:.0%} ({rst_count}/{total} 세션) - 연결 거부/차단 의심",
        )
