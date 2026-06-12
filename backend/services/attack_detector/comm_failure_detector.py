"""CommFailureDetector — T1499 통신 실패 패턴 탐지 (TCP RST 비율 기반)."""
from models.session import SessionModel
from services.attack_detector.base import AttackResult

_MIN_TCP_SESSIONS = 5
_HIGH_RST_RATIO = 0.8    # RST 비율 >= 80% → high
_MEDIUM_RST_RATIO = 0.4  # RST 비율 >= 40% → medium


class CommFailureDetector:
    def detect(
        self,
        sessions: list[SessionModel],
        rst_count: int = 0,
        icmp_unreachable: int = 0,
    ) -> AttackResult | None:
        # 세션 기반 탐지
        tcp_sessions = [s for s in sessions if s.protocol == "TCP"]
        total = len(tcp_sessions)
        session_rst = sum(1 for s in tcp_sessions if s.rst)

        # 외부에서 직접 카운트를 전달한 경우 합산
        effective_rst = session_rst + rst_count
        effective_total = max(total, effective_rst + icmp_unreachable, 1)
        ratio = effective_rst / effective_total

        if effective_rst + icmp_unreachable == 0:
            if total < _MIN_TCP_SESSIONS:
                return None
            if ratio < _MEDIUM_RST_RATIO:
                return None

        # 절대 건수 단독 조건 금지 — RST 비율이 높을 때만 통신 장애로 판단
        # (대형 캡처에서는 정상 트래픽에도 RST 수십 건이 자연 발생)
        if effective_rst >= 20 and ratio >= _HIGH_RST_RATIO:
            severity = "high"
        elif (effective_rst >= 10 and ratio >= _MEDIUM_RST_RATIO) or icmp_unreachable >= 20:
            severity = "medium"
        else:
            return None

        return AttackResult(
            attack_type="CommFailure",
            severity=severity,
            mitre_id="T1595",
            description=(
                f"RST {effective_rst}건 + ICMP Unreachable {icmp_unreachable}건 "
                f"— 연결 거부/차단 의심"
            ),
        )
