"""DoSDetector — T1499 단일 소스 서비스 거부 탐지."""
from models.session import SessionModel
from services.attack_detector.base import AttackResult

_PKT_HIGH   = 5000
_PKT_MEDIUM = 2000
_RATE_HIGH  = 5000.0  # pps
_RATE_MEDIUM = 500.0
_MIN_WINDOW_S = 1.0   # 1초 미만 버스트는 pps 신뢰 불가 (정상 다운로드도 순간 수만 pps)
_MAX_AVG_PKT_BYTES = 200  # flood는 소형 패킷 위주 — 대형 패킷은 정상 대역폭 사용

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
            avg_pkt = (s.bytes_sent + s.bytes_recv) / s.packet_count if s.packet_count else 0
            if avg_pkt > _MAX_AVG_PKT_BYTES:
                continue  # 대형 패킷 위주 세션은 정상 전송 (다운로드/스트리밍)
            # 순간 버스트의 pps는 의미 없음 — 지속 시간이 충분할 때만 rate 사용
            rate = s.packet_count / window_s if window_s >= _MIN_WINDOW_S else 0.0

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
                evidence=[f"{s.packet_count} 패킷 / {rate:.0f} pps ({s.src_ip}→{s.dst_ip})"],
                sample_count=s.packet_count,
            )
            if s.confidence == "low":
                result = result.downgrade()

            if best is None or _rank(result.severity) > _rank(best.severity):
                best = result

        return best
