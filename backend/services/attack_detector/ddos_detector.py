"""DDoSDetector — T1498/T1499 분산 서비스 거부 탐지."""
from collections import defaultdict

from models.session import SessionModel
from services.attack_detector.base import AttackResult

# 절대 pps floor 기준 (네트워크 분석 관점: 정상 서버 부하 오탐 방지).
# 정상 DNS/웹 서버는 다수 소스에서 fan-in 수신이 정상이라, 소스 수만으로는
# DDoS로 보지 않고 반드시 높은 절대 패킷 레이트를 동반해야 한다.
_RATE_HIGH = 10000.0  # pps — 볼류메트릭/애플리케이션 플러드 영역
_RATE_FLOOR = 2000.0  # pps — 이 미만이면 DDoS로 보지 않음 (정상 서버 부하)
_SRC_HIGH = 50        # floor 충족 시 다수 소스면 high 로 격상
_PRD_SRC_MIN = 6      # "분산"으로 보기 위한 최소 소스 수

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
            window_s = ts_max - ts_min if ts_max > ts_min else 0.001
            rate = total_pkts / window_s

            # DDoS requires at least _PRD_SRC_MIN distinct sources
            if unique_src < _PRD_SRC_MIN:
                continue

            # 절대 pps floor 미만은 정상 서버 부하로 간주 (소스 수 무관).
            # 예: DNS 서버에 33소스·995pps fan-in 은 정상 트래픽이지 DDoS 아님.
            if rate < _RATE_FLOOR:
                continue

            if rate >= _RATE_HIGH or unique_src >= _SRC_HIGH:
                severity = "high"
            else:
                severity = "medium"

            result = AttackResult(
                attack_type="DDoS",
                severity=severity,
                mitre_id="T1498",
                description=f"→ {dst_ip}: {rate:.0f} pps, {unique_src} sources",
            )

            if any(s.confidence == "low" for s in grp):
                result = result.downgrade()

            if best is None or _rank(result.severity) > _rank(best.severity):
                best = result

        return best
