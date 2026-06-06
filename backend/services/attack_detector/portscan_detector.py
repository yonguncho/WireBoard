"""PortScanDetector — T1046 포트 스캔 탐지."""
from collections import defaultdict

from models.session import SessionModel
from services.attack_detector.base import AttackResult

_HIGH_THRESHOLD = 100
_MEDIUM_THRESHOLD = 20
_SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3}


def _rank_severity(severity: str) -> int:
    return _SEVERITY_RANK.get(severity, 0)


class PortScanDetector:
    def detect(self, sessions: list[SessionModel]) -> AttackResult | None:
        # src_ip별 고유 dst_port 집합 집계
        scan_map: dict[tuple[str, str], set[int]] = defaultdict(set)
        low_confidence: dict[tuple[str, str], bool] = defaultdict(bool)

        for s in sessions:
            key = (s.src_ip, s.dst_ip)
            scan_map[key].add(s.dst_port)
            low_confidence[key] |= (s.confidence == "low")

        best: AttackResult | None = None

        for (src_ip, dst_ip), ports in scan_map.items():
            count = len(ports)
            if count >= _HIGH_THRESHOLD:
                severity = "high"
            elif count >= _MEDIUM_THRESHOLD:
                severity = "medium"
            else:
                continue

            result = AttackResult(
                attack_type="PortScan",
                severity=severity,
                mitre_id="T1046",
                description=f"{src_ip} → {dst_ip}: {count}개 포트 스캔",
                src_ip=src_ip,
            )

            if low_confidence.get((src_ip, dst_ip)):
                result = result.downgrade()

            if best is None or _rank_severity(result.severity) > _rank_severity(best.severity):
                best = result

        return best
