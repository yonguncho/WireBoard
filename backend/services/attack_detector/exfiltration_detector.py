"""ExfiltrationDetector — T1041 데이터 유출 탐지."""
from collections import defaultdict

from models.session import SessionModel
from services.attack_detector.base import AttackResult
from utils.net_utils import is_private as _is_private

_MB = 1_048_576
_BYTES_HIGH = 500 * _MB
_BYTES_MEDIUM = 100 * _MB
_CONN_HIGH = 20
_CONN_MEDIUM = 5
# PRD: 아웃바운드 비율 기반 탐지
_PRD_RATIO_THRESHOLD = 0.8   # 80% outbound
_PRD_BYTES_MIN = 1 * _MB     # 최소 1MB 전송

_SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3}


def _rank(s: str) -> int:
    return _SEVERITY_RANK.get(s, 0)


class ExfiltrationDetector:
    def detect(self, sessions: list[SessionModel]) -> AttackResult | None:
        if not sessions:
            return None

        by_src: dict[str, list[SessionModel]] = defaultdict(list)
        for s in sessions:
            if not _is_private(s.dst_ip):
                by_src[s.src_ip].append(s)

        best: AttackResult | None = None

        for src_ip, grp in by_src.items():
            connections = len(grp)
            bytes_out = sum(s.bytes_sent for s in grp)
            bytes_total = sum(s.bytes_sent + s.bytes_recv for s in grp)
            outbound_ratio = bytes_out / bytes_total if bytes_total > 0 else 0.0

            # 실제 아웃바운드 전송량이 없으면 연결 수와 무관하게 유출 아님
            # (일반 브라우징도 외부 연결 수백 개를 만들 수 있음)
            if bytes_out < _PRD_BYTES_MIN:
                continue

            if connections > _CONN_HIGH or bytes_out > _BYTES_HIGH:
                severity = "high"
            elif connections > _CONN_MEDIUM or bytes_out > _BYTES_MEDIUM:
                severity = "medium"
            elif outbound_ratio >= _PRD_RATIO_THRESHOLD and bytes_total >= _PRD_BYTES_MIN:
                # PRD: 80% 이상 아웃바운드 + 1MB 이상 전송
                if bytes_out >= _BYTES_HIGH:
                    severity = "high"
                elif bytes_out >= _BYTES_MEDIUM:
                    severity = "medium"
                else:
                    continue
            else:
                continue

            result = AttackResult(
                attack_type="Exfiltration",
                severity=severity,
                mitre_id="T1041",
                description=f"{src_ip}: {connections}개 외부 연결, {bytes_out // _MB} MB 전송 (아웃바운드 {outbound_ratio:.0%})",
                src_ip=src_ip,
            )

            if any(s.confidence == "low" for s in grp):
                result = result.downgrade()

            if best is None or _rank(result.severity) > _rank(best.severity):
                best = result

        return best
