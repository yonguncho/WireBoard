"""BruteForceDetector — T1110 브루트포스 탐지."""
from collections import defaultdict

from models.session import SessionModel
from services.attack_detector.base import AttackResult

_ATTEMPTS_HIGH = 50
_ATTEMPTS_MEDIUM = 10
_FAIL_RATE_THRESHOLD = 0.9

_SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3}


def _is_failed(s: SessionModel) -> bool:
    if s.bytes_recv == 0:
        return True
    if s.meta and s.meta.get("auth_success") is False:
        return True
    return False


def _rank(s: str) -> int:
    return _SEVERITY_RANK.get(s, 0)


class BruteForceDetector:
    def detect(self, sessions: list[SessionModel]) -> AttackResult | None:
        if not sessions:
            return None

        by_key: dict[tuple[str, str, int], list[SessionModel]] = defaultdict(list)
        for s in sessions:
            by_key[(s.src_ip, s.dst_ip, s.dst_port)].append(s)

        best: AttackResult | None = None

        for (src_ip, dst_ip, dst_port), grp in by_key.items():
            total = len(grp)
            if total < _ATTEMPTS_MEDIUM:
                continue

            fails = sum(1 for s in grp if _is_failed(s))
            fail_rate = fails / total

            if fail_rate < _FAIL_RATE_THRESHOLD:
                continue

            severity = "high" if total >= _ATTEMPTS_HIGH else "medium"

            result = AttackResult(
                attack_type="BruteForce",
                severity=severity,
                mitre_id="T1110",
                description=f"{src_ip} → {dst_ip}:{dst_port}: {total}회 시도, 실패율 {fail_rate:.0%}",
            )

            if any(s.confidence == "low" for s in grp):
                result = result.downgrade()

            if best is None or _rank(result.severity) > _rank(best.severity):
                best = result

        return best
