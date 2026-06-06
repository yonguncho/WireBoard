"""BruteForceDetector — T1110 브루트포스 탐지."""
from collections import defaultdict

from models.session import SessionModel
from services.attack_detector.base import AttackResult

_ATTEMPTS_HIGH = 50
_ATTEMPTS_MEDIUM = 10
_FAIL_RATE_THRESHOLD = 0.9
# PRD: 1초 윈도우 내 RST/ICMP 에러 10회 이상
_RST_PER_SEC_THRESHOLD = 10

_SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3}


def _is_failed(s: SessionModel) -> bool:
    if s.bytes_recv == 0:
        return True
    if s.meta and s.meta.get("auth_success") is False:
        return True
    if s.rst:
        # PRD: RST 플래그 = 연결 거부(실패) 지표
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
                src_ip=src_ip,
            )

            if any(s.confidence == "low" for s in grp):
                result = result.downgrade()

            if best is None or _rank(result.severity) > _rank(best.severity):
                best = result

        # PRD: 1초 윈도우 내 RST 패킷 10회 이상 → 브루트포스 탐지
        rst_sessions = [s for s in sessions if s.rst]
        if rst_sessions:
            windows: dict[int, int] = defaultdict(int)
            windows_src: dict[int, dict[str, int]] = defaultdict(lambda: defaultdict(int))
            for s in rst_sessions:
                sec = int(s.start_ts)
                windows[sec] += 1
                windows_src[sec][s.src_ip] += 1
            max_rst_per_sec = max(windows.values())
            if max_rst_per_sec >= _RST_PER_SEC_THRESHOLD:
                peak_sec = max(windows, key=windows.__getitem__)
                rst_src_ip = max(windows_src[peak_sec], key=windows_src[peak_sec].__getitem__, default="")
                rst_result = AttackResult(
                    attack_type="BruteForce",
                    severity="high" if max_rst_per_sec >= _ATTEMPTS_HIGH else "medium",
                    mitre_id="T1110",
                    description=f"RST flood: {max_rst_per_sec}회/초 탐지",
                    src_ip=rst_src_ip,
                )
                if any(s.confidence == "low" for s in rst_sessions):
                    rst_result = rst_result.downgrade()
                if best is None or _rank(rst_result.severity) > _rank(best.severity):
                    best = rst_result

        return best
