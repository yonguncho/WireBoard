"""BeaconDetector — T1071 비컨 통신 탐지 (버스트 기반 CV)."""
import math
from collections import defaultdict

from models.session import SessionModel
from services.attack_detector.base import AttackResult

_MIN_SAMPLES = 5
_HIGH_CV = 5.0    # CV ≤ 5% → high
_MEDIUM_CV = 10.0 # CV ≤ 10% → medium
_NOISE_CV = 20.0  # CV > 20% → 탐지 안 함
_BURST_WINDOW = 1.0  # 초, 이 간격 미만의 연속 패킷은 같은 burst로 취급
_SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3}


def _rank_severity(severity: str) -> int:
    return _SEVERITY_RANK.get(severity, 0)


def _compute_cv(values: list[float]) -> float:
    n = len(values)
    if n < 2:
        return float("inf")
    mean = sum(values) / n
    if mean == 0:
        return float("inf")
    # Bessel's correction으로 샘플 분산 계산
    variance = sum((v - mean) ** 2 for v in values) / (n - 1)
    std = math.sqrt(variance)
    return (std / mean) * 100.0


def _cluster_bursts(timestamps: list[float]) -> list[float]:
    """gap >= _BURST_WINDOW 를 기준으로 burst 시작 타임스탬프만 반환.

    Cobalt Strike jitter / Sliver burst mode 같은 C2 패턴은 짧은 burst 내에
    여러 패킷을 보낸 뒤 주기적으로 침묵하는 구조이므로, raw interval CV 대신
    burst 간 interval CV를 계산해야 탐지율이 유지된다.
    """
    if not timestamps:
        return []
    burst_starts = [timestamps[0]]
    for prev, curr in zip(timestamps, timestamps[1:]):
        if curr - prev >= _BURST_WINDOW:
            burst_starts.append(curr)
    return burst_starts


class BeaconDetector:
    def detect(self, sessions: list[SessionModel]) -> AttackResult | None:
        groups: dict[tuple[str, str], list] = defaultdict(list)
        for s in sessions:
            groups[(s.src_ip, s.dst_ip)].append(s)

        best: tuple[AttackResult, int] | None = None

        for (src_ip, dst_ip), group in groups.items():
            if len(group) < _MIN_SAMPLES:
                continue

            timestamps = sorted(s.start_ts for s in group)
            burst_ts = _cluster_bursts(timestamps)

            if len(burst_ts) < _MIN_SAMPLES:
                continue

            intervals = [burst_ts[i + 1] - burst_ts[i] for i in range(len(burst_ts) - 1)]

            cv = _compute_cv(intervals)

            if cv > _NOISE_CV:
                continue

            if cv <= _HIGH_CV:
                severity = "high"
            elif cv <= _MEDIUM_CV:
                severity = "medium"
            else:
                severity = "low"

            result = AttackResult(
                attack_type="Beacon",
                severity=severity,
                mitre_id="T1071",
                description=f"{src_ip} → {dst_ip}: CV={cv:.1f}%, {len(group)}회 접속 ({len(burst_ts)} bursts)",
            )

            if any(s.confidence == "low" for s in group):
                result = result.downgrade()

            group_size = len(group)
            if best is None:
                best = (result, group_size)
            elif _rank_severity(result.severity) > _rank_severity(best[0].severity):
                best = (result, group_size)
            elif _rank_severity(result.severity) == _rank_severity(best[0].severity) and group_size > best[1]:
                best = (result, group_size)

        return best[0] if best else None
