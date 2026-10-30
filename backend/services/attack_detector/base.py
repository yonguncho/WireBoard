"""공격 탐지 결과 공통 모델."""
from dataclasses import dataclass, field
from typing import List

_SEVERITY_ORDER = ["low", "medium", "high"]


def is_unanswered(s) -> bool:
    """서버에 닿지 못한 연결 — 응답 0바이트, RST 없음, 인증 결과 정보도 없음 (SYN 타임아웃 등).

    방화벽 차단·서버 다운의 흔적이지 공격 시도가 아니다. 2026-10-30 실사례: 방화벽에 막힌
    MES→DB(1433) 연결 재시도 15회가 'C2 beacon HIGH' + 'Brute force' 로 오탐돼 보고서 위험도 HIGH.
    """
    meta = getattr(s, "meta", None) or {}
    return s.bytes_recv == 0 and not s.rst and "auth_success" not in meta


@dataclass
class AttackResult:
    attack_type: str
    severity: str
    mitre_id: str
    description: str = ""
    src_ip: str = ""
    evidence: List[str] = field(default_factory=list)
    sample_count: int = 0
    confidence: str = field(default="")

    def __post_init__(self) -> None:
        if not self.confidence:
            self.confidence = self.severity

    def downgrade(self) -> "AttackResult":
        """severity를 1단계 낮춘다."""
        idx = _SEVERITY_ORDER.index(self.severity)
        new_severity = _SEVERITY_ORDER[max(0, idx - 1)]
        return AttackResult(
            attack_type=self.attack_type,
            severity=new_severity,
            mitre_id=self.mitre_id,
            description=self.description,
            src_ip=self.src_ip,
            evidence=list(self.evidence),
            sample_count=self.sample_count,
            confidence=new_severity,
        )
