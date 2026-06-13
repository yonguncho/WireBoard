"""공격 탐지 결과 공통 모델."""
from dataclasses import dataclass, field
from typing import List

_SEVERITY_ORDER = ["low", "medium", "high"]


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
