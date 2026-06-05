"""공격 탐지 결과 공통 모델."""
from dataclasses import dataclass

_SEVERITY_ORDER = ["low", "medium", "high"]


@dataclass
class AttackResult:
    attack_type: str
    severity: str
    mitre_id: str
    description: str = ""

    def downgrade(self) -> "AttackResult":
        """severity를 1단계 낮춘다."""
        idx = _SEVERITY_ORDER.index(self.severity)
        new_severity = _SEVERITY_ORDER[max(0, idx - 1)]
        return AttackResult(
            attack_type=self.attack_type,
            severity=new_severity,
            mitre_id=self.mitre_id,
            description=self.description,
        )
