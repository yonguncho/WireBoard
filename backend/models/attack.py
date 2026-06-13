"""AttackDetectionResult — 공격 탐지 결과 공용 모델 (API 직렬화용)."""
from typing import List, Optional
from pydantic import BaseModel


class AttackDetectionResult(BaseModel):
    attack_type: str
    severity: str
    mitre_id: Optional[str] = None
    confidence: str = "medium"
    evidence: List[str] = []
    sample_count: int = 0
    description: str = ""
    src_ip: str = ""
    detector_error: bool = False
