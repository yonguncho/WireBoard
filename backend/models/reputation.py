"""Reputation 관련 모델."""
from typing import List, Optional
from pydantic import BaseModel


class ReputationSourceResult(BaseModel):
    source: str
    is_malicious: bool = False
    is_reliable: bool = True
    country_code: Optional[str] = None
    asn: Optional[str] = None
    note: Optional[str] = None


class ReputationResult(BaseModel):
    ip: str
    is_malicious: bool = False
    sources: List[ReputationSourceResult] = []
