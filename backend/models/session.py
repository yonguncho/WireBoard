"""SessionModel — 공유 도메인 모델."""
import re
from typing import Optional

from pydantic import BaseModel, field_validator

_UUID_V4_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


class SessionModel(BaseModel):
    model_config = {"strict": True}

    session_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    start_ts: float
    end_ts: float
    bytes_sent: int
    bytes_recv: int
    packet_count: int
    payload_length: int
    confidence: str = "normal"
    rst: bool = False
    meta: Optional[dict] = None

    @field_validator("session_id")
    @classmethod
    def validate_uuid_v4(cls, v: str) -> str:
        if not _UUID_V4_RE.match(v):
            raise ValueError(f"session_id must be UUID v4: {v!r}")
        return v

    @field_validator("src_port", "dst_port")
    @classmethod
    def validate_port(cls, v: int) -> int:
        if not 0 <= v <= 65535:
            raise ValueError(f"port must be 0-65535, got {v}")
        return v
