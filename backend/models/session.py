"""SessionModel — 공유 도메인 모델."""
import ipaddress
import re
from typing import Literal, Optional

from pydantic import BaseModel, field_validator, model_validator

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
    confidence: Literal["low", "normal"] = "normal"
    rst: bool = False
    meta: Optional[dict] = None

    @field_validator("session_id")
    @classmethod
    def validate_uuid_v4(cls, v: str) -> str:
        if not _UUID_V4_RE.match(v):
            raise ValueError(f"session_id must be UUID v4: {v!r}")
        return v

    @field_validator("src_ip", "dst_ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError(f"유효하지 않은 IP 주소: {v!r}")
        return v

    @field_validator("src_port", "dst_port")
    @classmethod
    def validate_port(cls, v: int) -> int:
        if not 0 <= v <= 65535:
            raise ValueError(f"port must be 0-65535, got {v}")
        return v

    @field_validator("bytes_sent", "bytes_recv", "packet_count", "payload_length")
    @classmethod
    def validate_non_negative(cls, v: int) -> int:
        if v < 0:
            raise ValueError(f"음수 불가: {v}")
        return v

    @model_validator(mode="after")
    def validate_temporal_order(self) -> "SessionModel":
        if self.end_ts < self.start_ts:
            raise ValueError(f"end_ts({self.end_ts}) < start_ts({self.start_ts})")
        return self
