"""PacketRecord — 패킷 단위 저장 모델."""
from dataclasses import dataclass


@dataclass
class PacketRecord:
    ts: float          # unix timestamp (절대)
    direction: str     # "fwd" | "rev"
    proto: str         # TCP | UDP
    seq: int           # TCP seq (UDP=0)
    ack: int           # TCP ack (UDP=0)
    flags: str         # "SYN", "SYN+ACK", "ACK+PSH", "FIN+ACK", "RST" 등
    length: int        # wire 상 전체 패킷 바이트
    payload_len: int   # transport 헤더 이후 페이로드 바이트 수
    payload_hex: str   # 페이로드 앞 128 바이트 hex 문자열
