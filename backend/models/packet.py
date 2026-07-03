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
    # ── L3/L4 헤더 필드 (Wireshark식 레이어 분석·Expert Info용) ──────────
    # 기본값 존재: scapy/struct 폴백 및 레거시 파서는 미설정 시 0/False.
    window: int = 0    # TCP window size (raw, scale 미적용)
    ttl: int = 0       # IP TTL
    ip_id: int = 0     # IP identification
    df: bool = False   # IP Don't-Fragment 플래그
