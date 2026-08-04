"""공유 상수 — 여러 모듈에서 참조하는 값은 여기서 단일 정의."""
import os
import re

APP_VERSION = "7.13.3"  # 단일 버전 정의 — main.py/PDF 리포트 등에서 참조


def _env_bytes(name: str, default: int) -> int:
    """환경변수(바이트 정수)로 상한 재정의. 잘못된 값은 기본값 사용."""
    try:
        v = int(os.environ.get(name, "") or default)
        return v if v > 0 else default
    except (ValueError, TypeError):
        return default


# 바이너리 pcap/pcapng 한도 — 스트리밍 파싱이라 파일 크기만큼 메모리를 쓰지 않는다.
# 파싱 표현은 flow/packet 캡(_MAX_FLOW_COUNT×_MAX_PKTS_PER_FLOW)으로 별도 제한됨.
# WIREBOARD_MAX_PCAP_MB 로 재정의 가능(기본 2048MB=2GB).
MAX_UPLOAD_BYTES = _env_bytes("WIREBOARD_MAX_PCAP_MB", 2048) * 1024 * 1024 \
    if os.environ.get("WIREBOARD_MAX_PCAP_MB") else 2_147_483_648  # 2 GB
# 텍스트 로그(FortiGate/tcpdump hex 덤프·HAR JSON)는 전체를 메모리로 읽으므로 별도 한도.
MAX_TEXT_UPLOAD_BYTES = _env_bytes("WIREBOARD_MAX_TEXT_MB", 300) * 1024 * 1024 \
    if os.environ.get("WIREBOARD_MAX_TEXT_MB") else 314_572_800  # 300 MB

UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

UUID_V4_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

IPv4_RE = re.compile(
    r"^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)
