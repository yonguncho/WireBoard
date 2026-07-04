"""공유 상수 — 여러 모듈에서 참조하는 값은 여기서 단일 정의."""
import re

APP_VERSION = "7.5.0"  # 단일 버전 정의 — main.py/PDF 리포트 등에서 참조

MAX_UPLOAD_BYTES = 52_428_800  # 50 MB — 바이너리 pcap/pcapng 한도
# 텍스트 로그(FortiGate/tcpdump hex 덤프·HAR JSON)는 같은 정보를 바이너리보다
# 3~4배 크게 표현하므로 별도의 상향 한도를 적용한다(디코딩 후 ~1/4로 축소).
MAX_TEXT_UPLOAD_BYTES = 209_715_200  # 200 MB — .txt/.log/.tcpdump/.har

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
