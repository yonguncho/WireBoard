"""FortigateParser — FortiGate sniffer verbose 3/6 파서."""
import ipaddress
import logging
import re
import uuid
from datetime import datetime, timezone

from models.session import SessionModel

logger = logging.getLogger(__name__)

_LINE_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+)"              # timestamp
    r"\s+\S+"                                                        # interface
    r"\s+\S+"                                                        # direction
    r"\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:\.(\d+))?"         # src_ip[.src_port]
    r"\s*->\s*"
    r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:\.(\d+))?"            # dst_ip[.dst_port]
    r":\s+(\w+)"                                                     # proto
    r"\s+(\d+)"                                                      # payload_length
)

# 단순 형식: IP:port -> IP:port proto (타임스탬프 없음)
# 예: "192.168.1.1:1234 -> 10.0.0.1:80 tcp"
_SIMPLE_LINE_RE = re.compile(
    r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)"                 # src_ip:src_port
    r"\s*->\s*"
    r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)"                  # dst_ip:dst_port
    r"\s+(\w+)"                                                      # proto
)

_DETECT_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+\s+\w+\s+\w+\s+[\d.]+\s*->\s*[\d.]+:",
)

# 단순 형식 detect 정규식
_DETECT_SIMPLE_RE = re.compile(
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+\s*->\s*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+\s+\w+",
)


class FortigateParser:
    """FortiGate sniffer verbose 3/6 파서 (FortiGateParser 별칭 지원)."""
    def detect(self, data: bytes) -> bool:
        try:
            text = data.decode("utf-8", errors="replace")
        except UnicodeDecodeError:
            return False
        for line in text.splitlines()[:20]:
            if _DETECT_RE.search(line) or _DETECT_SIMPLE_RE.search(line):
                return True
        return False

    def parse(self, data: bytes, parse_warnings: list[str] | None = None) -> list[SessionModel]:
        try:
            text = data.decode("utf-8", errors="replace")
        except UnicodeDecodeError as exc:
            raise ValueError(f"UTF-8 디코딩 실패: {exc}") from exc

        sessions: list[SessionModel] = []
        now_ts = datetime.now(tz=timezone.utc).timestamp()
        for line in text.splitlines():
            stripped = line.strip()
            m = _LINE_RE.match(stripped)
            if m:
                ts_str, src_ip, src_port_str, dst_ip, dst_port_str, proto_str, payload_str = m.groups()
                payload_len = int(payload_str)
                src_port = int(src_port_str) if src_port_str else 0
                dst_port = int(dst_port_str) if dst_port_str else 0

                try:
                    ipaddress.ip_address(src_ip)
                    ipaddress.ip_address(dst_ip)
                except ValueError:
                    continue

                if not (0 <= src_port <= 65535 and 0 <= dst_port <= 65535):
                    continue

                try:
                    dt = datetime.strptime(ts_str.strip(), "%Y-%m-%d %H:%M:%S.%f").replace(tzinfo=timezone.utc)
                    start_ts = dt.timestamp()
                except ValueError:
                    start_ts = now_ts

                # verbose 3: payload=0 → confidence="low"
                # verbose 6: payload>0 → confidence="normal"
                # port 0: 포트 정보 없음 → confidence="low"
                confidence = "low" if payload_len == 0 or src_port == 0 or dst_port == 0 else "normal"

                sessions.append(SessionModel(
                    session_id=str(uuid.uuid4()),
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=proto_str.upper(),
                    start_ts=start_ts,
                    end_ts=start_ts,
                    bytes_sent=0,
                    bytes_recv=0,
                    packet_count=1,
                    payload_length=payload_len if confidence == "normal" else 0,
                    confidence=confidence,
                ))
                continue

            # 단순 형식: IP:port -> IP:port proto
            sm = _SIMPLE_LINE_RE.match(stripped)
            if sm:
                src_ip, src_port_str, dst_ip, dst_port_str, proto_str = sm.groups()
                src_port = int(src_port_str)
                dst_port = int(dst_port_str)

                try:
                    ipaddress.ip_address(src_ip)
                    ipaddress.ip_address(dst_ip)
                except ValueError:
                    continue

                if not (0 <= src_port <= 65535 and 0 <= dst_port <= 65535):
                    continue

                sessions.append(SessionModel(
                    session_id=str(uuid.uuid4()),
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=proto_str.upper(),
                    start_ts=now_ts,
                    end_ts=now_ts,
                    bytes_sent=0,
                    bytes_recv=0,
                    packet_count=1,
                    payload_length=0,
                    confidence="normal",
                ))

        return sessions


# 별칭 — PascalCase 형식 import 지원
FortiGateParser = FortigateParser
