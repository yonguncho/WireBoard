"""TcpdumpParser — tcpdump -tt 텍스트 출력 파서 (IPv4/IPv6 지원)."""
import ipaddress
import logging
import re
import time as _time
import uuid

from models.session import SessionModel

logger = logging.getLogger(__name__)

# 타임스탬프 그룹 (named): Unix float 또는 HH:MM:SS.ffffff
# IP/IP6 양쪽 허용
# 주소+포트: IPv4 `x.x.x.x.port` 또는 IPv6 `xxxx::xx.port`
_LINE_RE = re.compile(
    r"^(?P<ts>\d{2}:\d{2}:\d{2}\.\d+|\d+\.\d+)\s+IP6?\s+"
    r"(?P<src_addr>(?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]+)\.(?P<src_port>\d+)"
    r"\s+>\s+"
    r"(?P<dst_addr>(?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]+)\.(?P<dst_port>\d+):\s+"
    r"(?:Flags\s+\[(?P<flags>[A-Za-z.]+)\]|(?P<proto>\w+))"
)

_HH_RE = re.compile(r"^\d{2}:\d{2}:\d{2}\.\d+$")


def _parse_ts(ts_str: str) -> float:
    """Unix float 타임스탬프는 그대로 반환, HH:MM:SS 형식은 현재 시각 사용."""
    if _HH_RE.match(ts_str):
        return _time.time()
    try:
        return float(ts_str)
    except ValueError:
        return _time.time()


class TcpdumpParser:
    def detect(self, data: bytes) -> bool:
        try:
            text = data.decode("utf-8", errors="replace")
        except UnicodeDecodeError:
            return False
        for line in text.splitlines()[:10]:
            if _LINE_RE.match(line.strip()):
                return True
        return False

    def parse(self, data: bytes, parse_warnings: list[str] | None = None) -> list[SessionModel]:
        try:
            text = data.decode("utf-8", errors="replace")
        except UnicodeDecodeError as exc:
            raise ValueError(f"UTF-8 디코딩 실패: {exc}") from exc

        sessions: list[SessionModel] = []
        for line in text.splitlines():
            m = _LINE_RE.match(line.strip())
            if not m:
                continue

            src_addr = m.group("src_addr")
            dst_addr = m.group("dst_addr")
            src_port_str = m.group("src_port")
            dst_port_str = m.group("dst_port")
            flags_token = m.group("flags")
            proto_token = m.group("proto")
            ts_str = m.group("ts")

            src_port = int(src_port_str)
            dst_port = int(dst_port_str)
            if not (0 <= src_port <= 65535 and 0 <= dst_port <= 65535):
                continue

            try:
                ipaddress.ip_address(src_addr)
                ipaddress.ip_address(dst_addr)
            except ValueError:
                continue

            if flags_token is not None:
                protocol = "TCP"
                is_rst = "R" in flags_token
            else:
                proto_upper = (proto_token or "").upper()
                if proto_upper == "UDP":
                    protocol = "UDP"
                elif proto_upper in ("ICMP", "ICMP6", "ARP"):
                    protocol = proto_upper
                else:
                    protocol = "TCP"
                is_rst = False

            ts_val = _parse_ts(ts_str)

            sessions.append(SessionModel(
                session_id=str(uuid.uuid4()),
                src_ip=src_addr,
                dst_ip=dst_addr,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                start_ts=ts_val,
                end_ts=ts_val,
                bytes_sent=0,
                bytes_recv=0,
                packet_count=1,
                payload_length=0,
                confidence="normal",
                rst=is_rst,
            ))

        return sessions
