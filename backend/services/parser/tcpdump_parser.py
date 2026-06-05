"""TcpdumpParser — tcpdump -tt 텍스트 출력 파서 (기본 구현)."""
import ipaddress
import logging
import re
import uuid

from models.session import SessionModel

logger = logging.getLogger(__name__)

# Flags [XYZ] (TCP) 또는 proto token (UDP/ICMP) 양쪽 모두 매칭
_LINE_RE = re.compile(
    r"^(\d+\.\d+)\s+IP\s+([\d.]+)\.(\d+)\s+>\s+([\d.]+)\.(\d+):\s+"
    r"(?:Flags\s+\[([A-Za-z.]+)\]|(\w+))"
)


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
            ts, src_ip, src_port_str, dst_ip, dst_port_str, flags_token, proto_token = m.groups()

            src_port = int(src_port_str)
            dst_port = int(dst_port_str)
            if not (0 <= src_port <= 65535 and 0 <= dst_port <= 65535):
                continue

            try:
                if not (isinstance(ipaddress.ip_address(src_ip), ipaddress.IPv4Address) and
                        isinstance(ipaddress.ip_address(dst_ip), ipaddress.IPv4Address)):
                    continue
            except ValueError:
                continue

            # flags_token이 있으면 TCP (Flags [XYZ] 포맷)
            if flags_token is not None:
                protocol = "TCP"
                is_rst = "R" in flags_token
            else:
                protocol = "UDP" if (proto_token or "").upper() == "UDP" else "TCP"
                is_rst = False

            sessions.append(SessionModel(
                session_id=str(uuid.uuid4()),
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                start_ts=float(ts),
                end_ts=float(ts),
                bytes_sent=0,
                bytes_recv=0,
                packet_count=1,
                payload_length=0,
                confidence="normal",
                rst=is_rst,
            ))

        return sessions
