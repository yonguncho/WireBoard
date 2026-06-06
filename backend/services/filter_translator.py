"""FilterTranslator — 자연어 쿼리를 wireshark 스타일 필터 표현식으로 변환."""
import re
from dataclasses import dataclass, field

_PROTOCOL_KEYWORDS: dict[str, str] = {
    # 전송 계층
    "tcp": "tcp",
    "udp": "udp",
    "icmp": "icmp",
    "arp": "arp",
    # 애플리케이션 계층 — 웹
    "http": "http",
    "https": "tls",
    "http2": "tls",
    "h2": "tls",
    "quic": "quic",
    "websocket": "http",
    "ws": "http",
    "wss": "tls",
    # 보안/암호화
    "tls": "tls",
    "ssl": "tls",
    # 이메일
    "smtp": "smtp",
    "imap": "imap",
    "pop3": "pop3",
    # 파일/원격
    "ftp": "ftp",
    "sftp": "ssh",
    "ssh": "ssh",
    "telnet": "telnet",
    "rdp": "rdp",
    "vnc": "vnc",
    # 디렉터리/인증
    "ldap": "ldap",
    "ldaps": "ldap",
    "kerberos": "kerberos",
    "radius": "radius",
    # 네트워크 서비스
    "dns": "dns",
    "mdns": "dns",
    "snmp": "snmp",
    "ntp": "ntp",
    "dhcp": "dhcp",
    "tftp": "tftp",
    "sip": "sip",
    "rtp": "rtp",
    # 파일 공유
    "smb": "smb",
    "cifs": "smb",
    "netbios": "nbns",
    # 데이터베이스
    "mysql": "mysql",
    "mssql": "tcp",
    "postgresql": "tcp",
    "redis": "tcp",
    "mongodb": "tcp",
    # API/마이크로서비스
    "grpc": "tls",
    "thrift": "tcp",
}

# 키워드별 word-boundary 패턴 사전 컴파일 (sftp/tftp가 ftp를 포함하는 문제 방지)
_PROTOCOL_RE: dict[str, re.Pattern] = {
    kw: re.compile(r"\b" + re.escape(kw) + r"\b", re.IGNORECASE)
    for kw in _PROTOCOL_KEYWORDS
}

_IPv4_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
_PORT_PATTERN = re.compile(r"\b(?:port|포트)\s*[=:\s]?\s*(\d{1,5})\b", re.IGNORECASE)
_PORT_BARE = re.compile(r"\b(\d{1,5})\s*(?:번?\s*포트|번?\s*port)\b", re.IGNORECASE)
_SRC_KEYWORDS = re.compile(r"(?:from|src|source|출발|에서|보낸)", re.IGNORECASE)
_DST_KEYWORDS = re.compile(r"(?:to|dst|dest|destination|목적지|도착|에게|로\s*가는)", re.IGNORECASE)


@dataclass
class FilterResult:
    filter_expr: str
    tokens: list[str] = field(default_factory=list)


def _extract_ips(query: str) -> list[str]:
    return _IPv4_PATTERN.findall(query)


def _extract_ports(query: str) -> list[str]:
    ports: list[str] = []
    ports += _PORT_PATTERN.findall(query)
    ports += _PORT_BARE.findall(query)
    return list(dict.fromkeys(ports))


def _extract_protocols(query: str) -> list[str]:
    found = []
    for kw, expr in _PROTOCOL_KEYWORDS.items():
        if _PROTOCOL_RE[kw].search(query):
            found.append(expr)
    return list(dict.fromkeys(found))


def _classify_ip_direction(query: str, ip: str) -> str:
    before = query[: query.find(ip)]
    if _SRC_KEYWORDS.search(before):
        return f"ip.src == {ip}"
    if _DST_KEYWORDS.search(before):
        return f"ip.dst == {ip}"
    return f"(ip.src == {ip} or ip.dst == {ip})"


class FilterTranslator:
    def translate(self, query: str) -> FilterResult:
        tokens: list[str] = []

        for ip in _extract_ips(query):
            tokens.append(_classify_ip_direction(query, ip))

        for proto in _extract_protocols(query):
            tokens.append(proto)

        for port in _extract_ports(query):
            tokens.append(f"tcp.port == {port} or udp.port == {port}")

        if not tokens:
            tokens.append("frame")

        expr = " and ".join(f"({t})" if " or " in t else t for t in tokens)
        return FilterResult(filter_expr=expr, tokens=tokens)
