"""POST /api/filter, /api/filter/translate — 자연어 쿼리로 세션 필터링."""
import re
import logging

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

logger = logging.getLogger(__name__)

from services.filter_translator import FilterTranslator, UUID_RE

router = APIRouter()
_translator = FilterTranslator()

# Application-layer protocol tokens (meta 필드로 감지되는 프로토콜)
_APP_PROTO_TOKENS = frozenset({
    "http", "https", "tls", "ssl", "dns", "mdns",
    "smtp", "imap", "pop3", "ftp", "sftp", "ssh", "telnet", "snmp", "ntp", "dhcp",
    "tftp", "sip", "rtp", "smb", "cifs", "netbios", "ldap", "ldaps",
    "kerberos", "radius", "rdp", "vnc", "mysql", "mssql", "postgresql",
    "redis", "mongodb", "grpc", "thrift", "quic", "websocket", "ws", "wss",
    "http2", "h2",
})

# 모든 알려진 프로토콜 토큰
_ALL_PROTO_TOKENS = frozenset({
    "tcp", "udp", "icmp", "arp",
}) | _APP_PROTO_TOKENS


def _matches_protocol(session, token: str) -> bool:
    """Return True if session matches the protocol token.

    For transport-layer tokens (tcp, udp, icmp, arp) compare session.protocol.
    For application-layer tokens check session.protocol first, then session.meta
    so HAR sessions (protocol=TCP, meta.status_code set) match "http".
    """
    proto_lower = session.protocol.lower()
    if proto_lower == token:
        return True
    if token not in _APP_PROTO_TOKENS:
        return False
    meta = session.meta or {}
    if token in ("http", "https"):
        return meta.get("status_code") is not None
    if token == "tls":
        return bool(meta.get("tls_sni"))
    if token == "dns":
        return bool(meta.get("dns_query"))
    return False


class FilterRequest(BaseModel):
    upload_id: str
    query: str


def _session_matches(session, filter_expr: str, translator_tokens: list[str]) -> bool:
    for token in translator_tokens:
        if token == "frame":
            continue
        if token.startswith("ip.src =="):
            ip = token.split("==")[1].strip()
            if session.src_ip != ip:
                return False
        elif token.startswith("ip.dst =="):
            ip = token.split("==")[1].strip()
            if session.dst_ip != ip:
                return False
        elif token.startswith("(ip.src =="):
            m = re.search(r"ip\.src == (\S+) or ip\.dst == (\S+)", token)
            if m:
                ip = m.group(1).rstrip(")")
                if session.src_ip != ip and session.dst_ip != ip:
                    return False
        elif "tcp.port ==" in token or "udp.port ==" in token:
            m = re.search(r"== (\d+)", token)
            if m:
                port = int(m.group(1))
                if session.src_port != port and session.dst_port != port:
                    return False
        elif token in _ALL_PROTO_TOKENS:
            if not _matches_protocol(session, token):
                return False
    return True


async def _do_filter(body: FilterRequest, request: Request) -> dict:
    if not UUID_RE.match(body.upload_id):
        raise HTTPException(
            status_code=400,
            detail={"code": "invalid_uuid", "msg": "upload_id must be a valid UUID"},
        )
    logger.info("필터 요청: upload_id=%s query=%s", body.upload_id, body.query)
    store = request.app.state.session_store
    try:
        capture = store.get(body.upload_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="upload_id를 찾을 수 없습니다")

    try:
        result = _translator.translate(body.query)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail={"code": "invalid_filter", "msg": str(exc)})

    success = bool(result.tokens) and result.tokens != ["frame"]
    matched = [
        s for s in capture.sessions
        if _session_matches(s, result.filter_expr, result.tokens)
    ] if success else []

    return {
        "success": success,
        "filter_expr": result.filter_expr,
        "matched_count": len(matched),
        "sessions": [
            {
                "session_id": s.session_id,
                "src_ip": s.src_ip,
                "dst_ip": s.dst_ip,
                "src_port": s.src_port,
                "dst_port": s.dst_port,
                "protocol": s.protocol,
                "bytes_sent": s.bytes_sent,
                "bytes_recv": s.bytes_recv,
                "packet_count": s.packet_count,
            }
            for s in matched[:200]
        ],
    }


@router.post("/api/filter/translate")
async def filter_sessions_translate(body: FilterRequest, request: Request):
    return await _do_filter(body, request)


@router.post("/api/filter")
async def filter_sessions(body: FilterRequest, request: Request):
    return await _do_filter(body, request)
