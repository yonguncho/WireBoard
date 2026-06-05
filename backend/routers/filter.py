"""POST /api/filter — 자연어 쿼리로 세션 필터링."""
import re
import logging

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, field_validator

logger = logging.getLogger(__name__)

from services.filter_translator import FilterTranslator, UUID_RE

router = APIRouter()
_translator = FilterTranslator()


class FilterRequest(BaseModel):
    upload_id: str
    query: str

    @field_validator("upload_id")
    @classmethod
    def validate_uuid(cls, v: str) -> str:
        if not UUID_RE.match(v):
            raise ValueError("upload_id must be a valid UUID")
        return v


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
        elif token in ("dns", "http", "tls", "tcp", "udp", "icmp", "arp",
                       "smtp", "ftp", "ssh", "telnet", "snmp", "ntp", "dhcp"):
            if session.protocol.lower() != token:
                return False
    return True


@router.post("/api/filter")
async def filter_sessions(body: FilterRequest, request: Request):
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
    matched = [
        s for s in capture.sessions
        if _session_matches(s, result.filter_expr, result.tokens)
    ]

    return {
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
