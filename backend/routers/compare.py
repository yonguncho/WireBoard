"""POST /api/compare — 두 pcap 세션 비교 분석."""
import logging

from fastapi import APIRouter, Header, HTTPException, Request
from pydantic import BaseModel

logger = logging.getLogger(__name__)

from services.analytics.pcap_comparator import PcapComparator
from utils.constants import UUID_RE
from utils.capture_auth import check_capture_token

router = APIRouter()
_comparator = PcapComparator()

_MAX_SESSIONS = 300  # 응답에 포함할 최대 세션 수 (각 캡처별)


class CompareRequest(BaseModel):
    base_upload_id: str
    current_upload_id: str


def _extract_ports(sessions) -> set[int]:
    ports: set[int] = set()
    for s in sessions:
        ports.add(s.dst_port)
    return ports


def _serialize_session(s) -> dict:
    return {
        "session_id": s.session_id,
        "src_ip":     s.src_ip,
        "dst_ip":     s.dst_ip,
        "src_port":   s.src_port,
        "dst_port":   s.dst_port,
        "protocol":   s.protocol,
        "start_ts":   s.start_ts,
        "end_ts":     s.end_ts,
        "bytes_sent": s.bytes_sent,
        "bytes_recv": s.bytes_recv,
        "packet_count": s.packet_count,
        "rst":        s.rst,
    }


@router.post("/api/compare")
async def compare_captures(
    body: CompareRequest,
    request: Request,
    x_upload_token_base: str | None = Header(None, alias="X-Upload-Token-Base"),
    x_upload_token_current: str | None = Header(None, alias="X-Upload-Token-Current"),
):
    if not UUID_RE.match(body.base_upload_id):
        raise HTTPException(
            status_code=400,
            detail={"code": "invalid_uuid", "msg": "base_upload_id must be a valid UUID"},
        )
    if not UUID_RE.match(body.current_upload_id):
        raise HTTPException(
            status_code=400,
            detail={"code": "invalid_uuid", "msg": "current_upload_id must be a valid UUID"},
        )
    logger.info(
        "비교 요청: base=%s current=%s",
        body.base_upload_id,
        body.current_upload_id,
    )
    store = request.app.state.session_store
    try:
        base_capture = store.get(body.base_upload_id)
    except KeyError:
        raise HTTPException(status_code=404, detail={"code": "upload_not_found", "message": "업로드 파일 없음 (base)"})
    check_capture_token(base_capture, x_upload_token_base)
    try:
        current_capture = store.get(body.current_upload_id)
    except KeyError:
        raise HTTPException(status_code=404, detail={"code": "upload_not_found", "message": "업로드 파일 없음 (current)"})
    check_capture_token(current_capture, x_upload_token_current)

    result = _comparator.compare(base_capture.sessions, current_capture.sessions)

    base_ports = _extract_ports(base_capture.sessions)
    cur_ports = _extract_ports(current_capture.sessions)
    new_ports = sorted(cur_ports - base_ports)

    a_total = result.byte_ratio.get("a_total", 0)
    b_total = result.byte_ratio.get("b_total", 0)
    if a_total > 0:
        traffic_delta_pct = round((b_total - a_total) / a_total * 100.0, 2)
    elif b_total > 0:
        traffic_delta_pct = None  # base가 비어있어 의미있는 % 계산 불가
    else:
        traffic_delta_pct = 0.0  # 양쪽 모두 트래픽 없음

    base_sorted = sorted(base_capture.sessions, key=lambda s: s.start_ts)
    cur_sorted  = sorted(current_capture.sessions, key=lambda s: s.start_ts)

    return {
        "new_ips":           sorted(result.only_in_b),
        "removed_ips":       sorted(result.only_in_a),
        "common_ips":        sorted(result.common_ips),
        "new_ports":         new_ports,
        "traffic_delta_pct": traffic_delta_pct,
        "protocol_diff":     result.protocol_diff,
        "byte_ratio":        result.byte_ratio,
        "base_sessions":     [_serialize_session(s) for s in base_sorted[:_MAX_SESSIONS]],
        "compare_sessions":  [_serialize_session(s) for s in cur_sorted[:_MAX_SESSIONS]],
        "base_session_total":    len(base_capture.sessions),
        "compare_session_total": len(current_capture.sessions),
    }
