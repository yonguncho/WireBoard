"""POST /api/compare — 두 pcap 세션 비교 분석."""
import logging
import re

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

logger = logging.getLogger(__name__)

from services.analytics.pcap_comparator import PcapComparator

UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
)

router = APIRouter()
_comparator = PcapComparator()


class CompareRequest(BaseModel):
    base_upload_id: str
    current_upload_id: str


def _extract_ports(sessions) -> set[int]:
    ports: set[int] = set()
    for s in sessions:
        ports.add(s.dst_port)
    return ports


@router.post("/api/compare")
async def compare_captures(body: CompareRequest, request: Request):
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
        raise HTTPException(status_code=404, detail="base_upload_id를 찾을 수 없습니다")
    try:
        current_capture = store.get(body.current_upload_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="current_upload_id를 찾을 수 없습니다")

    result = _comparator.compare(base_capture.sessions, current_capture.sessions)

    base_ports = _extract_ports(base_capture.sessions)
    cur_ports = _extract_ports(current_capture.sessions)
    new_ports = sorted(cur_ports - base_ports)

    a_total = result.byte_ratio.get("a_total", 0)
    b_total = result.byte_ratio.get("b_total", 0)
    if a_total > 0:
        traffic_delta_pct = round((b_total - a_total) / a_total * 100.0, 2)
    else:
        traffic_delta_pct = 0.0

    return {
        "new_ips": sorted(result.only_in_b),
        "removed_ips": sorted(result.only_in_a),
        "common_ips": sorted(result.common_ips),
        "new_ports": new_ports,
        "traffic_delta_pct": traffic_delta_pct,
        "protocol_diff": result.protocol_diff,
        "byte_ratio": result.byte_ratio,
    }
