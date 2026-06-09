"""GET /api/health/{upload_id} — 통신 상태 진단."""
import logging

from fastapi import APIRouter, HTTPException, Request

from services.analytics import network_health
from utils.constants import UUID_RE

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/api/health/{upload_id}")
async def get_network_health(upload_id: str, request: Request):
    if not UUID_RE.match(upload_id):
        raise HTTPException(
            status_code=400,
            detail={"code": "invalid_uuid", "msg": "upload_id must be a valid UUID"},
        )
    try:
        capture = request.app.state.session_store.get(upload_id)
    except KeyError:
        raise HTTPException(status_code=404, detail={"code": "upload_not_found", "message": "업로드 파일 없음"})

    logger.info("통신 상태 진단 요청: upload_id=%s, sessions=%d icmp_events=%d",
                upload_id, len(capture.sessions), len(capture.icmp_events))
    return network_health.analyze(capture.sessions, capture.packet_map, capture.icmp_events)
