"""GET /api/yara/{upload_id} — YARA 서명 탐지 결과."""
import logging
from fastapi import APIRouter, HTTPException, Request
from utils.constants import UUID_RE

logger = logging.getLogger(__name__)
router = APIRouter()


def _validate(upload_id: str) -> None:
    if not UUID_RE.match(upload_id):
        raise HTTPException(status_code=400, detail={"code": "invalid_uuid", "msg": "upload_id must be a valid UUID"})


@router.get("/api/yara/{upload_id}")
async def get_yara(upload_id: str, request: Request):
    _validate(upload_id)
    store = request.app.state.session_store
    try:
        capture = store.get(upload_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="upload_id를 찾을 수 없습니다")

    detector = request.app.state.yara_detector
    matches = detector.scan_capture(capture)
    return {
        "available": detector.available,
        "match_count": len(matches),
        "matches": matches,
    }
