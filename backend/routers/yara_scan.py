"""GET /api/yara/{upload_id} — YARA 서명 탐지 결과."""
import logging
from fastapi import APIRouter, Header, HTTPException, Request
from utils.constants import UUID_RE
from utils.capture_auth import check_capture_token

logger = logging.getLogger(__name__)
router = APIRouter()


def _validate(upload_id: str) -> None:
    if not UUID_RE.match(upload_id):
        raise HTTPException(status_code=400, detail={"code": "invalid_uuid", "msg": "upload_id must be a valid UUID"})


@router.get("/api/yara/{upload_id}")
async def get_yara(
    upload_id: str,
    request: Request,
    x_upload_token: str | None = Header(None, alias="X-Upload-Token"),
):
    _validate(upload_id)
    store = request.app.state.session_store
    try:
        capture = store.get(upload_id)
    except KeyError:
        raise HTTPException(status_code=404, detail={"code": "upload_not_found", "message": "업로드 파일 없음"})

    check_capture_token(capture, x_upload_token)
    detector = request.app.state.yara_detector
    matches = detector.scan_capture(capture)
    return {
        "available": detector.available,
        "match_count": len(matches),
        "matches": matches,
    }
