"""GET /api/geoip/{upload_id} — GeoIP 분석 결과."""
import logging
from fastapi import APIRouter, HTTPException, Request
from utils.constants import UUID_RE

logger = logging.getLogger(__name__)
router = APIRouter()


def _validate(upload_id: str) -> None:
    if not UUID_RE.match(upload_id):
        raise HTTPException(status_code=400, detail={"code": "invalid_uuid", "msg": "upload_id must be a valid UUID"})


@router.get("/api/geoip/{upload_id}")
async def get_geoip(upload_id: str, request: Request):
    _validate(upload_id)
    store = request.app.state.session_store
    try:
        capture = store.get(upload_id)
    except KeyError:
        raise HTTPException(status_code=404, detail={"code": "upload_not_found", "message": "업로드 파일 없음"})

    analyzer = request.app.state.geoip_analyzer
    results = analyzer.analyze(capture.sessions, capture.attacks)
    return {"entries": results}
