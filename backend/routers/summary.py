"""GET /api/summary/{upload_id} — 자연어 분석 요약."""
import logging

from fastapi import APIRouter, Header, HTTPException, Request
from fastapi.responses import JSONResponse

from services.narrative.summary_builder import build_summary
from utils.constants import UUID_V4_RE
from utils.capture_auth import check_capture_token

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/api/summary/{upload_id}")
async def get_summary(
    upload_id: str,
    request: Request,
    x_upload_token: str | None = Header(None, alias="X-Upload-Token"),
):
    if not UUID_V4_RE.match(upload_id):
        raise HTTPException(status_code=400, detail={"code": "invalid_uuid", "msg": "upload_id must be UUID v4"})

    store = request.app.state.session_store
    try:
        capture = store.get(upload_id)
    except KeyError:
        raise HTTPException(status_code=404, detail={"code": "upload_not_found", "message": "업로드 파일 없음 — 분석을 먼저 실행하세요"})

    check_capture_token(capture, x_upload_token)
    attacks = capture.attacks

    sessions = capture.sessions

    result = build_summary(attacks, sessions)

    logger.info(
        "요약 생성: upload_id=%s risk=%s attacks=%d",
        upload_id, result.risk_level, len(attacks)
    )

    return JSONResponse({
        "headline": result.headline,
        "narrative": result.narrative,
        "risk_level": result.risk_level,
        "attacker_ips": result.attacker_ips,
        "victim_ips": result.victim_ips,
        "recommendations": result.recommendations,
        "attack_timeline": result.attack_timeline,
        "attack_explanations": result.attack_explanations,
    })
