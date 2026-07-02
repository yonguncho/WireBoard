"""GET /api/summary/{upload_id} — 자연어 분석 요약."""
import asyncio
import logging

from fastapi import APIRouter, Header, HTTPException, Request
from fastapi.responses import JSONResponse

from services.narrative.capture_summary import summarize_capture
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
        raise HTTPException(status_code=404, detail={"code": "upload_not_found", "message": "Upload not found — run analysis first"})

    check_capture_token(capture, x_upload_token)

    # Network-health + narrative — pure-CPU work; keep it off the event loop.
    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(None, summarize_capture, capture)

    logger.info(
        "요약 생성: upload_id=%s risk=%s score=%d attacks=%d",
        upload_id, result.risk_level, result.risk_score, len(capture.attacks)
    )

    return JSONResponse({
        "headline": result.headline,
        "narrative": result.narrative,
        "risk_level": result.risk_level,
        "risk_score": result.risk_score,
        "risk_factors": result.risk_factors,
        "diagnosis": result.diagnosis,
        "key_findings": result.key_findings,
        "health_overview": result.health_overview,
        "attacker_ips": result.attacker_ips,
        "victim_ips": result.victim_ips,
        "recommendations": result.recommendations,
        "attack_timeline": result.attack_timeline,
        "attack_explanations": result.attack_explanations,
    })
