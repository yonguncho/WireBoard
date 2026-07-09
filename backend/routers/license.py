"""GET /api/license/status + POST /api/license/activate — 라이선스 상태/활성화.

게이팅은 하지 않는다(상태 보고 + 활성화 저장만). 실제 제한은 licensing.should_gate()
를 참조하는 각 기능에서 적용하며, 기본(enforce off)에서는 아무것도 막지 않는다.
"""
import logging
import os
from pathlib import Path

from fastapi import APIRouter, Request
from pydantic import BaseModel

logger = logging.getLogger(__name__)

from services import licensing

router = APIRouter()


@router.get("/api/license/status")
async def license_status():
    return licensing.get_status()


class ActivateRequest(BaseModel):
    license: str


@router.post("/api/license/activate")
async def license_activate(body: ActivateRequest):
    token = (body.license or "").strip()
    if not token:
        return {"ok": False, "reason": "empty"}
    # 검증
    if token.startswith("WB1."):
        v = licensing.verify_offline(token)
    else:
        v = licensing.verify_online(token)
    if not v.get("valid"):
        return {"ok": False, "reason": v.get("reason", "invalid")}
    # license.dat 에 저장(실행파일 디렉터리 우선)
    import sys
    if getattr(sys, "frozen", False):
        target = Path(os.path.dirname(sys.executable)) / "license.dat"
    else:
        target = Path.cwd() / "license.dat"
    try:
        target.write_text(token, encoding="utf-8")
    except OSError as exc:
        logger.warning("license.dat 저장 실패: %s", exc)
        return {"ok": False, "reason": f"save_failed:{exc}"}
    # 환경변수에도 반영(현재 프로세스 즉시 반영)
    os.environ["WIREBOARD_LICENSE"] = token
    return {"ok": True, "status": licensing.get_status()}
