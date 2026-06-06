"""POST /api/annotations + GET /api/annotations/{upload_id} — 어노테이션 관리."""
import math

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field, model_validator

from utils.constants import UUID_RE

router = APIRouter()


class AnnotationCreate(BaseModel):
    upload_id: str
    start_ts: float
    end_ts: float
    comment: str = Field(..., max_length=2000)

    @model_validator(mode="after")
    def validate_ts(self) -> "AnnotationCreate":
        if not math.isfinite(self.start_ts) or self.start_ts < 0:
            raise ValueError("start_ts must be finite and non-negative")
        if not math.isfinite(self.end_ts) or self.end_ts < self.start_ts:
            raise ValueError("end_ts must be finite and >= start_ts")
        return self


@router.post("/api/annotations", status_code=201)
async def create_annotation(body: AnnotationCreate, request: Request):
    if not UUID_RE.match(body.upload_id):
        raise HTTPException(
            status_code=400,
            detail={"code": "invalid_uuid", "msg": "upload_id must be a valid UUID"},
        )
    session_store = request.app.state.session_store
    try:
        session_store.get(body.upload_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="upload_id를 찾을 수 없습니다")

    annotation = body.model_dump()
    request.app.state.annotations_store[body.upload_id].append(annotation)
    return {"status": "created", "annotation": annotation}


@router.get("/api/annotations/{upload_id}")
async def get_annotations(upload_id: str, request: Request):
    if not UUID_RE.match(upload_id):
        raise HTTPException(status_code=400, detail={"code": "invalid_uuid", "msg": "upload_id must be a valid UUID"})
    try:
        request.app.state.session_store.get(upload_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="upload_id를 찾을 수 없습니다")
    return list(request.app.state.annotations_store.get(upload_id, []))
