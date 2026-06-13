"""POST /api/annotations + GET /api/annotations/{upload_id} — 어노테이션 관리."""
import math

from fastapi import APIRouter, Header, HTTPException, Request
from pydantic import BaseModel, Field, model_validator

from utils.constants import UUID_RE
from utils.capture_auth import check_capture_token

router = APIRouter()

_MAX_ANNOTATIONS_PER_UPLOAD = 200


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
async def create_annotation(
    body: AnnotationCreate,
    request: Request,
    x_upload_token: str | None = Header(None, alias="X-Upload-Token"),
):
    if not UUID_RE.match(body.upload_id):
        raise HTTPException(
            status_code=400,
            detail={"code": "invalid_uuid", "msg": "upload_id must be a valid UUID"},
        )
    session_store = request.app.state.session_store
    try:
        capture = session_store.get(body.upload_id)
    except KeyError:
        raise HTTPException(status_code=404, detail={"code": "upload_not_found", "message": "업로드 파일 없음"})

    check_capture_token(capture, x_upload_token)
    ann_list = request.app.state.annotations_store[body.upload_id]
    if len(ann_list) >= _MAX_ANNOTATIONS_PER_UPLOAD:
        raise HTTPException(
            status_code=429,
            detail={"code": "annotation_limit_exceeded", "msg": f"upload당 최대 {_MAX_ANNOTATIONS_PER_UPLOAD}개 어노테이션 허용"},
        )
    annotation = body.model_dump()
    ann_list.append(annotation)
    return {"status": "created", "annotation": annotation}


@router.get("/api/annotations/{upload_id}")
async def get_annotations(
    upload_id: str,
    request: Request,
    x_upload_token: str | None = Header(None, alias="X-Upload-Token"),
):
    if not UUID_RE.match(upload_id):
        raise HTTPException(status_code=400, detail={"code": "invalid_uuid", "msg": "upload_id must be a valid UUID"})
    try:
        capture = request.app.state.session_store.get(upload_id)
    except KeyError:
        raise HTTPException(status_code=404, detail={"code": "upload_not_found", "message": "업로드 파일 없음"})
    check_capture_token(capture, x_upload_token)
    return list(request.app.state.annotations_store.get(upload_id, []))
