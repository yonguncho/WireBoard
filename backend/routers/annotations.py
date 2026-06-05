"""POST /api/annotations + GET /api/annotations/{upload_id} — 어노테이션 관리."""
import re

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

router = APIRouter()

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
)


class AnnotationCreate(BaseModel):
    upload_id: str
    start_ts: float
    end_ts: float
    comment: str


@router.post("/api/annotations", status_code=201)
async def create_annotation(body: AnnotationCreate, request: Request):
    if not _UUID_RE.match(body.upload_id):
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
    if not _UUID_RE.match(upload_id):
        raise HTTPException(status_code=400, detail={"code": "invalid_uuid", "msg": "upload_id must be a valid UUID"})
    try:
        request.app.state.session_store.get(upload_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="upload_id를 찾을 수 없습니다")
    return list(request.app.state.annotations_store.get(upload_id, []))
