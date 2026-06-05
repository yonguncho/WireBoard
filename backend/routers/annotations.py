"""POST /api/annotations + GET /api/annotations/{upload_id} — 어노테이션 관리."""
from collections import defaultdict

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

router = APIRouter()

_store: dict[str, list[dict]] = defaultdict(list)


class AnnotationCreate(BaseModel):
    upload_id: str
    ts: float
    text: str
    type: str = "marker"


@router.post("/api/annotations", status_code=201)
async def create_annotation(body: AnnotationCreate, request: Request):
    session_store = request.app.state.session_store
    try:
        session_store.get(body.upload_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="upload_id를 찾을 수 없습니다")

    annotation = body.model_dump()
    _store[body.upload_id].append(annotation)
    return {"status": "created", "annotation": annotation}


@router.get("/api/annotations/{upload_id}")
async def get_annotations(upload_id: str):
    return _store.get(upload_id, [])
