"""GET /api/export/{upload_id} + POST /api/export/{upload_id}/pdf — 데이터 내보내기."""
import logging
import re

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, Response

logger = logging.getLogger(__name__)

from services.export.state_exporter import StateExporter
from services.report.pdf_exporter import PdfExporter

router = APIRouter()

_exporter = StateExporter()
_pdf_exporter = PdfExporter()

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
)


def _validate_upload_id(upload_id: str) -> None:
    if not _UUID_RE.match(upload_id):
        raise HTTPException(status_code=400, detail={"code": "invalid_uuid", "msg": "upload_id must be a valid UUID"})


@router.get("/api/export/{upload_id}")
async def export_json(upload_id: str, request: Request):
    _validate_upload_id(upload_id)
    logger.info("JSON 내보내기 요청: upload_id=%s", upload_id)
    store = request.app.state.session_store
    try:
        capture = store.get(upload_id)
    except KeyError:
        logger.warning("upload_id 없음: %s", upload_id)
        raise HTTPException(status_code=404, detail="upload_id를 찾을 수 없습니다")

    annotations = list(request.app.state.annotations_store.get(upload_id, []))
    data = _exporter.export(capture.sessions, annotations=annotations)
    return JSONResponse(data)


@router.post("/api/export/{upload_id}/pdf")
async def export_pdf(upload_id: str, request: Request):
    _validate_upload_id(upload_id)
    logger.info("PDF 내보내기 요청: upload_id=%s", upload_id)
    store = request.app.state.session_store
    try:
        capture = store.get(upload_id)
    except KeyError:
        logger.warning("upload_id 없음: %s", upload_id)
        raise HTTPException(status_code=404, detail="upload_id를 찾을 수 없습니다")

    analysis_result = {
        "target_ip": capture.target_ip or "unknown",
        "sessions": capture.sessions,
        "attacks": capture.attacks,
        "summary": {
            "total_sessions": len(capture.sessions),
            "total_bytes": sum(s.bytes_sent + s.bytes_recv for s in capture.sessions),
        },
    }

    pdf_path = _pdf_exporter.generate(analysis_result)
    pdf_bytes = pdf_path.read_bytes()
    pdf_path.unlink(missing_ok=True)

    safe_suffix = re.sub(r"[^a-f0-9]", "", upload_id.lower())[:8]
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="report_{safe_suffix}.pdf"'},
    )
