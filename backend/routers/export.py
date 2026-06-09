"""GET /api/export/{upload_id} + POST /api/export/{upload_id}/pdf + GET /api/export/{upload_id}/ioc — 데이터 내보내기."""
import csv
import io
import logging
import re
from typing import List, Optional

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel

logger = logging.getLogger(__name__)

from services.export.state_exporter import StateExporter
from services.export_service import ExportService
from services.report.pdf_exporter import PdfExporter
from models.attack import AttackDetectionResult
from models.session import SessionModel
from utils.constants import UUID_RE

router = APIRouter()

_exporter = StateExporter()
_pdf_exporter = PdfExporter()
_export_svc = ExportService()

_FORMAT_CONTENT_TYPE = {
    "csv": "text/csv; charset=utf-8",
    "json": "application/json",
    "suricata": "text/plain; charset=utf-8",
    "snort": "text/plain; charset=utf-8",
    "excel": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "pdf": "application/pdf",
}


class ExportRequest(BaseModel):
    upload_id: str
    target_ip: Optional[str] = None
    format: str = "json"


@router.post("/api/export")
async def export_flexible(body: ExportRequest, request: Request):
    if not UUID_RE.match(body.upload_id):
        raise HTTPException(status_code=400, detail={"code": "invalid_uuid", "msg": "upload_id must be a valid UUID"})

    store = request.app.state.session_store
    try:
        capture = store.get(body.upload_id)
    except KeyError:
        raise HTTPException(status_code=404, detail={"code": "upload_not_found", "message": "업로드 파일 없음"})

    sessions: List[SessionModel] = capture.sessions
    if body.target_ip:
        sessions = [s for s in sessions if s.src_ip == body.target_ip or s.dst_ip == body.target_ip]

    attacks: List[AttackDetectionResult] = []
    for a in capture.attacks:
        if isinstance(a, dict):
            try:
                attacks.append(AttackDetectionResult(**a))
            except Exception:
                pass
        elif isinstance(a, AttackDetectionResult):
            attacks.append(a)

    fmt = body.format.lower()
    try:
        data = _export_svc.export(sessions, attacks, fmt)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    content_type = _FORMAT_CONTENT_TYPE.get(fmt, "application/octet-stream")
    safe_id = re.sub(r"[^a-f0-9]", "", body.upload_id.lower())[:8]
    ext = fmt if fmt not in ("suricata", "snort") else "rules"
    headers = {"Content-Disposition": f'attachment; filename="export_{safe_id}.{ext}"'}
    return Response(content=data, media_type=content_type, headers=headers)


def _validate_upload_id(upload_id: str) -> None:
    if not UUID_RE.match(upload_id):
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
        raise HTTPException(status_code=404, detail={"code": "upload_not_found", "message": "업로드 파일 없음"})

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
        raise HTTPException(status_code=404, detail={"code": "upload_not_found", "message": "업로드 파일 없음"})

    annotations = list(request.app.state.annotations_store.get(upload_id, []))
    analysis_result = {
        "target_ip": capture.target_ip or "unknown",
        "sessions": capture.sessions,
        "attacks": capture.attacks,
        "annotations": annotations,
        "summary": {
            "total_sessions": len(capture.sessions),
            "total_bytes": sum(s.bytes_sent + s.bytes_recv for s in capture.sessions),
        },
    }

    pdf_path, pdf_truncated = _pdf_exporter.generate(analysis_result)
    try:
        pdf_bytes = pdf_path.read_bytes()
    except OSError as exc:
        logger.error("PDF 읽기 실패: %s", exc)
        pdf_path.unlink(missing_ok=True)
        raise HTTPException(status_code=500, detail="PDF 파일 읽기 실패")
    finally:
        pdf_path.unlink(missing_ok=True)

    safe_suffix = re.sub(r"[^a-f0-9]", "", upload_id.lower())[:8]
    headers = {"Content-Disposition": f'attachment; filename="report_{safe_suffix}.pdf"'}
    if pdf_truncated:
        headers["X-Truncated"] = "true"
    return Response(content=pdf_bytes, media_type="application/pdf", headers=headers)


@router.get("/api/export/{upload_id}/ioc")
async def export_ioc(upload_id: str, request: Request):
    _validate_upload_id(upload_id)
    logger.info("IOC 내보내기 요청: upload_id=%s", upload_id)
    store = request.app.state.session_store
    try:
        capture = store.get(upload_id)
    except KeyError:
        logger.warning("upload_id 없음: %s", upload_id)
        raise HTTPException(status_code=404, detail={"code": "upload_not_found", "message": "업로드 파일 없음"})

    # attacker_ips 수집: 각 attack dict의 src_ip 필드 (비어 있지 않은 것만)
    seen_ips: dict[str, str] = {}  # ip -> attack_type
    for attack in capture.attacks:
        src_ip = attack.get("src_ip", "")
        if src_ip and src_ip not in seen_ips:
            seen_ips[src_ip] = attack.get("attack_type", "Unknown")

    # 도메인 수집: session.meta의 sni / dns_query / host 필드
    seen_domains: dict[str, str] = {}  # domain -> attack_type (출처 표시용)
    for session in capture.sessions:
        meta = session.meta or {}
        domain = meta.get("sni") or meta.get("dns_query") or meta.get("host") or ""
        if domain and domain not in seen_domains:
            seen_domains[domain] = "Beacon"

    # CSV 생성
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["type", "value", "source"])
    for ip, attack_type in seen_ips.items():
        writer.writerow(["ip", ip, attack_type])
    for domain, source in seen_domains.items():
        writer.writerow(["domain", domain, source])

    csv_bytes = buf.getvalue().encode("utf-8")
    safe_suffix = re.sub(r"[^a-f0-9]", "", upload_id.lower())[:8]
    headers = {
        "Content-Disposition": f'attachment; filename="ioc_{safe_suffix}.csv"',
    }
    return Response(content=csv_bytes, media_type="text/csv", headers=headers)
