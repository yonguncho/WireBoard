"""GET /api/export/{upload_id} + POST /api/export/{upload_id}/pdf + GET /api/export/{upload_id}/ioc — 데이터 내보내기."""
import csv
import io
import logging
import re

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, Response

logger = logging.getLogger(__name__)

from services.export.state_exporter import StateExporter
from services.report.pdf_exporter import PdfExporter
from utils.constants import UUID_RE

router = APIRouter()

_exporter = StateExporter()
_pdf_exporter = PdfExporter()


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
        raise HTTPException(status_code=404, detail="upload_id를 찾을 수 없습니다")

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
