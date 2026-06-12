"""GET /api/export/{upload_id} + POST /api/export/{upload_id}/pdf + GET /api/export/{upload_id}/ioc — 데이터 내보내기."""
import csv
import io
import ipaddress
import logging
import re
from typing import List, Optional

from fastapi import APIRouter, Header, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel

logger = logging.getLogger(__name__)

from services.export.state_exporter import StateExporter
from services.export_service import ExportService
from services.report.pdf_exporter import PdfExporter
from models.attack import AttackDetectionResult
from models.session import SessionModel
from utils.constants import UUID_RE
from utils.capture_auth import check_capture_token

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


_ALLOWED_FORMATS = set(_FORMAT_CONTENT_TYPE.keys())


class ExportRequest(BaseModel):
    upload_id: str
    target_ip: Optional[str] = None
    format: str  # required — 기본값 없음


@router.post("/api/export")
async def export_flexible(
    body: ExportRequest,
    request: Request,
    x_upload_token: str | None = Header(None, alias="X-Upload-Token"),
):
    if not UUID_RE.match(body.upload_id):
        raise HTTPException(status_code=400, detail={"code": "invalid_uuid", "msg": "upload_id must be a valid UUID"})

    # format 검증을 store 조회 전에 수행 (422 우선)
    fmt = body.format.lower()
    if fmt not in _ALLOWED_FORMATS:
        raise HTTPException(status_code=422, detail={"code": "invalid_format", "msg": f"지원하지 않는 형식: {body.format!r}"})

    # target_ip 검증
    if body.target_ip:
        try:
            ipaddress.ip_address(body.target_ip)
        except ValueError:
            raise HTTPException(status_code=400, detail={"code": "invalid_ip", "msg": f"유효하지 않은 target_ip: {body.target_ip!r}"})

    store = request.app.state.session_store
    try:
        capture = store.get(body.upload_id)
    except KeyError:
        raise HTTPException(status_code=404, detail={"code": "upload_not_found", "message": "업로드 파일 없음"})

    check_capture_token(capture, x_upload_token)

    sessions: List[SessionModel] = capture.sessions
    if body.target_ip:
        sessions = [s for s in sessions if s.src_ip == body.target_ip or s.dst_ip == body.target_ip]

    attacks: List[AttackDetectionResult] = []
    for a in capture.attacks:
        if isinstance(a, dict):
            try:
                attacks.append(AttackDetectionResult(**a))
            except Exception as exc:
                logger.warning("공격 결과 변환 실패 (silent drop): data=%r error=%s", a, exc)
        elif isinstance(a, AttackDetectionResult):
            attacks.append(a)

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
async def export_json(
    upload_id: str,
    request: Request,
    x_upload_token: str | None = Header(None, alias="X-Upload-Token"),
):
    _validate_upload_id(upload_id)
    logger.info("JSON 내보내기 요청: upload_id=%s", upload_id)
    store = request.app.state.session_store
    try:
        capture = store.get(upload_id)
    except KeyError:
        logger.warning("upload_id 없음: %s", upload_id)
        raise HTTPException(status_code=404, detail={"code": "upload_not_found", "message": "업로드 파일 없음"})

    check_capture_token(capture, x_upload_token)
    annotations = list(request.app.state.annotations_store.get(upload_id, []))
    data = _exporter.export(capture.sessions, annotations=annotations)
    return JSONResponse(data)


@router.post("/api/export/{upload_id}/pdf")
async def export_pdf(
    upload_id: str,
    request: Request,
    x_upload_token: str | None = Header(None, alias="X-Upload-Token"),
):
    _validate_upload_id(upload_id)
    logger.info("PDF 내보내기 요청: upload_id=%s", upload_id)
    store = request.app.state.session_store
    try:
        capture = store.get(upload_id)
    except KeyError:
        logger.warning("upload_id 없음: %s", upload_id)
        raise HTTPException(status_code=404, detail={"code": "upload_not_found", "message": "업로드 파일 없음"})

    check_capture_token(capture, x_upload_token)

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


def _sanitize_csv_cell(value: str) -> str:
    """스프레드시트 수식 인젝션 방지: 수식 시작 문자로 시작하는 값 앞에 탭 접두사 추가."""
    if value and value[0] in ("=", "+", "-", "@", "\t", "\r", "|", "%"):
        return "\t" + value
    return value


@router.get("/api/export/{upload_id}/ioc")
async def export_ioc(
    upload_id: str,
    request: Request,
    x_upload_token: str | None = Header(None, alias="X-Upload-Token"),
):
    _validate_upload_id(upload_id)
    logger.info("IOC 내보내기 요청: upload_id=%s", upload_id)
    store = request.app.state.session_store
    try:
        capture = store.get(upload_id)
    except KeyError:
        logger.warning("upload_id 없음: %s", upload_id)
        raise HTTPException(status_code=404, detail={"code": "upload_not_found", "message": "업로드 파일 없음"})

    check_capture_token(capture, x_upload_token)

    # attacker_ips 수집: 각 attack dict/AttackDetectionResult의 src_ip 필드
    seen_ips: dict[str, str] = {}  # ip -> attack_type
    for attack in capture.attacks:
        if isinstance(attack, dict):
            src_ip = attack.get("src_ip", "") or ""
            attack_type = attack.get("attack_type", "Unknown")
        else:
            src_ip = getattr(attack, "src_ip", "") or ""
            attack_type = getattr(attack, "attack_type", "Unknown")
        if src_ip and src_ip not in seen_ips:
            seen_ips[src_ip] = attack_type

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
        writer.writerow(["ip", _sanitize_csv_cell(ip), _sanitize_csv_cell(attack_type)])
    for domain, source in seen_domains.items():
        writer.writerow(["domain", _sanitize_csv_cell(domain), _sanitize_csv_cell(source)])

    csv_bytes = buf.getvalue().encode("utf-8")
    safe_suffix = re.sub(r"[^a-f0-9]", "", upload_id.lower())[:8]
    headers = {
        "Content-Disposition": f'attachment; filename="ioc_{safe_suffix}.csv"',
    }
    return Response(content=csv_bytes, media_type="text/csv", headers=headers)
