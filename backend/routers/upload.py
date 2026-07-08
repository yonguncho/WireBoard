"""POST /api/upload — 파일 수신 + 파싱 + 세션 저장."""
import json
import logging
import os
import re
import secrets
import tempfile
import uuid
from fastapi import APIRouter, Header, HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse, Response
from pydantic import ValidationError

logger = logging.getLogger(__name__)

from services.parser.pcap_parser import PcapParser
from services.parser.har_parser import HarParser
from services.parser.fortigate_parser import FortigateParser
from services.parser.tcpdump_parser import TcpdumpParser
from services.normalizer import SessionNormalizer
from store.session_store import ParsedCapture
from utils.constants import MAX_UPLOAD_BYTES, MAX_TEXT_UPLOAD_BYTES, UUID_RE
from utils.capture_auth import check_capture_token

router = APIRouter()

_ALLOWED_EXTENSIONS = {".pcap", ".pcapng", ".har", ".log", ".tcpdump", ".txt"}
# 텍스트 로그(hex 덤프·HAR JSON)는 바이너리보다 부피가 커 상향 한도 적용.
_TEXT_EXTENSIONS = {".txt", ".log", ".tcpdump", ".har"}
# 텍스트 포맷 파서 (pcap 매직이 아닐 때만 사용; PcapParser는 스트리밍 경로에서 별도 처리)
_TEXT_PARSERS = [HarParser(), FortigateParser(), TcpdumpParser()]
_CHUNK_SIZE = 65_536  # 64 KB read chunks


async def _spool_to_temp(file: UploadFile, max_bytes: int) -> tuple[str, int]:
    """업로드를 디스크 임시파일로 스풀 — 대용량도 전체를 메모리에 올리지 않는다.
    상한 초과 시 임시파일 삭제 후 413."""
    tmp = tempfile.NamedTemporaryFile(prefix="wb_up_", suffix=".bin", delete=False)
    total = 0
    try:
        while True:
            chunk = await file.read(_CHUNK_SIZE)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                limit_mb = max_bytes // (1024 * 1024)
                tmp.close()
                os.unlink(tmp.name)
                raise HTTPException(status_code=413, detail=f"File size exceeds the {limit_mb} MB limit")
            tmp.write(chunk)
    except HTTPException:
        raise
    finally:
        if not tmp.closed:
            tmp.close()
    return tmp.name, total


@router.post("/api/upload")
async def upload_file(request: Request, file: UploadFile) -> JSONResponse:
    filename = file.filename or ""
    _suffix = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    ext = ("." + _suffix) if _suffix else ""

    if ext not in _ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=415, detail=f"Unsupported file extension: {ext!r}")

    max_bytes = MAX_TEXT_UPLOAD_BYTES if ext in _TEXT_EXTENSIONS else MAX_UPLOAD_BYTES
    limit_mb = max_bytes // (1024 * 1024)

    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            cl_int = int(content_length)
            if cl_int < 0:
                raise HTTPException(status_code=400, detail="Content-Length cannot be negative")
            if cl_int > max_bytes:
                raise HTTPException(status_code=413, detail=f"File size exceeds the {limit_mb} MB limit")
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid Content-Length header")

    tmp_path, size = await _spool_to_temp(file, max_bytes)
    try:
        if size == 0:
            if ext in {".pcap", ".pcapng"}:
                raise HTTPException(status_code=400, detail="Empty files are not allowed")
            raise HTTPException(status_code=422, detail="Empty file: nothing to parse")

        parse_warnings: list[str] = []
        sessions = None
        pkt_map: dict = {}
        icmp_events: list = []
        source_type = None
        raw = b""  # 텍스트 경로에서만 전체 바이트 로드

        # 매직 바이트로 바이너리 pcap 여부 판정 (대용량 HAR/text를 PcapParser에 안 먹임)
        with open(tmp_path, "rb") as f:
            head = f.read(4)
        is_pcap = PcapParser().detect(head)

        if is_pcap:
            # ── 스트리밍 파싱 (GB급 pcap을 전체 메모리로 올리지 않음) ──
            try:
                p = PcapParser()
                with open(tmp_path, "rb") as f:
                    sessions, pkt_map = p.parse_stream(f, parse_warnings=parse_warnings,
                                                       max_bytes=MAX_UPLOAD_BYTES, size=size)
                icmp_events = list(p.icmp_events)
                source_type = "pcap"
                logger.info("pcap 스트리밍 파싱 완료: sessions=%d size=%d", len(sessions), size)
            except (ValueError, KeyError, TypeError) as exc:
                logger.warning("pcap 스트리밍 파싱 실패: %s", exc)
                parse_warnings.append(f"{type(exc).__name__}: {exc}")
        else:
            # ── 텍스트 포맷(HAR/FortiGate/tcpdump) — 전체 바이트 로드(텍스트 한도 내) ──
            if size > MAX_TEXT_UPLOAD_BYTES:
                raise HTTPException(status_code=413,
                                    detail=f"Text file size exceeds the {MAX_TEXT_UPLOAD_BYTES // (1024*1024)} MB limit")
            with open(tmp_path, "rb") as f:
                raw = f.read()
            for parser in _TEXT_PARSERS:
                if parser.detect(raw):
                    try:
                        result = parser.parse(raw, parse_warnings=parse_warnings)
                        if isinstance(result, tuple):
                            sessions, pkt_map = result
                        else:
                            sessions, pkt_map = result, {}
                        if not pkt_map:
                            pkt_map = getattr(parser, "packet_map", {}) or {}
                        icmp_events = list(getattr(parser, "icmp_events", []))
                        source_type = _source_type(parser)
                        logger.info("텍스트 파싱 완료: parser=%s sessions=%d warnings=%d",
                                    type(parser).__name__, len(sessions), len(parse_warnings))
                        break
                    except (ValueError, KeyError, TypeError, json.JSONDecodeError, ValidationError) as exc:
                        logger.warning("파서 예외: parser=%s error=%s", type(parser).__name__, exc)
                        parse_warnings.append(f"{type(exc).__name__}: {exc}")

        return await _finalize_upload(
            request, ext, sessions, pkt_map, icmp_events, source_type, parse_warnings, raw,
        )
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


async def _finalize_upload(request, ext, sessions, pkt_map, icmp_events, source_type,
                           parse_warnings, raw):
    # FortiGate/tcpdump verbose 로그에 16진수 덤프가 있으면 pcap으로 변환 후 재파싱.
    # 변환 성공 시 실제 바이트 수·포트·플래그가 채워진 고품질 세션으로 교체한다.
    pcap_bytes: bytes | None = None
    if source_type in ("fortigate", "tcpdump") and sessions is not None:
        try:
            from services.parser.raw_pcap_converter import convert_raw_log_to_pcap
            conv = convert_raw_log_to_pcap(raw)
            if conv is not None:
                converted, pkt_count = conv
                pcap_parser = PcapParser()
                re_sessions, re_pkt_map = pcap_parser.parse(converted, parse_warnings=parse_warnings, max_bytes=MAX_TEXT_UPLOAD_BYTES)
                if re_sessions:
                    sessions = re_sessions
                    pkt_map = re_pkt_map
                    icmp_events = list(getattr(pcap_parser, "icmp_events", []))
                    pcap_bytes = converted
                    logger.info("raw→pcap 변환 완료: packets=%d sessions=%d", pkt_count, len(re_sessions))
        except Exception as exc:  # 변환 실패는 치명적이지 않음 — 요약 세션 유지
            logger.warning("raw→pcap 변환 실패 (요약 세션 유지): %s", exc)

    if sessions is None:
        if ext == ".txt":
            # .txt는 허용되지만 인식 가능한 포맷이어야 함 — 일반 텍스트는 415
            detail = {"message": "Unsupported text file format (only FortiGate/tcpdump formats allowed)", "errors": parse_warnings} \
                     if parse_warnings else "Unsupported text file format (only FortiGate/tcpdump formats allowed)"
            raise HTTPException(status_code=415, detail=detail)
        detail = {"message": "Unsupported file format or corrupted file", "errors": parse_warnings} \
                 if parse_warnings else "Unsupported file format or corrupted file"
        raise HTTPException(status_code=400, detail=detail)

    sessions, pkt_map = SessionNormalizer().normalize(sessions, pkt_map)

    if len(sessions) == 0:
        detail = {"message": "No sessions were parsed (empty file or unrecognized format)", "errors": parse_warnings} \
                 if parse_warnings else "No sessions were parsed (empty file or unrecognized format)"
        raise HTTPException(status_code=422, detail=detail)

    upload_id = str(uuid.uuid4())
    capture_token = secrets.token_hex(16)
    capture = ParsedCapture(
        sessions=sessions,
        source_type=source_type,
        parse_warnings=parse_warnings,
        packet_map=pkt_map,
        icmp_events=icmp_events,
        capture_token=capture_token,
        pcap_bytes=pcap_bytes,
    )
    request.app.state.session_store.put(upload_id, capture)

    logger.info("업로드 완료: upload_id=%s source=%s sessions=%d",
                upload_id, source_type, len(sessions))
    return JSONResponse({
        "upload_id": upload_id,
        "capture_token": capture_token,
        "source_type": source_type,
        "session_count": len(sessions),
        "parse_warnings": parse_warnings,
        "pcap_available": pcap_bytes is not None,
    })


@router.get("/api/upload/{upload_id}/pcap")
async def download_pcap(
    upload_id: str,
    request: Request,
    x_upload_token: str | None = Header(None, alias="X-Upload-Token"),
) -> Response:
    """raw 로그(FortiGate/tcpdump)에서 변환된 pcap 다운로드."""
    if not UUID_RE.match(upload_id):
        raise HTTPException(status_code=400, detail={"code": "invalid_uuid", "msg": "upload_id must be a valid UUID"})
    store = request.app.state.session_store
    try:
        capture = store.get(upload_id)
    except KeyError:
        raise HTTPException(status_code=404, detail={"code": "upload_not_found", "message": "Upload not found"})

    check_capture_token(capture, x_upload_token)

    if not capture.pcap_bytes:
        raise HTTPException(status_code=404, detail={"code": "pcap_unavailable", "message": "No converted PCAP available (log has no hex dump)"})

    safe_id = re.sub(r"[^a-f0-9]", "", upload_id.lower())[:8]
    headers = {"Content-Disposition": f'attachment; filename="converted_{safe_id}.pcap"'}
    return Response(content=capture.pcap_bytes, media_type="application/vnd.tcpdump.pcap", headers=headers)


def _source_type(parser) -> str:
    name = type(parser).__name__.lower()
    if "pcap" in name:
        return "pcap"
    if "har" in name:
        return "har"
    if "forti" in name:
        return "fortigate"
    if "tcpdump" in name:
        return "tcpdump"
    return "unknown"
