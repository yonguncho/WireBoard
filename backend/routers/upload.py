"""POST /api/upload — 파일 수신 + 파싱 + 세션 저장."""
import json
import logging
import re
import secrets
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
from utils.constants import MAX_UPLOAD_BYTES, UUID_RE
from utils.capture_auth import check_capture_token

router = APIRouter()

_ALLOWED_EXTENSIONS = {".pcap", ".pcapng", ".har", ".log", ".tcpdump", ".txt"}
_PARSERS = [PcapParser(), HarParser(), FortigateParser(), TcpdumpParser()]
_CHUNK_SIZE = 65_536  # 64 KB read chunks


async def _read_stream_limited(file: UploadFile, max_bytes: int) -> bytes:
    """Read file in chunks; raise 413 without buffering the full payload on overflow."""
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = await file.read(_CHUNK_SIZE)
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise HTTPException(status_code=413, detail="File size exceeds the 50 MB limit")
        chunks.append(chunk)
    return b"".join(chunks)


@router.post("/api/upload")
async def upload_file(request: Request, file: UploadFile) -> JSONResponse:
    filename = file.filename or ""
    _suffix = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    ext = ("." + _suffix) if _suffix else ""

    if ext not in _ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=415, detail=f"Unsupported file extension: {ext!r}")

    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            cl_int = int(content_length)
            if cl_int < 0:
                raise HTTPException(status_code=400, detail="Content-Length cannot be negative")
            if cl_int > MAX_UPLOAD_BYTES:
                raise HTTPException(status_code=413, detail="File size exceeds the 50 MB limit")
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid Content-Length header")

    raw = await _read_stream_limited(file, MAX_UPLOAD_BYTES)

    if len(raw) == 0:
        # .pcap/.pcapng 빈 파일: 400 (bad request — 유효한 pcap이 아님)
        # 나머지 확장자 빈 파일: 422 (파싱 불가)
        if ext in {".pcap", ".pcapng"}:
            raise HTTPException(status_code=400, detail="Empty files are not allowed")
        raise HTTPException(status_code=422, detail="Empty file: nothing to parse")

    parse_warnings: list[str] = []
    sessions = None
    pkt_map: dict = {}
    icmp_events: list = []
    source_type = None

    for parser in _PARSERS:
        if parser.detect(raw):
            try:
                result = parser.parse(raw, parse_warnings=parse_warnings)
                # PcapParser returns (sessions, pkt_map); legacy parsers return list
                if isinstance(result, tuple):
                    sessions, pkt_map = result
                else:
                    sessions, pkt_map = result, {}
                # 레거시 파서가 self.packet_map 으로 합성 패킷을 노출하면 수용 (HAR 등)
                if not pkt_map:
                    pkt_map = getattr(parser, "packet_map", {}) or {}
                icmp_events = list(getattr(parser, "icmp_events", []))
                source_type = _source_type(parser)
                logger.info("파일 파싱 완료: parser=%s sessions=%d icmp_events=%d warnings=%d",
                            type(parser).__name__, len(sessions), len(icmp_events), len(parse_warnings))
                break
            except (ValueError, KeyError, TypeError, json.JSONDecodeError, ValidationError) as exc:
                logger.warning("파서 예외: parser=%s error=%s", type(parser).__name__, exc)
                parse_warnings.append(f"{type(exc).__name__}: {exc}")

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
                re_sessions, re_pkt_map = pcap_parser.parse(converted, parse_warnings=parse_warnings)
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
