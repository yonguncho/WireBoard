"""POST /api/upload — 파일 수신 + 파싱 + 세션 저장."""
import json
import logging
import secrets
import uuid
from fastapi import APIRouter, HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse
from pydantic import ValidationError

logger = logging.getLogger(__name__)

from services.parser.pcap_parser import PcapParser
from services.parser.har_parser import HarParser
from services.parser.fortigate_parser import FortigateParser
from services.parser.tcpdump_parser import TcpdumpParser
from services.normalizer import SessionNormalizer
from store.session_store import ParsedCapture
from utils.constants import MAX_UPLOAD_BYTES

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
            raise HTTPException(status_code=413, detail="파일 크기가 50 MB 제한 초과")
        chunks.append(chunk)
    return b"".join(chunks)


@router.post("/api/upload")
async def upload_file(request: Request, file: UploadFile) -> JSONResponse:
    filename = file.filename or ""
    _suffix = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    ext = ("." + _suffix) if _suffix else ""

    if ext not in _ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=415, detail=f"허용되지 않는 파일 확장자: {ext!r}")

    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            cl_int = int(content_length)
            if cl_int < 0:
                raise HTTPException(status_code=400, detail="Content-Length는 음수일 수 없습니다")
            if cl_int > MAX_UPLOAD_BYTES:
                raise HTTPException(status_code=413, detail="파일 크기가 50 MB 제한 초과")
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid Content-Length header")

    raw = await _read_stream_limited(file, MAX_UPLOAD_BYTES)

    if len(raw) == 0:
        # .pcap/.pcapng 빈 파일: 400 (bad request — 유효한 pcap이 아님)
        # 나머지 확장자 빈 파일: 422 (파싱 불가)
        if ext in {".pcap", ".pcapng"}:
            raise HTTPException(status_code=400, detail="빈 파일은 허용되지 않습니다")
        raise HTTPException(status_code=422, detail="빈 파일: 파싱할 내용이 없습니다")

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
                icmp_events = list(getattr(parser, "icmp_events", []))
                source_type = _source_type(parser)
                logger.info("파일 파싱 완료: parser=%s sessions=%d icmp_events=%d warnings=%d",
                            type(parser).__name__, len(sessions), len(icmp_events), len(parse_warnings))
                break
            except (ValueError, KeyError, TypeError, json.JSONDecodeError, ValidationError) as exc:
                logger.warning("파서 예외: parser=%s error=%s", type(parser).__name__, exc)
                parse_warnings.append(f"{type(exc).__name__}: {exc}")

    if sessions is None:
        if ext == ".txt":
            # .txt는 허용되지만 인식 가능한 포맷이어야 함 — 일반 텍스트는 415
            detail = {"message": "허용되지 않는 텍스트 파일 형식 (FortiGate/tcpdump 형식만 허용)", "errors": parse_warnings} \
                     if parse_warnings else "허용되지 않는 텍스트 파일 형식 (FortiGate/tcpdump 형식만 허용)"
            raise HTTPException(status_code=415, detail=detail)
        detail = {"message": "지원하지 않는 파일 형식 또는 손상된 파일", "errors": parse_warnings} \
                 if parse_warnings else "지원하지 않는 파일 형식 또는 손상된 파일"
        raise HTTPException(status_code=400, detail=detail)

    sessions, pkt_map = SessionNormalizer().normalize(sessions, pkt_map)

    if len(sessions) == 0:
        detail = {"message": "파싱된 세션이 없습니다 (빈 파일이거나 인식 불가한 형식)", "errors": parse_warnings} \
                 if parse_warnings else "파싱된 세션이 없습니다 (빈 파일이거나 인식 불가한 형식)"
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
    })


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
