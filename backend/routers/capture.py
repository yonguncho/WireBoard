"""라이브 캡처 — 인터페이스 선택 + BPF 필터로 로컬 PC에서 직접 pcap 캡처.

옵션 기능: Npcap/libpcap + 관리자 권한이 있을 때만 동작한다. 없으면 명확한
안내를 반환하고, 오프라인 분석 기능에는 전혀 영향을 주지 않는다.

캡처는 100% 로컬(자기 PC)에서만 이루어지며 외부로 전송하지 않는다 —
WireBoard의 "민감 캡처 외부 유출 없음" 원칙과 일치한다.
"""
import io
import ipaddress
import logging
import os
import secrets
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass, field

from fastapi import APIRouter, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

logger = logging.getLogger(__name__)

from services.parser.pcap_parser import PcapParser
from services.normalizer import SessionNormalizer
from store.session_store import ParsedCapture
from utils.constants import UUID_RE
from utils.capture_auth import check_capture_token

router = APIRouter()

# 안전 상한 — 폭주 방지
_MAX_PACKETS_CAP = 100_000
_MAX_SECONDS_CAP = 300
_MAX_CONCURRENT = 3

_captures: dict[str, "_LiveCapture"] = {}
_lock = threading.Lock()


@dataclass
class _LiveCapture:
    sniffer: object
    iface: str
    bpf: str
    started_at: float
    max_packets: int
    max_seconds: float
    timer: object = None
    stopped: bool = False


def _capture_available() -> tuple[bool, str]:
    """이 PC에서 라이브 캡처가 가능한지(라이브러리 관점). 권한은 start에서 판정."""
    try:
        import scapy.all as scapy  # noqa: PLC0415
    except Exception as exc:
        return False, f"scapy import 실패: {exc}"
    if not getattr(scapy.conf, "use_pcap", False):
        return False, ("Npcap/libpcap 드라이버가 감지되지 않았습니다. "
                       "Windows는 https://npcap.com 에서 Npcap 설치가 필요합니다.")
    return True, ""


def _iface_list() -> list[dict]:
    """캡처 가능한 네트워크 인터페이스 목록 (이름·설명·IP)."""
    import scapy.all as scapy  # noqa: PLC0415
    out: list[dict] = []
    try:
        ifaces = scapy.get_working_ifaces()
    except Exception as exc:
        logger.warning("인터페이스 조회 실패: %s", exc)
        return out
    for i in ifaces:
        ip = getattr(i, "ip", None)
        # 실사용 가능한 IP인지(루프백/미지정 제외) 판정 — 리터럴 대신 ipaddress 사용
        usable = False
        if ip:
            try:
                addr = ipaddress.ip_address(ip)
                usable = not (addr.is_loopback or addr.is_unspecified)
            except ValueError:
                usable = False
        out.append({
            "name": getattr(i, "name", str(i)),
            "description": getattr(i, "description", "") or "",
            "ip": ip,
            "mac": getattr(i, "mac", None),
            # IP 있는 유선/무선 인터페이스를 우선 노출
            "has_ip": usable,
        })
    return out


def _build_bpf(src: str | None, dst: str | None, port: int | None, host: str | None) -> str:
    """검증된 입력으로 BPF 필터 문자열 생성 (injection 방지 — IP/port만 허용)."""
    parts: list[str] = []

    def _ip(v: str, label: str) -> str:
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise HTTPException(status_code=400, detail={"code": "invalid_ip", "msg": f"{label} must be a valid IP: {v!r}"})
        return v

    if src:
        parts.append(f"src host {_ip(src, 'src')}")
    if dst:
        parts.append(f"dst host {_ip(dst, 'dst')}")
    if host:
        parts.append(f"host {_ip(host, 'host')}")
    if port is not None:
        if not (0 <= port <= 65535):
            raise HTTPException(status_code=400, detail={"code": "invalid_port", "msg": "port must be 0-65535"})
        parts.append(f"port {int(port)}")
    return " and ".join(parts)


class CaptureStartRequest(BaseModel):
    iface: str
    src: str | None = None
    dst: str | None = None
    port: int | None = None
    host: str | None = None
    max_packets: int = 5000
    max_seconds: int = 60


@router.get("/api/capture/capability")
async def capture_capability():
    ok, msg = _capture_available()
    return {"available": ok, "message": msg,
            "admin_note": "라이브 캡처는 관리자 권한으로 실행해야 합니다."}


@router.get("/api/capture/interfaces")
async def capture_interfaces():
    ok, msg = _capture_available()
    if not ok:
        raise HTTPException(status_code=501, detail={"code": "capture_unavailable", "message": msg})
    return {"interfaces": _iface_list()}


@router.post("/api/capture/start")
async def capture_start(body: CaptureStartRequest):
    ok, msg = _capture_available()
    if not ok:
        raise HTTPException(status_code=501, detail={"code": "capture_unavailable", "message": msg})

    with _lock:
        active = sum(1 for c in _captures.values() if not c.stopped)
        if active >= _MAX_CONCURRENT:
            raise HTTPException(status_code=429, detail={"code": "too_many_captures", "message": "동시 캡처 상한 초과"})

    import scapy.all as scapy  # noqa: PLC0415

    # 인터페이스 검증
    valid = {i["name"] for i in _iface_list()}
    if body.iface not in valid:
        raise HTTPException(status_code=400, detail={"code": "invalid_iface", "message": f"Unknown interface: {body.iface!r}"})

    bpf = _build_bpf(body.src, body.dst, body.port, body.host)
    max_packets = max(1, min(int(body.max_packets), _MAX_PACKETS_CAP))
    max_seconds = max(1, min(int(body.max_seconds), _MAX_SECONDS_CAP))

    cap_id = str(uuid.uuid4())

    # 패킷 수 상한 도달 시 자동 종료
    def _stop_filter(pkt):
        c = _captures.get(cap_id)
        return bool(c and c.sniffer and len(getattr(c.sniffer, "results", []) or []) >= max_packets)

    try:
        sniffer = scapy.AsyncSniffer(
            iface=body.iface,
            filter=bpf or None,
            store=True,
            stop_filter=_stop_filter,
        )
        sniffer.start()
    except (PermissionError, OSError) as exc:
        raise HTTPException(status_code=403, detail={
            "code": "capture_permission",
            "message": f"캡처 시작 실패(권한/드라이버). 관리자 권한으로 실행하고 Npcap을 확인하세요: {exc}",
        })
    except Exception as exc:
        raise HTTPException(status_code=500, detail={"code": "capture_error", "message": f"캡처 시작 오류: {exc}"})

    # 시간 상한 도달 시 자동 종료 타이머
    def _auto_stop():
        c = _captures.get(cap_id)
        if c and not c.stopped:
            try:
                c.sniffer.stop()
            except Exception:
                pass
            c.stopped = True

    timer = threading.Timer(max_seconds, _auto_stop)
    timer.daemon = True
    timer.start()

    with _lock:
        _captures[cap_id] = _LiveCapture(
            sniffer=sniffer, iface=body.iface, bpf=bpf,
            started_at=time.time(), max_packets=max_packets,
            max_seconds=max_seconds, timer=timer,
        )
    logger.info("라이브 캡처 시작: id=%s iface=%s bpf=%r limit=%d/%ds",
                cap_id, body.iface, bpf, max_packets, max_seconds)
    return {"capture_id": cap_id, "bpf": bpf, "max_packets": max_packets, "max_seconds": max_seconds}


@router.get("/api/capture/{capture_id}/status")
async def capture_status(capture_id: str):
    if not UUID_RE.match(capture_id):
        raise HTTPException(status_code=400, detail={"code": "invalid_uuid", "msg": "capture_id must be a valid UUID"})
    c = _captures.get(capture_id)
    if c is None:
        raise HTTPException(status_code=404, detail={"code": "capture_not_found", "message": "Capture not found"})
    count = len(getattr(c.sniffer, "results", []) or [])
    running = (not c.stopped) and getattr(c.sniffer, "running", False)
    return {
        "capture_id": capture_id, "running": running, "stopped": c.stopped,
        "packet_count": count, "elapsed": round(time.time() - c.started_at, 1),
        "max_packets": c.max_packets, "max_seconds": c.max_seconds, "bpf": c.bpf,
    }


@router.post("/api/capture/{capture_id}/stop")
async def capture_stop(capture_id: str, request: Request):
    if not UUID_RE.match(capture_id):
        raise HTTPException(status_code=400, detail={"code": "invalid_uuid", "msg": "capture_id must be a valid UUID"})
    c = _captures.get(capture_id)
    if c is None:
        raise HTTPException(status_code=404, detail={"code": "capture_not_found", "message": "Capture not found"})

    import scapy.all as scapy  # noqa: PLC0415

    try:
        if not c.stopped:
            c.sniffer.stop()
            c.stopped = True
        if c.timer:
            c.timer.cancel()
    except Exception as exc:
        logger.warning("캡처 정지 오류: %s", exc)

    pkts = list(getattr(c.sniffer, "results", []) or [])
    with _lock:
        _captures.pop(capture_id, None)

    if not pkts:
        raise HTTPException(status_code=422, detail={"code": "no_packets", "message": "No packets captured (check filter/interface)"})

    # 캡처 패킷 → pcap 바이트 → 기존 분석 파이프라인
    tmp = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
    tmp_path = tmp.name
    tmp.close()
    try:
        scapy.wrpcap(tmp_path, pkts)
        with open(tmp_path, "rb") as f:
            raw = f.read()
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass

    parse_warnings: list[str] = []
    try:
        sessions, pkt_map = PcapParser().parse(raw, parse_warnings=parse_warnings)
    except Exception as exc:
        raise HTTPException(status_code=500, detail={"code": "parse_error", "message": f"캡처 파싱 실패: {exc}"})

    sessions, pkt_map = SessionNormalizer().normalize(sessions, pkt_map)
    if not sessions:
        raise HTTPException(status_code=422, detail={"code": "no_sessions", "message": "캡처에서 세션을 추출하지 못함"})

    upload_id = str(uuid.uuid4())
    capture_token = secrets.token_hex(16)
    request.app.state.session_store.put(upload_id, ParsedCapture(
        sessions=sessions,
        source_type="live",
        parse_warnings=parse_warnings,
        packet_map=pkt_map,
        icmp_events=[],
        capture_token=capture_token,
        pcap_bytes=raw,  # 캡처본 다운로드 가능
    ))
    logger.info("라이브 캡처 완료: id=%s packets=%d sessions=%d upload_id=%s",
                capture_id, len(pkts), len(sessions), upload_id)
    return JSONResponse({
        "upload_id": upload_id,
        "capture_token": capture_token,
        "source_type": "live",
        "session_count": len(sessions),
        "packet_count": len(pkts),
        "parse_warnings": parse_warnings,
        "pcap_available": True,
    })
