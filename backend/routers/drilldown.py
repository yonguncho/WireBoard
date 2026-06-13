"""GET /api/drilldown/{upload_id}?ip=<ip> — IP별 세션 드릴다운."""
import ipaddress

from fastapi import APIRouter, Header, HTTPException, Query, Request

from utils.constants import UUID_RE
from utils.capture_auth import check_capture_token

router = APIRouter()


@router.get("/api/drilldown/{upload_id}")
async def drilldown(
    request: Request,
    upload_id: str,
    ip: str = Query(..., description="드릴다운할 IP 주소"),
    x_upload_token: str | None = Header(None, alias="X-Upload-Token"),
):
    if not UUID_RE.match(upload_id):
        raise HTTPException(status_code=400, detail={"code": "invalid_uuid", "msg": "upload_id must be a valid UUID"})
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(status_code=400, detail={"code": "invalid_ip", "msg": "ip must be a valid IP address"})
    try:
        capture = request.app.state.session_store.get(upload_id)
    except KeyError:
        raise HTTPException(status_code=404, detail={"code": "upload_not_found", "message": "업로드 파일 없음"})

    check_capture_token(capture, x_upload_token)

    matched = []
    for s in capture.sessions:
        if s.src_ip != ip and s.dst_ip != ip:
            continue
        matched.append({
            "session_id": s.session_id,
            "src_ip": s.src_ip,
            "dst_ip": s.dst_ip,
            "src_port": s.src_port,
            "dst_port": s.dst_port,
            "protocol": s.protocol,
            "bytes_sent": s.bytes_sent,
            "bytes_recv": s.bytes_recv,
            "packet_count": s.packet_count,
            "start_ts": s.start_ts,
            "end_ts": s.end_ts,
            "duration_s": round(s.end_ts - s.start_ts, 3),
            "rst": s.rst,
        })

    matched.sort(key=lambda x: x["bytes_sent"] + x["bytes_recv"], reverse=True)
    return {
        "ip": ip,
        "session_count": len(matched),
        "sessions": matched[:50],
        "truncated": len(matched) > 50,
    }
