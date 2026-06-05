"""GET /api/drilldown/{upload_id}?ip=<ip> — IP별 세션 드릴다운."""
import re

from fastapi import APIRouter, HTTPException, Query, Request

router = APIRouter()

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
)


@router.get("/api/drilldown/{upload_id}")
async def drilldown(upload_id: str, ip: str = Query(..., description="드릴다운할 IP 주소"), request: Request = None):
    if not _UUID_RE.match(upload_id):
        raise HTTPException(status_code=400, detail={"code": "invalid_uuid", "msg": "upload_id must be a valid UUID"})
    try:
        capture = request.app.state.session_store.get(upload_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="upload_id를 찾을 수 없습니다")

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
    return {"ip": ip, "session_count": len(matched), "sessions": matched[:50]}
