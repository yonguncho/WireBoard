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

    sessions = capture.sessions
    matched = []
    for s in sessions:
        src = s.get("src_ip") if isinstance(s, dict) else getattr(s, "src_ip", None)
        dst = s.get("dst_ip") if isinstance(s, dict) else getattr(s, "dst_ip", None)
        if src != ip and dst != ip:
            continue

        def _get(obj, key, default=None):
            return obj.get(key, default) if isinstance(obj, dict) else getattr(obj, key, default)

        matched.append({
            "session_id": _get(s, "session_id", ""),
            "src_ip": src,
            "dst_ip": dst,
            "src_port": _get(s, "src_port", 0),
            "dst_port": _get(s, "dst_port", 0),
            "protocol": _get(s, "protocol", "?"),
            "bytes_sent": _get(s, "bytes_sent", 0),
            "bytes_recv": _get(s, "bytes_recv", 0),
            "packet_count": _get(s, "packet_count", 0),
            "start_ts": _get(s, "start_ts", 0),
            "end_ts": _get(s, "end_ts", 0),
            "duration_s": round(_get(s, "end_ts", 0) - _get(s, "start_ts", 0), 3),
            "rst": _get(s, "rst", False),
        })

    matched.sort(key=lambda x: x["bytes_sent"] + x["bytes_recv"], reverse=True)
    return {"ip": ip, "session_count": len(matched), "sessions": matched[:50]}
