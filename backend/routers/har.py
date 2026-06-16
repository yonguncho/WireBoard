"""GET /api/har/{upload_id} — HAR 요청별 워터폴(타이밍·상태·크기) 데이터."""
from fastapi import APIRouter, Header, HTTPException, Request

from utils.constants import UUID_RE
from utils.capture_auth import check_capture_token

router = APIRouter()

_PHASES = ("blocked", "dns", "ssl", "connect", "send", "wait", "receive")


def _status_group(code: int) -> str:
    if 200 <= code < 300:
        return "2xx"
    if 300 <= code < 400:
        return "3xx"
    if 400 <= code < 500:
        return "4xx"
    if 500 <= code < 600:
        return "5xx"
    return "other"


@router.get("/api/har/{upload_id}")
async def get_har(
    upload_id: str,
    request: Request,
    x_upload_token: str | None = Header(None, alias="X-Upload-Token"),
):
    if not UUID_RE.match(upload_id):
        raise HTTPException(status_code=400, detail={"code": "invalid_uuid", "msg": "upload_id must be a valid UUID"})
    try:
        capture = request.app.state.session_store.get(upload_id)
    except KeyError:
        raise HTTPException(status_code=404, detail={"code": "upload_not_found", "message": "업로드 파일 없음"})

    check_capture_token(capture, x_upload_token)

    rows = [s for s in capture.sessions if s.meta and "url" in s.meta and "timings" in s.meta]
    if not rows:
        return {
            "source_type": capture.source_type,
            "count": 0,
            "entries": [],
            "summary": {"count": 0, "total_bytes": 0, "total_time_ms": 0.0,
                        "status_groups": {"2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, "other": 0}, "slowest": []},
        }

    rows.sort(key=lambda s: s.start_ts)
    page_start = rows[0].start_ts
    page_end = page_start

    entries = []
    status_groups = {"2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, "other": 0}
    total_bytes = 0

    for s in rows:
        m = s.meta
        raw = m.get("timings") or {}
        # HAR 표준: -1 = 해당 없음 → 레이아웃상 0 으로 처리
        timings = {}
        phase_sum = 0.0
        for p in _PHASES:
            v = raw.get(p, -1)
            try:
                v = float(v)
            except (TypeError, ValueError):
                v = -1.0
            v = v if v > 0 else 0.0
            timings[p] = round(v, 1)
            phase_sum += v

        total_ms = m.get("time_ms")
        try:
            total_ms = float(total_ms)
        except (TypeError, ValueError):
            total_ms = -1.0
        if total_ms <= 0:
            total_ms = phase_sum

        status = int(m.get("status_code") or 0)
        status_groups[_status_group(status)] += 1
        resp_size = int(m.get("resp_size") or 0)
        total_bytes += resp_size
        start_offset_ms = round((s.start_ts - page_start) * 1000.0, 1)
        page_end = max(page_end, s.start_ts + total_ms / 1000.0)

        entries.append({
            "session_id": s.session_id,
            "method": m.get("method", "GET"),
            "url": m.get("url", ""),
            "host": m.get("hostname", ""),
            "status": status,
            "mime": m.get("mime", ""),
            "start_offset_ms": start_offset_ms,
            "total_ms": round(total_ms, 1),
            "resp_size": resp_size,
            "timings": timings,
        })

    slowest = sorted(entries, key=lambda e: e["total_ms"], reverse=True)[:5]
    summary = {
        "count": len(entries),
        "total_bytes": total_bytes,
        "total_time_ms": round((page_end - page_start) * 1000.0, 1),
        "status_groups": status_groups,
        "slowest": [{"url": e["url"], "host": e["host"], "total_ms": e["total_ms"], "status": e["status"]} for e in slowest],
    }

    return {"source_type": capture.source_type, "count": len(entries), "entries": entries, "summary": summary}
