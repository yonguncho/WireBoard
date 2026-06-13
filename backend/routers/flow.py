"""GET /api/flow/{upload_id}?session_id=<sid> — 패킷 단위 흐름 조회."""
from fastapi import APIRouter, Header, HTTPException, Query, Request

from utils.constants import UUID_RE
from utils.capture_auth import check_capture_token

router = APIRouter()

_PARSER_MAX = 200  # pcap_parser._MAX_PKTS_PER_FLOW 와 동기화


@router.get("/api/flow/{upload_id}")
async def get_flow(
    request: Request,
    upload_id: str,
    session_id: str = Query(..., description="세션 UUID"),
    x_upload_token: str | None = Header(None, alias="X-Upload-Token"),
):
    if not UUID_RE.match(upload_id):
        raise HTTPException(
            status_code=400,
            detail={"code": "invalid_uuid", "msg": "upload_id must be a valid UUID"},
        )
    if not UUID_RE.match(session_id):
        raise HTTPException(
            status_code=400,
            detail={"code": "invalid_uuid", "msg": "session_id must be a valid UUID"},
        )

    try:
        capture = request.app.state.session_store.get(upload_id)
    except KeyError:
        raise HTTPException(status_code=404, detail={"code": "upload_not_found", "message": "업로드 파일 없음"})

    check_capture_token(capture, x_upload_token)

    session = next((s for s in capture.sessions if s.session_id == session_id), None)
    if session is None:
        raise HTTPException(status_code=404, detail={"code": "session_not_found", "message": "세션을 찾을 수 없습니다"})

    raw_pkts_all = capture.packet_map.get(session_id, [])
    truncated = len(raw_pkts_all) > _PARSER_MAX
    raw_pkts = raw_pkts_all[:_PARSER_MAX]
    base_ts  = raw_pkts[0].ts if raw_pkts else 0.0

    packets_out = []
    for p in raw_pkts:
        packets_out.append({
            "ts":          round(p.ts, 6),
            "rel_ts":      round(p.ts - base_ts, 6),
            "direction":   p.direction,
            "proto":       p.proto,
            "seq":         p.seq,
            "ack":         p.ack,
            "flags":       p.flags,
            "length":      p.length,
            "payload_len": p.payload_len,
            "payload_hex": p.payload_hex,
        })

    return {
        "session": {
            "session_id": session.session_id,
            "src_ip":     session.src_ip,
            "dst_ip":     session.dst_ip,
            "src_port":   session.src_port,
            "dst_port":   session.dst_port,
            "protocol":   session.protocol,
            "packet_count": session.packet_count,
            "bytes_sent": session.bytes_sent,
            "bytes_recv": session.bytes_recv,
            "start_ts":   session.start_ts,
            "end_ts":     session.end_ts,
            "duration_s": round(session.end_ts - session.start_ts, 3),
            "rst":        session.rst,
        },
        "packets":       packets_out,
        "packet_count":  len(raw_pkts_all),
        "truncated":     truncated,
    }
