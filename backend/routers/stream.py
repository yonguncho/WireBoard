"""GET /api/stream/{upload_id}?session_id=X&encoding=ascii|hex — Follow Stream."""
from fastapi import APIRouter, HTTPException, Query, Request

from utils.constants import UUID_RE

router = APIRouter()

_PARSER_MAX = 200


def _hex_to_bytes(hex_str: str) -> bytes:
    if not hex_str:
        return b""
    try:
        return bytes.fromhex(hex_str.replace(" ", ""))
    except ValueError:
        return b""


def _to_ascii(data: bytes) -> str:
    return "".join(chr(b) if 32 <= b < 127 or b in (9, 10, 13) else "." for b in data)


def _to_hexdump(data: bytes) -> str:
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hex_col = " ".join(f"{b:02x}" for b in chunk)
        ascii_col = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{i:04x}  {hex_col:<47}  {ascii_col}")
    return "\n".join(lines)


@router.get("/api/stream/{upload_id}")
async def get_stream(
    request: Request,
    upload_id: str,
    session_id: str = Query(..., description="세션 UUID"),
    encoding: str = Query("ascii", description="ascii | hex"),
):
    if not UUID_RE.match(upload_id):
        raise HTTPException(status_code=400, detail={"code": "invalid_uuid", "msg": "upload_id must be a valid UUID"})
    if not UUID_RE.match(session_id):
        raise HTTPException(status_code=400, detail={"code": "invalid_uuid", "msg": "session_id must be a valid UUID"})

    try:
        capture = request.app.state.session_store.get(upload_id)
    except KeyError:
        raise HTTPException(status_code=404, detail={"code": "upload_not_found", "message": "업로드 파일 없음"})

    session = next((s for s in capture.sessions if s.session_id == session_id), None)
    if session is None:
        raise HTTPException(status_code=404, detail={"code": "session_not_found", "message": "세션을 찾을 수 없습니다"})

    raw_pkts = capture.packet_map.get(session_id, [])
    base_ts = raw_pkts[0].ts if raw_pkts else 0.0

    data_pkts = sorted(
        [p for p in raw_pkts if p.payload_len > 0 and p.payload_hex],
        key=lambda p: p.ts,
    )

    segments = []
    for p in data_pkts:
        payload = _hex_to_bytes(p.payload_hex)
        if not payload:
            continue
        text = _to_hexdump(payload) if encoding == "hex" else _to_ascii(payload)
        segments.append({
            "direction": p.direction,
            "ts": round(p.ts, 6),
            "rel_ts": round(p.ts - base_ts, 6),
            "length": len(payload),
            "text": text,
            "flags": p.flags or "",
        })

    fwd_bytes = sum(s["length"] for s in segments if s["direction"] == "fwd")
    rev_bytes = sum(s["length"] for s in segments if s["direction"] == "rev")

    return {
        "session_id": session_id,
        "src_ip": session.src_ip,
        "dst_ip": session.dst_ip,
        "src_port": session.src_port,
        "dst_port": session.dst_port,
        "protocol": session.protocol,
        "encoding": encoding,
        "fwd_bytes": fwd_bytes,
        "rev_bytes": rev_bytes,
        "segments": segments,
        "truncated": len(raw_pkts) >= _PARSER_MAX,
    }
