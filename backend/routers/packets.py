"""GET /api/packets/{upload_id} — 전체 패킷 목록 (페이지네이션 + 필터)."""
import ipaddress

from fastapi import APIRouter, Header, HTTPException, Query, Request

from utils.constants import UUID_RE
from utils.capture_auth import check_capture_token

router = APIRouter()

_MAX_FLAT = 50_000  # 메모리 보호: 업로드당 최대 집계 패킷 수


@router.get("/api/packets/{upload_id}")
async def get_packets(
    request: Request,
    upload_id: str,
    offset: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    src_ip: str = Query(None),
    dst_ip: str = Query(None),
    proto: str = Query(None),
    flags: str = Query(None),
    session_id: str = Query(None),
    x_upload_token: str | None = Header(None, alias="X-Upload-Token"),
):
    if not UUID_RE.match(upload_id):
        raise HTTPException(
            status_code=400,
            detail={"code": "invalid_uuid", "msg": "upload_id must be a valid UUID"},
        )
    if src_ip is not None:
        try:
            ipaddress.ip_address(src_ip)
        except ValueError:
            raise HTTPException(status_code=400, detail={"code": "invalid_ip", "msg": "src_ip must be a valid IP address"})
    if dst_ip is not None:
        try:
            ipaddress.ip_address(dst_ip)
        except ValueError:
            raise HTTPException(status_code=400, detail={"code": "invalid_ip", "msg": "dst_ip must be a valid IP address"})
    if session_id is not None and not UUID_RE.match(session_id):
        raise HTTPException(status_code=400, detail={"code": "invalid_uuid", "msg": "session_id must be a valid UUID"})

    try:
        capture = request.app.state.session_store.get(upload_id)
    except KeyError:
        raise HTTPException(status_code=404, detail={"code": "upload_not_found", "message": "업로드 파일 없음"})

    check_capture_token(capture, x_upload_token)

    # session_id → SessionModel 룩업
    session_lookup = {s.session_id: s for s in capture.sessions}

    # session_id 지정 시 직접 룩업으로 O(n) flat 빌드 생략
    if session_id is not None:
        if session_lookup.get(session_id) is None:
            return {
                "total": 0,
                "total_unfiltered": 0,
                "truncated": False,
                "offset": offset,
                "limit": limit,
                "packets": [],
            }
        iter_items: list[tuple] | object = [(session_id, capture.packet_map.get(session_id, []))]
    else:
        iter_items = capture.packet_map.items()

    flat: list[dict] = []
    hit_limit = False

    for sid, pkts in iter_items:
        sess = session_lookup.get(sid)
        if sess is None:
            continue
        for p in pkts:
            if p.direction == "fwd":
                src_ip_p, src_port_p = sess.src_ip, sess.src_port
                dst_ip_p, dst_port_p = sess.dst_ip, sess.dst_port
            else:
                src_ip_p, src_port_p = sess.dst_ip, sess.dst_port
                dst_ip_p, dst_port_p = sess.src_ip, sess.src_port
            flat.append({
                "ts":          p.ts,
                "src_ip":      src_ip_p,
                "src_port":    src_port_p,
                "dst_ip":      dst_ip_p,
                "dst_port":    dst_port_p,
                "proto":       p.proto,
                "seq":         p.seq,
                "ack":         p.ack,
                "flags":       p.flags,
                "length":      p.length,
                "payload_len": p.payload_len,
                "payload_hex": p.payload_hex,
                "session_id":  sid,
            })
            if len(flat) >= _MAX_FLAT:
                hit_limit = True
                break
        if hit_limit:
            break

    flat.sort(key=lambda x: x["ts"])

    # 전역 번호 + 상대 시각 부여 (필터 전에 고정)
    base_ts = flat[0]["ts"] if flat else 0.0
    for i, p in enumerate(flat):
        p["no"]     = i + 1
        p["rel_ts"] = round(p["ts"] - base_ts, 6)

    total_unfiltered = len(flat)

    # 필터 적용
    if src_ip:
        flat = [p for p in flat if p["src_ip"] == src_ip]
    if dst_ip:
        flat = [p for p in flat if p["dst_ip"] == dst_ip]
    if proto:
        flat = [p for p in flat if p.get("proto") and p["proto"].upper() == proto.upper()]
    if flags:
        flat = [p for p in flat if p.get("flags") and flags.upper() in p["flags"].upper()]
    # session_id 필터는 source 단계(iter_items)에서 처리됨

    total = len(flat)
    page  = flat[offset: offset + limit]

    return {
        "total":             total,
        "total_unfiltered":  total_unfiltered,
        "truncated":         hit_limit,
        "offset":            offset,
        "limit":             limit,
        "packets":           page,
    }
