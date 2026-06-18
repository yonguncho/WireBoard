"""GET /api/flow/{upload_id}?session_id=<sid> — 패킷 단위 흐름 조회."""
from fastapi import APIRouter, Header, HTTPException, Query, Request

from utils.constants import UUID_RE
from utils.capture_auth import check_capture_token
from services.payload_extractor.tls_extractor import TLSExtractor, cipher_name

router = APIRouter()

_PARSER_MAX = 200  # pcap_parser._MAX_PKTS_PER_FLOW 와 동기화
_tls_extractor = TLSExtractor()


def _reassemble(pkts, direction: str, cap: int = 8192) -> bytes:
    """한 방향(fwd/rev) payload를 시간순으로 이어붙여 TLS 레코드 재조립."""
    buf = bytearray()
    for p in pkts:
        if p.direction == direction and p.payload_hex:
            try:
                buf.extend(bytes.fromhex(p.payload_hex))
            except ValueError:
                continue
            if len(buf) >= cap:
                break
    return bytes(buf)


def _extract_tls(session, pkts) -> dict | None:
    """세션 패킷에서 TLS 핸드셰이크(ClientHello/ServerHello) 정보를 추출."""
    client_bytes = _reassemble(pkts, "fwd")
    server_bytes = _reassemble(pkts, "rev")
    # TLS 레코드(0x16 0x03)로 시작하지 않으면 TLS 아님
    looks_tls = (
        (len(client_bytes) >= 2 and client_bytes[0] == 0x16 and client_bytes[1] == 0x03)
        or session.dst_port == 443 or session.src_port == 443
    )
    if not looks_tls:
        return None

    ch = _tls_extractor.extract(client_bytes)
    sh_cipher, sh_version = _tls_extractor.extract_server_hello(server_bytes)

    if not (ch.sni or ch.cipher_suites or sh_cipher):
        return None

    return {
        "sni": ch.sni,
        "alpn": ch.alpn,
        "ja4": ch.ja4,
        "client_version": ch.legacy_version,
        "negotiated_version": ch.negotiated_version or sh_version,
        "chosen_cipher": cipher_name(sh_cipher) if sh_cipher is not None else None,
        "offered_ciphers": [cipher_name(c) for c in ch.cipher_suites[:16]],
        "offered_cipher_count": len(ch.cipher_suites),
    }


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
        raise HTTPException(status_code=404, detail={"code": "upload_not_found", "message": "Upload not found"})

    check_capture_token(capture, x_upload_token)

    session = next((s for s in capture.sessions if s.session_id == session_id), None)
    if session is None:
        raise HTTPException(status_code=404, detail={"code": "session_not_found", "message": "Session not found"})

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
        "tls":           _extract_tls(session, raw_pkts_all),
    }
