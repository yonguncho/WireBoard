"""GET /api/geoip/{upload_id} 테스트."""
import uuid
import pytest
from fastapi.testclient import TestClient

def _make_capture(client, attacks, sessions_meta):
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))
    from store.session_store import ParsedCapture
    from models.session import SessionModel

    sessions = [
        SessionModel(
            session_id=str(uuid.uuid4()),
            src_ip="192.168.1.1", dst_ip="1.2.3.4",
            src_port=12345, dst_port=443, protocol="TCP",
            start_ts=1748000000.0, end_ts=1748000010.0,
            bytes_sent=1000, bytes_recv=500, packet_count=10,
            payload_length=800, meta=m,
        )
        for m in sessions_meta
    ]
    capture = ParsedCapture(sessions=sessions, source_type="pcap", attacks=attacks, target_ip="1.2.3.4")
    uid = str(uuid.uuid4())
    client.app.state.session_store.put(uid, capture)
    return uid

def test_geoip_basic(api_client):
    attacks = [{"attack_type": "PortScan", "severity": "high", "mitre_id": "T1046",
                "description": "스캔", "src_ip": "8.8.8.8"}]
    uid = _make_capture(api_client, attacks, [{}])
    resp = api_client.get(f"/api/geoip/{uid}")
    assert resp.status_code == 200
    data = resp.json()
    assert "entries" in data
    assert len(data["entries"]) >= 1
    entry = data["entries"][0]
    assert "ip" in entry and "country_name" in entry and "country_code" in entry

def test_geoip_no_attacks(api_client):
    uid = _make_capture(api_client, [], [{}])
    resp = api_client.get(f"/api/geoip/{uid}")
    assert resp.status_code == 200
    # 공격 없어도 외부 IP는 포함될 수 있음

def test_geoip_invalid_uuid(api_client):
    resp = api_client.get("/api/geoip/not-a-uuid")
    assert resp.status_code == 400

def test_geoip_not_found(api_client):
    resp = api_client.get(f"/api/geoip/{uuid.uuid4()}")
    assert resp.status_code == 404
