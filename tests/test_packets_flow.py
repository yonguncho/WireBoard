"""GET /api/packets + GET /api/flow 엔드포인트 테스트."""
import sys
import uuid
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))


def _make_app():
    from fastapi.testclient import TestClient
    from main import app
    return TestClient(app)


def _upload_and_analyze(client, pcap_bytes: bytes) -> str:
    """pcap 업로드 + 분석 후 upload_id 반환."""
    import io
    r = client.post("/api/upload", files={"file": ("test.pcap", io.BytesIO(pcap_bytes), "application/octet-stream")})
    assert r.status_code == 200
    uid = r.json()["upload_id"]
    client.post("/api/analyze", json={"upload_id": uid})
    return uid


class TestPacketsEndpoint:
    def test_returns_packet_list(self, pcap_bytes: bytes) -> None:
        client = _make_app()
        uid = _upload_and_analyze(client, pcap_bytes)
        r = client.get(f"/api/packets/{uid}")
        assert r.status_code == 200
        body = r.json()
        assert "packets" in body
        assert "total" in body
        assert isinstance(body["packets"], list)

    def test_packet_has_required_fields(self, pcap_bytes: bytes) -> None:
        client = _make_app()
        uid = _upload_and_analyze(client, pcap_bytes)
        r = client.get(f"/api/packets/{uid}?limit=10")
        assert r.status_code == 200
        pkts = r.json()["packets"]
        if pkts:
            p = pkts[0]
            for field in ("no", "ts", "rel_ts", "src_ip", "dst_ip", "src_port", "dst_port",
                          "proto", "flags", "length", "session_id"):
                assert field in p, f"필드 누락: {field}"

    def test_packets_sorted_by_ts(self, pcap_bytes: bytes) -> None:
        client = _make_app()
        uid = _upload_and_analyze(client, pcap_bytes)
        r = client.get(f"/api/packets/{uid}?limit=200")
        assert r.status_code == 200
        pkts = r.json()["packets"]
        if len(pkts) >= 2:
            timestamps = [p["ts"] for p in pkts]
            assert timestamps == sorted(timestamps), "패킷이 타임스탬프 순으로 정렬되지 않음"

    def test_rel_ts_starts_at_zero(self, pcap_bytes: bytes) -> None:
        client = _make_app()
        uid = _upload_and_analyze(client, pcap_bytes)
        r = client.get(f"/api/packets/{uid}")
        assert r.status_code == 200
        pkts = r.json()["packets"]
        if pkts:
            assert pkts[0]["rel_ts"] == 0.0

    def test_filter_by_proto(self, pcap_bytes: bytes) -> None:
        client = _make_app()
        uid = _upload_and_analyze(client, pcap_bytes)
        r = client.get(f"/api/packets/{uid}?proto=TCP")
        assert r.status_code == 200
        pkts = r.json()["packets"]
        for p in pkts:
            assert p["proto"] == "TCP"

    def test_filter_by_flags(self, pcap_bytes: bytes) -> None:
        client = _make_app()
        uid = _upload_and_analyze(client, pcap_bytes)
        r = client.get(f"/api/packets/{uid}?flags=SYN")
        assert r.status_code == 200
        pkts = r.json()["packets"]
        for p in pkts:
            assert "SYN" in p["flags"]

    def test_pagination_offset(self, pcap_bytes: bytes) -> None:
        client = _make_app()
        uid = _upload_and_analyze(client, pcap_bytes)
        r1 = client.get(f"/api/packets/{uid}?offset=0&limit=2")
        r2 = client.get(f"/api/packets/{uid}?offset=1&limit=2")
        assert r1.status_code == 200
        assert r2.status_code == 200
        p1 = r1.json()["packets"]
        p2 = r2.json()["packets"]
        if len(p1) >= 2 and len(p2) >= 1:
            assert p1[1]["no"] == p2[0]["no"], "offset 페이지네이션이 올바르지 않음"

    def test_invalid_uuid_returns_400(self) -> None:
        client = _make_app()
        r = client.get("/api/packets/not-a-uuid")
        assert r.status_code == 400

    def test_missing_upload_returns_404(self) -> None:
        client = _make_app()
        r = client.get(f"/api/packets/{uuid.uuid4()}")
        assert r.status_code == 404

    def test_invalid_session_id_returns_400(self) -> None:
        client = _make_app()
        # 유효하지 않은 UUID → 400
        r = client.get(f"/api/packets/{uuid.uuid4()}?session_id=not-a-uuid")
        assert r.status_code == 400

    def test_unknown_session_id_returns_empty(self, pcap_bytes: bytes) -> None:
        client = _make_app()
        uid = _upload_and_analyze(client, pcap_bytes)
        # 유효하지만 존재하지 않는 session_id → total=0, packets=[]
        r = client.get(f"/api/packets/{uid}?session_id={uuid.uuid4()}")
        assert r.status_code == 200
        body = r.json()
        assert body["total"] == 0
        assert body["packets"] == []

    def test_session_id_filter_returns_only_that_session(self, pcap_bytes: bytes) -> None:
        client = _make_app()
        uid = _upload_and_analyze(client, pcap_bytes)
        # 전체 패킷에서 session_id 하나 추출
        all_r = client.get(f"/api/packets/{uid}?limit=500")
        assert all_r.status_code == 200
        all_pkts = all_r.json()["packets"]
        if not all_pkts:
            return
        target_sid = all_pkts[0]["session_id"]
        # session_id 직접 룩업 경로
        r = client.get(f"/api/packets/{uid}?session_id={target_sid}&limit=500")
        assert r.status_code == 200
        body = r.json()
        for p in body["packets"]:
            assert p["session_id"] == target_sid, "다른 세션 패킷이 포함됨"


class TestFlowEndpoint:
    def test_returns_flow_data(self, pcap_bytes: bytes) -> None:
        client = _make_app()
        uid = _upload_and_analyze(client, pcap_bytes)
        # 세션 목록 가져오기
        dd = client.get(f"/api/drilldown/{uid}?ip=192.168.1.1")
        assert dd.status_code == 200
        sessions = dd.json()["sessions"]
        assert len(sessions) >= 1
        sid = sessions[0]["session_id"]

        r = client.get(f"/api/flow/{uid}?session_id={sid}")
        assert r.status_code == 200
        body = r.json()
        assert "session" in body
        assert "packets" in body
        assert "truncated" in body

    def test_flow_session_fields(self, pcap_bytes: bytes) -> None:
        client = _make_app()
        uid = _upload_and_analyze(client, pcap_bytes)
        dd = client.get(f"/api/drilldown/{uid}?ip=192.168.1.1")
        sid = dd.json()["sessions"][0]["session_id"]
        r = client.get(f"/api/flow/{uid}?session_id={sid}")
        body = r.json()
        sess = body["session"]
        for field in ("src_ip", "dst_ip", "src_port", "dst_port", "protocol",
                      "packet_count", "bytes_sent", "bytes_recv", "duration_s"):
            assert field in sess, f"session 필드 누락: {field}"

    def test_flow_packets_have_seq_ack_flags(self, pcap_bytes: bytes) -> None:
        client = _make_app()
        uid = _upload_and_analyze(client, pcap_bytes)
        dd = client.get(f"/api/drilldown/{uid}?ip=192.168.1.1")
        sid = dd.json()["sessions"][0]["session_id"]
        r = client.get(f"/api/flow/{uid}?session_id={sid}")
        for p in r.json()["packets"]:
            assert "seq" in p
            assert "ack" in p
            assert "flags" in p
            assert "direction" in p
            assert p["direction"] in ("fwd", "rev")

    def test_invalid_session_id_returns_404(self, pcap_bytes: bytes) -> None:
        client = _make_app()
        uid = _upload_and_analyze(client, pcap_bytes)
        r = client.get(f"/api/flow/{uid}?session_id={uuid.uuid4()}")
        assert r.status_code == 404
