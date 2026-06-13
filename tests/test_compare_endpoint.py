"""POST /api/compare HTTP 엔드포인트 테스트."""
import io
import sys
import uuid
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))


def _make_app():
    from fastapi.testclient import TestClient
    from main import app
    return TestClient(app)


def _upload_and_analyze(client, pcap_bytes: bytes, target_ip: str = "192.168.1.2") -> tuple[str, str]:
    r = client.post("/api/upload", files={"file": ("t.pcap", io.BytesIO(pcap_bytes), "application/octet-stream")})
    assert r.status_code == 200
    uid = r.json()["upload_id"]
    capture_token = r.json()["capture_token"]
    client.post("/api/analyze", json={"upload_id": uid, "target_ip": target_ip},
                headers={"X-Upload-Token": capture_token})
    return uid, capture_token


class TestCompareEndpointSuccess:
    def test_compare_two_uploads_returns_200(self, pcap_bytes):
        client = _make_app()
        uid_a, token_a = _upload_and_analyze(client, pcap_bytes)
        uid_b, token_b = _upload_and_analyze(client, pcap_bytes)
        r = client.post("/api/compare", json={"base_upload_id": uid_a, "current_upload_id": uid_b},
                        headers={"X-Upload-Token-Base": token_a, "X-Upload-Token-Current": token_b})
        assert r.status_code == 200

    def test_compare_response_has_required_keys(self, pcap_bytes):
        client = _make_app()
        uid_a, token_a = _upload_and_analyze(client, pcap_bytes)
        uid_b, token_b = _upload_and_analyze(client, pcap_bytes)
        r = client.post("/api/compare", json={"base_upload_id": uid_a, "current_upload_id": uid_b},
                        headers={"X-Upload-Token-Base": token_a, "X-Upload-Token-Current": token_b})
        body = r.json()
        for key in ("new_ips", "removed_ips", "common_ips", "new_ports",
                    "traffic_delta_pct", "protocol_diff", "byte_ratio"):
            assert key in body, f"키 누락: {key}"

    def test_compare_same_capture_no_new_ips(self, pcap_bytes):
        client = _make_app()
        uid_a, token_a = _upload_and_analyze(client, pcap_bytes)
        uid_b, token_b = _upload_and_analyze(client, pcap_bytes)
        body = client.post("/api/compare", json={"base_upload_id": uid_a, "current_upload_id": uid_b},
                           headers={"X-Upload-Token-Base": token_a, "X-Upload-Token-Current": token_b}).json()
        assert body["new_ips"] == []
        assert body["removed_ips"] == []

    def test_compare_same_capture_delta_zero(self, pcap_bytes):
        client = _make_app()
        uid_a, token_a = _upload_and_analyze(client, pcap_bytes)
        uid_b, token_b = _upload_and_analyze(client, pcap_bytes)
        body = client.post("/api/compare", json={"base_upload_id": uid_a, "current_upload_id": uid_b},
                           headers={"X-Upload-Token-Base": token_a, "X-Upload-Token-Current": token_b}).json()
        assert body["traffic_delta_pct"] == 0.0

    def test_compare_same_capture_has_common_ips(self, pcap_bytes):
        client = _make_app()
        uid_a, token_a = _upload_and_analyze(client, pcap_bytes)
        uid_b, token_b = _upload_and_analyze(client, pcap_bytes)
        body = client.post("/api/compare", json={"base_upload_id": uid_a, "current_upload_id": uid_b},
                           headers={"X-Upload-Token-Base": token_a, "X-Upload-Token-Current": token_b}).json()
        assert len(body["common_ips"]) > 0

    def test_compare_new_ips_is_list(self, pcap_bytes):
        client = _make_app()
        uid_a, token_a = _upload_and_analyze(client, pcap_bytes)
        uid_b, token_b = _upload_and_analyze(client, pcap_bytes)
        body = client.post("/api/compare", json={"base_upload_id": uid_a, "current_upload_id": uid_b},
                           headers={"X-Upload-Token-Base": token_a, "X-Upload-Token-Current": token_b}).json()
        assert isinstance(body["new_ips"], list)
        assert isinstance(body["removed_ips"], list)
        assert isinstance(body["common_ips"], list)
        assert isinstance(body["new_ports"], list)

    def test_compare_protocol_diff_is_dict(self, pcap_bytes):
        client = _make_app()
        uid_a, token_a = _upload_and_analyze(client, pcap_bytes)
        uid_b, token_b = _upload_and_analyze(client, pcap_bytes)
        body = client.post("/api/compare", json={"base_upload_id": uid_a, "current_upload_id": uid_b},
                           headers={"X-Upload-Token-Base": token_a, "X-Upload-Token-Current": token_b}).json()
        assert isinstance(body["protocol_diff"], dict)

    def test_compare_byte_ratio_has_totals(self, pcap_bytes):
        client = _make_app()
        uid_a, token_a = _upload_and_analyze(client, pcap_bytes)
        uid_b, token_b = _upload_and_analyze(client, pcap_bytes)
        body = client.post("/api/compare", json={"base_upload_id": uid_a, "current_upload_id": uid_b},
                           headers={"X-Upload-Token-Base": token_a, "X-Upload-Token-Current": token_b}).json()
        br = body["byte_ratio"]
        assert "a_total" in br
        assert "b_total" in br


class TestCompareEndpointErrors:
    def test_invalid_base_uuid_returns_400(self, pcap_bytes):
        client = _make_app()
        uid_b, token_b = _upload_and_analyze(client, pcap_bytes)
        r = client.post("/api/compare", json={"base_upload_id": "not-a-uuid", "current_upload_id": uid_b},
                        headers={"X-Upload-Token-Current": token_b})
        assert r.status_code == 400

    def test_invalid_current_uuid_returns_400(self, pcap_bytes):
        client = _make_app()
        uid_a, token_a = _upload_and_analyze(client, pcap_bytes)
        r = client.post("/api/compare", json={"base_upload_id": uid_a, "current_upload_id": "not-a-uuid"},
                        headers={"X-Upload-Token-Base": token_a})
        assert r.status_code == 400

    def test_unknown_base_upload_returns_404(self, pcap_bytes):
        client = _make_app()
        uid_b, token_b = _upload_and_analyze(client, pcap_bytes)
        r = client.post("/api/compare", json={"base_upload_id": str(uuid.uuid4()), "current_upload_id": uid_b},
                        headers={"X-Upload-Token-Current": token_b})
        assert r.status_code == 404

    def test_unknown_current_upload_returns_404(self, pcap_bytes):
        client = _make_app()
        uid_a, token_a = _upload_and_analyze(client, pcap_bytes)
        r = client.post("/api/compare", json={"base_upload_id": uid_a, "current_upload_id": str(uuid.uuid4())},
                        headers={"X-Upload-Token-Base": token_a})
        assert r.status_code == 404
