"""FilterTranslator 단위 테스트 + POST /api/filter 엔드포인트 테스트."""
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


def _upload_and_analyze(client, pcap_bytes: bytes) -> tuple[str, str]:
    r = client.post("/api/upload", files={"file": ("t.pcap", io.BytesIO(pcap_bytes), "application/octet-stream")})
    assert r.status_code == 200
    uid = r.json()["upload_id"]
    capture_token = r.json()["capture_token"]
    client.post("/api/analyze", json={"upload_id": uid}, headers={"X-Upload-Token": capture_token})
    return uid, capture_token


# ──────────────────── FilterTranslator 단위 테스트 ─────────────────────


class TestFilterTranslatorIp:
    def setup_method(self):
        from services.filter_translator import FilterTranslator
        self.t = FilterTranslator()

    def test_ip_only_any_direction(self):
        r = self.t.translate("192.168.1.1")
        assert "192.168.1.1" in r.filter_expr
        assert "ip.src" in r.filter_expr or "ip.dst" in r.filter_expr

    def test_ip_with_from_keyword(self):
        r = self.t.translate("from 192.168.1.1")
        assert "ip.src == 192.168.1.1" in r.filter_expr

    def test_ip_with_src_keyword(self):
        r = self.t.translate("src 10.0.0.1")
        assert "ip.src == 10.0.0.1" in r.filter_expr

    def test_ip_with_to_keyword(self):
        r = self.t.translate("to 10.0.0.2")
        assert "ip.dst == 10.0.0.2" in r.filter_expr

    def test_ip_with_dst_keyword(self):
        r = self.t.translate("dst 10.0.0.2")
        assert "ip.dst == 10.0.0.2" in r.filter_expr

    def test_two_ips_both_in_expr(self):
        r = self.t.translate("192.168.1.1 10.0.0.1")
        assert "192.168.1.1" in r.filter_expr
        assert "10.0.0.1" in r.filter_expr

    def test_unknown_query_returns_frame_token(self):
        r = self.t.translate("something random")
        assert r.tokens == ["frame"]
        assert r.filter_expr == "frame"


class TestFilterTranslatorProtocol:
    def setup_method(self):
        from services.filter_translator import FilterTranslator
        self.t = FilterTranslator()

    def test_tcp_token(self):
        r = self.t.translate("tcp traffic")
        assert "tcp" in r.tokens

    def test_udp_token(self):
        r = self.t.translate("udp")
        assert "udp" in r.tokens

    def test_dns_token(self):
        r = self.t.translate("dns queries")
        assert "dns" in r.tokens

    def test_https_maps_to_tls_not_http(self):
        r = self.t.translate("https")
        assert "tls" in r.tokens
        assert "http" not in r.tokens

    def test_tls_token(self):
        r = self.t.translate("tls session")
        assert "tls" in r.tokens

    def test_icmp_token(self):
        r = self.t.translate("icmp")
        assert "icmp" in r.tokens


class TestFilterTranslatorPort:
    def setup_method(self):
        from services.filter_translator import FilterTranslator
        self.t = FilterTranslator()

    def test_port_keyword(self):
        r = self.t.translate("port 443")
        assert "443" in r.filter_expr
        assert "tcp.port" in r.filter_expr or "udp.port" in r.filter_expr

    def test_port_number_only(self):
        r = self.t.translate("80번 포트")
        assert "80" in r.filter_expr

    def test_combined_ip_and_port(self):
        r = self.t.translate("192.168.1.1 port 443")
        assert "192.168.1.1" in r.filter_expr
        assert "443" in r.filter_expr

    def test_combined_ip_proto_port(self):
        r = self.t.translate("tcp from 192.168.1.1 port 80")
        assert "192.168.1.1" in r.filter_expr
        assert "80" in r.filter_expr
        assert "tcp" in r.tokens


# ──────────────────── /api/filter HTTP 엔드포인트 ─────────────────────


class TestFilterEndpoint:
    def test_filter_returns_200(self, pcap_bytes):
        client = _make_app()
        uid, capture_token = _upload_and_analyze(client, pcap_bytes)
        r = client.post("/api/filter", json={"upload_id": uid, "query": "192.168.1.1"},
                        headers={"X-Upload-Token": capture_token})
        assert r.status_code == 200

    def test_filter_response_has_required_keys(self, pcap_bytes):
        client = _make_app()
        uid, capture_token = _upload_and_analyze(client, pcap_bytes)
        r = client.post("/api/filter", json={"upload_id": uid, "query": "tcp"},
                        headers={"X-Upload-Token": capture_token})
        body = r.json()
        assert "success" in body
        assert "filter_expr" in body
        assert "matched_count" in body
        assert "sessions" in body

    def test_filter_matched_count_is_int(self, pcap_bytes):
        client = _make_app()
        uid, capture_token = _upload_and_analyze(client, pcap_bytes)
        r = client.post("/api/filter", json={"upload_id": uid, "query": "tcp"},
                        headers={"X-Upload-Token": capture_token})
        assert isinstance(r.json()["matched_count"], int)

    def test_filter_sessions_is_list(self, pcap_bytes):
        client = _make_app()
        uid, capture_token = _upload_and_analyze(client, pcap_bytes)
        r = client.post("/api/filter", json={"upload_id": uid, "query": "tcp"},
                        headers={"X-Upload-Token": capture_token})
        assert isinstance(r.json()["sessions"], list)

    def test_filter_by_ip_matches_session(self, pcap_bytes):
        client = _make_app()
        uid, capture_token = _upload_and_analyze(client, pcap_bytes)
        r = client.post("/api/filter", json={"upload_id": uid, "query": "192.168.1.1"},
                        headers={"X-Upload-Token": capture_token})
        body = r.json()
        if body["matched_count"] > 0:
            for s in body["sessions"]:
                assert s["src_ip"] == "192.168.1.1" or s["dst_ip"] == "192.168.1.1"

    def test_filter_empty_query_success_false(self, pcap_bytes):
        client = _make_app()
        uid, capture_token = _upload_and_analyze(client, pcap_bytes)
        r = client.post("/api/filter", json={"upload_id": uid, "query": "randomgarbage"},
                        headers={"X-Upload-Token": capture_token})
        assert r.status_code == 200
        assert r.json()["success"] is False

    def test_filter_invalid_uuid_returns_400(self):
        client = _make_app()
        r = client.post("/api/filter", json={"upload_id": "not-a-uuid", "query": "tcp"})
        assert r.status_code == 400

    def test_filter_unknown_upload_id_returns_404(self):
        client = _make_app()
        r = client.post("/api/filter", json={"upload_id": str(uuid.uuid4()), "query": "tcp"})
        assert r.status_code == 404

    def test_filter_translate_same_behavior(self, pcap_bytes):
        client = _make_app()
        uid, capture_token = _upload_and_analyze(client, pcap_bytes)
        r1 = client.post("/api/filter", json={"upload_id": uid, "query": "tcp"},
                         headers={"X-Upload-Token": capture_token})
        r2 = client.post("/api/filter/translate", json={"upload_id": uid, "query": "tcp"},
                         headers={"X-Upload-Token": capture_token})
        assert r1.status_code == r2.status_code == 200
        assert r1.json()["filter_expr"] == r2.json()["filter_expr"]

    def test_filter_session_fields_present(self, pcap_bytes):
        client = _make_app()
        uid, capture_token = _upload_and_analyze(client, pcap_bytes)
        r = client.post("/api/filter", json={"upload_id": uid, "query": "192.168.1.1"},
                        headers={"X-Upload-Token": capture_token})
        for s in r.json()["sessions"]:
            for field in ("session_id", "src_ip", "dst_ip", "src_port", "dst_port", "protocol"):
                assert field in s, f"필드 누락: {field}"
