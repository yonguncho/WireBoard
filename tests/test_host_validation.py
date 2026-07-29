"""F2 회귀 테스트 — Host/Origin 검증 미들웨어.

DNS 리바인딩(공격자 도메인이 127.0.0.1로 해석된 상태)과 교차 출처 호출이
차단되는지 확인한다. 정상 루프백 요청은 그대로 통과해야 한다.
"""
import pytest
from fastapi.testclient import TestClient

from main import app, _host_name

client = TestClient(app)


class TestHostHeader:
    def test_loopback_host_is_allowed(self):
        r = client.get("/health", headers={"Host": "127.0.0.1:8764"})
        assert r.status_code == 200

    def test_localhost_host_is_allowed(self):
        r = client.get("/health", headers={"Host": "localhost:8765"})
        assert r.status_code == 200

    def test_rebound_attacker_host_is_rejected(self):
        r = client.get("/health", headers={"Host": "attacker.example:8764"})
        assert r.status_code == 400
        assert r.json()["detail"]["code"] == "invalid_host"

    def test_rebinding_is_blocked_on_the_sensitive_routes_too(self):
        # 리바인딩이 노리는 실제 표적: 라이선스 이메일과 인터페이스 목록
        for path in ("/api/license/status", "/api/capture/interfaces"):
            r = client.get(path, headers={"Host": "evil.test"})
            assert r.status_code == 400, path

    def test_bare_hostname_without_port_is_rejected(self):
        r = client.get("/health", headers={"Host": "attacker.example"})
        assert r.status_code == 400


class TestOriginHeader:
    def test_same_origin_is_allowed(self):
        r = client.get("/health", headers={"Origin": "http://127.0.0.1:8764"})
        assert r.status_code == 200

    def test_cross_origin_is_denied(self):
        r = client.get("/health", headers={"Origin": "https://attacker.example"})
        assert r.status_code == 403
        assert r.json()["detail"]["code"] == "cross_origin_denied"

    def test_null_origin_is_denied(self):
        # 샌드박스 iframe / file:// 출처
        r = client.get("/health", headers={"Origin": "null"})
        assert r.status_code == 403

    def test_cross_origin_capture_start_is_denied(self):
        """F1의 CSRF 진입 벡터 — 빈 타입 Blob 본문의 교차 출처 POST."""
        r = client.post(
            "/api/capture/start",
            json={"iface": "Ethernet", "max_packets": 100000, "max_seconds": 300},
            headers={"Origin": "https://attacker.example"},
        )
        assert r.status_code == 403
        assert r.json()["detail"]["code"] == "cross_origin_denied"

    def test_no_origin_header_still_works(self):
        # 로컬 CLI·동일 출처 GET은 Origin을 보내지 않는다
        r = client.get("/health")
        assert r.status_code == 200


class TestHostNameParsing:
    @pytest.mark.parametrize("value,expected", [
        ("127.0.0.1:8764", "127.0.0.1"),
        ("127.0.0.1", "127.0.0.1"),
        ("LocalHost:8765", "localhost"),
        ("[::1]:8764", "[::1]"),
        ("[::1]", "[::1]"),
        ("  attacker.example:80  ", "attacker.example"),
    ])
    def test_port_is_stripped_and_case_folded(self, value, expected):
        assert _host_name(value) == expected
