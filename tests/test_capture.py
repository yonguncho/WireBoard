# -*- coding: utf-8 -*-
"""라이브 캡처 엔드포인트 테스트 — BPF 빌더·capability·graceful degradation.

실제 패킷 캡처는 관리자 권한 + Npcap이 필요해 CI/샌드박스에서 검증 불가.
여기서는 필터 생성·검증·에러 처리(권한/드라이버 부재)를 테스트한다.
"""
import sys
import uuid
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from fastapi import HTTPException
from routers import capture as cap


class TestBpfBuilder:
    def test_all_fields(self):
        bpf = cap._build_bpf("10.0.0.1", "10.0.0.2", 443, None)
        assert "src host 10.0.0.1" in bpf
        assert "dst host 10.0.0.2" in bpf
        assert "port 443" in bpf
        assert " and " in bpf

    def test_host_filter(self):
        assert cap._build_bpf(None, None, None, "8.8.8.8") == "host 8.8.8.8"

    def test_empty(self):
        assert cap._build_bpf(None, None, None, None) == ""

    def test_invalid_ip_rejected(self):
        with pytest.raises(HTTPException) as e:
            cap._build_bpf("not-an-ip", None, None, None)
        assert e.value.status_code == 400

    def test_invalid_port_rejected(self):
        with pytest.raises(HTTPException) as e:
            cap._build_bpf(None, None, 99999, None)
        assert e.value.status_code == 400

    def test_ipv6_host(self):
        assert cap._build_bpf(None, None, None, "2001:db8::1") == "host 2001:db8::1"


class TestCaptureEndpoints:
    def test_capability_endpoint(self, api_client):
        r = api_client.get("/api/capture/capability")
        assert r.status_code == 200
        body = r.json()
        assert "available" in body
        assert isinstance(body["available"], bool)

    def test_interfaces_endpoint(self, api_client):
        r = api_client.get("/api/capture/interfaces")
        # 캡처 가능(Npcap 있음) → 200 + 목록 / 불가 → 501
        assert r.status_code in (200, 501)
        if r.status_code == 200:
            assert "interfaces" in r.json()
            assert isinstance(r.json()["interfaces"], list)

    def test_status_unknown_capture_404(self, api_client):
        r = api_client.get(f"/api/capture/{uuid.uuid4()}/status")
        assert r.status_code == 404

    def test_status_bad_uuid_400(self, api_client):
        r = api_client.get("/api/capture/not-a-uuid/status")
        assert r.status_code == 400

    def test_stop_unknown_capture_404(self, api_client):
        r = api_client.post(f"/api/capture/{uuid.uuid4()}/stop")
        assert r.status_code == 404

    def test_start_invalid_iface_or_unavailable(self, api_client):
        # 존재하지 않는 인터페이스 → 400(가능 시) 또는 501(캡처 불가 시)
        r = api_client.post("/api/capture/start", json={"iface": "__nonexistent__"})
        assert r.status_code in (400, 501, 403)

    def test_start_invalid_ip_or_unavailable(self, api_client):
        r = api_client.post("/api/capture/start",
                            json={"iface": "__nonexistent__", "src": "bad-ip"})
        # capability 없으면 501, 있으면 iface 검증(400) 또는 ip 검증(400)
        assert r.status_code in (400, 501, 403)
