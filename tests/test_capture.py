# -*- coding: utf-8 -*-
"""라이브 캡처 엔드포인트 테스트 — BPF 빌더·capability·graceful degradation.

실제 패킷 캡처는 관리자 권한 + Npcap이 필요해 CI/샌드박스에서 검증 불가.
여기서는 필터 생성·검증·에러 처리(권한/드라이버 부재)를 테스트한다.
"""
import sys
import time
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


# ── F1 회귀: 자동 종료된 캡처의 버퍼 해제 ────────────────────────

class _FakeSniffer:
    """AsyncSniffer 대역 — start/stop 만 흉내내고 결과 버퍼를 들고 있는다."""

    def __init__(self, *a, **kw):
        self.results = [object()] * 5   # 수집된 패킷이 있는 상태
        self.running = True

    def start(self):
        self.running = True

    def stop(self):
        self.running = False


class TestAutoStopReleasesBuffer:
    """자동 종료 후 /stop 으로 수거되지 않은 캡처가 영구히 남지 않아야 한다."""

    @pytest.fixture
    def fast_capture(self, monkeypatch):
        import scapy.all as scapy

        monkeypatch.setattr(cap, "_capture_available", lambda: (True, ""))
        monkeypatch.setattr(cap, "_iface_list", lambda: [{"name": "test0"}])
        monkeypatch.setattr(scapy, "AsyncSniffer", _FakeSniffer)
        monkeypatch.setattr(cap, "_AUTO_STOP_GRACE_SECONDS", 0.3)
        cap._captures.clear()
        yield
        cap._captures.clear()

    def _start(self):
        import asyncio

        # asyncio.run() 은 루프를 닫아버려, get_event_loop() 를 쓰는 다른
        # 테스트 모듈(test_reputation_edge 등)을 깨뜨린다. 기존 패턴을 따른다.
        body = cap.CaptureStartRequest(iface="test0", max_packets=100, max_seconds=1)
        loop = asyncio.get_event_loop()
        return loop.run_until_complete(cap.capture_start(body))["capture_id"]

    def test_entry_is_removed_after_grace_period(self, fast_capture):
        cap_id = self._start()
        assert cap_id in cap._captures
        time.sleep(1.0 + 0.3 + 0.7)          # max_seconds + grace + 여유
        assert cap_id not in cap._captures, "자동 종료된 캡처가 _captures 에 남았다"

    def test_buffer_is_emptied_so_ram_is_freed(self, fast_capture):
        cap_id = self._start()
        sniffer = cap._captures[cap_id].sniffer
        time.sleep(1.0 + 0.3 + 0.7)
        assert sniffer.results == [], "패킷 버퍼가 해제되지 않았다"

    def test_explicit_stop_still_wins_before_grace(self, fast_capture):
        """정상 흐름(UI 는 1초 폴링) 에서는 reaper 가 데이터를 뺏어가면 안 된다."""
        cap_id = self._start()
        time.sleep(1.0 + 0.1)                # 자동 종료 직후, 유예 만료 전
        c = cap._captures.get(cap_id)
        assert c is not None, "유예 시간 안인데 항목이 사라졌다"
        assert len(c.sniffer.results) == 5, "유예 시간 안인데 버퍼가 비워졌다"
