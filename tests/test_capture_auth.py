# -*- coding: utf-8 -*-
"""F1 회귀 — 라이브 캡처 status/stop 의 X-Upload-Token 가드.

v7.13.1 까지 /api/capture/{id}/status 와 /stop 은 토큰을 요구하지 않았다.
check_capture_token 이 capture.py 에 임포트만 되어 있고 호출되지 않던 상태였다.
"""
import asyncio
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from fastapi import HTTPException
from routers import capture as cap


class _FakeSniffer:
    def __init__(self, *a, **kw):
        self.results = [object()] * 3
        self.running = True

    def start(self):
        self.running = True

    def stop(self):
        self.running = False


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


@pytest.fixture
def started(monkeypatch):
    """캡처 하나를 시작하고 (id, token) 을 돌려준다."""
    import scapy.all as scapy

    monkeypatch.setattr(cap, "_capture_available", lambda: (True, ""))
    monkeypatch.setattr(cap, "_iface_list", lambda: [{"name": "test0"}])
    monkeypatch.setattr(scapy, "AsyncSniffer", _FakeSniffer)
    cap._captures.clear()
    body = cap.CaptureStartRequest(iface="test0", max_packets=10, max_seconds=300)
    r = _run(cap.capture_start(body))
    yield r["capture_id"], r["capture_token"]
    cap._captures.clear()


class TestStartIssuesToken:
    def test_start_returns_a_token(self, started):
        _, token = started
        assert isinstance(token, str) and len(token) == 32   # secrets.token_hex(16)

    def test_token_is_stored_on_the_capture(self, started):
        cap_id, token = started
        assert cap._captures[cap_id].capture_token == token

    def test_capture_token_has_no_default(self):
        """빈 토큰이면 check_capture_token 이 통째로 무력화되므로 기본값이 없어야 한다."""
        import dataclasses
        f = {x.name: x for x in dataclasses.fields(cap._LiveCapture)}["capture_token"]
        assert f.default is dataclasses.MISSING
        assert f.default_factory is dataclasses.MISSING


class TestStatusGuard:
    def test_no_token_is_rejected(self, started):
        cap_id, _ = started
        with pytest.raises(HTTPException) as e:
            _run(cap.capture_status(cap_id, None))
        assert e.value.status_code == 403

    def test_wrong_token_is_rejected(self, started):
        cap_id, _ = started
        with pytest.raises(HTTPException) as e:
            _run(cap.capture_status(cap_id, "0" * 32))
        assert e.value.status_code == 403

    def test_correct_token_is_accepted(self, started):
        cap_id, token = started
        out = _run(cap.capture_status(cap_id, token))
        assert out["capture_id"] == cap_id
        assert out["packet_count"] == 3

    def test_unknown_id_is_404_not_403(self, started):
        """404 판정이 토큰 검사보다 앞서야 한다 (upload.py 와 동일한 순서)."""
        with pytest.raises(HTTPException) as e:
            _run(cap.capture_status("6415e3c7-7f7f-4ac0-9cd6-2387c7d891da", None))
        assert e.value.status_code == 404


class TestStopGuard:
    def test_no_token_is_rejected_and_capture_survives(self, started):
        cap_id, _ = started
        with pytest.raises(HTTPException) as e:
            _run(cap.capture_stop(cap_id, None, None))
        assert e.value.status_code == 403
        # 거부된 요청이 캡처를 소비해서는 안 된다
        assert cap_id in cap._captures

    def test_wrong_token_is_rejected(self, started):
        cap_id, _ = started
        with pytest.raises(HTTPException) as e:
            _run(cap.capture_stop(cap_id, None, "f" * 32))
        assert e.value.status_code == 403
        assert cap_id in cap._captures
