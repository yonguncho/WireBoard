# -*- coding: utf-8 -*-
"""HAR 견고성 회귀 테스트 — BOM·비표준 엔트리·업로드 경로."""
import io
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from services.parser.har_parser import HarParser


def _har(entries) -> bytes:
    return json.dumps({"log": {"version": "1.2", "entries": entries}}).encode("utf-8")


_ENTRY = {
    "request": {"method": "GET", "url": "https://example.com/", "headers": []},
    "response": {"status": 200, "headers": [], "content": {}},
    "timings": {"wait": 10}, "time": 10,
    "startedDateTime": "2026-01-01T00:00:00.000Z",
}


class TestHarBom:
    def test_bom_prefixed_har_detected(self):
        data = b"\xef\xbb\xbf" + _har([_ENTRY])
        assert HarParser().detect(data) is True

    def test_bom_prefixed_har_parses(self):
        data = b"\xef\xbb\xbf" + _har([_ENTRY])
        sessions = HarParser().parse(data)
        assert len(sessions) == 1
        assert sessions[0].meta["url"] == "https://example.com/"


class TestHarBadEntries:
    def test_missing_request_entry_skipped_not_fatal(self):
        data = _har([{"response": {"status": 200}}, _ENTRY])
        warnings = []
        sessions = HarParser().parse(data, warnings)
        assert len(sessions) == 1  # 정상 1개는 살아남음
        assert any("skipped" in w for w in warnings)

    def test_entry_without_url_skipped(self):
        data = _har([{"request": {"method": "GET"}}, _ENTRY])
        sessions = HarParser().parse(data)
        assert len(sessions) == 1

    def test_non_dict_entry_skipped(self):
        data = _har(["garbage", 123, _ENTRY])
        sessions = HarParser().parse(data)
        assert len(sessions) == 1

    def test_all_bad_entries_returns_empty_not_crash(self):
        data = _har([{"foo": "bar"}, {"request": {}}])
        sessions = HarParser().parse(data)
        assert sessions == []

    def test_weird_port_clamped(self):
        e = dict(_ENTRY)
        e = {**_ENTRY, "request": {"method": "GET", "url": "http://h.com:99999/"}}
        # urlparse는 99999 포트를 raise할 수 있음 → 엔트리 skip 되거나 클램프. 크래시만 안 하면 OK.
        sessions = HarParser().parse(_har([e, _ENTRY]))
        assert len(sessions) >= 1


class TestHarUploadPath:
    def test_bom_har_uploads_ok(self, api_client):
        data = b"\xef\xbb\xbf" + _har([_ENTRY, _ENTRY])
        r = api_client.post("/api/upload",
                            files={"file": ("t.har", io.BytesIO(data), "application/json")})
        assert r.status_code == 200, r.text
        assert r.json()["source_type"] == "har"
        assert r.json()["session_count"] == 2

    def test_mixed_har_uploads_ok(self, api_client):
        data = _har([{"_type": "ws"}, {"request": {"method": "GET"}}, _ENTRY])
        r = api_client.post("/api/upload",
                            files={"file": ("m.har", io.BytesIO(data), "application/json")})
        assert r.status_code == 200
        assert r.json()["session_count"] == 1
