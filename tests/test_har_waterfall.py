"""HAR 워터폴 엔드포인트 + 파서 합성 패킷/타이밍 테스트."""
import io
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))


def _make_app():
    from fastapi.testclient import TestClient
    from main import app
    return TestClient(app)


def _har_bytes(entries: list[dict]) -> bytes:
    return json.dumps({"log": {"entries": entries}}).encode()


def _entry(url: str, status: int, *, method: str = "GET", started: str, time_ms: float,
           timings: dict, body: int = 0) -> dict:
    return {
        "startedDateTime": started,
        "time": time_ms,
        "request": {"method": method, "url": url, "headers": [], "bodySize": 0},
        "response": {"status": status, "statusText": "", "headers": [],
                     "bodySize": body, "content": {"mimeType": "application/json"}},
        "timings": timings,
    }


_SAMPLE = [
    _entry("https://api.example.com/v1/users", 200, started="2024-01-01T00:00:00.000Z",
           time_ms=123.4, body=2048,
           timings={"blocked": 1.0, "dns": 5.0, "connect": 10.0, "ssl": 8.0, "send": 0.5, "wait": 90.0, "receive": 16.9}),
    _entry("https://cdn.other.net/a.js", 404, method="POST", started="2024-01-01T00:00:00.200Z",
           time_ms=40.0, body=0,
           timings={"blocked": 0.5, "dns": -1, "connect": -1, "ssl": -1, "send": 0.2, "wait": 38, "receive": 1.3}),
    _entry("https://api.example.com/v1/ping", 500, started="2024-01-01T00:00:00.400Z",
           time_ms=12.0, body=10,
           timings={"blocked": 0, "dns": 0, "connect": 0, "ssl": 0, "send": 0.1, "wait": 11, "receive": 0.9}),
]


def _upload_har(client, entries) -> tuple[str, str]:
    r = client.post("/api/upload", files={"file": ("t.har", io.BytesIO(_har_bytes(entries)), "application/json")})
    assert r.status_code == 200, r.text
    j = r.json()
    assert j["source_type"] == "har"
    return j["upload_id"], j["capture_token"]


class TestHarWaterfallEndpoint:
    def test_returns_entries_and_summary(self):
        client = _make_app()
        uid, tok = _upload_har(client, _SAMPLE)
        r = client.get(f"/api/har/{uid}", headers={"X-Upload-Token": tok})
        assert r.status_code == 200
        d = r.json()
        assert d["count"] == 3
        assert d["summary"]["status_groups"] == {"2xx": 1, "3xx": 0, "4xx": 1, "5xx": 1, "other": 0}
        assert d["summary"]["total_bytes"] == 2058
        assert d["summary"]["total_time_ms"] > 0

    def test_entries_sorted_by_start_with_offsets(self):
        client = _make_app()
        uid, tok = _upload_har(client, _SAMPLE)
        d = client.get(f"/api/har/{uid}", headers={"X-Upload-Token": tok}).json()
        offsets = [e["start_offset_ms"] for e in d["entries"]]
        assert offsets == sorted(offsets)
        assert offsets[0] == 0.0

    def test_negative_timings_clamped_to_zero(self):
        client = _make_app()
        uid, tok = _upload_har(client, _SAMPLE)
        d = client.get(f"/api/har/{uid}", headers={"X-Upload-Token": tok}).json()
        post_entry = next(e for e in d["entries"] if e["method"] == "POST")
        # HAR -1(해당없음)은 0 으로 정규화되어야 함
        assert post_entry["timings"]["dns"] == 0.0
        assert post_entry["timings"]["ssl"] == 0.0
        assert all(v >= 0 for v in post_entry["timings"].values())

    def test_requires_capture_token(self):
        client = _make_app()
        uid, _ = _upload_har(client, _SAMPLE)
        r = client.get(f"/api/har/{uid}")
        assert r.status_code in (401, 403)

    def test_invalid_uuid_rejected(self):
        client = _make_app()
        r = client.get("/api/har/not-a-uuid")
        assert r.status_code == 400


class TestHarSyntheticPackets:
    def test_flow_has_request_response_packets(self):
        client = _make_app()
        uid, tok = _upload_har(client, _SAMPLE)
        d = client.get(f"/api/har/{uid}", headers={"X-Upload-Token": tok}).json()
        sid = d["entries"][0]["session_id"]
        flow = client.get(f"/api/flow/{uid}?session_id={sid}", headers={"X-Upload-Token": tok}).json()
        assert flow["packet_count"] >= 2
        dirs = {p["direction"] for p in flow["packets"]}
        assert dirs == {"fwd", "rev"}

    def test_distinct_hosts_get_distinct_ips(self):
        from services.parser.har_parser import HarParser
        sessions = HarParser().parse(_har_bytes(_SAMPLE))
        by_host = {s.meta["hostname"]: s.dst_ip for s in sessions}
        # 같은 호스트는 같은 IP, 다른 호스트는 다른 IP
        same_host = [s.dst_ip for s in sessions if s.meta["hostname"] == "api.example.com"]
        assert len(set(same_host)) == 1
        assert by_host["api.example.com"] != by_host["cdn.other.net"]
