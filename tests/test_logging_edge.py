# -*- coding: utf-8 -*-
"""Edge cases: structured logging — request/response/error events are valid JSON with required fields."""
import io
import json
import os
import sys
import uuid

import pytest

BACKEND_DIR = os.path.join(os.path.dirname(__file__), "..", "backend")
sys.path.insert(0, os.path.abspath(BACKEND_DIR))

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient
from main import app


client = TestClient(app)


def _capture_stdout(func, *args, **kwargs):
    """Capture print() output from middleware."""
    import contextlib
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        result = func(*args, **kwargs)
    return result, buf.getvalue()


# ── Request/response log events ─────────────────────────────────

class TestRequestResponseLogging:
    def test_request_event_is_valid_json(self):
        _, output = _capture_stdout(client.get, "/api/health")
        lines = [l for l in output.strip().split("\n") if l.strip()]
        assert len(lines) >= 1
        parsed = json.loads(lines[0])
        assert parsed["event"] == "request"

    def test_request_event_has_required_fields(self):
        _, output = _capture_stdout(client.get, "/api/health")
        lines = [l for l in output.strip().split("\n") if l.strip()]
        request_line = next(l for l in lines if '"event": "request"' in l or json.loads(l).get("event") == "request")
        parsed = json.loads(request_line)
        for field in ("event", "method", "path", "requestId", "ts"):
            assert field in parsed, f"Missing field {field!r} in request event"

    def test_response_event_is_valid_json(self):
        _, output = _capture_stdout(client.get, "/api/health")
        lines = [l for l in output.strip().split("\n") if l.strip()]
        resp_lines = [l for l in lines if json.loads(l).get("event") == "response"]
        assert len(resp_lines) >= 1

    def test_response_event_has_required_fields(self):
        _, output = _capture_stdout(client.get, "/api/health")
        lines = [l for l in output.strip().split("\n") if l.strip()]
        resp_line = next((l for l in lines if json.loads(l).get("event") == "response"), None)
        assert resp_line is not None
        parsed = json.loads(resp_line)
        for field in ("event", "status", "durationMs", "requestId"):
            assert field in parsed, f"Missing field {field!r} in response event"

    def test_request_id_consistent_across_events(self):
        _, output = _capture_stdout(client.get, "/api/health")
        lines = [l for l in output.strip().split("\n") if l.strip()]
        events = [json.loads(l) for l in lines]
        req_ids = {e["requestId"] for e in events if "requestId" in e}
        assert len(req_ids) == 1, f"requestId mismatch across events: {req_ids}"

    def test_request_id_is_uuid_format(self):
        _, output = _capture_stdout(client.get, "/api/health")
        lines = [l for l in output.strip().split("\n") if l.strip()]
        event = json.loads(lines[0])
        rid = event.get("requestId", "")
        import re
        assert re.match(r"^[0-9a-f-]{36}$", rid), f"requestId not UUID: {rid!r}"

    def test_duration_ms_is_non_negative(self):
        _, output = _capture_stdout(client.get, "/api/health")
        lines = [l for l in output.strip().split("\n") if l.strip()]
        resp_line = next((l for l in lines if json.loads(l).get("event") == "response"), None)
        assert resp_line is not None
        parsed = json.loads(resp_line)
        assert parsed["durationMs"] >= 0

    def test_method_captured_correctly(self):
        _, output = _capture_stdout(client.get, "/api/health")
        lines = [l for l in output.strip().split("\n") if l.strip()]
        req_line = next(l for l in lines if json.loads(l).get("event") == "request")
        parsed = json.loads(req_line)
        assert parsed["method"] == "GET"

    def test_path_captured_correctly(self):
        _, output = _capture_stdout(client.get, "/api/health")
        lines = [l for l in output.strip().split("\n") if l.strip()]
        req_line = next(l for l in lines if json.loads(l).get("event") == "request")
        parsed = json.loads(req_line)
        assert parsed["path"] == "/api/health"

    def test_post_method_captured(self):
        _, output = _capture_stdout(
            client.post, "/api/analyze",
            json={"upload_id": "not-a-uuid", "target_ip": "1.2.3.4"},
        )
        lines = [l for l in output.strip().split("\n") if l.strip()]
        req_line = next(l for l in lines if json.loads(l).get("event") == "request")
        parsed = json.loads(req_line)
        assert parsed["method"] == "POST"

    def test_404_response_status_logged(self):
        _, output = _capture_stdout(client.get, "/api/nonexistent-route-xyz")
        lines = [l for l in output.strip().split("\n") if l.strip()]
        resp_lines = [json.loads(l) for l in lines if json.loads(l).get("event") == "response"]
        if resp_lines:
            assert resp_lines[0]["status"] == 404

    def test_each_request_has_unique_request_id(self):
        _, out1 = _capture_stdout(client.get, "/api/health")
        _, out2 = _capture_stdout(client.get, "/api/health")
        lines1 = [l for l in out1.strip().split("\n") if l.strip()]
        lines2 = [l for l in out2.strip().split("\n") if l.strip()]
        rid1 = json.loads(lines1[0]).get("requestId")
        rid2 = json.loads(lines2[0]).get("requestId")
        assert rid1 != rid2, "Two separate requests should have different requestIds"
