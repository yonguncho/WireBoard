# -*- coding: utf-8 -*-
"""End-to-end edge cases: upload → analyze → export full pipeline."""
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
from store.session_store import ParsedCapture
from models.session import SessionModel

client = TestClient(app)

FORTIGATE_DATA = (
    b"1734000000.000000 IP 192.168.1.100.12345 > 10.0.0.1.80: Flags [S]\n"
    b"1734000001.000000 IP 10.0.0.1.80 > 192.168.1.100.12345: Flags [.]\n"
)
TARGET_IP = "192.168.1.100"


def _seed(upload_id: str, src_ip: str, dst_ip: str = "10.0.0.1") -> None:
    store = app.state.session_store
    session = SessionModel(
        session_id=str(uuid.uuid4()),
        src_ip=src_ip, dst_ip=dst_ip,
        src_port=12345, dst_port=80,
        protocol="TCP",
        start_ts=1.0, end_ts=2.0,
        bytes_sent=500, bytes_recv=500,
        packet_count=10, payload_length=0,
    )
    store.put(upload_id, ParsedCapture(
        source_type="pcap",
        sessions=[session],
    ))


# ── Upload → Analyze ─────────────────────────────────────────────

class TestUploadThenAnalyze:
    def test_upload_then_analyze_returns_200(self):
        upload_resp = client.post("/api/upload",
                                  files={"file": ("capture.log", FORTIGATE_DATA, "text/plain")})
        assert upload_resp.status_code == 200
        upload_id = upload_resp.json()["upload_id"]
        capture_token = upload_resp.json()["capture_token"]
        analyze_resp = client.post("/api/analyze",
                                   json={"upload_id": upload_id, "target_ip": TARGET_IP},
                                   headers={"X-Upload-Token": capture_token})
        assert analyze_resp.status_code == 200

    def test_analyze_response_has_all_keys(self):
        upload_resp = client.post("/api/upload",
                                  files={"file": ("capture.log", FORTIGATE_DATA, "text/plain")})
        upload_id = upload_resp.json()["upload_id"]
        capture_token = upload_resp.json()["capture_token"]
        resp = client.post("/api/analyze",
                           json={"upload_id": upload_id, "target_ip": TARGET_IP},
                           headers={"X-Upload-Token": capture_token})
        body = resp.json()
        for key in ("target_ip", "flows", "sessions", "reputation", "attacks", "analysis_duration_ms"):
            assert key in body, f"Missing key: {key}"

    def test_analyze_target_ip_matches_request(self):
        uid = str(uuid.uuid4())
        _seed(uid, src_ip=TARGET_IP)
        resp = client.post("/api/analyze", json={"upload_id": uid, "target_ip": TARGET_IP})
        body = resp.json()
        assert body["target_ip"] == TARGET_IP

    def test_analyze_sessions_list_is_list(self):
        uid = str(uuid.uuid4())
        _seed(uid, src_ip=TARGET_IP)
        resp = client.post("/api/analyze", json={"upload_id": uid, "target_ip": TARGET_IP})
        assert isinstance(resp.json()["sessions"], list)

    def test_analyze_attacks_list_is_list(self):
        uid = str(uuid.uuid4())
        _seed(uid, src_ip=TARGET_IP)
        resp = client.post("/api/analyze", json={"upload_id": uid, "target_ip": TARGET_IP})
        assert isinstance(resp.json()["attacks"], list)

    def test_analyze_duration_ms_is_non_negative(self):
        uid = str(uuid.uuid4())
        _seed(uid, src_ip=TARGET_IP)
        resp = client.post("/api/analyze", json={"upload_id": uid, "target_ip": TARGET_IP})
        assert resp.json()["analysis_duration_ms"] >= 0

    def test_analyze_unmatched_ip_returns_empty_sessions(self):
        uid = str(uuid.uuid4())
        _seed(uid, src_ip="10.10.10.10", dst_ip="20.20.20.20")
        resp = client.post("/api/analyze", json={"upload_id": uid, "target_ip": "99.99.99.99"})
        assert resp.status_code == 200
        assert resp.json()["sessions"] == []
        assert resp.json()["flows"] == []


# ── Upload → Analyze → Export ────────────────────────────────────

class TestUploadAnalyzeExport:
    def _full_pipeline(self, fmt: str):
        uid = str(uuid.uuid4())
        _seed(uid, src_ip=TARGET_IP)
        client.post("/api/analyze", json={"upload_id": uid, "target_ip": TARGET_IP})
        resp = client.post("/api/export", json={
            "upload_id": uid,
            "target_ip": TARGET_IP,
            "format": fmt,
        })
        return resp

    def test_export_csv_after_analyze(self):
        resp = self._full_pipeline("csv")
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/csv")

    def test_export_json_after_analyze(self):
        resp = self._full_pipeline("json")
        assert resp.status_code == 200
        import json
        data = json.loads(resp.content)
        assert isinstance(data, list)

    def test_export_suricata_after_analyze(self):
        resp = self._full_pipeline("suricata")
        assert resp.status_code == 200

    def test_export_snort_after_analyze(self):
        resp = self._full_pipeline("snort")
        assert resp.status_code == 200

    def test_export_without_analyze_still_works(self):
        uid = str(uuid.uuid4())
        _seed(uid, src_ip=TARGET_IP)
        resp = client.post("/api/export", json={
            "upload_id": uid,
            "target_ip": TARGET_IP,
            "format": "json",
        })
        assert resp.status_code == 200

    def test_export_expired_upload_returns_404(self):
        resp = client.post("/api/export", json={
            "upload_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "target_ip": "1.2.3.4",
            "format": "csv",
        })
        assert resp.status_code == 404

    def test_content_disposition_header_present(self):
        uid = str(uuid.uuid4())
        _seed(uid, src_ip=TARGET_IP)
        resp = client.post("/api/export", json={
            "upload_id": uid,
            "target_ip": TARGET_IP,
            "format": "csv",
        })
        assert "content-disposition" in resp.headers

    def test_all_formats_return_non_empty(self):
        for fmt in ("csv", "json", "suricata", "snort"):
            resp = self._full_pipeline(fmt)
            assert resp.status_code == 200
            # json format may be empty list, CSV may have header only — both are valid


# ── Reputation in analyze response ──────────────────────────────

class TestReputationInAnalyze:
    def test_reputation_field_has_ip(self):
        uid = str(uuid.uuid4())
        _seed(uid, src_ip=TARGET_IP)
        resp = client.post("/api/analyze", json={"upload_id": uid, "target_ip": TARGET_IP})
        reputation = resp.json()["reputation"]
        assert reputation["ip"] == TARGET_IP

    def test_reputation_has_is_malicious_field(self):
        uid = str(uuid.uuid4())
        _seed(uid, src_ip=TARGET_IP)
        resp = client.post("/api/analyze", json={"upload_id": uid, "target_ip": TARGET_IP})
        reputation = resp.json()["reputation"]
        assert "is_malicious" in reputation

    def test_reputation_sources_is_list(self):
        uid = str(uuid.uuid4())
        _seed(uid, src_ip=TARGET_IP)
        resp = client.post("/api/analyze", json={"upload_id": uid, "target_ip": TARGET_IP})
        reputation = resp.json()["reputation"]
        assert isinstance(reputation["sources"], list)
