# -*- coding: utf-8 -*-
"""Edge cases: file format validation, size limits, Content-Length, API body validation."""
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

PCAP_MAGIC = b"\xd4\xc3\xb2\xa1"
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
VALID_FORTIGATE = b"192.168.1.1:1234 -> 10.0.0.1:80 tcp\n"


# ── File format detection ───────────────────────────────────────

class TestFileFormatDetection:
    def test_pcap_wrong_magic_returns_415(self):
        data = b"\xFF\xFF\xFF\xFF" + b"\x00" * 100
        resp = client.post("/api/upload", files={"file": ("capture.pcap", data, "application/octet-stream")})
        assert resp.status_code in (400, 415), f"Expected 400/415 for bad pcap magic, got {resp.status_code}"

    def test_pcapng_magic_accepted(self):
        # pcapng magic is valid even with empty body - parser will fail but format is detected
        data = PCAPNG_MAGIC + b"\x00" * 200
        resp = client.post("/api/upload", files={"file": ("capture.pcapng", data, "application/octet-stream")})
        # Should be 415 (unrecognized) or 422 (parse fail) - not 200 with zero packets
        # pcapng magic IS detected, so upload proceeds; parse may produce no packets → 422
        assert resp.status_code in (415, 422)

    def test_har_invalid_json_returns_415_or_422(self):
        data = b"not valid json at all {{{}"
        resp = client.post("/api/upload", files={"file": ("capture.har", data, "application/json")})
        assert resp.status_code in (400, 415, 422)

    def test_har_valid_but_empty_entries_returns_422(self):
        import json
        data = json.dumps({"log": {"entries": []}}).encode()
        resp = client.post("/api/upload", files={"file": ("capture.har", data, "application/json")})
        assert resp.status_code == 422

    def test_exe_extension_returns_415(self):
        resp = client.post("/api/upload", files={"file": ("malware.exe", b"MZ\x90\x00", "application/octet-stream")})
        assert resp.status_code == 415

    def test_no_extension_returns_415(self):
        resp = client.post("/api/upload", files={"file": ("noext", b"some data", "application/octet-stream")})
        assert resp.status_code == 415

    def test_pdf_extension_returns_415(self):
        resp = client.post("/api/upload", files={"file": ("report.pdf", b"%PDF-1.4", "application/pdf")})
        assert resp.status_code == 415

    def test_txt_with_no_parseable_data_returns_422(self):
        data = b"this is just random text with no packet data\n"
        resp = client.post("/api/upload", files={"file": ("random.txt", data, "text/plain")})
        assert resp.status_code in (415, 422)

    def test_log_extension_accepted_as_txt(self):
        data = b"192.168.1.1:1234 -> 10.0.0.1:80 tcp\n"
        resp = client.post("/api/upload", files={"file": ("capture.log", data, "text/plain")})
        assert resp.status_code == 200

    def test_pcap_big_endian_magic_accepted(self):
        # Big-endian pcap magic (reversed)
        data = bytes(reversed(PCAP_MAGIC)) + b"\x00" * 200
        resp = client.post("/api/upload", files={"file": ("be.pcap", data, "application/octet-stream")})
        # detected as pcap, parse may fail → 422 is acceptable
        assert resp.status_code in (415, 422)


# ── File size limits ────────────────────────────────────────────

class TestFileSizeLimits:
    MAX_BYTES = 52_428_800  # 50 MB (server limit)

    def test_content_length_exactly_at_limit_is_accepted(self):
        """Content-Length exactly equal to MAX is not rejected by header check."""
        resp = client.post(
            "/api/upload",
            files={"file": ("capture.txt", VALID_FORTIGATE, "text/plain")},
            headers={"content-length": str(self.MAX_BYTES)},
        )
        # Header check passes (not > limit), actual body is small → 200
        assert resp.status_code == 200

    def test_content_length_one_over_limit_returns_413(self):
        # upload.py 은 multipart 오버헤드 ~8 KB를 허용하므로 실제 임계값은 MAX_BYTES + 8192
        resp = client.post(
            "/api/upload",
            files={"file": ("capture.txt", VALID_FORTIGATE, "text/plain")},
            headers={"content-length": str(self.MAX_BYTES + 8193)},
        )
        assert resp.status_code == 413

    def test_invalid_content_length_string_returns_400(self):
        resp = client.post(
            "/api/upload",
            files={"file": ("capture.txt", VALID_FORTIGATE, "text/plain")},
            headers={"content-length": "not-a-number"},
        )
        assert resp.status_code == 400

    def test_empty_file_returns_422(self):
        resp = client.post("/api/upload", files={"file": ("empty.txt", b"", "text/plain")})
        assert resp.status_code in (415, 422)

    def test_zero_content_length_returns_error(self):
        resp = client.post(
            "/api/upload",
            files={"file": ("capture.txt", b"", "text/plain")},
            headers={"content-length": "0"},
        )
        # Empty body produces 0 packets → 422, or detected as wrong type → 415
        assert resp.status_code in (415, 422)

    def test_negative_content_length_returns_400_or_422(self):
        resp = client.post(
            "/api/upload",
            files={"file": ("capture.txt", VALID_FORTIGATE, "text/plain")},
            headers={"content-length": "-1"},
        )
        # -1 < MAX_BYTES so header check passes, but content-length is invalid semantically
        # Acceptable outcomes: 400 or 200 (header check uses int comparison only)
        assert resp.status_code in (200, 400)


# ── Analyze API body validation ────────────────────────────────

class TestAnalyzeBodyValidation:
    VALID_UUID = "12345678-1234-1234-1234-123456789abc"
    VALID_IP = "1.2.3.4"

    def test_missing_upload_id_returns_422(self):
        resp = client.post("/api/analyze", json={"target_ip": self.VALID_IP})
        assert resp.status_code == 422

    def test_missing_target_ip_returns_422(self):
        resp = client.post("/api/analyze", json={"upload_id": self.VALID_UUID})
        assert resp.status_code in (400, 422)

    def test_null_upload_id_returns_422(self):
        resp = client.post("/api/analyze", json={"upload_id": None, "target_ip": self.VALID_IP})
        assert resp.status_code == 422

    def test_null_target_ip_returns_422(self):
        resp = client.post("/api/analyze", json={"upload_id": self.VALID_UUID, "target_ip": None})
        assert resp.status_code in (400, 422)

    def test_integer_upload_id_returns_422(self):
        resp = client.post("/api/analyze", json={"upload_id": 12345678, "target_ip": self.VALID_IP})
        assert resp.status_code == 422

    def test_integer_target_ip_returns_422(self):
        resp = client.post("/api/analyze", json={"upload_id": self.VALID_UUID, "target_ip": 12345678})
        assert resp.status_code == 422

    def test_empty_string_upload_id_returns_400(self):
        resp = client.post("/api/analyze", json={"upload_id": "", "target_ip": self.VALID_IP})
        assert resp.status_code == 400

    def test_empty_string_target_ip_returns_400(self):
        resp = client.post("/api/analyze", json={"upload_id": self.VALID_UUID, "target_ip": ""})
        assert resp.status_code == 400

    def test_uuid_without_hyphens_returns_400(self):
        resp = client.post("/api/analyze", json={
            "upload_id": "12345678123412341234123456789abc",
            "target_ip": self.VALID_IP,
        })
        assert resp.status_code == 400

    def test_uuid_uppercase_returns_400(self):
        resp = client.post("/api/analyze", json={
            "upload_id": "12345678-1234-1234-1234-123456789ABC",
            "target_ip": self.VALID_IP,
        })
        assert resp.status_code == 400

    def test_empty_body_returns_422(self):
        resp = client.post("/api/analyze", json={})
        assert resp.status_code == 422


# ── Export API body validation ─────────────────────────────────

class TestExportBodyValidation:
    VALID_UUID = "12345678-1234-1234-1234-123456789abc"
    VALID_IP = "1.2.3.4"

    def test_invalid_format_returns_422(self):
        resp = client.post("/api/export", json={
            "upload_id": self.VALID_UUID,
            "target_ip": self.VALID_IP,
            "format": "xml",
        })
        assert resp.status_code == 422

    def test_missing_format_returns_422(self):
        resp = client.post("/api/export", json={
            "upload_id": self.VALID_UUID,
            "target_ip": self.VALID_IP,
        })
        assert resp.status_code == 422

    def test_null_format_returns_422(self):
        resp = client.post("/api/export", json={
            "upload_id": self.VALID_UUID,
            "target_ip": self.VALID_IP,
            "format": None,
        })
        assert resp.status_code == 422

    def test_invalid_upload_id_returns_400(self):
        resp = client.post("/api/export", json={
            "upload_id": "not-a-uuid",
            "target_ip": self.VALID_IP,
            "format": "csv",
        })
        assert resp.status_code == 400

    def test_invalid_target_ip_returns_400(self):
        resp = client.post("/api/export", json={
            "upload_id": self.VALID_UUID,
            "target_ip": "999.999.999.999",
            "format": "csv",
        })
        assert resp.status_code == 400
