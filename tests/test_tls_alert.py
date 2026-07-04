# -*- coding: utf-8 -*-
"""TLS Alert 디코드 + 타임라인 오류 오버레이 테스트."""
import struct
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from models.session import SessionModel
from services.payload_extractor.tls_extractor import scan_tls_records
from services.analytics.flow_timeline import FlowTimeline


def _tls_record(content_type: int, body: bytes) -> bytes:
    return bytes([content_type, 0x03, 0x03]) + struct.pack("!H", len(body)) + body


class TestTlsAlertScan:
    def test_fatal_handshake_failure_alert(self):
        # Alert record: level=fatal(2), desc=handshake_failure(40)
        rec = _tls_record(0x15, bytes([2, 40]))
        r = scan_tls_records(rec)
        assert len(r["alerts"]) == 1
        a = r["alerts"][0]
        assert a["level"] == "fatal"
        assert a["description"] == "handshake_failure"

    def test_certificate_expired_alert(self):
        rec = _tls_record(0x15, bytes([2, 45]))
        r = scan_tls_records(rec)
        assert r["alerts"][0]["description"] == "certificate_expired"

    def test_handshake_stage_detection(self):
        # ClientHello handshake record (type 0x16, hs msg 0x01)
        hs_body = bytes([0x01, 0, 0, 4, 0, 0, 0, 0])  # ClientHello + 4-byte len + stub
        rec = _tls_record(0x16, hs_body)
        r = scan_tls_records(rec)
        assert "ClientHello" in r["handshake"]

    def test_handshake_then_alert_sequence(self):
        hs = _tls_record(0x16, bytes([0x02, 0, 0, 4, 0, 0, 0, 0]))  # ServerHello
        alert = _tls_record(0x15, bytes([2, 48]))  # unknown_ca
        r = scan_tls_records(hs + alert)
        assert "ServerHello" in r["handshake"]
        assert r["alerts"][0]["description"] == "unknown_ca"

    def test_non_tls_returns_empty(self):
        r = scan_tls_records(b"GET / HTTP/1.1\r\n")
        assert r["alerts"] == [] and r["handshake"] == []


class TestTimelineErrorOverlay:
    def _sess(self, ts, rst=False, sent=100, recv=100, proto="TCP"):
        return SessionModel(
            session_id=str(uuid.uuid4()), src_ip="10.0.0.1", dst_ip="10.0.0.2",
            src_port=5000, dst_port=443, protocol=proto,
            start_ts=ts, end_ts=ts + 1,
            bytes_sent=sent, bytes_recv=recv, packet_count=4,
            payload_length=0, rst=rst,
        )

    def test_bucket_has_error_fields(self):
        sessions = [self._sess(100.0), self._sess(101.0, rst=True),
                    self._sess(102.0, sent=200, recv=0)]  # no-reply
        r = FlowTimeline(window_seconds=60).compute(sessions)
        b = r.buckets[0]
        for k in ("rst", "no_reply", "errors"):
            assert k in b
        assert b["rst"] == 1
        assert b["no_reply"] == 1
        assert b["errors"] == 2

    def test_clean_bucket_zero_errors(self):
        r = FlowTimeline(window_seconds=60).compute([self._sess(100.0)])
        assert r.buckets[0]["errors"] == 0
