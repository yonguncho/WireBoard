# -*- coding: utf-8 -*-
"""DNS 쿼리↔응답 매칭 테스트 — 응답시간·무응답·rcode."""
import struct
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from models.packet import PacketRecord
from models.session import SessionModel
from services.analytics import dns_matcher


def _dns_msg(txid: int, name: str, qr: bool, rcode: int = 0, qtype: int = 1) -> bytes:
    flags = (0x8000 if qr else 0x0000) | (rcode & 0xF)
    ancount = 1 if (qr and rcode == 0) else 0
    hdr = struct.pack("!HHHHHH", txid, flags, 1, ancount, 0, 0)
    # QNAME
    body = b""
    for label in name.split("."):
        body += bytes([len(label)]) + label.encode()
    body += b"\x00"
    body += struct.pack("!HH", qtype, 1)  # QTYPE, QCLASS
    if ancount:
        # 최소 A 레코드 (name ptr, type A, class IN, ttl, rdlen=4, 1.2.3.4)
        body += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + bytes([1, 2, 3, 4])
    return hdr + body


def _dns_session(sid=None):
    return SessionModel(
        session_id=sid or str(uuid.uuid4()),
        src_ip="10.0.0.5", dst_ip="8.8.8.8",
        src_port=50000, dst_port=53, protocol="UDP",
        start_ts=1000.0, end_ts=1001.0,
        bytes_sent=40, bytes_recv=56, packet_count=2, payload_length=40,
    )


def _pkt(ts, direction, payload: bytes):
    return PacketRecord(ts=ts, direction=direction, proto="UDP", seq=0, ack=0,
                        flags="", length=len(payload) + 28, payload_len=len(payload),
                        payload_hex=payload.hex())


class TestDnsMatching:
    def test_query_response_matched_with_time(self):
        s = _dns_session()
        pkts = [
            _pkt(1000.0, "fwd", _dns_msg(0x1234, "example.com", qr=False)),
            _pkt(1000.05, "rev", _dns_msg(0x1234, "example.com", qr=True, rcode=0)),
        ]
        r = dns_matcher.match([s], {s.session_id: pkts})
        assert r["total"] == 1
        assert r["answered"] == 1
        assert r["unanswered"] == 0
        # 50ms 응답
        assert 49 <= r["slowest"][0]["response_time_ms"] <= 51
        assert r["p95_ms"] > 0

    def test_unanswered_query_flagged(self):
        s = _dns_session()
        pkts = [_pkt(1000.0, "fwd", _dns_msg(0x2222, "timeout.example", qr=False))]
        r = dns_matcher.match([s], {s.session_id: pkts})
        assert r["unanswered"] == 1
        assert r["answered"] == 0
        assert r["unanswered_queries"][0]["name"] == "timeout.example"

    def test_servfail_counted_as_error(self):
        s = _dns_session()
        pkts = [
            _pkt(1000.0, "fwd", _dns_msg(0x3333, "broken.example", qr=False)),
            _pkt(1000.02, "rev", _dns_msg(0x3333, "broken.example", qr=True, rcode=2)),
        ]
        r = dns_matcher.match([s], {s.session_id: pkts})
        assert r["errors"] == 1
        assert r["rcode_dist"].get("SERVFAIL") == 1

    def test_nxdomain_rcode(self):
        s = _dns_session()
        pkts = [
            _pkt(1000.0, "fwd", _dns_msg(0x4444, "nope.example", qr=False)),
            _pkt(1000.01, "rev", _dns_msg(0x4444, "nope.example", qr=True, rcode=3)),
        ]
        r = dns_matcher.match([s], {s.session_id: pkts})
        assert r["rcode_dist"].get("NXDOMAIN") == 1

    def test_non_dns_sessions_ignored(self):
        s = SessionModel(
            session_id=str(uuid.uuid4()), src_ip="10.0.0.5", dst_ip="1.1.1.1",
            src_port=50000, dst_port=443, protocol="TCP",
            start_ts=1000.0, end_ts=1001.0,
            bytes_sent=100, bytes_recv=100, packet_count=2, payload_length=100,
        )
        r = dns_matcher.match([s], {s.session_id: []})
        assert r["total"] == 0

    def test_panels_exposes_dns_timing(self, api_client):
        from conftest import build_pcap
        pcap = build_pcap(num_packets=3)
        up = api_client.post("/api/upload",
                             files={"file": ("t.pcap", pcap, "application/octet-stream")})
        uid = up.json()["upload_id"]; token = up.json()["capture_token"]
        r = api_client.get(f"/api/panels/{uid}", headers={"X-Upload-Token": token})
        assert r.status_code == 200
        dt = r.json()["dns_timing"]
        for k in ("total", "answered", "unanswered", "p95_ms", "slowest", "unanswered_queries"):
            assert k in dt

    def test_percentiles_reasonable(self):
        s = _dns_session()
        pkts = []
        # 10 queries with increasing response times 10..100ms
        for i in range(10):
            txid = 0x1000 + i
            pkts.append(_pkt(1000.0 + i, "fwd", _dns_msg(txid, f"h{i}.example", qr=False)))
            pkts.append(_pkt(1000.0 + i + (i + 1) * 0.01, "rev", _dns_msg(txid, f"h{i}.example", qr=True)))
        r = dns_matcher.match([s], {s.session_id: pkts})
        assert r["answered"] == 10
        assert r["p50_ms"] <= r["p95_ms"] <= r["max_ms"]
