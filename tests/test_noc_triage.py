# -*- coding: utf-8 -*-
"""NOC 트리아지 3종 테스트 — 네트워크vs앱 판정, 오류율 Conversations, 캡처 품질."""
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from models.packet import PacketRecord
from models.session import SessionModel
from services.analytics import network_health


def _session(src="10.0.0.1", dst="10.0.0.2", proto="TCP", **kw):
    defaults = dict(
        session_id=str(uuid.uuid4()),
        src_ip=src, dst_ip=dst,
        src_port=50000, dst_port=443, protocol=proto,
        start_ts=1000.0, end_ts=1005.0,
        bytes_sent=500, bytes_recv=500,
        packet_count=6, payload_length=500,
    )
    defaults.update(kw)
    return SessionModel(**defaults)


def _pkt(ts, direction, flags="ACK", payload=0, seq=0):
    return PacketRecord(ts=ts, direction=direction, proto="TCP", seq=seq,
                        ack=0, flags=flags, length=60 + payload,
                        payload_len=payload, payload_hex="")


def _handshake(t0=1000.0, rtt=0.01):
    """SYN → SYN+ACK → ACK 3패킷."""
    return [
        _pkt(t0, "fwd", "SYN"),
        _pkt(t0 + rtt, "rev", "SYN+ACK"),
        _pkt(t0 + rtt * 2, "fwd", "ACK"),
    ]


class TestBottleneckVerdict:
    def test_slow_server_fast_network_is_application(self):
        """iRTT 10ms + 서버 응답 2초 → application 병목."""
        s = _session()
        pkts = _handshake(rtt=0.01) + [
            _pkt(1000.05, "fwd", "ACK+PSH", payload=200, seq=1),   # 요청
            _pkt(1002.10, "rev", "ACK+PSH", payload=400, seq=1),   # 응답 (2초 뒤)
        ]
        result = network_health.analyze([s], {s.session_id: pkts})
        sh = result["sessions"][0]
        assert sh["server_delay_ms"] is not None and sh["server_delay_ms"] > 1000
        assert sh["bottleneck"] == "application"
        assert result["verdict"]["side"] == "application"
        assert "APPLICATION" in result["verdict"]["headline"]

    def test_fast_server_is_no_bottleneck(self):
        """iRTT 10ms + 서버 응답 30ms → 병목 없음."""
        s = _session()
        pkts = _handshake(rtt=0.01) + [
            _pkt(1000.05, "fwd", "ACK+PSH", payload=200, seq=1),
            _pkt(1000.08, "rev", "ACK+PSH", payload=400, seq=1),
        ]
        result = network_health.analyze([s], {s.session_id: pkts})
        sh = result["sessions"][0]
        assert sh["bottleneck"] in ("none", "indeterminate")
        assert result["verdict"]["side"] == "none"

    def test_syn_timeout_is_network(self):
        """SYN만 있고 응답 전무 → network 병목."""
        s = _session(bytes_sent=0, bytes_recv=0)
        pkts = [_pkt(1000.0, "fwd", "SYN"), _pkt(1003.0, "fwd", "SYN")]
        result = network_health.analyze([s], {s.session_id: pkts})
        sh = result["sessions"][0]
        assert sh["bottleneck"] == "network"
        assert result["verdict"]["side"] == "network"

    def test_refused_is_server(self):
        """SYN → RST(rev) → server 병목."""
        s = _session(bytes_sent=0, bytes_recv=0)
        pkts = [_pkt(1000.0, "fwd", "SYN"), _pkt(1000.01, "rev", "RST")]
        result = network_health.analyze([s], {s.session_id: pkts})
        sh = result["sessions"][0]
        assert sh["bottleneck"] == "server"
        assert result["verdict"]["side"] == "server"


class TestCaptureQuality:
    def test_no_handshake_warning(self):
        """SYN 없는 TCP 세션 다수 → 캡처 품질 경고."""
        sessions, pkt_map = [], {}
        for _ in range(4):
            s = _session()
            # 핸드셰이크 없이 데이터 패킷만 (캡처 시작 전 연결)
            pkt_map[s.session_id] = [
                _pkt(1000.0, "fwd", "ACK+PSH", payload=100, seq=1),
                _pkt(1000.1, "rev", "ACK+PSH", payload=100, seq=1),
            ]
            sessions.append(s)
        result = network_health.analyze(sessions, pkt_map)
        q = result["capture_quality"]
        assert q["handshake_not_captured"] == 4
        assert any("before the capture" in w for w in q["warnings"])

    def test_clean_capture_no_warnings(self):
        s = _session()
        pkts = _handshake() + [
            _pkt(1000.05, "fwd", "ACK+PSH", payload=100, seq=1),
            _pkt(1000.10, "rev", "ACK+PSH", payload=100, seq=1),
        ]
        result = network_health.analyze([s], {s.session_id: pkts})
        assert result["capture_quality"]["warnings"] == []

    def test_packetless_warning(self):
        sessions = [_session() for _ in range(3)]
        result = network_health.analyze(sessions, {})
        assert result["capture_quality"]["packetless_sessions"] == 3
        assert any("no packet data" in w for w in result["capture_quality"]["warnings"])


class TestConversationErrorColumns:
    def test_panel9_has_error_fields(self, api_client):
        from conftest import build_pcap
        pcap = build_pcap(num_packets=3)
        up = api_client.post("/api/upload",
                             files={"file": ("t.pcap", pcap, "application/octet-stream")})
        uid = up.json()["upload_id"]
        token = up.json()["capture_token"]
        r = api_client.get(f"/api/panels/{uid}", headers={"X-Upload-Token": token})
        assert r.status_code == 200
        convs = r.json()["panel9_conversations"]
        assert len(convs) >= 1
        for c in convs:
            for key in ("sessions", "rst", "no_reply", "issue_rate"):
                assert key in c, f"panel9 conversation에 '{key}' 누락"
