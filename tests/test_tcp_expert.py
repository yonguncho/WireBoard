# -*- coding: utf-8 -*-
"""TCP Expert Info 분석 테스트 — 재전송·dup-ack·zero-window·순서역전·손실."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from models.packet import PacketRecord
from services.analytics import tcp_expert


def _p(direction, seq=0, ack=0, flags="ACK", payload=0, window=65535):
    return PacketRecord(
        ts=0.0, direction=direction, proto="TCP",
        seq=seq, ack=ack, flags=flags, length=60 + payload,
        payload_len=payload, payload_hex="", window=window,
    )


def _tags_at(result, i):
    return set(result["events"][i]["tags"])


class TestRetransmission:
    def test_same_seq_with_payload_is_retransmission(self):
        pkts = [
            _p("fwd", seq=100, payload=100),   # 원본
            _p("fwd", seq=100, payload=100),   # 재전송 (동일 seq)
        ]
        r = tcp_expert.analyze_flow(pkts)
        assert "retransmission" in _tags_at(r, 1)
        assert r["summary"].get("retransmission") == 1

    def test_new_seq_not_retransmission(self):
        pkts = [
            _p("fwd", seq=100, payload=100),
            _p("fwd", seq=200, payload=100),   # 다음 세그먼트 — 정상
        ]
        r = tcp_expert.analyze_flow(pkts)
        assert "retransmission" not in _tags_at(r, 1)


class TestOutOfOrderAndLoss:
    def test_lower_seq_is_out_of_order(self):
        pkts = [
            _p("fwd", seq=300, payload=100),
            _p("fwd", seq=200, payload=100),   # 앞선 seq — 순서 역전
        ]
        r = tcp_expert.analyze_flow(pkts)
        assert "out_of_order" in _tags_at(r, 1)

    def test_seq_gap_is_lost_segment(self):
        pkts = [
            _p("fwd", seq=100, payload=100),   # end=200
            _p("fwd", seq=500, payload=100),   # 기대(200)보다 앞 → 손실
        ]
        r = tcp_expert.analyze_flow(pkts)
        assert "lost_segment" in _tags_at(r, 1)


class TestDuplicateAck:
    def test_repeated_ack_no_payload_is_dup_ack(self):
        pkts = [
            _p("rev", ack=1000, payload=0),
            _p("rev", ack=1000, payload=0),   # 동일 ACK 반복 → dup-ack
        ]
        r = tcp_expert.analyze_flow(pkts)
        assert "duplicate_ack" in _tags_at(r, 1)

    def test_advancing_ack_not_dup(self):
        pkts = [
            _p("rev", ack=1000, payload=0),
            _p("rev", ack=1500, payload=0),
        ]
        r = tcp_expert.analyze_flow(pkts)
        assert "duplicate_ack" not in _tags_at(r, 1)


class TestZeroWindow:
    def test_zero_window_flagged(self):
        pkts = [_p("rev", ack=100, payload=0, window=0)]
        r = tcp_expert.analyze_flow(pkts)
        assert "zero_window" in _tags_at(r, 0)

    def test_syn_zero_window_not_flagged(self):
        # SYN은 초기 window 협상 — zero window로 보지 않음
        pkts = [_p("fwd", seq=0, flags="SYN", window=0)]
        r = tcp_expert.analyze_flow(pkts)
        assert "zero_window" not in _tags_at(r, 0)

    def test_window_recovery_flagged(self):
        pkts = [
            _p("rev", ack=100, payload=0, window=0),      # zero window
            _p("rev", ack=100, payload=0, window=65535),  # 회복
        ]
        r = tcp_expert.analyze_flow(pkts)
        assert "window_full" in _tags_at(r, 1)


class TestAggregate:
    def test_aggregate_buckets_by_severity(self):
        pkt_map = {
            "flow1": [_p("fwd", seq=100, payload=100), _p("fwd", seq=100, payload=100)],
            "flow2": [_p("rev", ack=1, window=0)],
        }
        agg = tcp_expert.aggregate(pkt_map)
        assert agg["retransmission"] == 1
        assert agg["zero_window"] == 1
        assert agg["flows_with_issues"] == 2
        # zero_window는 warn, retransmission은 note 버킷
        warn_tags = {e["tag"] for e in agg["by_severity"]["warn"]}
        note_tags = {e["tag"] for e in agg["by_severity"]["note"]}
        assert "zero_window" in warn_tags
        assert "retransmission" in note_tags

    def test_clean_flow_no_events(self):
        pkt_map = {"f": [_p("fwd", seq=1, payload=50), _p("fwd", seq=51, payload=50)]}
        agg = tcp_expert.aggregate(pkt_map)
        assert agg["flows_with_issues"] == 0
        assert agg["totals"] == {}


class TestExpertApiContract:
    """panels/flow 응답에 Expert Info + 레이어 필드가 포함되는지."""

    def _upload(self, api_client):
        from conftest import build_pcap
        pcap = build_pcap(num_packets=3)
        up = api_client.post("/api/upload",
                             files={"file": ("t.pcap", pcap, "application/octet-stream")})
        return up.json()["upload_id"], up.json()["capture_token"]

    def test_panels_has_expert_info(self, api_client):
        uid, token = self._upload(api_client)
        r = api_client.get(f"/api/panels/{uid}", headers={"X-Upload-Token": token})
        assert r.status_code == 200
        ei = r.json()["expert_info"]
        for key in ("totals", "by_severity", "retransmission", "zero_window"):
            assert key in ei

    def test_flow_packets_have_expert_and_layer_fields(self, api_client):
        uid, token = self._upload(api_client)
        panels = api_client.get(f"/api/panels/{uid}", headers={"X-Upload-Token": token}).json()
        # 세션 하나의 flow 조회
        from main import app
        cap = app.state.session_store.get(uid)
        sid = cap.sessions[0].session_id
        r = api_client.get(f"/api/flow/{uid}?session_id={sid}", headers={"X-Upload-Token": token})
        assert r.status_code == 200
        body = r.json()
        assert "expert_summary" in body and "expert_worst" in body
        assert "ip_badge" in body["session"]
        for p in body["packets"]:
            assert "expert" in p and isinstance(p["expert"], list)
            assert "delta_ts" in p and "window" in p and "ttl" in p
        assert panels["expert_info"] is not None
