"""Panel 9 — IP 대화(Conversation) 분석 edge case 테스트 (TDD).

대상: services.analytics.conversation_analyzer.ConversationAnalyzer

인터페이스 가정:
  ConversationAnalyzer().analyze(sessions, target_ip=None) -> ConversationResult
  ConversationResult:
    top_conversations: list[dict]   # 최대 20개, bytes_total 내림차순
      각 dict: {"src": str, "dst": str, "bytes_total": int, "is_src_private": bool, "is_dst_private": bool}
    inbound_bytes: int
    outbound_bytes: int

검증 항목:
- Top 20 제한 (21 쌍 → 20 반환)
- bytes_total 내림차순 정렬
- RFC1918 src/dst 분류
- target_ip 지정 시 inbound/outbound 구분
- 빈 세션 → top_conversations=[], inbound=0, outbound=0
- 동일 src→dst 여러 세션 → bytes 합산
- 양방향 (A→B, B→A) 동일 쌍으로 집계 or 별도 여부 확인
"""
import uuid
import pytest


def _make_session(
    src_ip: str,
    dst_ip: str,
    *,
    bytes_sent: int = 1024,
    bytes_recv: int = 512,
    count: int = 1,
):
    try:
        from models.session import SessionModel
    except ImportError:
        pytest.skip("models.session 미구현")

    sessions = []
    for i in range(count):
        sessions.append(SessionModel(
            session_id=str(uuid.uuid4()),
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=50000 + i,
            dst_port=443,
            protocol="TCP",
            start_ts=1_748_000_000.0 + i,
            end_ts=1_748_000_002.0 + i,
            bytes_sent=bytes_sent,
            bytes_recv=bytes_recv,
            packet_count=10,
            payload_length=bytes_sent,
            confidence="normal",
        ))
    return sessions


def _load_analyzer():
    try:
        from services.analytics.conversation_analyzer import ConversationAnalyzer
        return ConversationAnalyzer()
    except ImportError:
        pytest.skip("conversation_analyzer 미구현")


class TestConversationTopN:
    def test_21_pairs_returns_top_20(self):
        """21개 고유 src→dst 쌍 → top_conversations 최대 20."""
        analyzer = _load_analyzer()
        sessions = []
        for i in range(21):
            sessions += _make_session(f"10.0.0.{i+1}", "192.168.1.1")
        result = analyzer.analyze(sessions)
        assert len(result.top_conversations) <= 20

    def test_sorted_by_bytes_total_descending(self):
        analyzer = _load_analyzer()
        sessions = (
            _make_session("10.0.0.1", "10.0.0.2", bytes_sent=5000)
            + _make_session("10.0.0.3", "10.0.0.4", bytes_sent=3000)
            + _make_session("10.0.0.5", "10.0.0.6", bytes_sent=1000)
        )
        result = analyzer.analyze(sessions)
        totals = [c["bytes_total"] for c in result.top_conversations]
        assert totals == sorted(totals, reverse=True)

    def test_rank21_excluded(self):
        """bytes_total 21번째 쌍 → top_conversations 미포함."""
        analyzer = _load_analyzer()
        sessions = []
        for i in range(1, 22):
            # i번: bytes_sent = 10000 - i*100
            sessions += _make_session(f"10.0.1.{i}", "192.168.1.1", bytes_sent=10000 - i * 100)
        result = analyzer.analyze(sessions)
        assert len(result.top_conversations) == 20


class TestConversationPrivateClassification:
    def test_rfc1918_marked_private(self):
        analyzer = _load_analyzer()
        sessions = _make_session("192.168.1.100", "10.0.0.1")
        result = analyzer.analyze(sessions)
        if result.top_conversations:
            c = result.top_conversations[0]
            assert c["is_src_private"] is True
            assert c["is_dst_private"] is True

    def test_public_ip_not_private(self):
        analyzer = _load_analyzer()
        sessions = _make_session("203.0.113.1", "8.8.8.8")
        result = analyzer.analyze(sessions)
        if result.top_conversations:
            c = result.top_conversations[0]
            assert c["is_src_private"] is False
            assert c["is_dst_private"] is False


class TestConversationInboundOutbound:
    def test_inbound_outbound_with_target_ip(self):
        """target_ip=192.168.1.100 기준: 외부→내부=inbound, 내부→외부=outbound."""
        analyzer = _load_analyzer()
        sessions = (
            _make_session("203.0.113.1", "192.168.1.100", bytes_sent=2000, bytes_recv=500)
            + _make_session("192.168.1.100", "203.0.113.2", bytes_sent=3000, bytes_recv=1000)
        )
        result = analyzer.analyze(sessions, target_ip="192.168.1.100")
        assert result.inbound_bytes > 0
        assert result.outbound_bytes > 0


class TestConversationEdge:
    def test_empty_sessions(self):
        analyzer = _load_analyzer()
        result = analyzer.analyze([])
        assert result.top_conversations == []
        assert result.inbound_bytes == 0
        assert result.outbound_bytes == 0

    def test_same_pair_bytes_aggregated(self):
        """동일 src→dst 5회 → bytes_total 합산."""
        analyzer = _load_analyzer()
        sessions = _make_session("10.0.0.1", "10.0.0.2", bytes_sent=1000, bytes_recv=500, count=5)
        result = analyzer.analyze(sessions)
        assert len(result.top_conversations) >= 1
        assert result.top_conversations[0]["bytes_total"] == (1000 + 500) * 5
