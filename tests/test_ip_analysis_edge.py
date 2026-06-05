"""Panel 1 — IP 분석 edge case 테스트 (TDD).

대상: services.analytics.ip_analyzer.IpAnalyzer  (또는 동등한 인터페이스)

인터페이스 가정:
  IpAnalyzer().analyze(sessions: list[SessionModel]) -> IpAnalysisResult
  IpAnalysisResult:
    top_src: list[dict]  # [{"ip": str, "bytes": int, "is_private": bool}, ...]
    top_dst: list[dict]
    # 각 리스트 최대 20개, bytes 내림차순 정렬

검증 항목:
- Top 20 제한: 21개 IP → 상위 20개만
- 정확히 20개 IP → 전부 포함
- RFC1918 분류: 10.x, 172.16-31.x, 192.168.x.x → is_private=True
- 공인 IP (203.0.113.x) → is_private=False
- bytes 내림차순 정렬 보장
- 동점 tie-breaking: 안정적 정렬 (순서 보존)
- 빈 세션 → top_src=[], top_dst=[]
- 동일 src_ip 세션 여러 개 → bytes 합산
- src/dst 별 독립 집계
"""
import uuid
import pytest


def _make_session(src_ip: str, dst_ip: str, *, count: int = 1):
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
            dst_port=80,
            protocol="TCP",
            start_ts=1_748_000_000.0 + i,
            end_ts=1_748_000_001.0 + i,
            bytes_sent=512,
            bytes_recv=512,
            packet_count=5,
            payload_length=512,
            confidence="normal",
        ))
    return sessions


def _load_analyzer():
    try:
        from services.analytics.ip_analyzer import IpAnalyzer
        return IpAnalyzer()
    except ImportError:
        pytest.skip("ip_analyzer 미구현")


class TestIpAnalyzerTopN:
    def test_21_src_ips_returns_top_20(self):
        """21개 고유 src_ip → top_src 최대 20개."""
        analyzer = _load_analyzer()
        sessions = []
        for i in range(21):
            sessions += _make_session(f"10.0.0.{i+1}", "192.168.1.1")
        result = analyzer.analyze(sessions)
        assert len(result.top_src) <= 20

    def test_exactly_20_src_ips_all_included(self):
        """정확히 20개 고유 src_ip → 전부 포함."""
        analyzer = _load_analyzer()
        sessions = []
        for i in range(20):
            sessions += _make_session(f"10.0.0.{i+1}", "192.168.1.1")
        result = analyzer.analyze(sessions)
        assert len(result.top_src) == 20

    def test_sorted_by_bytes_descending(self):
        """bytes 내림차순 정렬."""
        analyzer = _load_analyzer()
        # 10.0.0.1: 5회(2560B), 10.0.0.2: 3회(1536B), 10.0.0.3: 1회(512B)
        sessions = (
            _make_session("10.0.0.1", "192.168.1.1", count=5)
            + _make_session("10.0.0.2", "192.168.1.1", count=3)
            + _make_session("10.0.0.3", "192.168.1.1", count=1)
        )
        result = analyzer.analyze(sessions)
        vals = [item["bytes"] for item in result.top_src]
        assert vals == sorted(vals, reverse=True)

    def test_top20_excludes_rank21(self):
        """21번째 IP(최소 count)는 top_src 에 포함되지 않는다."""
        analyzer = _load_analyzer()
        sessions = []
        # 1~20: 각 10회, 21번: 1회
        for i in range(1, 21):
            sessions += _make_session(f"10.0.0.{i}", "192.168.1.1", count=10)
        sessions += _make_session("10.0.0.99", "192.168.1.1", count=1)
        result = analyzer.analyze(sessions)
        assert len(result.top_src) == 20
        ips_in_top20 = {item["ip"] for item in result.top_src}
        assert "10.0.0.99" not in ips_in_top20


class TestIpAnalyzerPrivateClassification:
    def test_10_x_is_private(self):
        analyzer = _load_analyzer()
        sessions = _make_session("10.0.0.1", "203.0.113.1")
        result = analyzer.analyze(sessions)
        src = {item["ip"]: item for item in result.top_src}
        assert src.get("10.0.0.1", {}).get("is_private") is True

    def test_172_16_is_private(self):
        analyzer = _load_analyzer()
        sessions = _make_session("172.16.0.1", "203.0.113.1")
        result = analyzer.analyze(sessions)
        src = {item["ip"]: item for item in result.top_src}
        assert src.get("172.16.0.1", {}).get("is_private") is True

    def test_192_168_is_private(self):
        analyzer = _load_analyzer()
        sessions = _make_session("192.168.1.100", "203.0.113.1")
        result = analyzer.analyze(sessions)
        src = {item["ip"]: item for item in result.top_src}
        assert src.get("192.168.1.100", {}).get("is_private") is True

    def test_203_0_113_is_public(self):
        analyzer = _load_analyzer()
        sessions = _make_session("203.0.113.1", "192.168.1.1")
        result = analyzer.analyze(sessions)
        src = {item["ip"]: item for item in result.top_src}
        assert src.get("203.0.113.1", {}).get("is_private") is False

    def test_172_32_is_public(self):
        """172.32.x.x 는 RFC1918 범위 아님 → public."""
        analyzer = _load_analyzer()
        sessions = _make_session("172.32.0.1", "192.168.1.1")
        result = analyzer.analyze(sessions)
        src = {item["ip"]: item for item in result.top_src}
        assert src.get("172.32.0.1", {}).get("is_private") is False


class TestIpAnalyzerEdge:
    def test_empty_sessions_returns_empty_lists(self):
        analyzer = _load_analyzer()
        result = analyzer.analyze([])
        assert result.top_src == []
        assert result.top_dst == []

    def test_same_src_ip_aggregated(self):
        """같은 src_ip 5회 → top_src 에 bytes=2560(5×512) 으로 집계."""
        analyzer = _load_analyzer()
        sessions = _make_session("10.0.0.1", "192.168.1.1", count=5)
        result = analyzer.analyze(sessions)
        byte_map = {item["ip"]: item["bytes"] for item in result.top_src}
        assert byte_map.get("10.0.0.1") == 5 * 512

    def test_src_dst_independent(self):
        """같은 IP가 src, dst 양쪽에 등장 — 각각 독립 집계."""
        analyzer = _load_analyzer()
        sessions = (
            _make_session("10.0.0.1", "10.0.0.2", count=3)
            + _make_session("10.0.0.2", "10.0.0.1", count=2)
        )
        result = analyzer.analyze(sessions)
        src_bytes = {item["ip"]: item["bytes"] for item in result.top_src}
        dst_bytes = {item["ip"]: item["bytes"] for item in result.top_dst}
        assert src_bytes.get("10.0.0.1") == 3 * 512
        assert dst_bytes.get("10.0.0.2") == 3 * 512

    def test_single_session_in_top1(self):
        """세션 1개 → top_src[0].bytes == 512(bytes_sent)."""
        analyzer = _load_analyzer()
        sessions = _make_session("10.0.0.1", "10.0.0.2")
        result = analyzer.analyze(sessions)
        assert len(result.top_src) == 1
        assert result.top_src[0]["bytes"] == 512
