"""Panel 8 — DNS 쿼리 분석 + NXDOMAIN edge case 테스트 (TDD).

대상: services.analytics.dns_analyzer.DnsAnalyzer

인터페이스 가정:
  DnsAnalyzer().analyze(sessions) -> DnsAnalysisResult
  DnsAnalysisResult:
    query_counts: dict[str, int]    # 도메인별 쿼리 수
    query_types: dict[str, int]     # {"A": 10, "AAAA": 2, "CNAME": 1, ...}
    nxdomain_count: int
    nxdomain_domains: list[str]     # NXDOMAIN 응답 도메인 목록
    nxdomain_sources: list[str]     # NXDOMAIN 많은 src_ip

DNS 메타데이터:
  meta["dns_query"]   : str          (질의 도메인)
  meta["dns_type"]    : str          ("A", "AAAA", "CNAME", ...)
  meta["dns_rcode"]   : str          ("NOERROR", "NXDOMAIN", ...)

검증 항목:
- A/AAAA/CNAME/MX 타입 카운트
- NXDOMAIN 응답 집계 (nxdomain_count, nxdomain_domains)
- NXDOMAIN 비율 높은 src_ip → nxdomain_sources
- 비-DNS 세션(meta 없음) → 스킵
- 빈 세션 → 모두 비어 있음
- 동일 도메인 여러 쿼리 → 합산
- NXDOMAIN rate ≥ 50% src_ip → nxdomain_sources 포함
"""
import uuid
import pytest


def _make_dns_session(
    src_ip: str = "192.168.1.100",
    query: str | None = None,
    qtype: str | None = None,
    rcode: str | None = None,
):
    try:
        from models.session import SessionModel
    except ImportError:
        pytest.skip("models.session 미구현")

    meta: dict = {}
    if query:
        meta["dns_query"] = query
    if qtype:
        meta["dns_type"] = qtype
    if rcode:
        meta["dns_rcode"] = rcode

    return SessionModel(
        session_id=str(uuid.uuid4()),
        src_ip=src_ip,
        dst_ip="8.8.8.8",
        src_port=50000,
        dst_port=53,
        protocol="UDP",
        start_ts=1_748_000_000.0,
        end_ts=1_748_000_000.5,
        bytes_sent=64,
        bytes_recv=128,
        packet_count=2,
        payload_length=64,
        confidence="normal",
        meta=meta if meta else None,
    )


def _load_analyzer():
    try:
        from services.analytics.dns_analyzer import DnsAnalyzer
        return DnsAnalyzer()
    except ImportError:
        pytest.skip("dns_analyzer 미구현")


class TestDnsQueryCounts:
    def test_domain_counted(self):
        analyzer = _load_analyzer()
        sessions = [_make_dns_session(query="example.com", qtype="A")]
        result = analyzer.analyze(sessions)
        assert result.query_counts.get("example.com") == 1

    def test_same_domain_aggregated(self):
        analyzer = _load_analyzer()
        sessions = [_make_dns_session(query="evil.com", qtype="A") for _ in range(5)]
        result = analyzer.analyze(sessions)
        assert result.query_counts.get("evil.com") == 5


class TestDnsQueryTypes:
    def test_a_aaaa_cname_types(self):
        analyzer = _load_analyzer()
        sessions = [
            _make_dns_session(query="a.com", qtype="A"),
            _make_dns_session(query="b.com", qtype="AAAA"),
            _make_dns_session(query="c.com", qtype="CNAME"),
            _make_dns_session(query="d.com", qtype="MX"),
        ]
        result = analyzer.analyze(sessions)
        assert result.query_types.get("A") == 1
        assert result.query_types.get("AAAA") == 1
        assert result.query_types.get("CNAME") == 1
        assert result.query_types.get("MX") == 1

    def test_unknown_type_handled(self):
        analyzer = _load_analyzer()
        sessions = [_make_dns_session(query="x.com", qtype="XTYPE")]
        result = analyzer.analyze(sessions)
        total = sum(result.query_types.values())
        assert total >= 1


class TestNxdomain:
    def test_nxdomain_count(self):
        """NXDOMAIN 응답 3개 → nxdomain_count=3."""
        analyzer = _load_analyzer()
        sessions = [
            _make_dns_session(query=f"nonexist{i}.com", qtype="A", rcode="NXDOMAIN")
            for i in range(3)
        ]
        result = analyzer.analyze(sessions)
        assert result.nxdomain_count == 3

    def test_nxdomain_domains_collected(self):
        analyzer = _load_analyzer()
        sessions = [
            _make_dns_session(query="ghost.com", qtype="A", rcode="NXDOMAIN"),
        ]
        result = analyzer.analyze(sessions)
        assert "ghost.com" in result.nxdomain_domains

    def test_noerror_not_counted_as_nxdomain(self):
        analyzer = _load_analyzer()
        sessions = [_make_dns_session(query="ok.com", qtype="A", rcode="NOERROR")]
        result = analyzer.analyze(sessions)
        assert result.nxdomain_count == 0

    def test_high_nxdomain_src_in_sources(self):
        """NXDOMAIN 비율 높은 src_ip → nxdomain_sources 포함."""
        analyzer = _load_analyzer()
        # src 10.0.0.1: 10 NXDOMAIN / 10 총 쿼리 (100%)
        sessions = [
            _make_dns_session(src_ip="10.0.0.1", query=f"bad{i}.com", qtype="A", rcode="NXDOMAIN")
            for i in range(10)
        ]
        result = analyzer.analyze(sessions)
        assert "10.0.0.1" in result.nxdomain_sources


class TestDnsEdge:
    def test_empty_sessions(self):
        analyzer = _load_analyzer()
        result = analyzer.analyze([])
        assert result.query_counts == {}
        assert result.query_types == {}
        assert result.nxdomain_count == 0
        assert result.nxdomain_domains == []

    def test_non_dns_session_skipped(self):
        """meta 없는 세션 → 에러 없이 스킵."""
        analyzer = _load_analyzer()
        sessions = [_make_dns_session()]  # meta 없음
        result = analyzer.analyze(sessions)
        assert isinstance(result.query_counts, dict)
