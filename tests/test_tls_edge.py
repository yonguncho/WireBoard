"""Panel 7 — TLS 핸드셰이크 분석 edge case 테스트 (TDD).

대상: services.analytics.tls_analyzer.TlsAnalyzer

인터페이스 가정:
  TlsAnalyzer().analyze(sessions) -> TlsAnalysisResult
  TlsAnalysisResult:
    sni_counts: dict[str, int]      # SNI 도메인별 카운트
    ja4_fingerprints: list[str]     # 고유 JA4 지문 목록
    tls_versions: dict[str, int]    # {"TLS 1.2": 3, "TLS 1.3": 5}
    cert_cns: list[str]             # 인증서 CN 목록

TLS 메타데이터는 session.meta 에 저장:
  meta["tls_sni"]     : str
  meta["ja4"]         : str
  meta["tls_version"] : str  ("TLS 1.2", "TLS 1.3", ...)
  meta["cert_cn"]     : str

검증 항목:
- SNI 도메인별 카운트 정확성
- JA4 지문 고유 집합 반환
- TLS 버전별 카운트
- cert_cn 수집
- meta 없는 세션 → 에러 없이 스킵
- 빈 세션 → 모두 비어 있음
- 알 수 없는 TLS 버전("SSLv3") → "unknown" 또는 그대로 처리
- 동일 SNI 여러 세션 → 합산
"""
import uuid
import pytest


def _make_tls_session(
    sni: str | None = None,
    ja4: str | None = None,
    tls_version: str | None = None,
    cert_cn: str | None = None,
):
    try:
        from models.session import SessionModel
    except ImportError:
        pytest.skip("models.session 미구현")

    meta: dict = {}
    if sni:
        meta["tls_sni"] = sni
    if ja4:
        meta["ja4"] = ja4
    if tls_version:
        meta["tls_version"] = tls_version
    if cert_cn:
        meta["cert_cn"] = cert_cn

    return SessionModel(
        session_id=str(uuid.uuid4()),
        src_ip="192.168.1.100",
        dst_ip="203.0.113.1",
        src_port=50000,
        dst_port=443,
        protocol="TCP",
        start_ts=1_748_000_000.0,
        end_ts=1_748_000_002.0,
        bytes_sent=4096,
        bytes_recv=8192,
        packet_count=20,
        payload_length=4096,
        confidence="normal",
        meta=meta if meta else None,
    )


def _load_analyzer():
    try:
        from services.analytics.tls_analyzer import TlsAnalyzer
        return TlsAnalyzer()
    except ImportError:
        pytest.skip("tls_analyzer 미구현")


class TestSniCounts:
    def test_single_sni_counted(self):
        analyzer = _load_analyzer()
        sessions = [_make_tls_session(sni="example.com")]
        result = analyzer.analyze(sessions)
        assert result.sni_counts.get("example.com") == 1

    def test_same_sni_aggregated(self):
        """같은 SNI 5회 → count=5."""
        analyzer = _load_analyzer()
        sessions = [_make_tls_session(sni="api.example.com") for _ in range(5)]
        result = analyzer.analyze(sessions)
        assert result.sni_counts.get("api.example.com") == 5

    def test_different_sni_independent(self):
        analyzer = _load_analyzer()
        sessions = [
            _make_tls_session(sni="a.com"),
            _make_tls_session(sni="a.com"),
            _make_tls_session(sni="b.com"),
        ]
        result = analyzer.analyze(sessions)
        assert result.sni_counts.get("a.com") == 2
        assert result.sni_counts.get("b.com") == 1


class TestJA4Fingerprints:
    def test_unique_ja4_collected(self):
        """고유 JA4 지문 반환."""
        analyzer = _load_analyzer()
        sessions = [
            _make_tls_session(ja4="t13d1715h2_abc123"),
            _make_tls_session(ja4="t13d1715h2_abc123"),  # 중복
            _make_tls_session(ja4="t13d1715h2_def456"),
        ]
        result = analyzer.analyze(sessions)
        assert len(result.ja4_fingerprints) == 2
        assert "t13d1715h2_abc123" in result.ja4_fingerprints
        assert "t13d1715h2_def456" in result.ja4_fingerprints


class TestTlsVersions:
    def test_tls12_and_13_counted(self):
        analyzer = _load_analyzer()
        sessions = [
            _make_tls_session(tls_version="TLS 1.2"),
            _make_tls_session(tls_version="TLS 1.2"),
            _make_tls_session(tls_version="TLS 1.3"),
        ]
        result = analyzer.analyze(sessions)
        assert result.tls_versions.get("TLS 1.2") == 2
        assert result.tls_versions.get("TLS 1.3") == 1

    def test_unknown_version_handled(self):
        """SSLv3 등 알 수 없는 버전 → 에러 없이 집계."""
        analyzer = _load_analyzer()
        sessions = [_make_tls_session(tls_version="SSLv3")]
        result = analyzer.analyze(sessions)
        total = sum(result.tls_versions.values())
        assert total == 1


class TestTlsEdge:
    def test_empty_sessions(self):
        analyzer = _load_analyzer()
        result = analyzer.analyze([])
        assert result.sni_counts == {}
        assert result.ja4_fingerprints == []
        assert result.tls_versions == {}

    def test_non_tls_session_skipped(self):
        """meta 없는 세션 → 에러 없이 스킵."""
        analyzer = _load_analyzer()
        sessions = [_make_tls_session()]  # meta 없음
        result = analyzer.analyze(sessions)
        assert isinstance(result.sni_counts, dict)

    def test_cert_cn_collected(self):
        analyzer = _load_analyzer()
        sessions = [_make_tls_session(cert_cn="CN=example.com")]
        result = analyzer.analyze(sessions)
        assert "CN=example.com" in result.cert_cns
