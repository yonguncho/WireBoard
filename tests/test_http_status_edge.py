"""Panel 4 — HTTP 응답 코드 분석 edge case 테스트 (TDD).

대상: services.analytics.http_status_analyzer.HttpStatusAnalyzer

인터페이스 가정:
  HttpStatusAnalyzer().analyze(sessions) -> HttpStatusResult
  HttpStatusResult:
    counts: dict[int, int]          # {200: 5, 404: 2, ...}
    groups: dict[str, int]          # {"2xx": 5, "3xx": 1, "4xx": 2, "5xx": 0}
    top_errors: list[dict]          # 4xx/5xx 코드 상위 N개

HTTP 상태는 session.meta["status_code"] 에 저장된다고 가정.

검증 항목:
- 200/301/302/400/403/404/500 각각 정확 집계
- 2xx/3xx/4xx/5xx 그룹 집계
- HAR 출처가 아닌 세션(meta 없음) → 스킵 (에러 없음)
- 빈 세션 → counts={}, groups 전부 0
- top_errors 에는 4xx, 5xx만 포함
- 알 수 없는 상태 코드(999) → "unknown" 그룹 또는 무시
- 동일 상태 코드 여러 세션 → 합산
"""
import uuid
import pytest


def _make_session(status_code: int | None = None):
    try:
        from models.session import SessionModel
    except ImportError:
        pytest.skip("models.session 미구현")

    meta = {"status_code": status_code, "method": "GET"} if status_code is not None else None
    return SessionModel(
        session_id=str(uuid.uuid4()),
        src_ip="192.168.1.100",
        dst_ip="10.0.0.1",
        src_port=50000,
        dst_port=80,
        protocol="TCP",
        start_ts=1_748_000_000.0,
        end_ts=1_748_000_001.0,
        bytes_sent=512,
        bytes_recv=512,
        packet_count=5,
        payload_length=512,
        confidence="normal",
        meta=meta,
    )


def _load_analyzer():
    try:
        from services.analytics.http_status_analyzer import HttpStatusAnalyzer
        return HttpStatusAnalyzer()
    except ImportError:
        pytest.skip("http_status_analyzer 미구현")


class TestHttpStatusCounts:
    def test_200_counted(self):
        analyzer = _load_analyzer()
        sessions = [_make_session(200) for _ in range(5)]
        result = analyzer.analyze(sessions)
        assert result.counts.get(200) == 5

    def test_404_counted(self):
        analyzer = _load_analyzer()
        sessions = [_make_session(404)] * 3
        result = analyzer.analyze(sessions)
        assert result.counts.get(404) == 3

    def test_500_counted(self):
        analyzer = _load_analyzer()
        sessions = [_make_session(500)] * 2
        result = analyzer.analyze(sessions)
        assert result.counts.get(500) == 2

    def test_multiple_codes(self):
        """200×3, 301×1, 404×2 각각 정확."""
        analyzer = _load_analyzer()
        sessions = (
            [_make_session(200)] * 3
            + [_make_session(301)] * 1
            + [_make_session(404)] * 2
        )
        result = analyzer.analyze(sessions)
        assert result.counts.get(200) == 3
        assert result.counts.get(301) == 1
        assert result.counts.get(404) == 2


class TestHttpStatusGroups:
    def test_2xx_group(self):
        analyzer = _load_analyzer()
        sessions = [_make_session(200), _make_session(201), _make_session(204)]
        result = analyzer.analyze(sessions)
        assert result.groups.get("2xx") == 3

    def test_3xx_group(self):
        analyzer = _load_analyzer()
        sessions = [_make_session(301), _make_session(302)]
        result = analyzer.analyze(sessions)
        assert result.groups.get("3xx") == 2

    def test_4xx_group(self):
        analyzer = _load_analyzer()
        sessions = [_make_session(400), _make_session(403), _make_session(404)]
        result = analyzer.analyze(sessions)
        assert result.groups.get("4xx") == 3

    def test_5xx_group(self):
        analyzer = _load_analyzer()
        sessions = [_make_session(500), _make_session(503)]
        result = analyzer.analyze(sessions)
        assert result.groups.get("5xx") == 2


class TestHttpStatusEdge:
    def test_empty_sessions(self):
        analyzer = _load_analyzer()
        result = analyzer.analyze([])
        assert result.counts == {}
        assert all(v == 0 for v in result.groups.values())

    def test_sessions_without_meta_skipped(self):
        """meta 없는 세션(비-HAR) → 에러 없이 스킵."""
        analyzer = _load_analyzer()
        sessions = [_make_session(None), _make_session(None)]
        result = analyzer.analyze(sessions)
        assert isinstance(result.counts, dict)

    def test_top_errors_contains_only_4xx_5xx(self):
        """top_errors 는 4xx, 5xx만 포함."""
        analyzer = _load_analyzer()
        sessions = (
            [_make_session(200)] * 5
            + [_make_session(404)] * 3
            + [_make_session(500)] * 2
        )
        result = analyzer.analyze(sessions)
        for item in result.top_errors:
            code = item.get("code") or item.get("status_code")
            assert 400 <= code < 600, f"top_errors에 4xx/5xx 외 코드 포함: {code}"

    def test_unknown_status_code_handled(self):
        """상태 코드 999 → 에러 없이 처리 (unknown 그룹 또는 무시)."""
        analyzer = _load_analyzer()
        sessions = [_make_session(999)]
        result = analyzer.analyze(sessions)
        assert isinstance(result.counts, dict)
