"""Panel 3 — 플로우 타임라인 edge case 테스트 (TDD).

대상: services.analytics.flow_timeline.FlowTimeline

인터페이스 가정:
  FlowTimeline(window_seconds=60).compute(sessions) -> TimelineResult
  TimelineResult:
    buckets: list[dict]  # [{"ts": float, "count": int}, ...]
    # ts = 버킷 시작 타임스탬프, window_seconds 간격
    # 오름차순 정렬

검증 항목:
- 단일 세션 → 1개 버킷
- 60 초 윈도우 내 모든 세션 → 1개 버킷에 집계
- 정확히 2개 윈도우에 걸친 세션 → 2개 버킷
- bucket.ts 오름차순 정렬
- 빈 세션 → buckets=[]
- window_seconds 파라미터 변경 반영
- 버킷 경계(ts % window == 0) 정확성
- count 합산 = len(sessions)
"""
import uuid
import pytest


def _make_session(ts_start: float, *, ts_end: float | None = None):
    try:
        from models.session import SessionModel
    except ImportError:
        pytest.skip("models.session 미구현")

    if ts_end is None:
        ts_end = ts_start + 1.0

    return SessionModel(
        session_id=str(uuid.uuid4()),
        src_ip="192.168.1.100",
        dst_ip="10.0.0.1",
        src_port=50000,
        dst_port=80,
        protocol="TCP",
        start_ts=ts_start,
        end_ts=ts_end,
        bytes_sent=512,
        bytes_recv=512,
        packet_count=5,
        payload_length=512,
        confidence="normal",
    )


def _load_timeline(window_seconds: int = 60):
    try:
        from services.analytics.flow_timeline import FlowTimeline
        return FlowTimeline(window_seconds=window_seconds)
    except ImportError:
        pytest.skip("flow_timeline 미구현")


class TestFlowTimelineBuckets:
    def test_empty_returns_empty(self):
        tl = _load_timeline()
        result = tl.compute([])
        assert result.buckets == []

    def test_single_session_one_bucket(self):
        tl = _load_timeline()
        sessions = [_make_session(1_748_000_000.0)]
        result = tl.compute(sessions)
        assert len(result.buckets) == 1
        assert result.buckets[0]["count"] == 1

    def test_sessions_in_same_window_one_bucket(self):
        """60 초 윈도우 내 5개 세션 → 1개 버킷 count=5."""
        tl = _load_timeline(window_seconds=60)
        base = 1_748_000_000.0
        sessions = [_make_session(base + i) for i in range(5)]
        result = tl.compute(sessions)
        assert len(result.buckets) == 1
        assert result.buckets[0]["count"] == 5

    def test_two_windows_two_buckets(self):
        """60 초 이상 간격 → 2개 버킷."""
        tl = _load_timeline(window_seconds=60)
        sessions = [
            _make_session(1_748_000_000.0),
            _make_session(1_748_000_065.0),
        ]
        result = tl.compute(sessions)
        assert len(result.buckets) == 2

    def test_buckets_ascending_order(self):
        """buckets 은 ts 오름차순."""
        tl = _load_timeline(window_seconds=60)
        sessions = [
            _make_session(1_748_000_130.0),
            _make_session(1_748_000_000.0),
            _make_session(1_748_000_065.0),
        ]
        result = tl.compute(sessions)
        tss = [b["ts"] for b in result.buckets]
        assert tss == sorted(tss)

    def test_total_count_equals_session_count(self):
        """모든 버킷 count 합 == 입력 세션 수."""
        tl = _load_timeline(window_seconds=60)
        sessions = [_make_session(1_748_000_000.0 + i * 10) for i in range(20)]
        result = tl.compute(sessions)
        total = sum(b["count"] for b in result.buckets)
        assert total == 20

    def test_window_parameter_respected(self):
        """window_seconds=30 → 30 초 경계에서 분리."""
        tl = _load_timeline(window_seconds=30)
        sessions = [
            _make_session(1_748_000_000.0),
            _make_session(1_748_000_035.0),
        ]
        result = tl.compute(sessions)
        assert len(result.buckets) == 2

    def test_bucket_ts_is_window_aligned(self):
        """버킷 ts 는 window_seconds 경계에 정렬된다."""
        window = 60
        tl = _load_timeline(window_seconds=window)
        sessions = [_make_session(1_748_000_037.5)]
        result = tl.compute(sessions)
        bucket_ts = result.buckets[0]["ts"]
        assert bucket_ts % window == 0.0


class TestFlowTimelineEdge:
    def test_session_on_boundary_belongs_to_correct_bucket(self):
        """ts 가 정확히 버킷 경계인 세션은 해당 버킷에 속한다."""
        tl = _load_timeline(window_seconds=60)
        # 1_748_000_060 은 두 번째 60 초 버킷 시작
        sessions = [
            _make_session(1_748_000_000.0),
            _make_session(1_748_000_060.0),
        ]
        result = tl.compute(sessions)
        assert len(result.buckets) == 2
        total = sum(b["count"] for b in result.buckets)
        assert total == 2
