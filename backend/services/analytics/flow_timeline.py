"""FlowTimeline — Panel 3: 시간대별 플로우 버킷."""
import math
from collections import defaultdict
from dataclasses import dataclass, field

from models.session import SessionModel


@dataclass
class TimelineResult:
    buckets: list = field(default_factory=list)


class FlowTimeline:
    def __init__(self, window_seconds: int = 60) -> None:
        self._window = window_seconds

    def compute(self, sessions: list[SessionModel]) -> TimelineResult:
        if not sessions:
            return TimelineResult()

        bucket_bytes: dict[float, int] = defaultdict(int)
        bucket_count: dict[float, int] = defaultdict(int)
        bucket_rst: dict[float, int] = defaultdict(int)       # 오류 오버레이용
        bucket_noreply: dict[float, int] = defaultdict(int)
        for s in sessions:
            bucket_ts = float(math.floor(s.start_ts / self._window) * self._window)
            bucket_bytes[bucket_ts] += s.bytes_sent + s.bytes_recv
            bucket_count[bucket_ts] += 1
            if s.rst:
                bucket_rst[bucket_ts] += 1
            if (s.protocol or "").upper() == "TCP" and s.bytes_sent > 0 and s.bytes_recv == 0:
                bucket_noreply[bucket_ts] += 1

        buckets = [
            {
                "ts": ts, "bytes": bucket_bytes[ts], "count": bucket_count[ts],
                # "언제부터 문제였나" — 시간축 오류 오버레이
                "rst": bucket_rst[ts], "no_reply": bucket_noreply[ts],
                "errors": bucket_rst[ts] + bucket_noreply[ts],
            }
            for ts in sorted(bucket_bytes.keys())
        ]
        return TimelineResult(buckets=buckets)
