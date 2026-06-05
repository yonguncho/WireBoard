"""HttpStatusAnalyzer — Panel 4: HTTP 응답 코드 분석."""
from collections import defaultdict
from dataclasses import dataclass, field

from models.session import SessionModel


@dataclass
class HttpStatusResult:
    counts: dict = field(default_factory=dict)
    groups: dict = field(default_factory=dict)
    top_errors: list = field(default_factory=list)


def _group_name(code: int) -> str:
    if 200 <= code < 300:
        return "2xx"
    if 300 <= code < 400:
        return "3xx"
    if 400 <= code < 500:
        return "4xx"
    if 500 <= code < 600:
        return "5xx"
    return "unknown"


class HttpStatusAnalyzer:
    def analyze(self, sessions: list[SessionModel]) -> HttpStatusResult:
        code_counts: dict[int, int] = defaultdict(int)
        groups: dict[str, int] = {"2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0}

        for s in sessions:
            if not s.meta:
                continue
            code = s.meta.get("status_code") or s.meta.get("status")
            if code is None:
                continue
            try:
                code = int(code)
            except (TypeError, ValueError):
                continue
            if code == 0:
                continue
            code_counts[code] += 1
            grp = _group_name(code)
            if grp in groups:
                groups[grp] += 1

        error_codes = {
            code: cnt
            for code, cnt in code_counts.items()
            if 400 <= code < 600
        }
        top_errors = [
            {"status_code": code, "count": cnt}
            for code, cnt in sorted(error_codes.items(), key=lambda x: -x[1])
        ]

        return HttpStatusResult(
            counts=dict(code_counts),
            groups=groups,
            top_errors=top_errors,
        )
