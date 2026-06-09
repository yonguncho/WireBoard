"""HTTPExtractor — HTTP 요청/응답 페이로드 파싱."""
from dataclasses import dataclass
from typing import Optional

_HTTP_METHODS = frozenset({
    "GET", "POST", "PUT", "DELETE", "PATCH",
    "HEAD", "OPTIONS", "TRACE", "CONNECT",
})


@dataclass
class HTTPResult:
    method: Optional[str] = None
    uri: Optional[str] = None
    host: Optional[str] = None
    user_agent: Optional[str] = None
    status_code: Optional[int] = None


class HTTPExtractor:
    def extract(self, payload: bytes) -> Optional[HTTPResult]:
        if not payload:
            return None
        try:
            text = payload.decode("ascii", errors="strict")
        except (UnicodeDecodeError, ValueError):
            return None

        lines = text.split("\r\n")
        if not lines:
            return None

        first_line = lines[0]
        result = HTTPResult()

        if first_line.startswith("HTTP/"):
            parts = first_line.split(" ", 2)
            if len(parts) < 2:
                return None
            try:
                result.status_code = int(parts[1])
            except ValueError:
                return None
        else:
            parts = first_line.split(" ")
            if len(parts) < 3:
                return None
            method = parts[0]
            if method not in _HTTP_METHODS:
                return None
            result.method = method
            result.uri = parts[1]

        for line in lines[1:]:
            if not line:
                break
            if ":" not in line:
                continue
            name, _, value = line.partition(":")
            key = name.strip().lower()
            val = value.strip()
            if key == "host":
                result.host = val
            elif key == "user-agent":
                result.user_agent = val

        return result
