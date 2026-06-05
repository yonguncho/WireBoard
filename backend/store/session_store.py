"""SessionStore — LRU(max=10) + TTL 세션 캐시."""
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Optional

from models.session import SessionModel


@dataclass
class ParsedCapture:
    sessions: list
    source_type: str
    parse_warnings: list = field(default_factory=list)


class SessionStore:
    MAX_SIZE = 10

    def __init__(self, ttl_seconds: float = 3600.0) -> None:
        self._ttl = ttl_seconds
        self._store: OrderedDict[str, tuple[ParsedCapture, float]] = OrderedDict()

    def put(self, key: str, value: ParsedCapture) -> None:
        self.evict_expired()
        if key in self._store:
            self._store.move_to_end(key)
        self._store[key] = (value, time.monotonic())
        if len(self._store) > self.MAX_SIZE:
            self._store.popitem(last=False)

    def get(self, key: str) -> ParsedCapture:
        if key not in self._store:
            raise KeyError(key)
        value, inserted_at = self._store[key]
        if time.monotonic() - inserted_at >= self._ttl:
            del self._store[key]
            raise KeyError(key)
        self._store.move_to_end(key)
        return value

    def evict_expired(self) -> int:
        now = time.monotonic()
        expired = [k for k, (_, ts) in self._store.items() if now - ts >= self._ttl]
        for k in expired:
            del self._store[k]
        return len(expired)
