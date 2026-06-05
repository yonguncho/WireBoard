"""SessionStore — LRU(max=10) + TTL 세션 캐시."""
import copy
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Callable, Optional

from models.session import SessionModel


@dataclass
class ParsedCapture:
    sessions: list
    source_type: str
    parse_warnings: list = field(default_factory=list)
    target_ip: str = ""
    attacks: list = field(default_factory=list)


class SessionStore:
    MAX_SIZE = 10

    def __init__(self, ttl_seconds: float = 3600.0, on_evict: Callable[[str], None] | None = None) -> None:
        self._ttl = ttl_seconds
        self._on_evict = on_evict
        self._store: OrderedDict[str, tuple[ParsedCapture, float]] = OrderedDict()
        self._lock = threading.Lock()

    def _do_evict(self, key: str) -> None:
        del self._store[key]
        if self._on_evict is not None:
            self._on_evict(key)

    def put(self, key: str, value: ParsedCapture) -> None:
        with self._lock:
            self._evict_expired_locked()
            if key in self._store:
                self._store.move_to_end(key)
            self._store[key] = (value, time.monotonic())
            if len(self._store) > self.MAX_SIZE:
                evicted_key, _ = self._store.popitem(last=False)
                if self._on_evict is not None:
                    self._on_evict(evicted_key)

    def get(self, key: str) -> ParsedCapture:
        with self._lock:
            if key not in self._store:
                raise KeyError(key)
            value, inserted_at = self._store[key]
            if time.monotonic() - inserted_at >= self._ttl:
                self._do_evict(key)
                raise KeyError(key)
            self._store.move_to_end(key)
            return copy.deepcopy(value)

    def update_analysis(self, key: str, target_ip: str, attacks: list) -> None:
        with self._lock:
            if key not in self._store:
                raise KeyError(key)
            value, ts = self._store[key]
            value.target_ip = target_ip
            value.attacks = list(attacks)

    def evict_expired(self) -> int:
        with self._lock:
            return self._evict_expired_locked()

    def _evict_expired_locked(self) -> int:
        now = time.monotonic()
        expired = [k for k, (_, ts) in self._store.items() if now - ts >= self._ttl]
        for k in expired:
            self._do_evict(k)
        return len(expired)
