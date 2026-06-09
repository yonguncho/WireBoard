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
    packet_map: dict = field(default_factory=dict)  # session_id -> list[PacketRecord]
    icmp_events: list = field(default_factory=list)  # ICMP 에러 이벤트 (type 3/11)


class SessionStore:
    MAX_SIZE = 10

    def __init__(self, ttl_seconds: float = 3600.0, on_evict: Callable[[str], None] | None = None) -> None:
        self._ttl = ttl_seconds
        self._on_evict = on_evict
        self._store: OrderedDict[str, tuple[ParsedCapture, float]] = OrderedDict()
        self._lock = threading.Lock()

    def _delete_locked(self, key: str) -> None:
        """락 보유 상태에서 스토어에서 키를 삭제만 한다. 콜백은 락 해제 후 호출자가 담당."""
        del self._store[key]

    def _fire_evict(self, key: str) -> None:
        """on_evict 콜백을 락 외부에서 안전하게 호출한다."""
        if self._on_evict is not None:
            self._on_evict(key)

    def put(self, key: str, value: ParsedCapture) -> None:
        evicted_keys: list[str] = []
        with self._lock:
            self._evict_expired_locked(evicted_keys)
            if key in self._store:
                self._store.move_to_end(key)
            self._store[key] = (value, time.monotonic())
            if len(self._store) > self.MAX_SIZE:
                lru_key, _ = self._store.popitem(last=False)
                evicted_keys.append(lru_key)
        for k in evicted_keys:
            self._fire_evict(k)

    def get(self, key: str) -> ParsedCapture:
        evicted: bool = False
        with self._lock:
            if key not in self._store:
                raise KeyError(key)
            value, inserted_at = self._store[key]
            if time.monotonic() - inserted_at >= self._ttl:
                self._delete_locked(key)
                evicted = True
            else:
                self._store.move_to_end(key)
                result = copy.deepcopy(value)
        if evicted:
            self._fire_evict(key)
            raise KeyError(key)
        return result

    def update_analysis(self, key: str, target_ip: str, attacks: list) -> None:
        evicted: bool = False
        with self._lock:
            if key not in self._store:
                raise KeyError(key)
            value, ts = self._store[key]
            if time.monotonic() - ts >= self._ttl:
                self._delete_locked(key)
                evicted = True
            else:
                value.target_ip = target_ip
                value.attacks = list(attacks)
        if evicted:
            self._fire_evict(key)
            raise KeyError(key)

    def evict_expired(self) -> int:
        evicted_keys: list[str] = []
        with self._lock:
            self._evict_expired_locked(evicted_keys)
        for k in evicted_keys:
            self._fire_evict(k)
        return len(evicted_keys)

    def _evict_expired_locked(self, out: list[str] | None = None) -> int:
        now = time.monotonic()
        expired = [k for k, (_, ts) in self._store.items() if now - ts >= self._ttl]
        for k in expired:
            self._delete_locked(k)
            if out is not None:
                out.append(k)
        return len(expired)
