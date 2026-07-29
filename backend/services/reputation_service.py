"""ReputationService — 외부 위협 인텔리전스 조회 (ip-api, Feodo, URLhaus, AbuseIPDB)."""
import asyncio
import logging
import os
import time
from typing import Optional

logger = logging.getLogger(__name__)

try:
    import httpx
    _HTTPX_AVAILABLE = True
except ImportError:
    _HTTPX_AVAILABLE = False

from models.reputation import ReputationResult, ReputationSourceResult

_FEODO_CACHE: set = set()
# -inf 로 초기화해 첫 조회는 항상 다운로드를 강제한다.
# (0.0 이면 monotonic 에포크 후 1시간 내 기동 시 빈 캐시를 '신선'으로 오인해 블록리스트를 안 받음)
_FEODO_CACHE_TS: float = float("-inf")
_FEODO_CACHE_TTL: float = 3600.0
_FEODO_LOCK: asyncio.Lock | None = None


def _get_feodo_lock() -> asyncio.Lock:
    global _FEODO_LOCK
    if _FEODO_LOCK is None:
        _FEODO_LOCK = asyncio.Lock()
    return _FEODO_LOCK

_IPAPI_URL = "https://ip-api.com/json/{ip}?fields=countryCode,as,org,status"
_FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
_URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/host/"
_ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

_ABUSE_THRESHOLD = 70

# 오프라인이 기본 태세다. 외부 조회는 명시적 옵트인일 때만 수행한다.
# ENABLE_EXTERNAL_REPUTATION 을 1/true/yes/on 으로 설정해야 활성화되며,
# 그 외의 값·미설정·오타는 모두 비활성화로 떨어진다(fail-closed).
#
# 이 플래그는 네 개 소스 **전부**를 덮는다:
#   - ip-api / urlhaus / abuseipdb : 조회 IP가 그대로 외부로 나가는 per-IP 조회
#   - feodo                        : IP를 노출하진 않지만 외부 네트워크 접속 자체가
#                                    발생하므로, "외부 API 0건" 보장을 지키려면 함께 막아야 한다.
#                                    단 게이트는 캐시 조회 아래에 두어, 이미 받아둔
#                                    블록리스트는 오프라인에서도 계속 응답한다.
_EXTERNAL_REPUTATION_ENABLED: bool = (
    os.environ.get("ENABLE_EXTERNAL_REPUTATION", "0").strip().lower()
    in ("1", "true", "yes", "on")
)


class ReputationService:
    async def _lookup_ipapi(self, ip: str) -> ReputationSourceResult:
        if not _EXTERNAL_REPUTATION_ENABLED:
            return ReputationSourceResult(source="ip-api", is_reliable=False, note="외부 조회 비활성화 (ENABLE_EXTERNAL_REPUTATION 미설정)")
        if not _HTTPX_AVAILABLE:
            return ReputationSourceResult(source="ip-api", is_reliable=False)
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(_IPAPI_URL.format(ip=ip))
                if resp.status_code != 200:
                    return ReputationSourceResult(source="ip-api", is_reliable=False)
                ct = resp.headers.get("content-type", "")
                if "application/json" not in ct:
                    return ReputationSourceResult(source="ip-api", is_reliable=False)
                data = resp.json()
                return ReputationSourceResult(
                    source="ip-api",
                    is_malicious=False,
                    is_reliable=True,
                    country_code=data.get("countryCode"),
                    asn=data.get("as"),
                )
        except httpx.TimeoutException:
            return ReputationSourceResult(source="ip-api", is_reliable=False)
        except Exception as exc:
            logger.debug("ip-api 조회 실패: %s", exc)
            return ReputationSourceResult(source="ip-api", is_reliable=False)

    async def _lookup_feodo(self, ip: str) -> ReputationSourceResult:
        global _FEODO_CACHE, _FEODO_CACHE_TS
        now = time.monotonic()
        if now - _FEODO_CACHE_TS < _FEODO_CACHE_TTL:
            return ReputationSourceResult(
                source="feodo",
                is_malicious=(ip in _FEODO_CACHE),
                is_reliable=True,
            )
        # 캐시 미스 이후부터가 실제 외부 접속이다 — 여기서 막는다.
        # (위의 캐시 히트 분기는 그대로 통과하므로 받아둔 목록은 오프라인에서도 유효)
        if not _EXTERNAL_REPUTATION_ENABLED:
            return ReputationSourceResult(
                source="feodo",
                is_reliable=False,
                note="외부 조회 비활성화 (ENABLE_EXTERNAL_REPUTATION 미설정)",
            )
        if not _HTTPX_AVAILABLE:
            return ReputationSourceResult(source="feodo", is_reliable=False)
        async with _get_feodo_lock():
            if time.monotonic() - _FEODO_CACHE_TS < _FEODO_CACHE_TTL:
                return ReputationSourceResult(
                    source="feodo",
                    is_malicious=(ip in _FEODO_CACHE),
                    is_reliable=True,
                )
            try:
                async with httpx.AsyncClient(timeout=10.0) as client:
                    resp = await client.get(_FEODO_URL)
                    if resp.status_code != 200:
                        _FEODO_CACHE_TS = time.monotonic()
                        return ReputationSourceResult(source="feodo", is_reliable=False)
                    data = resp.json()
                    ips = {entry["ip_address"] for entry in data if isinstance(entry, dict) and "ip_address" in entry}
                    _FEODO_CACHE = ips
                    _FEODO_CACHE_TS = time.monotonic()
                    return ReputationSourceResult(
                        source="feodo",
                        is_malicious=(ip in ips),
                        is_reliable=True,
                    )
            except httpx.TimeoutException:
                _FEODO_CACHE_TS = time.monotonic()
                return ReputationSourceResult(source="feodo", is_reliable=False)
            except Exception as exc:
                logger.debug("feodo 조회 실패: %s", exc)
                _FEODO_CACHE_TS = time.monotonic()
                return ReputationSourceResult(source="feodo", is_reliable=False)

    async def _lookup_urlhaus(self, ip: str) -> ReputationSourceResult:
        if not _EXTERNAL_REPUTATION_ENABLED:
            return ReputationSourceResult(source="urlhaus", is_reliable=False, note="외부 조회 비활성화 (ENABLE_EXTERNAL_REPUTATION 미설정)")
        if not _HTTPX_AVAILABLE:
            return ReputationSourceResult(source="urlhaus", is_reliable=False)
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.post(_URLHAUS_URL, data={"host": ip})
                if resp.status_code != 200:
                    return ReputationSourceResult(source="urlhaus", is_reliable=False)
                data = resp.json()
                is_malicious = data.get("query_status") == "is_host"
                return ReputationSourceResult(source="urlhaus", is_malicious=is_malicious)
        except httpx.TimeoutException:
            return ReputationSourceResult(source="urlhaus", is_reliable=False)
        except Exception as exc:
            logger.debug("urlhaus 조회 실패: %s", exc)
            return ReputationSourceResult(source="urlhaus", is_reliable=False)

    async def _lookup_abuseipdb(self, ip: str) -> ReputationSourceResult:
        # ABUSEIPDB_API_KEY 만으로 게이트되어 있어, 오프라인 스위치를 꺼도 키가
        # 설정돼 있으면 캡처 IP가 계속 외부로 나가던 구멍을 닫는다.
        if not _EXTERNAL_REPUTATION_ENABLED:
            return ReputationSourceResult(
                source="abuseipdb",
                is_reliable=False,
                note="외부 조회 비활성화 (ENABLE_EXTERNAL_REPUTATION 미설정)",
            )
        api_key = os.environ.get("ABUSEIPDB_API_KEY", "")
        if not api_key:
            return ReputationSourceResult(
                source="abuseipdb",
                is_reliable=False,
                note="AbuseIPDB API key not configured",
            )
        if not _HTTPX_AVAILABLE:
            return ReputationSourceResult(source="abuseipdb", is_reliable=False)
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(
                    _ABUSEIPDB_URL,
                    params={"ipAddress": ip, "maxAgeInDays": 30},
                    headers={"Key": api_key, "Accept": "application/json"},
                )
                if resp.status_code == 429:
                    return ReputationSourceResult(
                        source="abuseipdb",
                        is_reliable=False,
                        note="AbuseIPDB quota exceeded",
                    )
                if resp.status_code != 200:
                    return ReputationSourceResult(source="abuseipdb", is_reliable=False)
                data = resp.json()
                score = data.get("data", {}).get("abuseConfidenceScore", 0)
                country = data.get("data", {}).get("countryCode")
                return ReputationSourceResult(
                    source="abuseipdb",
                    is_malicious=(score >= _ABUSE_THRESHOLD),
                    is_reliable=True,
                    country_code=country,
                )
        except httpx.TimeoutException:
            return ReputationSourceResult(source="abuseipdb", is_reliable=False)
        except Exception as exc:
            logger.debug("abuseipdb 조회 실패: %s", exc)
            return ReputationSourceResult(source="abuseipdb", is_reliable=False)

    async def lookup_all(self, ip: str) -> ReputationResult:
        sources = []
        lookups = [
            self._lookup_ipapi(ip),
            self._lookup_feodo(ip),
            self._lookup_urlhaus(ip),
            self._lookup_abuseipdb(ip),
        ]
        results = await asyncio.gather(*lookups, return_exceptions=True)
        for r in results:
            if isinstance(r, ReputationSourceResult):
                sources.append(r)

        is_malicious = any(s.is_malicious and s.is_reliable for s in sources)
        return ReputationResult(ip=ip, is_malicious=is_malicious, sources=sources)
