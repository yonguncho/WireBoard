"""ReputationService — 외부 위협 인텔리전스 조회 (ip-api, Feodo, URLhaus, AbuseIPDB)."""
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
_FEODO_CACHE_TS: float = 0.0
_FEODO_CACHE_TTL: float = 3600.0

_IPAPI_URL = "http://ip-api.com/json/{ip}?fields=countryCode,as,org,status"
_FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
_URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/host/"
_ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

_ABUSE_THRESHOLD = 70


class ReputationService:
    async def _lookup_ipapi(self, ip: str) -> ReputationSourceResult:
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
        if not _HTTPX_AVAILABLE:
            return ReputationSourceResult(source="feodo", is_reliable=False)
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(_FEODO_URL)
                if resp.status_code != 200:
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
            return ReputationSourceResult(source="feodo", is_reliable=False)
        except Exception as exc:
            logger.debug("feodo 조회 실패: %s", exc)
            return ReputationSourceResult(source="feodo", is_reliable=False)

    async def _lookup_urlhaus(self, ip: str) -> ReputationSourceResult:
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
        import asyncio
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
