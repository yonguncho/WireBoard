"""GeoIP 분석 — geoip2(mmdb) 우선, 없으면 내장 CIDR 폴백.

폴백 CIDR 테이블은 geoip_fallback.json 에서 로드한다.
(ADR-005 준수: 바인딩 주소 리터럴은 .py 소스에 포함하지 않는다)
"""
import ipaddress
import json
import logging
from pathlib import Path

from utils.net_utils import is_private as _is_private

logger = logging.getLogger(__name__)

# ── 내장 폴백 테이블 — JSON 파일에서 로드 ──────────────────────────────
_FALLBACK: list[tuple[ipaddress.IPv4Network, str, str]] = []

_FALLBACK_JSON = Path(__file__).parent / "geoip_fallback.json"

def _load_fallback() -> None:
    """geoip_fallback.json 에서 CIDR 테이블을 로드한다."""
    try:
        raw = json.loads(_FALLBACK_JSON.read_text(encoding="utf-8"))
        for cidr, country, cc in raw:
            try:
                _FALLBACK.append((ipaddress.IPv4Network(cidr, strict=False), country, cc))
            except ValueError as e:
                logger.warning("폴백 CIDR 파싱 오류 %s: %s", cidr, e)
        logger.debug("GeoIP 폴백 테이블 로드 완료: %d 항목", len(_FALLBACK))
    except Exception as e:
        logger.error("geoip_fallback.json 로드 실패: %s", e)

_load_fallback()


def _fallback_lookup(ip_str: str) -> tuple[str, str]:
    """CIDR 테이블 폴백. (country_name, country_code) 반환."""
    try:
        addr = ipaddress.IPv4Address(ip_str)
    except ValueError:
        return "Unknown", "ZZ"
    for net, country, cc in _FALLBACK:
        if addr in net:
            return country, cc
    return "Unknown", "ZZ"


class GeoIpAnalyzer:
    def __init__(self) -> None:
        self._reader = None
        self._load_mmdb()

    def _load_mmdb(self) -> None:
        """GeoLite2-Country.mmdb 검색 — 실행파일 디렉터리 또는 backend 루트."""
        try:
            import geoip2.database
        except ImportError:
            logger.debug("geoip2 패키지 없음 — 폴백 모드")
            return

        search_paths = [
            Path(__file__).parent.parent.parent / "GeoLite2-Country.mmdb",
            Path(__file__).parent.parent / "GeoLite2-Country.mmdb",
            Path(__file__).parent / "GeoLite2-Country.mmdb",
        ]
        import sys
        if getattr(sys, "frozen", False):
            import os
            exe_dir = Path(os.path.dirname(sys.executable))
            search_paths.insert(0, exe_dir / "GeoLite2-Country.mmdb")

        for p in search_paths:
            if p.exists():
                try:
                    self._reader = geoip2.database.Reader(str(p))
                    logger.info("GeoIP2 mmdb 로드: %s", p)
                    return
                except Exception as e:
                    logger.warning("mmdb 로드 실패 %s: %s", p, e)

        logger.info("GeoLite2-Country.mmdb 없음 — 내장 CIDR 폴백 사용")

    def lookup(self, ip: str) -> dict:
        """IP 주소 → {ip, country_name, country_code} 딕셔너리 반환."""
        if self._reader is not None:
            try:
                resp = self._reader.country(ip)
                return {
                    "ip": ip,
                    "country_name": resp.country.name or "Unknown",
                    "country_code": resp.country.iso_code or "ZZ",
                }
            except Exception:
                pass
        country_name, country_code = _fallback_lookup(ip)
        return {"ip": ip, "country_name": country_name, "country_code": country_code}

    def analyze(self, sessions: list, attacks: list) -> list[dict]:
        """세션/공격에서 관련 IP를 추출하여 GeoIP 조회 결과 목록 반환.

        중복 IP 제거. attacker_ips 우선, 이후 dst_ip 외부 IP 추가.
        최대 100건.
        """
        ips_seen: set[str] = set()
        results: list[dict] = []

        # 공격자 IP 우선
        for attack in attacks:
            src = attack.get("src_ip", "")
            if src and src not in ips_seen:
                ips_seen.add(src)
                info = self.lookup(src)
                info["role"] = "attacker"
                info["attack_type"] = attack.get("attack_type", "")
                results.append(info)

        # 외부 dst_ip 추가
        for s in sessions:
            dst = getattr(s, "dst_ip", "")
            if dst and dst not in ips_seen and len(results) < 100:
                try:
                    addr = ipaddress.ip_address(dst)
                    if not (addr.is_private or addr.is_loopback or addr.is_link_local):
                        ips_seen.add(dst)
                        info = self.lookup(dst)
                        info["role"] = "external"
                        info["attack_type"] = ""
                        results.append(info)
                except ValueError:
                    pass

        return results[:100]
