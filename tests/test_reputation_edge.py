# -*- coding: utf-8 -*-
"""Edge cases: reputation service error/timeout/quota handling."""
import asyncio
import importlib
import os
import sys
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

BACKEND_DIR = os.path.join(os.path.dirname(__file__), "..", "backend")
sys.path.insert(0, os.path.abspath(BACKEND_DIR))

pytest.importorskip("httpx")

import httpx
import services.reputation_service as reputation_service
from services.reputation_service import ReputationService


@pytest.fixture
def external_enabled(monkeypatch):
    """외부 조회를 명시적으로 켠다.

    v7.13.0 까지는 _EXTERNAL_REPUTATION_ENABLED 의 기본값이 True 였기 때문에
    아래 테스트들이 아무 설정 없이 통과했다. 기본값이 오프라인(옵트인)으로
    바뀌면서, 테스트가 암묵적으로 의존하던 전제를 스스로 밝히도록 만든 것이다.
    검증 대상 로직 자체는 하나도 완화하지 않았다 — 각 조회의 성공/악성 판정
    경로는 그대로 실행된다.
    """
    monkeypatch.setattr(reputation_service, "_EXTERNAL_REPUTATION_ENABLED", True)


def _flag_value() -> bool:
    """현재 환경변수로 모듈을 다시 읽어 플래그 판정 결과를 얻는다."""
    return importlib.reload(reputation_service)._EXTERNAL_REPUTATION_ENABLED


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def _mock_response(status_code: int, json_data=None, content_type="application/json; charset=utf-8"):
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code
    resp.headers = {"content-type": content_type}
    if json_data is not None:
        resp.json = MagicMock(return_value=json_data)
    return resp


# ── ip-api ───────────────────────────────────────────────────────

class TestIpApiEdge:
    def test_timeout_returns_unreliable(self):
        svc = ReputationService()
        with patch("httpx.AsyncClient") as mock_cls:
            mock_ctx = AsyncMock()
            mock_ctx.__aenter__ = AsyncMock(return_value=mock_ctx)
            mock_ctx.__aexit__ = AsyncMock(return_value=False)
            mock_ctx.get = AsyncMock(side_effect=httpx.TimeoutException("timeout"))
            mock_cls.return_value = mock_ctx
            result = _run(svc._lookup_ipapi("1.2.3.4"))
        assert result.is_reliable is False
        assert result.source == "ip-api"

    def test_non_200_returns_unreliable(self):
        svc = ReputationService()
        with patch("httpx.AsyncClient") as mock_cls:
            mock_ctx = AsyncMock()
            mock_ctx.__aenter__ = AsyncMock(return_value=mock_ctx)
            mock_ctx.__aexit__ = AsyncMock(return_value=False)
            mock_ctx.get = AsyncMock(return_value=_mock_response(503))
            mock_cls.return_value = mock_ctx
            result = _run(svc._lookup_ipapi("1.2.3.4"))
        assert result.is_reliable is False

    def test_non_json_content_type_returns_unreliable(self):
        svc = ReputationService()
        with patch("httpx.AsyncClient") as mock_cls:
            mock_ctx = AsyncMock()
            mock_ctx.__aenter__ = AsyncMock(return_value=mock_ctx)
            mock_ctx.__aexit__ = AsyncMock(return_value=False)
            mock_ctx.get = AsyncMock(return_value=_mock_response(200, json_data={}, content_type="text/html"))
            mock_cls.return_value = mock_ctx
            result = _run(svc._lookup_ipapi("1.2.3.4"))
        assert result.is_reliable is False

    def test_success_returns_reliable(self, external_enabled):
        svc = ReputationService()
        json_data = {"countryCode": "US", "as": "AS1234 Acme ISP", "org": "Acme"}
        with patch("httpx.AsyncClient") as mock_cls:
            mock_ctx = AsyncMock()
            mock_ctx.__aenter__ = AsyncMock(return_value=mock_ctx)
            mock_ctx.__aexit__ = AsyncMock(return_value=False)
            mock_ctx.get = AsyncMock(return_value=_mock_response(200, json_data=json_data))
            mock_cls.return_value = mock_ctx
            result = _run(svc._lookup_ipapi("1.2.3.4"))
        assert result.is_reliable is True
        assert result.source == "ip-api"
        assert result.country_code == "US"


# ── Feodo Tracker ────────────────────────────────────────────────

class TestFeodoEdge:
    def setup_method(self):
        import services.reputation_service as svc_module
        svc_module._FEODO_CACHE = set()
        svc_module._FEODO_CACHE_TS = 0.0

    def test_timeout_returns_unreliable(self):
        svc = ReputationService()
        with patch("httpx.AsyncClient") as mock_cls:
            mock_ctx = AsyncMock()
            mock_ctx.__aenter__ = AsyncMock(return_value=mock_ctx)
            mock_ctx.__aexit__ = AsyncMock(return_value=False)
            mock_ctx.get = AsyncMock(side_effect=httpx.TimeoutException("timeout"))
            mock_cls.return_value = mock_ctx
            result = _run(svc._lookup_feodo("1.2.3.4"))
        assert result.is_reliable is False

    def test_ip_in_blocklist_is_malicious(self, external_enabled):
        svc = ReputationService()
        blocklist = [{"ip_address": "1.2.3.4"}, {"ip_address": "5.6.7.8"}]
        with patch("httpx.AsyncClient") as mock_cls:
            mock_ctx = AsyncMock()
            mock_ctx.__aenter__ = AsyncMock(return_value=mock_ctx)
            mock_ctx.__aexit__ = AsyncMock(return_value=False)
            mock_ctx.get = AsyncMock(return_value=_mock_response(200, json_data=blocklist))
            mock_cls.return_value = mock_ctx
            result = _run(svc._lookup_feodo("1.2.3.4"))
        assert result.is_malicious is True

    def test_ip_not_in_blocklist_not_malicious(self):
        svc = ReputationService()
        blocklist = [{"ip_address": "5.6.7.8"}]
        with patch("httpx.AsyncClient") as mock_cls:
            mock_ctx = AsyncMock()
            mock_ctx.__aenter__ = AsyncMock(return_value=mock_ctx)
            mock_ctx.__aexit__ = AsyncMock(return_value=False)
            mock_ctx.get = AsyncMock(return_value=_mock_response(200, json_data=blocklist))
            mock_cls.return_value = mock_ctx
            result = _run(svc._lookup_feodo("9.9.9.9"))
        assert result.is_malicious is False

    def test_cache_hit_does_not_make_new_request(self):
        import services.reputation_service as svc_module
        import time
        svc_module._FEODO_CACHE = {"1.2.3.4"}
        svc_module._FEODO_CACHE_TS = time.monotonic()
        svc = ReputationService()
        with patch("httpx.AsyncClient") as mock_cls:
            result = _run(svc._lookup_feodo("1.2.3.4"))
            mock_cls.assert_not_called()
        assert result.is_malicious is True


# ── URLhaus ──────────────────────────────────────────────────────

class TestUrlhausEdge:
    def test_timeout_returns_unreliable(self):
        svc = ReputationService()
        with patch("httpx.AsyncClient") as mock_cls:
            mock_ctx = AsyncMock()
            mock_ctx.__aenter__ = AsyncMock(return_value=mock_ctx)
            mock_ctx.__aexit__ = AsyncMock(return_value=False)
            mock_ctx.post = AsyncMock(side_effect=httpx.TimeoutException("timeout"))
            mock_cls.return_value = mock_ctx
            result = _run(svc._lookup_urlhaus("1.2.3.4"))
        assert result.is_reliable is False

    def test_host_match_is_malicious(self, external_enabled):
        svc = ReputationService()
        with patch("httpx.AsyncClient") as mock_cls:
            mock_ctx = AsyncMock()
            mock_ctx.__aenter__ = AsyncMock(return_value=mock_ctx)
            mock_ctx.__aexit__ = AsyncMock(return_value=False)
            mock_ctx.post = AsyncMock(return_value=_mock_response(
                200, json_data={"query_status": "is_host"}))
            mock_cls.return_value = mock_ctx
            result = _run(svc._lookup_urlhaus("1.2.3.4"))
        assert result.is_malicious is True

    def test_no_match_not_malicious(self):
        svc = ReputationService()
        with patch("httpx.AsyncClient") as mock_cls:
            mock_ctx = AsyncMock()
            mock_ctx.__aenter__ = AsyncMock(return_value=mock_ctx)
            mock_ctx.__aexit__ = AsyncMock(return_value=False)
            mock_ctx.post = AsyncMock(return_value=_mock_response(
                200, json_data={"query_status": "no_results"}))
            mock_cls.return_value = mock_ctx
            result = _run(svc._lookup_urlhaus("9.9.9.9"))
        assert result.is_malicious is False


# ── AbuseIPDB ────────────────────────────────────────────────────

class TestAbuseIPDBEdge:
    def test_no_api_key_returns_note(self, external_enabled):
        svc = ReputationService()
        with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": ""}):
            result = _run(svc._lookup_abuseipdb("1.2.3.4"))
        assert result.note is not None
        assert "key" in result.note.lower() or "configured" in result.note.lower()

    def test_quota_exceeded_429_returns_note(self, external_enabled):
        svc = ReputationService()
        with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "fake-key"}):
            with patch("httpx.AsyncClient") as mock_cls:
                mock_ctx = AsyncMock()
                mock_ctx.__aenter__ = AsyncMock(return_value=mock_ctx)
                mock_ctx.__aexit__ = AsyncMock(return_value=False)
                mock_ctx.get = AsyncMock(return_value=_mock_response(429))
                mock_cls.return_value = mock_ctx
                result = _run(svc._lookup_abuseipdb("1.2.3.4"))
        assert "quota" in (result.note or "").lower()

    def test_timeout_returns_unreliable(self):
        svc = ReputationService()
        with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "fake-key"}):
            with patch("httpx.AsyncClient") as mock_cls:
                mock_ctx = AsyncMock()
                mock_ctx.__aenter__ = AsyncMock(return_value=mock_ctx)
                mock_ctx.__aexit__ = AsyncMock(return_value=False)
                mock_ctx.get = AsyncMock(side_effect=httpx.TimeoutException("timeout"))
                mock_cls.return_value = mock_ctx
                result = _run(svc._lookup_abuseipdb("1.2.3.4"))
        assert result.is_reliable is False

    def test_high_abuse_score_is_malicious(self, external_enabled):
        svc = ReputationService()
        resp_data = {"data": {"abuseConfidenceScore": 90, "countryCode": "RU"}}
        with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "fake-key"}):
            with patch("httpx.AsyncClient") as mock_cls:
                mock_ctx = AsyncMock()
                mock_ctx.__aenter__ = AsyncMock(return_value=mock_ctx)
                mock_ctx.__aexit__ = AsyncMock(return_value=False)
                mock_ctx.get = AsyncMock(return_value=_mock_response(200, json_data=resp_data))
                mock_cls.return_value = mock_ctx
                result = _run(svc._lookup_abuseipdb("1.2.3.4"))
        assert result.is_malicious is True

    def test_low_abuse_score_not_malicious(self):
        svc = ReputationService()
        resp_data = {"data": {"abuseConfidenceScore": 10, "countryCode": "US"}}
        with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "fake-key"}):
            with patch("httpx.AsyncClient") as mock_cls:
                mock_ctx = AsyncMock()
                mock_ctx.__aenter__ = AsyncMock(return_value=mock_ctx)
                mock_ctx.__aexit__ = AsyncMock(return_value=False)
                mock_ctx.get = AsyncMock(return_value=_mock_response(200, json_data=resp_data))
                mock_cls.return_value = mock_ctx
                result = _run(svc._lookup_abuseipdb("1.2.3.4"))
        assert result.is_malicious is False


# ── lookup_all aggregation ───────────────────────────────────────

class TestLookupAllAggregation:
    def setup_method(self):
        import services.reputation_service as svc_module
        svc_module._FEODO_CACHE = set()
        svc_module._FEODO_CACHE_TS = 0.0

    def test_all_sources_fail_returns_not_malicious(self):
        svc = ReputationService()
        with patch.object(svc, "_lookup_ipapi", new=AsyncMock(side_effect=Exception("err"))), \
             patch.object(svc, "_lookup_feodo", new=AsyncMock(side_effect=Exception("err"))), \
             patch.object(svc, "_lookup_urlhaus", new=AsyncMock(side_effect=Exception("err"))), \
             patch.object(svc, "_lookup_abuseipdb", new=AsyncMock(side_effect=Exception("err"))):
            result = _run(svc.lookup_all("1.2.3.4"))
        assert result.is_malicious is False
        assert result.ip == "1.2.3.4"

    def test_one_malicious_source_marks_result(self):
        from models.reputation import ReputationSourceResult
        svc = ReputationService()
        malicious_source = ReputationSourceResult(source="feodo", is_malicious=True)
        clean_source = ReputationSourceResult(source="ip-api", is_malicious=False)
        with patch.object(svc, "_lookup_ipapi", new=AsyncMock(return_value=clean_source)), \
             patch.object(svc, "_lookup_feodo", new=AsyncMock(return_value=malicious_source)), \
             patch.object(svc, "_lookup_urlhaus", new=AsyncMock(return_value=clean_source)), \
             patch.object(svc, "_lookup_abuseipdb", new=AsyncMock(return_value=clean_source)):
            result = _run(svc.lookup_all("1.2.3.4"))
        assert result.is_malicious is True

    def test_unreliable_malicious_source_does_not_mark_result(self):
        from models.reputation import ReputationSourceResult
        svc = ReputationService()
        unreliable = ReputationSourceResult(source="feodo", is_malicious=True, is_reliable=False)
        clean = ReputationSourceResult(source="ip-api", is_malicious=False)
        with patch.object(svc, "_lookup_ipapi", new=AsyncMock(return_value=clean)), \
             patch.object(svc, "_lookup_feodo", new=AsyncMock(return_value=unreliable)), \
             patch.object(svc, "_lookup_urlhaus", new=AsyncMock(return_value=clean)), \
             patch.object(svc, "_lookup_abuseipdb", new=AsyncMock(return_value=clean)):
            result = _run(svc.lookup_all("1.2.3.4"))
        assert result.is_malicious is False


# ── F3 회귀: 오프라인이 기본 태세인지 ────────────────────────────

class TestExternalReputationDefaultOff:
    """기본 설정에서 캡처 유래 IP가 밖으로 나가지 않아야 한다."""

    @pytest.fixture(autouse=True)
    def _restore_module_flag(self):
        """_flag_value() 의 importlib.reload 가 다른 테스트로 새지 않게 되돌린다."""
        yield
        os.environ.pop("ENABLE_EXTERNAL_REPUTATION", None)
        importlib.reload(reputation_service)

    def test_unset_env_means_disabled(self, monkeypatch):
        monkeypatch.delenv("ENABLE_EXTERNAL_REPUTATION", raising=False)
        assert _flag_value() is False

    @pytest.mark.parametrize("value", ["", "0", "false", "no", "off", "2", "y", "enabled", "  ", "nonsense"])
    def test_non_optin_values_stay_disabled(self, monkeypatch, value):
        monkeypatch.setenv("ENABLE_EXTERNAL_REPUTATION", value)
        assert _flag_value() is False

    @pytest.mark.parametrize("value", ["1", "true", "TRUE", "yes", "on", " On "])
    def test_explicit_optin_enables(self, monkeypatch, value):
        monkeypatch.setenv("ENABLE_EXTERNAL_REPUTATION", value)
        assert _flag_value() is True

    @pytest.mark.parametrize("method,source", [
        ("_lookup_ipapi", "ip-api"),
        ("_lookup_urlhaus", "urlhaus"),
        ("_lookup_abuseipdb", "abuseipdb"),
    ])
    def test_per_ip_lookups_make_no_request_when_disabled(self, monkeypatch, method, source):
        monkeypatch.setattr(reputation_service, "_EXTERNAL_REPUTATION_ENABLED", False)
        # AbuseIPDB 는 키가 있어도 막혀야 한다 (v7.13.0 에서는 키만으로 게이트됨)
        monkeypatch.setenv("ABUSEIPDB_API_KEY", "dummy-key")
        with patch("httpx.AsyncClient") as client_cls:
            res = _run(getattr(ReputationService(), method)("203.0.113.77"))
        assert client_cls.call_count == 0, f"{source} 가 외부 접속을 시도했다"
        assert res.is_reliable is False
        assert res.source == source

    def test_feodo_download_is_gated_when_disabled(self, monkeypatch):
        monkeypatch.setattr(reputation_service, "_EXTERNAL_REPUTATION_ENABLED", False)
        monkeypatch.setattr(reputation_service, "_FEODO_CACHE_TS", 0.0)  # 캐시 만료 상태
        with patch("httpx.AsyncClient") as client_cls:
            res = _run(ReputationService()._lookup_feodo("203.0.113.77"))
        assert client_cls.call_count == 0
        assert res.is_reliable is False

    def test_warm_feodo_cache_still_answers_when_disabled(self, monkeypatch):
        """게이트는 캐시 조회 '아래'에 있어야 한다 — 받아둔 목록은 오프라인에서도 유효."""
        monkeypatch.setattr(reputation_service, "_EXTERNAL_REPUTATION_ENABLED", False)
        monkeypatch.setattr(reputation_service, "_FEODO_CACHE", {"203.0.113.77"})
        monkeypatch.setattr(reputation_service, "_FEODO_CACHE_TS", time.monotonic())
        with patch("httpx.AsyncClient") as client_cls:
            res = _run(ReputationService()._lookup_feodo("203.0.113.77"))
        assert client_cls.call_count == 0
        assert res.is_reliable is True
        assert res.is_malicious is True
