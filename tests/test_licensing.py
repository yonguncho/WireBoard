# -*- coding: utf-8 -*-
"""라이선스 검증 테스트 — 오프라인 서명 라운드트립 + 상태/엔드포인트.

기본(enforce off)에서는 아무것도 게이팅하지 않음을 함께 검증한다.
"""
import base64
import importlib
import json
import sys
from datetime import date, timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from services import licensing


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _sign(payload: dict) -> str:
    """테스트용: 저장된 개인키로 토큰 생성(공개키와 쌍이어야 함)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key_path = Path(r"C:\AI_WORKPLACE\secrets\wireboard_license_ed25519.key")
    if not key_path.is_file():
        pytest.skip("라이선스 개인키 없음(빌드 환경)")
    priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(key_path.read_text().strip()))
    pb = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode()
    return "WB1." + _b64url(pb) + "." + _b64url(priv.sign(pb))


class TestOfflineVerify:
    def test_valid_perpetual_license(self):
        tok = _sign({"email": "a@b.com", "expires": None, "seats": 1, "issued": "2026-01-01"})
        r = licensing.verify_offline(tok)
        assert r["valid"] is True
        assert r["email"] == "a@b.com"
        assert r["method"] == "offline"

    def test_expired_license_rejected(self):
        past = (date.today() - timedelta(days=1)).isoformat()
        tok = _sign({"email": "a@b.com", "expires": past, "seats": 1})
        r = licensing.verify_offline(tok)
        assert r["valid"] is False
        assert r["reason"] == "expired"

    def test_future_expiry_valid(self):
        fut = (date.today() + timedelta(days=365)).isoformat()
        tok = _sign({"email": "a@b.com", "expires": fut, "seats": 3})
        r = licensing.verify_offline(tok)
        assert r["valid"] is True and r["seats"] == 3

    def test_tampered_payload_rejected(self):
        tok = _sign({"email": "a@b.com", "expires": None, "seats": 1})
        prefix, payload_b64, sig = tok.split(".", 2)
        # payload 변조
        bad_payload = _b64url(json.dumps({"email": "evil@x.com", "expires": None, "seats": 999}).encode())
        r = licensing.verify_offline(f"{prefix}.{bad_payload}.{sig}")
        assert r["valid"] is False
        assert "signature_invalid" in r["reason"]

    def test_garbage_rejected(self):
        assert licensing.verify_offline("not-a-token")["valid"] is False
        assert licensing.verify_offline("WB1.x.y")["valid"] is False


class TestStatusAndGating:
    def test_default_unlicensed_not_enforced(self, monkeypatch):
        monkeypatch.delenv("WIREBOARD_LICENSE", raising=False)
        monkeypatch.delenv("WIREBOARD_LICENSE_ENFORCE", raising=False)
        importlib.reload(licensing)
        st = licensing.get_status()
        assert st["state"] == "unlicensed"
        assert st["enforced"] is False
        # 게이팅 꺼져 있으므로 미라이선스여도 제한 없음
        assert licensing.should_gate() is False

    def test_env_license_makes_licensed(self, monkeypatch):
        tok = _sign({"email": "z@z.com", "expires": None, "seats": 1})
        monkeypatch.setenv("WIREBOARD_LICENSE", tok)
        importlib.reload(licensing)
        assert licensing.get_status()["state"] == "licensed"
        assert licensing.is_licensed() is True

    def test_enforce_on_unlicensed_gates(self, monkeypatch):
        monkeypatch.delenv("WIREBOARD_LICENSE", raising=False)
        monkeypatch.setenv("WIREBOARD_LICENSE_ENFORCE", "1")
        importlib.reload(licensing)
        assert licensing.should_gate() is True

    def teardown_method(self):
        # 모듈 상태 원복
        import os
        os.environ.pop("WIREBOARD_LICENSE", None)
        os.environ.pop("WIREBOARD_LICENSE_ENFORCE", None)
        importlib.reload(licensing)


class TestLicenseEndpoints:
    def test_status_endpoint(self, api_client):
        r = api_client.get("/api/license/status")
        assert r.status_code == 200
        assert "state" in r.json() and "enforced" in r.json()

    def test_activate_invalid(self, api_client):
        r = api_client.post("/api/license/activate", json={"license": "bogus"})
        assert r.status_code == 200
        assert r.json()["ok"] is False

    def test_activate_empty(self, api_client):
        r = api_client.post("/api/license/activate", json={"license": ""})
        assert r.json()["ok"] is False
