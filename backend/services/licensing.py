"""라이선스 검증 — 오프라인 서명 라이선스(Ed25519) + 온라인 검증(Lemon Squeezy).

설계 원칙:
- **기본 비활성·비게이팅**: 라이선스가 없어도 아무 기능도 막지 않는다. 이 모듈은
  상태를 '보고'만 하며, 게이팅(워터마크/제한)은 별도로 켤 때만 적용한다
  (`WIREBOARD_LICENSE_ENFORCE=1`). → 현재 사용자/테스트 동작에 영향 없음.
- **오프라인 우선**: 오프라인 서명 라이선스 파일이면 인터넷 없이 검증(프라이버시).
  온라인(LS) 검증은 키가 설정된 경우에만 선택적으로 시도.

라이선스 파일 포맷(오프라인):  WB1.<b64url(payload_json)>.<b64url(ed25519_sig)>
payload = {"email": str, "expires": "YYYY-MM-DD"|null, "seats": int, "issued": "..."}
서명 대상 = payload_json 원문 바이트. 공개키는 아래 상수에 embed(개인키는 별도 보관).
"""
from __future__ import annotations

import base64
import json
import logging
import os
from datetime import date, datetime
from pathlib import Path

logger = logging.getLogger(__name__)

# 오프라인 라이선스 검증용 Ed25519 공개키(hex). 개인키는 제품 소유자만 보관하며
# tools/sign_license.py 로 라이선스를 발급한다.
_LICENSE_PUBKEY_HEX = "14396986630b45cad6e121e7c2e9004d51effd4434461dc64e645a203a55b05b"

# 게이팅 활성화 여부(기본 꺼짐 — 아무것도 막지 않음)
_ENFORCE = os.environ.get("WIREBOARD_LICENSE_ENFORCE", "0").strip().lower() in ("1", "true", "yes", "on")

# Lemon Squeezy 온라인 검증(선택). 스토어/제품이 설정된 경우에만 사용.
_LS_VALIDATE_URL = "https://api.lemonsqueezy.com/v1/licenses/validate"


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _license_source() -> str | None:
    """라이선스 문자열을 환경변수 또는 파일에서 로드."""
    key = os.environ.get("WIREBOARD_LICENSE")
    if key:
        return key.strip()
    # 실행파일/작업 디렉터리의 license.dat
    candidates = [Path.cwd() / "license.dat"]
    import sys
    if getattr(sys, "frozen", False):
        candidates.insert(0, Path(os.path.dirname(sys.executable)) / "license.dat")
    for p in candidates:
        try:
            if p.is_file():
                return p.read_text(encoding="utf-8").strip()
        except OSError:
            continue
    return None


def verify_offline(token: str) -> dict:
    """오프라인 서명 라이선스 검증. 반환: {valid, email, expires, seats, reason}."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except Exception:
        return {"valid": False, "reason": "crypto_unavailable"}
    try:
        prefix, payload_b64, sig_b64 = token.split(".", 2)
        if prefix != "WB1":
            return {"valid": False, "reason": "bad_prefix"}
        payload_bytes = _b64url_decode(payload_b64)
        signature = _b64url_decode(sig_b64)
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(_LICENSE_PUBKEY_HEX))
        pub.verify(signature, payload_bytes)  # 서명 불일치면 예외
        payload = json.loads(payload_bytes.decode("utf-8"))
    except Exception as exc:
        return {"valid": False, "reason": f"signature_invalid:{type(exc).__name__}"}

    # 만료 검사
    expires = payload.get("expires")
    if expires:
        try:
            exp = datetime.strptime(expires, "%Y-%m-%d").date()
            if exp < date.today():
                return {"valid": False, "reason": "expired", "expires": expires,
                        "email": payload.get("email")}
        except ValueError:
            return {"valid": False, "reason": "bad_expires"}
    return {
        "valid": True,
        "email": payload.get("email"),
        "expires": expires,
        "seats": payload.get("seats", 1),
        "issued": payload.get("issued"),
        "method": "offline",
    }


def verify_online(license_key: str, instance_name: str = "wireboard") -> dict:
    """Lemon Squeezy 온라인 라이선스 검증(선택적). httpx 없거나 오프라인이면 실패 반환."""
    try:
        import httpx  # noqa: PLC0415
    except Exception:
        return {"valid": False, "reason": "httpx_unavailable"}
    try:
        with httpx.Client(timeout=5.0) as client:
            resp = client.post(_LS_VALIDATE_URL,
                               data={"license_key": license_key, "instance_name": instance_name},
                               headers={"Accept": "application/json"})
            if resp.status_code != 200:
                return {"valid": False, "reason": f"http_{resp.status_code}"}
            data = resp.json()
            valid = bool(data.get("valid")) and data.get("license_key", {}).get("status") == "active"
            meta = data.get("meta", {})
            return {
                "valid": valid,
                "email": meta.get("customer_email"),
                "method": "online",
                "reason": None if valid else data.get("error", "inactive"),
            }
    except Exception as exc:
        return {"valid": False, "reason": f"network:{type(exc).__name__}"}


def get_status() -> dict:
    """현재 라이선스 상태. 게이팅은 하지 않고 상태만 반환.

    state: "licensed" | "unlicensed"
    enforced: 게이팅 활성 여부(기본 False → 미라이선스여도 제한 없음)
    """
    token = _license_source()
    result: dict = {"state": "unlicensed", "enforced": _ENFORCE, "email": None,
                    "expires": None, "method": None, "reason": None}
    if not token:
        result["reason"] = "no_license"
        return result

    # 오프라인 서명 라이선스 우선(WB1.으로 시작)
    if token.startswith("WB1."):
        v = verify_offline(token)
    else:
        v = verify_online(token)
    if v.get("valid"):
        result.update(state="licensed", email=v.get("email"), expires=v.get("expires"),
                      method=v.get("method"))
    else:
        result["reason"] = v.get("reason")
    return result


def is_licensed() -> bool:
    return get_status()["state"] == "licensed"


def should_gate() -> bool:
    """게이팅(워터마크/제한)을 적용해야 하는가? enforce가 켜져 있고 미라이선스일 때만 True."""
    if not _ENFORCE:
        return False
    return not is_licensed()
