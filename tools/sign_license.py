#!/usr/bin/env python3
"""오프라인 라이선스 발급 도구 (제품 소유자 전용).

개인키(secrets에 보관, 절대 배포 금지)로 서명된 라이선스 토큰을 만든다.
사용:
    python tools/sign_license.py --email user@example.com [--expires 2027-12-31] [--seats 1]
      [--key C:\\AI_WORKPLACE\\secrets\\wireboard_license_ed25519.key]

출력 토큰을 사용자에게 전달 → 앱의 라이선스 활성화(또는 license.dat)에 붙여넣으면 된다.
공개키는 backend/services/licensing.py 의 _LICENSE_PUBKEY_HEX 와 일치해야 한다.
"""
import argparse
import base64
import json
import os
from datetime import date


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--email", required=True)
    ap.add_argument("--expires", default=None, help="YYYY-MM-DD (없으면 영구)")
    ap.add_argument("--seats", type=int, default=1)
    ap.add_argument("--key", default=r"C:\AI_WORKPLACE\secrets\wireboard_license_ed25519.key")
    args = ap.parse_args()

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    priv_hex = open(args.key, encoding="utf-8").read().strip()
    priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(priv_hex))

    payload = {
        "email": args.email,
        "expires": args.expires,
        "seats": args.seats,
        "issued": date.today().isoformat(),
    }
    payload_bytes = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    sig = priv.sign(payload_bytes)
    token = "WB1." + _b64url(payload_bytes) + "." + _b64url(sig)
    print(token)


if __name__ == "__main__":
    main()
