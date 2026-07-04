"""TLSExtractor — TLS ClientHello SNI + 간소화된 JA4 지문 추출."""
import hashlib
import struct
from dataclasses import dataclass, field
from typing import List, Optional

_TLS_HANDSHAKE = 0x16
_TLS_CLIENT_HELLO = 0x01
_TLS_SERVER_HELLO = 0x02
_EXT_SNI = 0x0000
_EXT_ALPN = 0x0010
_EXT_SUPPORTED_GROUPS = 0x000A
_EXT_SUPPORTED_VERSIONS = 0x002B

_TLS_VERSION_MAP = {0x0300: "s3", 0x0301: "10", 0x0302: "11", 0x0303: "12", 0x0304: "13"}

# 사람이 읽을 수 있는 TLS 버전 표기
_READABLE_VERSION = {
    0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1",
    0x0303: "TLS 1.2", 0x0304: "TLS 1.3",
}

# 자주 쓰이는 cipher suite 코드 → 이름
_CIPHER_NAMES = {
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0x1304: "TLS_AES_128_CCM_SHA256",
    0xc02b: "ECDHE-ECDSA-AES128-GCM-SHA256",
    0xc02f: "ECDHE-RSA-AES128-GCM-SHA256",
    0xc02c: "ECDHE-ECDSA-AES256-GCM-SHA384",
    0xc030: "ECDHE-RSA-AES256-GCM-SHA384",
    0xcca9: "ECDHE-ECDSA-CHACHA20-POLY1305",
    0xcca8: "ECDHE-RSA-CHACHA20-POLY1305",
    0x009c: "AES128-GCM-SHA256",
    0x009d: "AES256-GCM-SHA384",
    0x002f: "AES128-SHA",
    0x0035: "AES256-SHA",
    0xc013: "ECDHE-RSA-AES128-SHA",
    0xc014: "ECDHE-RSA-AES256-SHA",
    0xc027: "ECDHE-RSA-AES128-SHA256",
    0x000a: "DES-CBC3-SHA",
}


def cipher_name(code: int) -> str:
    """cipher suite 코드를 이름으로(미상이면 16진수)."""
    return _CIPHER_NAMES.get(code, f"0x{code:04x}")


# TLS record content types
_TLS_CT_ALERT = 0x15
_TLS_CT_HANDSHAKE = 0x16
_TLS_CT_APPDATA = 0x17
_TLS_CT_CCS = 0x14
_TLS_CONTENT_TYPES = {0x14, 0x15, 0x16, 0x17}

# handshake message types (record 0x16 첫 바이트)
_HS_NAMES = {1: "ClientHello", 2: "ServerHello", 11: "Certificate",
             12: "ServerKeyExchange", 13: "CertificateRequest",
             14: "ServerHelloDone", 16: "ClientKeyExchange", 20: "Finished"}

# alert description 코드 → 이름 (RFC 5246/8446)
_ALERT_DESC = {
    0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac",
    21: "decryption_failed", 22: "record_overflow", 30: "decompression_failure",
    40: "handshake_failure", 41: "no_certificate", 42: "bad_certificate",
    43: "unsupported_certificate", 44: "certificate_revoked", 45: "certificate_expired",
    46: "certificate_unknown", 47: "illegal_parameter", 48: "unknown_ca",
    49: "access_denied", 50: "decode_error", 51: "decrypt_error",
    70: "protocol_version", 71: "insufficient_security", 80: "internal_error",
    86: "inappropriate_fallback", 90: "user_canceled", 100: "no_renegotiation",
    110: "unsupported_extension", 112: "unrecognized_name",
    113: "bad_certificate_status_response", 115: "unknown_psk_identity",
    116: "certificate_required", 120: "no_application_protocol",
}
_ALERT_LEVEL = {1: "warning", 2: "fatal"}


def scan_tls_records(data: bytes) -> dict:
    """재조립 바이트에서 TLS 레코드를 훑어 handshake 단계와 alert를 수집한다.

    Returns {"handshake": [메시지명...], "alerts": [{level, description, code}...]}
    caplen(128~1024B) 내 레코드만 보이지만 초기 핸드셰이크/Alert는 대개 앞쪽에 있다.
    """
    handshake: list[str] = []
    alerts: list[dict] = []
    if len(data) < 5 or data[0] not in _TLS_CONTENT_TYPES:
        return {"handshake": handshake, "alerts": alerts}
    offset = 0
    guard = 0
    while offset + 5 <= len(data) and guard < 64:
        guard += 1
        ct = data[offset]
        ver_hi = data[offset + 1]
        if ct not in _TLS_CONTENT_TYPES or ver_hi != 0x03:
            break
        rec_len = struct.unpack_from("!H", data, offset + 3)[0]
        body = data[offset + 5: offset + 5 + rec_len]
        if ct == _TLS_CT_HANDSHAKE and body:
            name = _HS_NAMES.get(body[0])
            if name and name not in handshake:
                handshake.append(name)
        elif ct == _TLS_CT_ALERT and len(body) >= 2:
            alerts.append({
                "level": _ALERT_LEVEL.get(body[0], str(body[0])),
                "description": _ALERT_DESC.get(body[1], f"alert_{body[1]}"),
                "code": body[1],
            })
        if rec_len == 0:
            break
        offset += 5 + rec_len
    return {"handshake": handshake, "alerts": alerts}


@dataclass
class TLSResult:
    sni: Optional[str] = None
    ja4: Optional[str] = None
    tls_version: Optional[str] = None
    cipher_suites: List[int] = field(default_factory=list)
    alpn: Optional[str] = None
    legacy_version: Optional[str] = None      # ClientHello legacy_version (읽기용)
    negotiated_version: Optional[str] = None  # supported_versions 기준 실제 협상 버전


class TLSExtractor:
    def extract(self, payload: bytes) -> TLSResult:
        result = TLSResult()
        try:
            self._parse(payload, result)
        except Exception:
            pass
        return result

    def _parse(self, data: bytes, result: TLSResult) -> None:
        if len(data) < 5:
            return
        content_type = data[0]
        if content_type != _TLS_HANDSHAKE:
            return

        record_len = struct.unpack_from("!H", data, 3)[0]
        if len(data) < 5 + record_len:
            return

        hs_data = data[5:5 + record_len]
        if len(hs_data) < 4:
            return
        hs_type = hs_data[0]
        if hs_type != _TLS_CLIENT_HELLO:
            return

        hs_len = (hs_data[1] << 16) | (hs_data[2] << 8) | hs_data[3]
        body = hs_data[4:4 + hs_len]
        if len(body) < 34:
            return

        client_version = struct.unpack_from("!H", body, 0)[0]
        result.tls_version = _TLS_VERSION_MAP.get(client_version, "00")
        result.legacy_version = _READABLE_VERSION.get(client_version)

        offset = 34
        if offset >= len(body):
            return

        session_id_len = body[offset]
        offset += 1 + session_id_len
        if offset + 2 > len(body):
            return

        cipher_len = struct.unpack_from("!H", body, offset)[0]
        offset += 2
        ciphers = []
        for i in range(0, cipher_len, 2):
            if offset + i + 2 > len(body):
                break
            c = struct.unpack_from("!H", body, offset + i)[0]
            if c != 0x0000:
                ciphers.append(c)
        result.cipher_suites = ciphers
        offset += cipher_len

        if offset >= len(body):
            return
        comp_len = body[offset]
        offset += 1 + comp_len

        if offset + 2 > len(body):
            self._build_ja4(result, [])
            return

        ext_total = struct.unpack_from("!H", body, offset)[0]
        offset += 2
        ext_end = offset + ext_total
        ext_types = []

        while offset + 4 <= ext_end and offset + 4 <= len(body):
            ext_type, ext_len = struct.unpack_from("!HH", body, offset)
            ext_data = body[offset + 4:offset + 4 + ext_len]
            offset += 4 + ext_len
            ext_types.append(ext_type)

            if ext_type == _EXT_SNI and len(ext_data) >= 5:
                list_len = struct.unpack_from("!H", ext_data, 0)[0]
                name_type = ext_data[2]
                if name_type == 0 and len(ext_data) >= 5:
                    name_len = struct.unpack_from("!H", ext_data, 3)[0]
                    if len(ext_data) >= 5 + name_len:
                        result.sni = ext_data[5:5 + name_len].decode("ascii", errors="replace")

            elif ext_type == _EXT_ALPN and len(ext_data) >= 2:
                alpn_list_len = struct.unpack_from("!H", ext_data, 0)[0]
                p = 2
                protos: List[str] = []
                while p < 2 + alpn_list_len and p < len(ext_data):
                    plen = ext_data[p]
                    p += 1
                    if p + plen > len(ext_data):
                        break
                    protos.append(ext_data[p:p + plen].decode("ascii", errors="replace"))
                    p += plen
                if protos:
                    result.alpn = ", ".join(protos)

            elif ext_type == _EXT_SUPPORTED_VERSIONS and len(ext_data) >= 1:
                # ClientHello: 1바이트 길이 + 버전 목록 → 최고 버전 채택
                vlist_len = ext_data[0]
                best = 0
                q = 1
                while q + 2 <= 1 + vlist_len and q + 2 <= len(ext_data):
                    v = struct.unpack_from("!H", ext_data, q)[0]
                    if (v & 0xFF00) == 0x0300 and v <= 0x0304 and v > best:
                        best = v
                    q += 2
                if best:
                    result.negotiated_version = _READABLE_VERSION.get(best)

        self._build_ja4(result, ext_types)

    def extract_server_hello(self, payload: bytes) -> tuple[Optional[int], Optional[str]]:
        """ServerHello에서 (선택된 cipher 코드, 협상 버전)을 추출."""
        try:
            return self._parse_server_hello(payload)
        except Exception:
            return None, None

    def _parse_server_hello(self, data: bytes) -> tuple[Optional[int], Optional[str]]:
        if len(data) < 5 or data[0] != _TLS_HANDSHAKE:
            return None, None
        record_len = struct.unpack_from("!H", data, 3)[0]
        hs_data = data[5:5 + record_len]
        if len(hs_data) < 4 or hs_data[0] != _TLS_SERVER_HELLO:
            return None, None
        hs_len = (hs_data[1] << 16) | (hs_data[2] << 8) | hs_data[3]
        body = hs_data[4:4 + hs_len]
        if len(body) < 38:
            return None, None

        legacy_version = struct.unpack_from("!H", body, 0)[0]
        version = _READABLE_VERSION.get(legacy_version)
        offset = 34
        session_id_len = body[offset]
        offset += 1 + session_id_len
        if offset + 3 > len(body):
            return None, version
        cipher = struct.unpack_from("!H", body, offset)[0]
        offset += 2
        offset += 1  # compression method

        # 확장 파싱: supported_versions(0x002b) → TLS 1.3 실제 버전
        if offset + 2 <= len(body):
            ext_total = struct.unpack_from("!H", body, offset)[0]
            offset += 2
            ext_end = min(offset + ext_total, len(body))
            while offset + 4 <= ext_end:
                ext_type, ext_len = struct.unpack_from("!HH", body, offset)
                ext_data = body[offset + 4:offset + 4 + ext_len]
                offset += 4 + ext_len
                if ext_type == _EXT_SUPPORTED_VERSIONS and len(ext_data) >= 2:
                    v = struct.unpack_from("!H", ext_data, 0)[0]
                    version = _READABLE_VERSION.get(v, version)
        return cipher, version

    def _build_ja4(self, result: TLSResult, ext_types: List[int]) -> None:
        version = result.tls_version or "00"
        sni_type = "d" if result.sni else "i"
        n_ciphers = f"{len(result.cipher_suites):02d}"
        n_exts = f"{len(ext_types):02d}"
        cipher_str = ",".join(f"{c:04x}" for c in sorted(result.cipher_suites))
        ext_str = ",".join(f"{e:04x}" for e in sorted(ext_types))
        c_hash = hashlib.sha256(cipher_str.encode()).hexdigest()[:12]
        e_hash = hashlib.sha256(ext_str.encode()).hexdigest()[:12]
        result.ja4 = f"t{version}{sni_type}{n_ciphers}{n_exts}_{c_hash}_{e_hash}"
