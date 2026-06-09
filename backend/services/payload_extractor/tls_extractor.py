"""TLSExtractor — TLS ClientHello SNI + 간소화된 JA4 지문 추출."""
import hashlib
import struct
from dataclasses import dataclass, field
from typing import List, Optional

_TLS_HANDSHAKE = 0x16
_TLS_CLIENT_HELLO = 0x01
_EXT_SNI = 0x0000
_EXT_ALPN = 0x0010
_EXT_SUPPORTED_GROUPS = 0x000A
_EXT_SUPPORTED_VERSIONS = 0x002B

_TLS_VERSION_MAP = {0x0300: "s3", 0x0301: "10", 0x0302: "11", 0x0303: "12", 0x0304: "13"}


@dataclass
class TLSResult:
    sni: Optional[str] = None
    ja4: Optional[str] = None
    tls_version: Optional[str] = None
    cipher_suites: List[int] = field(default_factory=list)


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

        self._build_ja4(result, ext_types)

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
