"""QUIC 분석 — long-header 식별(버전/타입) + Initial 패킷 복호화로 SNI 추출.

QUIC(UDP)는 현대 웹 트래픽의 큰 축이다. 포트(443/UDP)만 보고 "QUIC"라 찍는 대신
long-header를 파싱해 버전·패킷타입·DCID를 뽑고, Initial 패킷은 RFC 9001의
고정 salt로 복호화해 ClientHello의 SNI("어느 서비스로 가는 연결인가")를 얻는다.

복호화는 cryptography 라이브러리가 있을 때만(graceful). 없으면 식별만 수행.
"""
from __future__ import annotations

import struct

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives import hashes, hmac
    _CRYPTO = True
except Exception:  # pragma: no cover
    _CRYPTO = False

# QUIC 버전 → 이름
_VERSIONS = {
    0x00000001: "QUIC v1 (RFC 9000)",
    0x6b3343cf: "QUIC v2 (RFC 9369)",
    0x51303433: "gQUIC Q043",
    0x51303436: "gQUIC Q046",
    0x51303530: "gQUIC Q050",
}
_LONG_PACKET_TYPES_V1 = {0: "Initial", 1: "0-RTT", 2: "Handshake", 3: "Retry"}

# RFC 9001 §5.2 initial salt (v1) / RFC 9369 (v2)
_INITIAL_SALT_V1 = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
_INITIAL_SALT_V2 = bytes.fromhex("0dede3def700a6db819381be6e269dcbf9bd2ed9")


def _version_name(v: int) -> str:
    if v == 0:
        return "Version Negotiation"
    if (v & 0xFF000000) == 0xFF000000:
        return f"QUIC draft-{v & 0xFF}"
    return _VERSIONS.get(v, f"QUIC 0x{v:08x}")


def _decode_varint(data: bytes, off: int) -> tuple[int, int]:
    """QUIC 가변길이 정수 디코드 → (값, 다음 오프셋)."""
    b = data[off]
    prefix = b >> 6
    length = 1 << prefix
    val = b & 0x3F
    for i in range(1, length):
        val = (val << 8) | data[off + i]
    return val, off + length


def inspect(payload: bytes) -> dict | None:
    """UDP payload가 QUIC long-header면 식별 정보를 반환, 아니면 None.

    반환: {is_quic, form, version, version_name, packet_type, dcid(hex), sni?}
    """
    if len(payload) < 6:
        return None
    first = payload[0]
    # long header: 최상위 비트(0x80)=1, 고정비트(0x40)=1
    if not (first & 0x80):
        return None
    version = struct.unpack_from("!I", payload, 1)[0]
    off = 5
    if off >= len(payload):
        return None
    dcid_len = payload[off]; off += 1
    if off + dcid_len > len(payload):
        return None
    dcid = payload[off:off + dcid_len]; off += dcid_len
    if off >= len(payload):
        return None
    scid_len = payload[off]; off += 1
    if off + scid_len > len(payload):
        return None
    scid = payload[off:off + scid_len]; off += scid_len

    ptype_bits = (first & 0x30) >> 4
    is_v2 = version == 0x6b3343cf
    # v2는 패킷타입 매핑이 다름(Initial=1). v1 기준 이름 + v2 보정.
    if is_v2:
        v2_types = {1: "Initial", 2: "0-RTT", 3: "Handshake", 0: "Retry"}
        packet_type = v2_types.get(ptype_bits, str(ptype_bits))
    else:
        packet_type = _LONG_PACKET_TYPES_V1.get(ptype_bits, str(ptype_bits))

    result = {
        "is_quic": True,
        "form": "long",
        "version": version,
        "version_name": _version_name(version),
        "packet_type": packet_type,
        "dcid": dcid.hex(),
        "scid": scid.hex(),
        "sni": None,
    }

    # Initial 패킷이면 복호화 시도 → SNI
    if packet_type == "Initial" and version in (0x00000001, 0x6b3343cf) and _CRYPTO:
        try:
            sni = _initial_sni(payload, off, dcid, is_v2)
            if sni:
                result["sni"] = sni
        except Exception:
            pass
    return result


def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    h = hmac.HMAC(salt, hashes.SHA256())
    h.update(ikm)
    return h.finalize()


def _hkdf_expand_label(secret: bytes, label: str, length: int) -> bytes:
    full_label = b"tls13 " + label.encode()
    info = struct.pack("!H", length) + bytes([len(full_label)]) + full_label + b"\x00"
    out = b""
    t = b""
    counter = 1
    while len(out) < length:
        h = hmac.HMAC(secret, hashes.SHA256())
        h.update(t + info + bytes([counter]))
        t = h.finalize()
        out += t
        counter += 1
    return out[:length]


def _initial_sni(payload: bytes, hdr_off: int, dcid: bytes, is_v2: bool) -> str | None:
    """RFC 9001 초기 키로 Initial 패킷을 복호화하고 CRYPTO 프레임에서 SNI 추출."""
    salt = _INITIAL_SALT_V2 if is_v2 else _INITIAL_SALT_V1
    key_label = "quicv2 key" if is_v2 else "quic key"
    iv_label = "quicv2 iv" if is_v2 else "quic iv"
    hp_label = "quicv2 hp" if is_v2 else "quic hp"

    initial_secret = _hkdf_extract(salt, dcid)
    client_secret = _hkdf_expand_label(initial_secret, "client in", 32)
    key = _hkdf_expand_label(client_secret, key_label, 16)
    iv = _hkdf_expand_label(client_secret, iv_label, 12)
    hp = _hkdf_expand_label(client_secret, hp_label, 16)

    off = hdr_off
    token_len, off = _decode_varint(payload, off)
    off += token_len
    length, off = _decode_varint(payload, off)
    pn_offset = off
    # header protection sample: pn_offset+4 부터 16바이트
    sample = payload[pn_offset + 4: pn_offset + 20]
    if len(sample) < 16:
        return None
    enc = Cipher(algorithms.AES(hp), modes.ECB()).encryptor()
    mask = enc.update(sample) + enc.finalize()
    first = payload[0] ^ (mask[0] & 0x0F)
    pn_len = (first & 0x03) + 1
    pn_bytes = bytes(payload[pn_offset + i] ^ mask[1 + i] for i in range(pn_len))
    packet_number = int.from_bytes(pn_bytes, "big")

    # AAD = 보호 해제된 헤더(첫 바이트 교정 + 패킷번호 평문)
    header = bytearray(payload[:pn_offset + pn_len])
    header[0] = first
    for i in range(pn_len):
        header[pn_offset + i] = pn_bytes[i]

    ct_start = pn_offset + pn_len
    ct_end = pn_offset + length  # length는 pn+payload 길이
    ciphertext = payload[ct_start:ct_end]
    if len(ciphertext) < 16:
        return None

    nonce = bytearray(iv)
    pn_full = packet_number.to_bytes(12, "big")
    nonce = bytes(a ^ b for a, b in zip(nonce, pn_full))

    plaintext = AESGCM(key).decrypt(nonce, ciphertext, bytes(header))
    crypto = _reassemble_crypto(plaintext)
    return _client_hello_sni(crypto)


def _reassemble_crypto(frames: bytes) -> bytes:
    """QUIC 프레임에서 CRYPTO(0x06) 프레임 데이터를 offset 순으로 이어붙임."""
    chunks: dict[int, bytes] = {}
    off = 0
    n = len(frames)
    while off < n:
        ftype = frames[off]; off += 1
        if ftype == 0x00:  # PADDING
            continue
        if ftype == 0x01:  # PING
            continue
        if ftype == 0x06:  # CRYPTO
            c_off, off = _decode_varint(frames, off)
            c_len, off = _decode_varint(frames, off)
            chunks[c_off] = frames[off:off + c_len]
            off += c_len
            continue
        break  # 알 수 없는 프레임 → 중단
    out = b""
    for o in sorted(chunks):
        out += chunks[o]
    return out


def _read_name(data: bytes, off: int) -> tuple[str, int]:
    length = struct.unpack_from("!H", data, off)[0]
    off += 2
    return data[off:off + length].decode("ascii", "replace"), off + length


def _client_hello_sni(hs: bytes) -> str | None:
    """TLS ClientHello handshake 메시지(레코드 아님)에서 SNI 추출."""
    if len(hs) < 4 or hs[0] != 0x01:  # handshake type 1 = ClientHello
        return None
    body_len = (hs[1] << 16) | (hs[2] << 8) | hs[3]
    body = hs[4:4 + body_len]
    off = 2 + 32  # legacy_version + random
    if off >= len(body):
        return None
    sid_len = body[off]; off += 1 + sid_len
    cs_len = struct.unpack_from("!H", body, off)[0]; off += 2 + cs_len
    comp_len = body[off]; off += 1 + comp_len
    if off + 2 > len(body):
        return None
    ext_total = struct.unpack_from("!H", body, off)[0]; off += 2
    end = off + ext_total
    while off + 4 <= end and off + 4 <= len(body):
        etype, elen = struct.unpack_from("!HH", body, off); off += 4
        edata = body[off:off + elen]; off += elen
        if etype == 0x0000 and len(edata) >= 5:  # SNI
            name_len = struct.unpack_from("!H", edata, 3)[0]
            return edata[5:5 + name_len].decode("ascii", "replace")
    return None
