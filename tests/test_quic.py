# -*- coding: utf-8 -*-
"""QUIC 분석 테스트 — long-header 식별 + SNI 파싱 + Initial 복호화 라운드트립."""
import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from services.analytics import quic_analyzer as q


def _long_header(version: int, ptype_bits: int, dcid: bytes, scid: bytes = b"", body: bytes = b"\x00" * 40) -> bytes:
    first = 0x80 | 0x40 | (ptype_bits << 4)
    return (bytes([first]) + struct.pack("!I", version)
            + bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid + body)


class TestIdentification:
    def test_v1_initial(self):
        pkt = _long_header(0x00000001, 0, bytes.fromhex("8394c8f03e515708"))
        r = q.inspect(pkt)
        assert r and r["is_quic"]
        assert "v1" in r["version_name"]
        assert r["packet_type"] == "Initial"
        assert r["dcid"] == "8394c8f03e515708"

    def test_v2_handshake(self):
        pkt = _long_header(0x6b3343cf, 3, b"\xaa\xbb")
        r = q.inspect(pkt)
        assert "v2" in r["version_name"]
        assert r["packet_type"] == "Handshake"

    def test_draft_version(self):
        pkt = _long_header(0xff00001d, 0, b"\x01\x02")
        r = q.inspect(pkt)
        assert "draft" in r["version_name"]

    def test_gquic_version(self):
        pkt = _long_header(0x51303530, 0, b"\x01")
        assert "gQUIC" in q.inspect(pkt)["version_name"]

    def test_short_header_not_quic_longform(self):
        # short header (0x40, no 0x80) → long-form 식별 대상 아님
        assert q.inspect(b"\x40" + b"\x00" * 20) is None

    def test_non_quic_payload(self):
        assert q.inspect(b"GET / HTTP/1.1\r\n") is None
        assert q.inspect(b"\x00\x01") is None


class TestClientHelloSni:
    def _client_hello(self, sni: str) -> bytes:
        server_name = sni.encode()
        sni_ext_body = (struct.pack("!H", len(server_name) + 3) + b"\x00"
                        + struct.pack("!H", len(server_name)) + server_name)
        sni_ext = struct.pack("!HH", 0x0000, len(sni_ext_body)) + sni_ext_body
        exts = sni_ext
        body = (b"\x03\x03" + b"\x00" * 32 + b"\x00"          # ver + random + sid_len
                + struct.pack("!H", 2) + b"\x13\x01"           # cipher suites
                + b"\x01\x00"                                   # compression
                + struct.pack("!H", len(exts)) + exts)
        return bytes([0x01]) + struct.pack("!I", len(body))[1:] + body  # HS type + 3-byte len

    def test_sni_extracted(self):
        hs = self._client_hello("example.com")
        assert q._client_hello_sni(hs) == "example.com"

    def test_no_sni(self):
        # ClientHello without SNI ext
        body = b"\x03\x03" + b"\x00" * 32 + b"\x00" + struct.pack("!H", 2) + b"\x13\x01" + b"\x01\x00" + struct.pack("!H", 0)
        hs = bytes([0x01]) + struct.pack("!I", len(body))[1:] + body
        assert q._client_hello_sni(hs) is None


@pytest.mark.skipif(not q._CRYPTO, reason="cryptography 미설치")
class TestInitialDecryptRoundTrip:
    """모듈의 키 유도로 Initial을 직접 암호화 → inspect()가 SNI를 복호화 추출하는지."""

    def _build_initial(self, dcid: bytes, sni: str) -> bytes:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        ch = TestClientHelloSni()._client_hello(sni)
        # CRYPTO frame: type 0x06, offset 0, length, data
        crypto = b"\x06" + b"\x00" + _varint(len(ch)) + ch
        plaintext = crypto  # 프레임들(패딩 없이)

        salt = q._INITIAL_SALT_V1
        initial_secret = q._hkdf_extract(salt, dcid)
        cs = q._hkdf_expand_label(initial_secret, "client in", 32)
        key = q._hkdf_expand_label(cs, "quic key", 16)
        iv = q._hkdf_expand_label(cs, "quic iv", 12)
        hp = q._hkdf_expand_label(cs, "quic hp", 16)

        pn = 0
        pn_len = 1
        pn_bytes = pn.to_bytes(pn_len, "big")
        # 보호 해제 헤더 구성
        first = 0x80 | 0x40 | 0x00 | (pn_len - 1)  # long, Initial, pn_len
        length = pn_len + len(plaintext) + 16  # pn + ct + tag
        header = (bytes([first]) + struct.pack("!I", 0x00000001)
                  + bytes([len(dcid)]) + dcid + b"\x00"       # scid_len 0
                  + b"\x00"                                    # token length varint 0
                  + _varint(length) + pn_bytes)
        pn_offset = len(header) - pn_len

        nonce = bytes(a ^ b for a, b in zip(iv, pn.to_bytes(12, "big")))
        ct = AESGCM(key).encrypt(nonce, plaintext, header)

        packet = bytearray(header + ct)
        # header protection 적용
        sample = ct[4 - pn_len: 4 - pn_len + 16]
        enc = Cipher(algorithms.AES(hp), modes.ECB()).encryptor()
        mask = enc.update(sample) + enc.finalize()
        packet[0] ^= mask[0] & 0x0F
        for i in range(pn_len):
            packet[pn_offset + i] ^= mask[1 + i]
        return bytes(packet)

    def test_roundtrip_sni(self):
        dcid = bytes.fromhex("8394c8f03e515708")
        pkt = self._build_initial(dcid, "cloudflare-quic.com")
        r = q.inspect(pkt)
        assert r["packet_type"] == "Initial"
        assert r["sni"] == "cloudflare-quic.com"


class TestQuicUploadIntegration:
    """QUIC Initial이 담긴 UDP pcap 업로드 → 세션 meta에 QUIC 버전/SNI 반영."""

    def _quic_udp_pcap(self, quic_payload: bytes) -> bytes:
        # Ethernet + IPv4 + UDP(dst 443) + quic_payload
        eth = bytes([0x00,0x11,0x22,0x33,0x44,0x55, 0xAA,0xBB,0xCC,0xDD,0xEE,0xFF, 0x08,0x00])
        udp = struct.pack(">HHHH", 50000, 443, 8 + len(quic_payload), 0) + quic_payload
        src = bytes(int(x) for x in "10.0.0.1".split("."))
        dst = bytes(int(x) for x in "10.0.0.2".split("."))
        total = 20 + len(udp)
        ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, 0x1234, 0, 64, 17, 0, src, dst)
        pkt = eth + ip + udp
        gh = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        rec = struct.pack("<IIII", 1_748_000_000, 0, len(pkt), len(pkt))
        return gh + rec + pkt

    @pytest.mark.skipif(not q._CRYPTO, reason="cryptography 미설치")
    def test_quic_initial_sni_in_session_meta(self):
        from services.parser.pcap_parser import PcapParser
        dcid = bytes.fromhex("8394c8f03e515708")
        initial = TestInitialDecryptRoundTrip()._build_initial(dcid, "example.org")
        pcap = self._quic_udp_pcap(initial)
        sessions, _ = PcapParser().parse(pcap)
        assert len(sessions) == 1
        meta = sessions[0].meta or {}
        assert "QUIC" in (meta.get("app_proto") or "")
        assert meta.get("quic_sni") == "example.org"

    def test_quic_identification_without_crypto_path(self):
        # Handshake 패킷(복호화 불필요) → 버전/타입만
        from services.parser.pcap_parser import PcapParser
        hs = _long_header(0x00000001, 2, b"\xab\xcd", body=b"\x00" * 30)
        pcap = self._quic_udp_pcap(hs)
        sessions, _ = PcapParser().parse(pcap)
        meta = sessions[0].meta or {}
        assert "QUIC v1" in (meta.get("app_proto") or "")
        assert meta.get("quic_type") == "Handshake"


def _varint(n: int) -> bytes:
    if n < 64:
        return bytes([n])
    if n < 16384:
        return struct.pack("!H", n | 0x4000)
    return struct.pack("!I", n | 0x80000000)
