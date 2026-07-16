# -*- coding: utf-8 -*-
"""TlsEnricher — 파싱 시점 SNI + 핸드셰이크 수립/실패 판정 테스트.

대상: services.analytics.tls_enricher.TlsEnricher

계약:
  enrich(sessions, packet_map) — TCP 세션의 재조립 payload에서 ClientHello를 찾아
  meta에 tls_sni / ja4 / tls_version / tls_handshake / tls_fail_reason 을 주입 (in-place).

  tls_handshake 판정:
    complete   : Finished 관측 또는 ServerHello+cipher (TLS 1.3 대응)
    failed     : fatal Alert / ClientHello 후 RST / ClientHello 후 서버 무응답
    incomplete : ServerHello는 있으나 완료 확증 없음
"""
import struct

import pytest

from conftest import make_session, make_uuid


# ── 합성 TLS 레코드 빌더 ─────────────────────────────────────────────────────

def build_client_hello(sni: str = "example.com") -> bytes:
    """SNI 확장을 포함한 최소 유효 ClientHello 레코드."""
    host = sni.encode("ascii")
    server_name = b"\x00" + struct.pack("!H", len(host)) + host
    sn_list = struct.pack("!H", len(server_name)) + server_name
    sni_ext = struct.pack("!HH", 0x0000, len(sn_list)) + sn_list
    ciphers = struct.pack("!HH", 0x1301, 0xC02F)
    body = struct.pack("!H", 0x0303)            # legacy_version TLS 1.2
    body += b"\x00" * 32                         # random
    body += b"\x00"                              # session_id len=0
    body += struct.pack("!H", len(ciphers)) + ciphers
    body += b"\x01\x00"                          # compression: null
    body += struct.pack("!H", len(sni_ext)) + sni_ext
    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def build_server_hello(cipher: int = 0xC02F) -> bytes:
    """cipher를 선택한 최소 유효 ServerHello 레코드 (TLS 1.2)."""
    body = struct.pack("!H", 0x0303)            # server_version
    body += b"\x00" * 32                         # random
    body += b"\x00"                              # session_id len=0
    body += struct.pack("!H", cipher)
    body += b"\x00"                              # compression: null
    hs = b"\x02" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x03" + struct.pack("!H", len(hs)) + hs


def build_fatal_alert(desc: int = 40) -> bytes:
    """fatal Alert 레코드 (기본: 40 handshake_failure)."""
    return b"\x15\x03\x03\x00\x02" + bytes([2, desc])


def make_pkt(direction: str, payload: bytes):
    from models.packet import PacketRecord
    return PacketRecord(
        ts=1.0, direction=direction, proto="TCP",
        seq=0, ack=0, flags="ACK+PSH",
        length=len(payload) + 54, payload_len=len(payload),
        payload_hex=payload.hex(),
    )


def make_tls_session(pkts, rst: bool = False, dst_port: int = 443):
    s = make_session(dst_port=dst_port, protocol="TCP", rst=rst)
    return s, {s.session_id: pkts}


@pytest.fixture()
def enricher():
    from services.analytics.tls_enricher import TlsEnricher
    return TlsEnricher()


# ── 핸드셰이크 판정 ──────────────────────────────────────────────────────────

class TestHandshakeOutcome:
    def test_complete_handshake(self, enricher):
        """CH(fwd) + SH(rev, cipher 선택) → complete + SNI/버전 주입."""
        pkts = [make_pkt("fwd", build_client_hello("www.google.com")),
                make_pkt("rev", build_server_hello())]
        s, pmap = make_tls_session(pkts)
        enricher.enrich([s], pmap)
        assert s.meta["tls_sni"] == "www.google.com"
        assert s.meta["tls_handshake"] == "complete"
        assert s.meta["tls_version"] == "TLS 1.2"
        assert "tls_fail_reason" not in s.meta
        assert s.meta.get("ja4")

    def test_fatal_alert_failed(self, enricher):
        """CH(fwd) + fatal alert(rev) → failed + 사유 fatal_alert:handshake_failure."""
        pkts = [make_pkt("fwd", build_client_hello("bad.example.com")),
                make_pkt("rev", build_fatal_alert(40))]
        s, pmap = make_tls_session(pkts)
        enricher.enrich([s], pmap)
        assert s.meta["tls_sni"] == "bad.example.com"
        assert s.meta["tls_handshake"] == "failed"
        assert s.meta["tls_fail_reason"] == "fatal_alert:handshake_failure"

    def test_rst_after_client_hello(self, enricher):
        """CH(fwd) 후 서버 응답 없음 + RST → failed(rst_after_client_hello)."""
        pkts = [make_pkt("fwd", build_client_hello("blocked.example.com"))]
        s, pmap = make_tls_session(pkts, rst=True)
        enricher.enrich([s], pmap)
        assert s.meta["tls_handshake"] == "failed"
        assert s.meta["tls_fail_reason"] == "rst_after_client_hello"

    def test_no_server_response(self, enricher):
        """CH(fwd) 후 서버 응답 없음 (RST도 없음) → failed(no_server_response)."""
        pkts = [make_pkt("fwd", build_client_hello("silent.example.com"))]
        s, pmap = make_tls_session(pkts, rst=False)
        enricher.enrich([s], pmap)
        assert s.meta["tls_handshake"] == "failed"
        assert s.meta["tls_fail_reason"] == "no_server_response"

    def test_reversed_direction_client_hello(self, enricher):
        """ClientHello가 rev 방향이어도 (중간 캡처) SNI를 찾는다."""
        pkts = [make_pkt("rev", build_client_hello("rev.example.com")),
                make_pkt("fwd", build_server_hello())]
        s, pmap = make_tls_session(pkts)
        enricher.enrich([s], pmap)
        assert s.meta["tls_sni"] == "rev.example.com"
        assert s.meta["tls_handshake"] == "complete"


# ── 비대상 세션 보호 ─────────────────────────────────────────────────────────

class TestNonTlsSessions:
    def test_non_tls_payload_untouched(self, enricher):
        """HTTP 평문 등 TLS 아닌 세션은 meta를 건드리지 않는다."""
        pkts = [make_pkt("fwd", b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")]
        s, pmap = make_tls_session(pkts, dst_port=80)
        original_meta = s.meta
        enricher.enrich([s], pmap)
        assert s.meta == original_meta

    def test_udp_session_skipped(self, enricher):
        s = make_session(protocol="UDP", dst_port=443)
        pmap = {s.session_id: [make_pkt("fwd", build_client_hello())]}
        enricher.enrich([s], pmap)
        assert not (s.meta or {}).get("tls_sni")

    def test_no_packets_skipped(self, enricher):
        s = make_session(dst_port=443)
        enricher.enrich([s], {})
        assert not (s.meta or {}).get("tls_sni")

    def test_existing_meta_preserved(self, enricher):
        """기존 meta 키(app_proto 등)를 보존한 채 TLS 키만 추가."""
        pkts = [make_pkt("fwd", build_client_hello("keep.example.com")),
                make_pkt("rev", build_server_hello())]
        s, pmap = make_tls_session(pkts)
        s.meta = {"app_proto": "HTTP/2 (h2c)"}
        enricher.enrich([s], pmap)
        assert s.meta["app_proto"] == "HTTP/2 (h2c)"
        assert s.meta["tls_sni"] == "keep.example.com"


# ── TlsAnalyzer 집계 연동 ────────────────────────────────────────────────────

class TestAnalyzerAggregation:
    def _analyze(self, sessions):
        from services.analytics.tls_analyzer import TlsAnalyzer
        return TlsAnalyzer().analyze(sessions)

    def test_ok_fail_counts(self):
        sessions = []
        for i in range(3):
            s = make_session(dst_port=443)
            s.meta = {"tls_sni": "ok.example.com", "tls_version": "TLS 1.2",
                      "tls_handshake": "complete"}
            sessions.append(s)
        for i in range(2):
            s = make_session(dst_port=443)
            s.meta = {"tls_sni": "fail.example.com", "tls_version": "TLS 1.2",
                      "tls_handshake": "failed", "tls_fail_reason": "no_server_response"}
            sessions.append(s)
        result = self._analyze(sessions)
        assert result.handshake_ok == 3
        assert result.handshake_fail == 2

    def test_entries_failed_first_with_count(self):
        """entries는 실패 우선 정렬 + 세션 수 count 집계."""
        sessions = []
        for _ in range(5):
            s = make_session(dst_port=443)
            s.meta = {"tls_sni": "ok.example.com", "tls_version": "TLS 1.3",
                      "tls_handshake": "complete"}
            sessions.append(s)
        s = make_session(dst_port=443)
        s.meta = {"tls_sni": "fail.example.com", "tls_version": "TLS 1.2",
                  "tls_handshake": "failed", "tls_fail_reason": "rst_after_client_hello"}
        sessions.append(s)
        result = self._analyze(sessions)
        assert result.entries[0]["sni"] == "fail.example.com"
        assert result.entries[0]["handshake"] == "failed"
        assert result.entries[0]["fail_reason"] == "rst_after_client_hello"
        ok_entry = next(e for e in result.entries if e["sni"] == "ok.example.com")
        assert ok_entry["count"] == 5
        assert ok_entry["handshake"] == "complete"

    def test_legacy_meta_without_handshake(self):
        """tls_handshake 없는 기존 meta도 entries에 나온다 (하위호환)."""
        s = make_session(dst_port=443)
        s.meta = {"tls_sni": "legacy.example.com", "tls_version": "TLS 1.2"}
        result = self._analyze([s])
        assert result.entries[0]["sni"] == "legacy.example.com"
        assert result.entries[0]["handshake"] == ""
        assert result.handshake_ok == 0
        assert result.handshake_fail == 0
