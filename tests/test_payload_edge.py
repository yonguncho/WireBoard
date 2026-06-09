# -*- coding: utf-8 -*-
"""Edge cases: HTTP, DNS, TLS payload extractor field coverage."""
import os
import struct
import sys

import pytest

BACKEND_DIR = os.path.join(os.path.dirname(__file__), "..", "backend")
sys.path.insert(0, os.path.abspath(BACKEND_DIR))

from services.payload_extractor.http_extractor import HTTPExtractor
from services.payload_extractor.dns_extractor import DNSExtractor
from services.payload_extractor.tls_extractor import TLSExtractor

http = HTTPExtractor()
dns = DNSExtractor()
tls = TLSExtractor()


# ── HTTPExtractor ────────────────────────────────────────────────

class TestHTTPExtractor:
    def test_get_request_parsed(self):
        payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: TestBot/1.0\r\n\r\n"
        result = http.extract(payload)
        assert result is not None
        assert result.method == "GET"
        assert result.uri == "/index.html"
        assert result.host == "example.com"
        assert result.user_agent == "TestBot/1.0"

    def test_post_request_parsed(self):
        payload = b"POST /api/data HTTP/1.1\r\nHost: api.example.com\r\n\r\n"
        result = http.extract(payload)
        assert result is not None
        assert result.method == "POST"
        assert result.uri == "/api/data"

    def test_http_response_parsed(self):
        payload = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
        result = http.extract(payload)
        assert result is not None
        assert result.status_code == 200

    def test_http_404_response(self):
        payload = b"HTTP/1.1 404 Not Found\r\n\r\n"
        result = http.extract(payload)
        assert result is not None
        assert result.status_code == 404

    def test_empty_payload_returns_none(self):
        assert http.extract(b"") is None

    def test_binary_payload_returns_none(self):
        assert http.extract(b"\x00\x01\x02\x03\xFF\xFE") is None

    def test_malformed_request_line_returns_none(self):
        payload = b"INVALID\r\n\r\n"
        assert http.extract(payload) is None

    def test_missing_host_header(self):
        payload = b"GET /path HTTP/1.1\r\n\r\n"
        result = http.extract(payload)
        assert result is not None
        assert result.method == "GET"
        assert result.host is None

    def test_non_ascii_user_agent_no_crash(self):
        payload = b"GET / HTTP/1.1\r\nUser-Agent: \xff\xfe\xfd\r\n\r\n"
        result = http.extract(payload)
        # Should not crash; result may be None or have garbled UA
        assert result is None or isinstance(result.user_agent, str) or result.user_agent is None

    def test_all_http_methods_detected(self):
        for method in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"):
            payload = f"{method} /path HTTP/1.1\r\nHost: h.com\r\n\r\n".encode()
            result = http.extract(payload)
            assert result is not None
            assert result.method == method

    def test_very_long_uri_parsed(self):
        uri = "/" + "a" * 2000
        payload = f"GET {uri} HTTP/1.1\r\nHost: x.com\r\n\r\n".encode()
        result = http.extract(payload)
        assert result is not None
        assert result.uri == uri


# ── DNSExtractor ─────────────────────────────────────────────────

class TestDNSExtractor:
    def _build_query(self, name: str, qtype: int = 1) -> bytes:
        """Build minimal DNS query packet."""
        header = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
        qname = b""
        for label in name.split("."):
            encoded = label.encode()
            qname += bytes([len(encoded)]) + encoded
        qname += b"\x00"
        question = qname + struct.pack("!HH", qtype, 1)
        return header + question

    def _build_response_a(self, name: str, ip: str) -> bytes:
        """Build minimal DNS A response."""
        import socket
        header = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
        qname = b""
        for label in name.split("."):
            encoded = label.encode()
            qname += bytes([len(encoded)]) + encoded
        qname += b"\x00"
        question = qname + struct.pack("!HH", 1, 1)
        answer = b"\xc0\x0c"  # compressed pointer
        answer += struct.pack("!HHIH", 1, 1, 300, 4)
        answer += socket.inet_aton(ip)
        return header + question + answer

    def _build_nxdomain(self, name: str) -> bytes:
        header = struct.pack("!HHHHHH", 0x1234, 0x8183, 1, 0, 0, 0)
        qname = b""
        for label in name.split("."):
            encoded = label.encode()
            qname += bytes([len(encoded)]) + encoded
        qname += b"\x00"
        question = qname + struct.pack("!HH", 1, 1)
        return header + question

    def test_query_parses_name(self):
        payload = self._build_query("example.com")
        result = dns.extract(payload)
        assert result is not None
        assert result.query_name == "example.com"

    def test_query_type_a(self):
        payload = self._build_query("example.com", qtype=1)
        result = dns.extract(payload)
        assert result is not None
        assert result.query_type == "A"

    def test_query_type_aaaa(self):
        payload = self._build_query("example.com", qtype=28)
        result = dns.extract(payload)
        assert result is not None
        assert result.query_type == "AAAA"

    def test_a_response_has_ip(self):
        payload = self._build_response_a("example.com", "93.184.216.34")
        result = dns.extract(payload)
        assert result is not None
        assert "93.184.216.34" in result.response_ips

    def test_nxdomain_detected(self):
        payload = self._build_nxdomain("nonexistent.example.com")
        result = dns.extract(payload)
        assert result is not None
        assert result.is_nxdomain is True

    def test_too_short_payload_returns_none(self):
        assert dns.extract(b"\x00\x01\x02") is None

    def test_empty_payload_returns_none(self):
        assert dns.extract(b"") is None

    def test_random_binary_no_crash(self):
        result = dns.extract(b"\xFF" * 100)
        assert result is None or hasattr(result, "query_name")

    def test_non_nxdomain_response(self):
        payload = self._build_response_a("ok.com", "1.1.1.1")
        result = dns.extract(payload)
        assert result is not None
        assert result.is_nxdomain is False


# ── TLSExtractor ─────────────────────────────────────────────────

class TestTLSExtractor:
    def _build_client_hello(self, sni: str | None = "example.com") -> bytes:
        """Build minimal TLS 1.2 ClientHello with optional SNI."""
        # Cipher suites: two entries
        ciphers = struct.pack("!HH", 0xC02B, 0xC02C)
        cipher_len = struct.pack("!H", len(ciphers))
        # Compression methods
        compression = b"\x01\x00"
        # Extensions
        extensions = b""
        if sni:
            sni_bytes = sni.encode()
            sni_len = struct.pack("!H", len(sni_bytes))
            list_len = struct.pack("!H", len(sni_bytes) + 3)
            sni_data = list_len + b"\x00" + sni_len + sni_bytes
            ext_len = struct.pack("!H", len(sni_data))
            extensions += struct.pack("!H", 0x0000) + ext_len + sni_data
        ext_total = struct.pack("!H", len(extensions))
        # ClientHello body
        ch_body = (
            b"\x03\x03"          # client_version: TLS 1.2
            + b"\x00" * 32       # Random (32 bytes)
            + b"\x00"            # session_id length = 0
            + cipher_len + ciphers
            + compression
            + ext_total + extensions
        )
        # Handshake header
        ch_len = struct.pack("!I", len(ch_body))[1:]  # 3-byte length
        handshake = b"\x01" + ch_len + ch_body
        # TLS record header
        hs_len = struct.pack("!H", len(handshake))
        record = b"\x16\x03\x01" + hs_len + handshake
        return record

    def test_sni_extracted(self):
        payload = self._build_client_hello("example.com")
        result = tls.extract(payload)
        assert result.sni == "example.com"

    def test_no_sni_returns_none(self):
        payload = self._build_client_hello(sni=None)
        result = tls.extract(payload)
        assert result.sni is None

    def test_ja4_populated(self):
        payload = self._build_client_hello("example.com")
        result = tls.extract(payload)
        assert result.ja4 is not None
        assert isinstance(result.ja4, str)
        assert len(result.ja4) > 0

    def test_non_tls_record_returns_empty(self):
        payload = b"\x17\x03\x03\x00\x10" + b"\x00" * 16  # application data, not handshake
        result = tls.extract(payload)
        assert result.sni is None

    def test_empty_payload_no_crash(self):
        result = tls.extract(b"")
        assert result is not None
        assert result.sni is None

    def test_too_short_payload_no_crash(self):
        result = tls.extract(b"\x16\x03")
        assert result is not None

    def test_truncated_at_random_returns_gracefully(self):
        payload = self._build_client_hello("test.com")
        truncated = payload[:20]  # cut off mid-record
        result = tls.extract(truncated)
        assert result is not None  # should not raise

    def test_binary_garbage_no_crash(self):
        result = tls.extract(b"\xFF" * 200)
        assert result is not None
        assert result.sni is None

    def test_different_sni_values(self):
        for hostname in ("sub.example.com", "192.168.1.1", "a.b.c.d.e.f"):
            payload = self._build_client_hello(hostname)
            result = tls.extract(payload)
            assert result.sni == hostname, f"Expected {hostname}, got {result.sni}"
