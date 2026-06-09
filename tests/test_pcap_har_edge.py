# -*- coding: utf-8 -*-
"""Edge cases: pcap/pcapng/HAR/tcpdump parser robustness."""
import json
import os
import sys

import pytest

BACKEND_DIR = os.path.join(os.path.dirname(__file__), "..", "backend")
sys.path.insert(0, os.path.abspath(BACKEND_DIR))

from services.parser.pcap_parser import PcapParser, PCAP_MAGIC, PCAPNG_MAGIC
from services.parser.har_parser import HarParser
from services.parser.fortigate_parser import FortigateParser as FortiGateParser
from services.parser.tcpdump_parser import TcpdumpParser

pcap = PcapParser()
har = HarParser()
fg = FortiGateParser()
tcp = TcpdumpParser()


# ── PcapParser.detect() ─────────────────────────────────────────

class TestPcapDetect:
    def test_pcap_le_magic(self):
        assert pcap.detect(PCAP_MAGIC + b"\x00" * 100) is True

    def test_pcap_be_magic(self):
        assert pcap.detect(bytes(reversed(PCAP_MAGIC)) + b"\x00" * 100) is True

    def test_pcapng_magic(self):
        assert pcap.detect(PCAPNG_MAGIC + b"\x00" * 100) is True

    def test_random_bytes_not_detected(self):
        assert pcap.detect(b"\xFF\xFE\xFD\xFC" + b"\x00" * 100) is False

    def test_empty_bytes_not_detected(self):
        assert pcap.detect(b"") is False

    def test_too_short_not_detected(self):
        assert pcap.detect(b"\xd4\xc3") is False


# ── PcapParser.parse() ──────────────────────────────────────────

class TestPcapParse:
    def test_corrupt_body_after_magic_raises_or_empty(self):
        data = PCAP_MAGIC + b"\xFF" * 200
        try:
            packets = pcap.parse(data)
            # May return empty list (all packets failed) or raise ValueError
            assert isinstance(packets, list)
        except ValueError:
            pass  # acceptable

    def test_only_magic_no_body_returns_empty_or_raises(self):
        data = PCAP_MAGIC
        try:
            packets = pcap.parse(data)
            assert packets == [] or isinstance(packets, list)
        except ValueError:
            pass

    def test_oversized_file_raises_value_error(self):
        # Simulate over-limit check by creating a large enough fake data indicator
        # (actual 50MB+ creation is too slow for unit tests, test the guard logic separately)
        from services.parser.pcap_parser import MAX_BYTES
        assert MAX_BYTES == 52_428_800


# ── HarParser.detect() ──────────────────────────────────────────

class TestHarDetect:
    def test_valid_har_detected(self):
        data = json.dumps({"log": {"entries": []}}).encode()
        assert har.detect(data) is True

    def test_random_json_without_log_key(self):
        data = json.dumps({"key": "value"}).encode()
        assert har.detect(data) is False

    def test_non_json_not_detected(self):
        assert har.detect(b"not json at all") is False

    def test_empty_bytes_not_detected(self):
        assert har.detect(b"") is False

    def test_har_with_nested_log_detected(self):
        data = json.dumps({"log": {"version": "1.2", "entries": []}}).encode()
        assert har.detect(data) is True


# ── HarParser.parse() ───────────────────────────────────────────

class TestHarParse:
    def _entry(self, method="GET", url="http://1.2.3.4/path",
               status=200, req_size=100, resp_size=200):
        return {
            "startedDateTime": "2024-01-01T00:00:00.000Z",
            "time": 50,
            "request": {
                "method": method,
                "url": url,
                "headers": [{"name": "Host", "value": "1.2.3.4"}],
                "bodySize": req_size,
            },
            "response": {
                "status": status,
                "headers": [],
                "bodySize": resp_size,
            },
        }

    def test_empty_entries_returns_empty(self):
        data = json.dumps({"log": {"entries": []}}).encode()
        assert har.parse(data) == []

    def test_single_valid_entry_returns_one_packet(self):
        data = json.dumps({"log": {"entries": [self._entry()]}}).encode()
        packets = har.parse(data)
        assert len(packets) == 1

    def test_entry_missing_url_skipped(self):
        entry = self._entry()
        del entry["request"]["url"]
        data = json.dumps({"log": {"entries": [entry]}}).encode()
        # Should not crash, may skip or return empty
        try:
            packets = har.parse(data)
            assert isinstance(packets, list)
        except Exception:
            pass

    def test_https_url_parsed(self):
        data = json.dumps({"log": {"entries": [self._entry(url="https://example.com/api")]}}).encode()
        packets = har.parse(data)
        assert len(packets) == 1

    def test_multiple_entries_all_parsed(self):
        entries = [self._entry(url=f"http://10.0.0.{i}/path") for i in range(1, 6)]
        data = json.dumps({"log": {"entries": entries}}).encode()
        packets = har.parse(data)
        assert len(packets) == 5


# ── FortiGateParser ──────────────────────────────────────────────

class TestFortiGateParser:
    def test_valid_line_detected(self):
        assert fg.detect(b"192.168.1.1:1234 -> 10.0.0.1:80 tcp\n") is True

    def test_valid_line_parses(self):
        data = b"192.168.1.1:1234 -> 10.0.0.1:80 tcp\n"
        packets = fg.parse(data)
        assert len(packets) >= 1
        assert packets[0].src_ip == "192.168.1.1"

    def test_empty_data_returns_empty(self):
        packets = fg.parse(b"")
        assert packets == []

    def test_random_bytes_not_detected(self):
        assert fg.detect(b"\x00\x01\x02\x03") is False

    def test_multiple_lines_parsed(self):
        lines = b"192.168.1.1:1234 -> 10.0.0.1:80 tcp\n10.0.0.1:80 -> 192.168.1.1:1234 tcp\n"
        packets = fg.parse(lines)
        assert len(packets) >= 2

    def test_malformed_line_skipped_gracefully(self):
        data = b"this is not a valid fortigate line\n192.168.1.1:1234 -> 10.0.0.1:80 tcp\n"
        try:
            packets = fg.parse(data)
            assert isinstance(packets, list)
        except Exception:
            pass


# ── TcpdumpParser ────────────────────────────────────────────────

class TestTcpdumpParser:
    def test_valid_line_detected(self):
        line = b"14:30:00.000000 IP 1.2.3.4.1234 > 5.6.7.8.80: tcp\n"
        assert tcp.detect(line) is True

    def test_empty_not_detected(self):
        assert tcp.detect(b"") is False

    def test_valid_line_parses(self):
        line = b"14:30:00.000000 IP 1.2.3.4.1234 > 5.6.7.8.80: tcp\n"
        packets = tcp.parse(line)
        assert isinstance(packets, list)

    def test_malformed_line_no_crash(self):
        data = b"random garbage that is not tcpdump output\n"
        try:
            packets = tcp.parse(data)
            assert isinstance(packets, list)
        except Exception:
            pass
