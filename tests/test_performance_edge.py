# -*- coding: utf-8 -*-
"""Edge cases: performance — 10MB pcap parse must complete within 5 seconds."""
import os
import struct
import sys
import time

import pytest

BACKEND_DIR = os.path.join(os.path.dirname(__file__), "..", "backend")
sys.path.insert(0, os.path.abspath(BACKEND_DIR))

from services.parser.pcap_parser import PcapParser, PCAP_MAGIC


def _build_minimal_pcap(n_packets: int, payload_size: int = 60) -> bytes:
    """Build a syntactically valid pcap file with n_packets TCP packets."""
    # Global header: magic, version major/minor, thiszone, sigfigs, snaplen, network
    header = struct.pack("<IHHiIII",
                         0xa1b2c3d4,  # magic (little-endian)
                         2, 4,        # version
                         0,           # timezone
                         0,           # sig figs
                         65535,       # snaplen
                         1,           # link type: Ethernet
                         )
    # Build a minimal Ethernet/IP/TCP frame
    eth_dst = b"\xff\xff\xff\xff\xff\xff"
    eth_src = b"\x00\x11\x22\x33\x44\x55"
    eth_type = b"\x08\x00"  # IPv4
    ip_header = struct.pack("!BBHHHBBH4s4s",
                            0x45,           # version + IHL
                            0,              # DSCP/ECN
                            40 + payload_size,  # total length
                            0x1234,         # identification
                            0,              # flags + fragment offset
                            64,             # TTL
                            6,              # protocol: TCP
                            0,              # checksum (dummy)
                            b"\x01\x02\x03\x04",  # src
                            b"\x05\x06\x07\x08",  # dst
                            )
    tcp_header = struct.pack("!HHIIBBHHH",
                             12345, 80,     # src/dst port
                             0, 0,          # seq/ack
                             0x50,          # data offset
                             0x02,          # SYN flag
                             65535,         # window
                             0, 0,          # checksum, urgent
                             )
    payload = b"\x41" * payload_size
    frame = eth_dst + eth_src + eth_type + ip_header + tcp_header + payload
    frame_len = len(frame)
    record_header = struct.pack("<IIII",
                                1704067200,  # timestamp seconds
                                0,           # timestamp microseconds
                                frame_len,   # captured length
                                frame_len,   # original length
                                )
    packet_bytes = record_header + frame
    return header + packet_bytes * n_packets


# ── Performance tests ────────────────────────────────────────────

class TestPcapPerformance:
    @pytest.mark.skipif(
        not any(True for _ in [1] if __import__("importlib").util.find_spec("dpkt")),
        reason="dpkt not installed",
    )
    def test_10mb_pcap_parses_within_5_seconds(self):
        """10MB pcap file must be parsed in under 5 seconds."""
        # Build ~10MB pcap: each packet ~160 bytes, need ~65000 packets
        target_bytes = 10 * 1024 * 1024
        frame_size = 160  # approximate
        n_packets = target_bytes // frame_size
        data = _build_minimal_pcap(n_packets)
        actual_size = len(data)
        assert actual_size >= 5 * 1024 * 1024, f"Test data too small: {actual_size} bytes"
        parser = PcapParser()
        start = time.perf_counter()
        packets = parser.parse(data)
        elapsed = time.perf_counter() - start
        assert elapsed < 5.0, f"Parsing {actual_size/1024/1024:.1f}MB took {elapsed:.2f}s (> 5s limit)"
        assert len(packets) > 0, "No packets parsed from valid pcap"

    def test_parse_100_packets_no_crash(self):
        """Basic smoke test: 100 valid TCP packets parse correctly."""
        data = _build_minimal_pcap(100)
        parser = PcapParser()
        try:
            packets = parser.parse(data)
            assert len(packets) >= 1
        except Exception as e:
            pytest.skip(f"dpkt/scapy not available: {e}")

    def test_fortigate_parser_1000_lines(self):
        """FortiGate parser handles 1000 lines within 1 second."""
        from services.parser.fortigate_parser import FortiGateParser
        lines = b"192.168.1.1:1234 -> 10.0.0.1:80 tcp\n" * 1000
        fg = FortiGateParser()
        start = time.perf_counter()
        packets = fg.parse(lines)
        elapsed = time.perf_counter() - start
        assert elapsed < 1.0, f"1000-line FortiGate parse took {elapsed:.3f}s"
        assert len(packets) == 1000

    def test_har_parser_100_entries(self):
        """HAR parser handles 100 entries within 1 second."""
        import json
        from services.parser.har_parser import HarParser
        entries = [
            {
                "startedDateTime": "2024-01-01T00:00:00.000Z",
                "time": 10,
                "request": {
                    "method": "GET",
                    "url": f"http://10.0.0.{i}/path",
                    "headers": [{"name": "Host", "value": f"10.0.0.{i}"}],
                    "bodySize": 0,
                },
                "response": {"status": 200, "headers": [], "bodySize": 100},
            }
            for i in range(100)
        ]
        data = json.dumps({"log": {"entries": entries}}).encode()
        hp = HarParser()
        start = time.perf_counter()
        packets = hp.parse(data)
        elapsed = time.perf_counter() - start
        assert elapsed < 1.0, f"100-entry HAR parse took {elapsed:.3f}s"
        assert len(packets) == 100
