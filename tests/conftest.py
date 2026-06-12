# -*- coding: utf-8 -*-
"""Shared fixtures and path setup for the WireBoard test suite."""
import io
import json
import os
import struct
import sys
import uuid

import pytest

BACKEND_DIR = os.path.join(os.path.dirname(__file__), "..", "backend")
sys.path.insert(0, os.path.abspath(BACKEND_DIR))


# ── helpers ──────────────────────────────────────────────────────────────────

def make_uuid() -> str:
    return str(uuid.uuid4())


def make_session(src_ip="1.2.3.4", dst_ip="5.6.7.8", **kwargs):
    from models.session import SessionModel
    defaults = dict(
        session_id=make_uuid(),
        src_ip=src_ip, dst_ip=dst_ip,
        src_port=12345, dst_port=80,
        protocol="TCP",
        start_ts=1.0, end_ts=2.0,
        bytes_sent=500, bytes_recv=500,
        packet_count=10, payload_length=0,
    )
    defaults.update(kwargs)
    return SessionModel(**defaults)


def make_attack(attack_type="DoS", confidence="high", mitre_id="T1498.001"):
    from models.attack import AttackDetectionResult
    return AttackDetectionResult(
        attack_type=attack_type,
        severity=confidence,
        confidence=confidence,
        evidence=["test evidence"],
        mitre_id=mitre_id,
    )


def _build_minimal_pcap(
    src_ip="192.168.1.2",
    dst_ip="192.168.1.1",
    src_port=12345,
    dst_port=80,
) -> bytes:
    """Build a minimal valid PCAP file with one TCP SYN packet."""
    # Global header (little-endian, Ethernet DLT=1)
    global_hdr = struct.pack(
        "<IHHiIII",
        0xA1B2C3D4,  # magic LE
        2, 4,         # version 2.4
        0,            # timezone
        0,            # timestamp accuracy
        65535,        # snaplen
        1,            # network = Ethernet
    )

    # Ethernet header (14 bytes)
    eth = bytes([
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,   # dst MAC
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,   # src MAC
        0x08, 0x00,                             # EtherType = IPv4
    ])

    # IP header (20 bytes, no options)
    src_bytes = bytes(int(x) for x in src_ip.split("."))
    dst_bytes = bytes(int(x) for x in dst_ip.split("."))
    ip = struct.pack(
        ">BBHHHBBH4s4s",
        0x45, 0,             # version=4, IHL=5, DSCP=0
        40,                  # total length (IP + TCP, no payload)
        0x1234, 0,           # ID, flags+frag
        64, 6, 0,            # TTL=64, proto=TCP(6), checksum=0
        src_bytes, dst_bytes,
    )

    # TCP header (20 bytes)
    tcp = struct.pack(
        ">HHIIBBHHH",
        src_port, dst_port,
        1, 0,                # seq=1, ack=0
        0x50, 0x02,          # data offset=5*4=20, flags=SYN
        8192, 0, 0,          # window, checksum, urgent
    )

    pkt = eth + ip + tcp    # 14 + 20 + 20 = 54 bytes
    pkt_hdr = struct.pack("<IIII", 1_000_000, 0, len(pkt), len(pkt))
    return global_hdr + pkt_hdr + pkt


def _build_minimal_har(url="http://192.168.1.2/", src_ip="192.168.1.2") -> str:
    har = {
        "log": {
            "version": "1.2",
            "creator": {"name": "conftest", "version": "1.0"},
            "entries": [{
                "startedDateTime": "2024-01-01T00:00:00.000Z",
                "time": 50,
                "request": {
                    "method": "GET",
                    "url": url,
                    "httpVersion": "HTTP/1.1",
                    "headers": [],
                    "queryString": [],
                    "cookies": [],
                    "headersSize": -1,
                    "bodySize": 0,
                },
                "response": {
                    "status": 200,
                    "statusText": "OK",
                    "httpVersion": "HTTP/1.1",
                    "headers": [],
                    "cookies": [],
                    "content": {"size": 0, "mimeType": "text/html"},
                    "redirectURL": "",
                    "headersSize": -1,
                    "bodySize": 0,
                },
                "cache": {},
                "timings": {"send": 0, "wait": 50, "receive": 0},
            }],
        }
    }
    return json.dumps(har)


# ── pytest fixtures ──────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def pcap_bytes() -> bytes:
    return _build_minimal_pcap(src_ip="192.168.1.2", dst_ip="192.168.1.1")


@pytest.fixture(scope="session")
def har_json() -> str:
    return _build_minimal_har()


@pytest.fixture(scope="session")
def fortigate_v3_text() -> str:
    return (
        "2024-01-01 12:00:00.123456 port1 in 192.168.1.2.12345 -> 192.168.1.1.80: TCP 0\n"
        "2024-01-01 12:00:00.234567 port1 out 192.168.1.1.80 -> 192.168.1.2.12345: TCP 0\n"
    )


@pytest.fixture(scope="session")
def fortigate_v6_text() -> str:
    """FortiGate verbose 6 형식 텍스트 — 포트 포함, payload > 0."""
    return (
        "2024-01-01 12:00:00.123456 port1 in 192.168.1.100.12345 -> 10.0.0.2.80: tcp 40\n"
        "2024-01-01 12:00:00.234567 port1 out 10.0.0.2.80 -> 192.168.1.100.12345: tcp 40\n"
    )


@pytest.fixture(scope="session")
def tcpdump_text() -> str:
    """tcpdump -tt 형식 텍스트 — Unix timestamp, IPv4 TCP."""
    return (
        "1748000000.123456 IP 192.168.1.2.12345 > 192.168.1.1.80: Flags [S], seq 0\n"
        "1748000001.234567 IP 192.168.1.1.80 > 192.168.1.2.12345: Flags [S.], seq 0\n"
    )


@pytest.fixture(scope="session")
def tcpdump_ipv6_text() -> str:
    """tcpdump -tt 형식 텍스트 — Unix timestamp, IPv6 TCP."""
    return (
        "1748000000.123456 IP6 2001:db8::1.12345 > 2001:db8::2.80: Flags [S], seq 0\n"
        "1748000001.234567 IP6 2001:db8::2.80 > 2001:db8::1.12345: Flags [S.], seq 0\n"
    )


def _build_minimal_pcap_multi(
    src_ip="192.168.1.2",
    dst_ip="192.168.1.1",
    src_port=12345,
    dst_port=80,
    num_packets=1,
) -> bytes:
    """Build a minimal valid PCAP file with num_packets TCP SYN packets."""
    global_hdr = struct.pack(
        "<IHHiIII",
        0xA1B2C3D4, 2, 4, 0, 0, 65535, 1,
    )
    eth = bytes([
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x08, 0x00,
    ])
    src_bytes = bytes(int(x) for x in src_ip.split("."))
    dst_bytes = bytes(int(x) for x in dst_ip.split("."))
    ip = struct.pack(
        ">BBHHHBBH4s4s",
        0x45, 0, 40, 0x1234, 0, 64, 6, 0, src_bytes, dst_bytes,
    )
    tcp = struct.pack(
        ">HHIIBBHHH",
        src_port, dst_port, 1, 0, 0x50, 0x02, 8192, 0, 0,
    )
    pkt = eth + ip + tcp
    records = b""
    for i in range(num_packets):
        records += struct.pack("<IIII", 1_000_000 + i, 0, len(pkt), len(pkt)) + pkt
    return global_hdr + records


def build_pcap(
    num_packets=1,
    src_ip="192.168.1.2",
    dst_ip="192.168.1.1",
    src_port=12345,
    dst_port=80,
) -> bytes:
    """Standalone helper (not a fixture) for tests that call build_pcap(n) directly."""
    return _build_minimal_pcap_multi(
        src_ip=src_ip, dst_ip=dst_ip,
        src_port=src_port, dst_port=dst_port,
        num_packets=num_packets,
    )


def build_pcap_portscan(
    attacker_ip="10.0.0.1",
    victim_ip="192.168.1.100",
    num_ports=100,
) -> bytes:
    """Build a PCAP with TCP SYN packets to many ports (simulates port scan)."""
    global_hdr = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    eth = bytes([
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x08, 0x00,
    ])
    src_bytes = bytes(int(x) for x in attacker_ip.split("."))
    dst_bytes = bytes(int(x) for x in victim_ip.split("."))

    records = b""
    for port in range(1, num_ports + 1):
        ip = struct.pack(
            ">BBHHHBBH4s4s",
            0x45, 0, 40, port, 0, 64, 6, 0, src_bytes, dst_bytes,
        )
        tcp = struct.pack(
            ">HHIIBBHHH",
            50000 + port, port, 1, 0, 0x50, 0x02, 8192, 0, 0,
        )
        pkt = eth + ip + tcp
        records += struct.pack("<IIII", 1_748_000_000 + port, 0, len(pkt), len(pkt)) + pkt
    return global_hdr + records


# build_pcap 은 standalone 함수로도 노출되어 있으므로 fixture를 별도로 추가하지 않음
# test_packet_record.py 등에서는 `from conftest import build_pcap` 로 직접 사용


@pytest.fixture
def api_client():
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient
    from main import app
    app.state.session_store.clear()
    app.state.annotations_store.clear()
    yield TestClient(app)
    app.state.session_store.clear()
    app.state.annotations_store.clear()


@pytest.fixture
def fastapi_client(api_client):
    return api_client


@pytest.fixture
def seeded_store(api_client):
    """Returns (client, upload_id, target_ip) with a pre-seeded session store."""
    from main import app
    from store.session_store import ParsedCapture
    target_ip = "1.2.3.4"
    upload_id = make_uuid()
    store = app.state.session_store
    store.put(upload_id, ParsedCapture(
        source_type="pcap",
        sessions=[make_session(src_ip=target_ip)],
    ))
    return api_client, upload_id, target_ip
