"""WireBoard v5.0 — 공유 테스트 픽스처."""
import json
import struct
import sys
import uuid
from pathlib import Path
from typing import Generator

import pytest
from fastapi.testclient import TestClient

# backend 경로를 sys.path에 추가 (구현 전 TDD — 구현 후 import 성공)
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

# ───────────────────────────── pcap 빌더 ──────────────────────────────

_PCAP_GLOBAL_HEADER: bytes = struct.pack(
    "<IHHiIII",
    0xA1B2C3D4,  # magic (microseconds)
    2, 4,        # version major/minor
    0, 0,        # timezone, sigfigs
    65535,       # snaplen
    1,           # linktype: ethernet
)


def build_pcap(num_packets: int = 5) -> bytes:
    """최소한의 구조적으로 유효한 pcap 바이트를 생성한다.

    각 패킷은 42 bytes: Ethernet(14) + IPv4(20) + TCP(8 minimum).
    """
    out = bytearray(_PCAP_GLOBAL_HEADER)
    for i in range(num_packets):
        eth = bytes([
            0x00, 0x0c, 0x29, 0x00, 0x00, 0x01,  # dst MAC
            0x00, 0x0c, 0x29, 0x00, 0x00, 0x02,  # src MAC
            0x08, 0x00,                            # ethertype: IPv4
        ])
        ip = bytes([
            0x45, 0x00, 0x00, 0x28,               # version/IHL/TOS/total_len=40
            0x00, i % 256, 0x40, 0x00,            # id, flags (DF), fragment
            0x40, 0x06,                            # TTL=64, proto=TCP
            0x00, 0x00,                            # checksum (0 = 테스트용)
            0xc0, 0xa8, 0x01, 0x01,               # src: 192.168.1.1
            0xc0, 0xa8, 0x01, 0x02,               # dst: 192.168.1.2
        ])
        tcp = bytes([
            0x00, 0x50,                            # sport=80
            (0x1f & 0xff), (0x90 & 0xff),         # dport=8080
            0x00, 0x00, 0x00, i % 256,            # seq
            0x00, 0x00, 0x00, 0x00,               # ack
            0x50, 0x02,                            # data_offset=5, SYN
            0xff, 0xff,                            # window
            0x00, 0x00, 0x00, 0x00,               # checksum, urgent
        ])
        pkt = eth + ip + tcp
        ts_sec = 1_748_000_000 + i
        out += struct.pack("<IIII", ts_sec, 0, len(pkt), len(pkt))
        out += pkt
    return bytes(out)


def build_pcap_portscan(src_ip_last: int = 1, num_ports: int = 100) -> bytes:
    """단일 src → num_ports 개 dst_port 를 가진 pcap (PortScan 테스트용)."""
    out = bytearray(_PCAP_GLOBAL_HEADER)
    for port in range(1, num_ports + 1):
        eth = bytes([0x00, 0x0c, 0x29, 0, 0, 0x01, 0x00, 0x0c, 0x29, 0, 0, 0x02, 0x08, 0x00])
        ip = bytes([
            0x45, 0x00, 0x00, 0x28, 0x00, port % 256, 0x40, 0x00,
            0x40, 0x06, 0x00, 0x00,
            0xc0, 0xa8, 0x01, src_ip_last % 256,  # src: 192.168.1.X
            0xc0, 0xa8, 0x01, 0x10,               # dst: 192.168.1.16
        ])
        dport_hi, dport_lo = divmod(port, 256)
        tcp = bytes([
            0x00, 0x50,            # sport=80
            dport_hi, dport_lo,    # dport=port
            0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00,
            0x50, 0x04,            # RST (4번 비트)
            0xff, 0xff,
            0x00, 0x00, 0x00, 0x00,
        ])
        pkt = eth + ip + tcp
        ts_sec = 1_748_000_000 + port
        out += struct.pack("<IIII", ts_sec, 0, len(pkt), len(pkt))
        out += pkt
    return bytes(out)


# ───────────────────────────── HAR 빌더 ──────────────────────────────

def build_har(num_entries: int = 3) -> str:
    """최소 유효 HAR JSON 문자열."""
    entries = []
    for i in range(num_entries):
        entries.append({
            "startedDateTime": f"2026-06-04T10:00:{i:02d}.000Z",
            "time": 50,
            "request": {
                "method": "GET",
                "url": f"http://example.com/api/item/{i}",
                "headers": [],
                "queryString": [],
                "cookies": [],
                "headersSize": -1,
                "bodySize": -1,
            },
            "response": {
                "status": 200,
                "statusText": "OK",
                "headers": [],
                "cookies": [],
                "content": {"mimeType": "application/json", "size": 128},
                "redirectURL": "",
                "headersSize": -1,
                "bodySize": 128,
            },
            "cache": {},
            "timings": {"send": 0, "wait": 50, "receive": 0},
        })
    return json.dumps({"log": {"version": "1.2", "entries": entries}})


# ───────────────────────── FortiGate 텍스트 빌더 ──────────────────────

def build_fortigate_verbose3(num_lines: int = 5) -> str:
    """FortiGate verbose 3 sniffer 텍스트 (payload_length=0)."""
    lines = []
    for i in range(num_lines):
        usec = 123456 + i * 111111
        lines.append(
            f"2026-06-04 10:00:0{i}.{usec} eth1 in "
            f"192.168.1.100 -> 10.0.0.1: tcp 0"
        )
    return "\n".join(lines)


def build_fortigate_verbose6(num_lines: int = 3) -> str:
    """FortiGate verbose 6 sniffer 텍스트 (hex payload 포함)."""
    lines = []
    for i in range(num_lines):
        lines.append(
            f"2026-06-04 10:00:0{i}.123456 eth1 in "
            f"192.168.1.100 -> 10.0.0.1: tcp 40"
        )
        lines.append("0x0000: 4500 0028 0001 4000 4006 0000 c0a8 0164")
        lines.append("0x0010: 0a00 0001 0050 1f90 0000 0001 0000 0000")
    return "\n".join(lines)


# ─────────────────────────────── Fixtures ────────────────────────────

@pytest.fixture(scope="session")
def pcap_bytes() -> bytes:
    return build_pcap(num_packets=5)


@pytest.fixture(scope="session")
def pcap_portscan_bytes() -> bytes:
    return build_pcap_portscan(num_ports=100)


@pytest.fixture(scope="session")
def har_json() -> str:
    return build_har(num_entries=3)


@pytest.fixture(scope="session")
def fortigate_v3_text() -> str:
    return build_fortigate_verbose3(num_lines=5)


@pytest.fixture(scope="session")
def fortigate_v6_text() -> str:
    return build_fortigate_verbose6(num_lines=3)


@pytest.fixture()
def api_client() -> Generator[TestClient, None, None]:
    try:
        from main import app  # noqa: PLC0415
    except ImportError as exc:
        pytest.skip(f"backend 미구현 — 구현 후 테스트 실행 가능: {exc}")
    with TestClient(app) as client:
        yield client
