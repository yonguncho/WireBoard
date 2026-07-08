# -*- coding: utf-8 -*-
"""대용량 스트리밍 파싱 검증 — 전체를 메모리로 올리지 않고 파일 핸들에서 파싱."""
import io
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from services.parser.pcap_parser import PcapParser


def _multiflow_pcap(num_flows: int, pkts_per_flow: int = 3) -> bytes:
    """여러 flow(고유 src port)로 구성된 pcap 바이트."""
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    eth = bytes([0x00,0x11,0x22,0x33,0x44,0x55, 0xAA,0xBB,0xCC,0xDD,0xEE,0xFF, 0x08,0x00])
    src = bytes(int(x) for x in "10.0.0.1".split("."))
    dst = bytes(int(x) for x in "10.0.0.2".split("."))
    ts = 1_748_000_000
    for flow in range(num_flows):
        sport = 1024 + (flow % 60000)
        for k in range(pkts_per_flow):
            ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 40, flow & 0xFFFF, 0, 64, 6, 0, src, dst)
            tcp = struct.pack(">HHIIBBHHH", sport, 443, k + 1, 0, 0x50, 0x10, 8192, 0, 0)
            pkt = eth + ip + tcp
            out += struct.pack("<IIII", ts, k, len(pkt), len(pkt)) + pkt
            ts += 1
    return out


class TestStreamParse:
    def test_parse_stream_matches_parse(self):
        data = _multiflow_pcap(50)
        p1 = PcapParser()
        s_bytes, _ = p1.parse(data)
        p2 = PcapParser()
        s_stream, _ = p2.parse_stream(io.BytesIO(data), size=len(data))
        assert len(s_stream) == len(s_bytes)
        assert len(s_stream) == 50  # 50 flows

    def test_stream_from_real_file_handle(self, tmp_path):
        data = _multiflow_pcap(200)
        f = tmp_path / "big.pcap"
        f.write_bytes(data)
        p = PcapParser()
        with open(f, "rb") as fh:
            sessions, pkt_map = p.parse_stream(fh, size=len(data))
        assert len(sessions) == 200

    def test_stream_size_limit_enforced(self):
        data = _multiflow_pcap(5)
        p = PcapParser()
        try:
            p.parse_stream(io.BytesIO(data), max_bytes=10, size=len(data))
            assert False, "should have raised on size > max_bytes"
        except ValueError:
            pass

    def test_streamed_upload_endpoint(self, api_client):
        # ~200 flows → 스트리밍 경로로 업로드/파싱
        data = _multiflow_pcap(200)
        r = api_client.post("/api/upload",
                            files={"file": ("big.pcap", io.BytesIO(data), "application/octet-stream")})
        assert r.status_code == 200, r.text
        assert r.json()["source_type"] == "pcap"
        assert r.json()["session_count"] == 200
