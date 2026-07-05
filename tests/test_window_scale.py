# -*- coding: utf-8 -*-
"""TCP window scale 옵션 파싱 검증 — 실제 window 계산 정확도."""
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from services.parser.pcap_parser import PcapParser


def _pcap_with_syn_wscale(shift: int) -> bytes:
    """SYN 패킷(window scale 옵션 포함) 1개 pcap."""
    global_hdr = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    eth = bytes([0x00,0x11,0x22,0x33,0x44,0x55, 0xAA,0xBB,0xCC,0xDD,0xEE,0xFF, 0x08,0x00])

    # TCP options: MSS(2 opt,len4) + NOP + WScale(3 opt,len3,shift) → 8 bytes (data offset 7 words=28)
    opts = struct.pack("!BBH", 2, 4, 1460) + bytes([1]) + struct.pack("!BBB", 3, 3, shift)
    # pad options to multiple of 4 → 8 bytes already
    data_off = (20 + len(opts)) // 4  # 28//4 = 7
    tcp = struct.pack(">HHIIBBHHH", 50000, 443, 1, 0, (data_off << 4), 0x02, 8192, 0, 0) + opts

    src = bytes(int(x) for x in "192.168.1.2".split("."))
    dst = bytes(int(x) for x in "192.168.1.1".split("."))
    total = 20 + len(tcp)
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, 0x1234, 0, 64, 6, 0, src, dst)

    pkt = eth + ip + tcp
    rec = struct.pack("<IIII", 1_748_000_000, 0, len(pkt), len(pkt))
    return global_hdr + rec + pkt


class TestWindowScaleParsing:
    def test_wscale_stored_in_meta(self):
        sessions, _ = PcapParser().parse(_pcap_with_syn_wscale(7))
        assert len(sessions) == 1
        assert sessions[0].meta is not None
        assert sessions[0].meta.get("wscale_fwd") == 7

    def test_no_wscale_no_meta_key(self):
        # shift 0 은 여전히 옵션 존재(값 0) → 저장됨. 옵션 자체가 없으면 미저장.
        sessions, _ = PcapParser().parse(_pcap_with_syn_wscale(0))
        assert sessions[0].meta.get("wscale_fwd") == 0

    def test_scaled_window_via_flow_endpoint(self, api_client):
        pcap = _pcap_with_syn_wscale(7)
        up = api_client.post("/api/upload",
                             files={"file": ("w.pcap", pcap, "application/octet-stream")})
        uid = up.json()["upload_id"]; token = up.json()["capture_token"]
        from main import app
        sid = app.state.session_store.get(uid).sessions[0].session_id
        r = api_client.get(f"/api/flow/{uid}?session_id={sid}", headers={"X-Upload-Token": token})
        assert r.status_code == 200
        body = r.json()
        assert body["session"]["wscale"]["fwd"] == 7
        assert body["session"]["wscale"]["fwd_factor"] == 128
        # SYN 패킷은 raw window (scale 미적용)
        syn = body["packets"][0]
        assert syn["window"] == 8192
        assert syn["window_scaled"] == 8192  # SYN은 scale 전
