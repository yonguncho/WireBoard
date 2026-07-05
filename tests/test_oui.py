# -*- coding: utf-8 -*-
"""MAC OUI 벤더 조회 + 파서 MAC 캡처 테스트."""
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from services.analytics import oui
from services.parser.pcap_parser import PcapParser


class TestOuiLookup:
    def test_known_vendor(self):
        r = oui.lookup("00:0c:29:aa:bb:cc")  # VMware
        assert r["vendor"] == "VMware"
        assert r["oui"] == "000C29"

    def test_dash_and_case_insensitive(self):
        assert oui.lookup("00-00-0C-11-22-33")["vendor"] == "Cisco"

    def test_locally_administered(self):
        # 02:.. → locally administered bit set
        r = oui.lookup("02:11:22:33:44:55")
        assert r["local"] is True
        assert r["vendor"] == "Locally-administered"

    def test_multicast_bit(self):
        r = oui.lookup("01:00:5e:00:00:01")
        assert r["multicast"] is True

    def test_unknown_vendor(self):
        r = oui.lookup("fe:dc:ba:98:76:54")
        assert r["vendor"] in ("Unknown vendor", "Locally-administered")

    def test_invalid_returns_none(self):
        assert oui.lookup("") is None
        assert oui.lookup("zz") is None


def _pcap_with_macs(src_mac: bytes, dst_mac: bytes) -> bytes:
    global_hdr = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    eth = dst_mac + src_mac + bytes([0x08, 0x00])
    tcp = struct.pack(">HHIIBBHHH", 50000, 443, 1, 0, 0x50, 0x02, 8192, 0, 0)
    src = bytes(int(x) for x in "192.168.1.2".split("."))
    dst = bytes(int(x) for x in "192.168.1.1".split("."))
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 40, 0x1234, 0, 64, 6, 0, src, dst)
    pkt = eth + ip + tcp
    rec = struct.pack("<IIII", 1_748_000_000, 0, len(pkt), len(pkt))
    return global_hdr + rec + pkt


class TestParserCapturesMac:
    def test_src_mac_stored_in_meta(self):
        vmware = bytes([0x00, 0x0c, 0x29, 0x01, 0x02, 0x03])
        cisco = bytes([0x00, 0x00, 0x0c, 0x0a, 0x0b, 0x0c])
        sessions, _ = PcapParser().parse(_pcap_with_macs(vmware, cisco))
        assert sessions[0].meta.get("mac_src") == "00:0c:29:01:02:03"
        assert oui.lookup(sessions[0].meta["mac_src"])["vendor"] == "VMware"
