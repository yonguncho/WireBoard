# -*- coding: utf-8 -*-
"""IPv6 파싱 검증 — 듀얼스택 캡처가 더 이상 무음 폐기되지 않아야 한다."""
import io
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from services.parser.pcap_parser import PcapParser


def _ipv6_tcp_syn_pcap() -> bytes:
    """IPv6 + TCP SYN 1패킷 pcap (Ethernet, DLT=1)."""
    global_hdr = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)

    # Ethernet: EtherType 0x86DD (IPv6)
    eth = bytes([0x00,0x11,0x22,0x33,0x44,0x55, 0xAA,0xBB,0xCC,0xDD,0xEE,0xFF, 0x86,0xDD])

    # TCP header (20 bytes), SYN
    tcp = struct.pack(">HHIIBBHHH", 50000, 443, 1, 0, 0x50, 0x02, 8192, 0, 0)

    # IPv6 header (40 bytes)
    src = bytes.fromhex("20010db8000000000000000000000001")
    dst = bytes.fromhex("20010db8000000000000000000000002")
    ip6 = struct.pack(
        ">IHBB", (6 << 28), len(tcp), 6, 64,  # ver=6, payload_len, next=TCP(6), hop=64
    ) + src + dst

    pkt = eth + ip6 + tcp
    rec = struct.pack("<IIII", 1_748_000_000, 0, len(pkt), len(pkt))
    return global_hdr + rec + pkt


class TestIPv6Parsing:
    def test_ipv6_tcp_session_parsed(self):
        sessions, pkt_map = PcapParser().parse(_ipv6_tcp_syn_pcap())
        assert len(sessions) == 1, "IPv6 TCP 세션이 파싱되지 않음 (무음 폐기 회귀)"
        s = sessions[0]
        assert s.protocol == "TCP"
        assert s.src_ip == "2001:db8::1"
        assert s.dst_ip == "2001:db8::2"
        assert s.dst_port == 443

    def test_ipv6_packet_has_layer_fields(self):
        sessions, pkt_map = PcapParser().parse(_ipv6_tcp_syn_pcap())
        pkts = pkt_map[sessions[0].session_id]
        assert len(pkts) == 1
        p = pkts[0]
        assert p.ttl == 64          # IPv6 hop limit
        assert p.window == 8192     # TCP window
        assert p.df is True         # IPv6는 항상 DF
        assert "SYN" in p.flags
