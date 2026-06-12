"""PacketRecord dataclass 단위 테스트."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))


class TestPacketRecordCreation:
    def test_creation_with_all_fields(self):
        from models.packet import PacketRecord
        p = PacketRecord(
            ts=1_748_000_000.0,
            direction="fwd",
            proto="TCP",
            seq=1000,
            ack=500,
            flags="SYN",
            length=60,
            payload_len=20,
            payload_hex="deadbeef",
        )
        assert p.ts == 1_748_000_000.0
        assert p.direction == "fwd"
        assert p.proto == "TCP"
        assert p.seq == 1000
        assert p.ack == 500
        assert p.flags == "SYN"
        assert p.length == 60
        assert p.payload_len == 20
        assert p.payload_hex == "deadbeef"

    def test_fwd_direction(self):
        from models.packet import PacketRecord
        p = PacketRecord(ts=0.0, direction="fwd", proto="TCP",
                         seq=0, ack=0, flags="", length=0, payload_len=0, payload_hex="")
        assert p.direction == "fwd"

    def test_rev_direction(self):
        from models.packet import PacketRecord
        p = PacketRecord(ts=0.0, direction="rev", proto="TCP",
                         seq=0, ack=0, flags="", length=0, payload_len=0, payload_hex="")
        assert p.direction == "rev"

    def test_udp_proto(self):
        from models.packet import PacketRecord
        p = PacketRecord(ts=0.0, direction="fwd", proto="UDP",
                         seq=0, ack=0, flags="", length=48, payload_len=20, payload_hex="")
        assert p.proto == "UDP"

    def test_udp_seq_ack_zero(self):
        from models.packet import PacketRecord
        p = PacketRecord(ts=0.0, direction="fwd", proto="UDP",
                         seq=0, ack=0, flags="", length=48, payload_len=20, payload_hex="")
        assert p.seq == 0
        assert p.ack == 0

    def test_flags_syn_ack(self):
        from models.packet import PacketRecord
        p = PacketRecord(ts=0.0, direction="fwd", proto="TCP",
                         seq=1, ack=1, flags="SYN+ACK", length=60, payload_len=0, payload_hex="")
        assert "SYN" in p.flags
        assert "ACK" in p.flags

    def test_empty_payload_hex(self):
        from models.packet import PacketRecord
        p = PacketRecord(ts=0.0, direction="fwd", proto="TCP",
                         seq=0, ack=0, flags="ACK", length=40, payload_len=0, payload_hex="")
        assert p.payload_hex == ""

    def test_payload_hex_is_string(self):
        from models.packet import PacketRecord
        p = PacketRecord(ts=1.0, direction="fwd", proto="TCP",
                         seq=100, ack=50, flags="PSH+ACK",
                         length=100, payload_len=60, payload_hex="48656c6c6f")
        assert isinstance(p.payload_hex, str)


class TestPacketRecordFromParser:
    """pcap_parser가 생성하는 PacketRecord가 올바른 구조를 갖는지 검증."""

    def _get_first_packet(self, pcap_bytes: bytes):
        import struct
        from services.parser.pcap_parser import PcapParser
        sessions, pkt_map = PcapParser().parse(pcap_bytes)
        if not pkt_map:
            return None
        first_sid = next(iter(pkt_map))
        pkts = pkt_map[first_sid]
        return pkts[0] if pkts else None

    def test_parser_produces_packet_record(self):
        from conftest import build_pcap
        pcap = build_pcap(5)
        p = self._get_first_packet(pcap)
        assert p is not None

    def test_parser_packet_direction_is_fwd_or_rev(self):
        from conftest import build_pcap
        pcap = build_pcap(5)
        p = self._get_first_packet(pcap)
        if p:
            assert p.direction in ("fwd", "rev")

    def test_parser_packet_proto_is_string(self):
        from conftest import build_pcap
        pcap = build_pcap(5)
        p = self._get_first_packet(pcap)
        if p:
            assert isinstance(p.proto, str)
            assert len(p.proto) > 0

    def test_parser_packet_flags_is_string(self):
        from conftest import build_pcap
        pcap = build_pcap(5)
        p = self._get_first_packet(pcap)
        if p:
            assert isinstance(p.flags, str)

    def test_parser_packet_ts_positive(self):
        from conftest import build_pcap
        pcap = build_pcap(5)
        p = self._get_first_packet(pcap)
        if p:
            assert p.ts > 0

    def test_parser_packet_length_positive(self):
        from conftest import build_pcap
        pcap = build_pcap(5)
        p = self._get_first_packet(pcap)
        if p:
            assert p.length > 0
