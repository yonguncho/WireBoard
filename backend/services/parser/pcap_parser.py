"""PcapParser — dpkt primary, scapy fallback, struct tertiary."""
import io
import logging
import socket
import struct
import uuid

from models.packet import PacketRecord
from models.session import SessionModel
from utils.constants import MAX_UPLOAD_BYTES

logger = logging.getLogger(__name__)

_MAGIC_LE    = 0xA1B2C3D4
_MAGIC_BE    = 0xD4C3B2A1
_MAGIC_NS_LE = 0xA1B23C4D
_MAGIC_NS_BE = 0x4D3CB2A1
_MAGIC_PCAPNG = 0x0A0D0D0A

_VALID_MAGICS_LE = {_MAGIC_LE, _MAGIC_BE, _MAGIC_NS_LE, _MAGIC_NS_BE, _MAGIC_PCAPNG}
_STRUCT_MAGICS   = {_MAGIC_LE, _MAGIC_BE, _MAGIC_NS_LE, _MAGIC_NS_BE}

_VLAN_ETHERTYPES = {0x8100, 0x88A8}

# 흐름당 최대 기록 패킷 수 (메모리 상한)
_MAX_PKTS_PER_FLOW = 200
# 패킷당 저장 payload 바이트 수 (YARA 탐지 + 세션 재생 품질 향상)
_PAYLOAD_CAPTURE_BYTES = 128


def _tcp_flags_str(flags_int: int) -> str:
    parts = []
    if flags_int & 0x02: parts.append("SYN")
    if flags_int & 0x10: parts.append("ACK")
    if flags_int & 0x01: parts.append("FIN")
    if flags_int & 0x04: parts.append("RST")
    if flags_int & 0x08: parts.append("PSH")
    if flags_int & 0x20: parts.append("URG")
    return "+".join(parts) if parts else "—"


class PcapParser:
    def detect(self, data: bytes) -> bool:
        if len(data) < 4:
            return False
        magic = struct.unpack_from("<I", data, 0)[0]
        return magic in _VALID_MAGICS_LE

    def parse(
        self,
        data: bytes,
        parse_warnings: list[str] | None = None,
    ) -> tuple[list[SessionModel], dict[str, list]]:
        """(sessions, packet_map) 튜플 반환. packet_map: session_id -> list[PacketRecord]"""
        if len(data) > MAX_UPLOAD_BYTES:
            raise ValueError(f"입력 크기 {len(data)} 바이트가 50 MB 제한 초과")
        if len(data) < 24:
            raise ValueError("pcap 파일이 너무 짧습니다 (global header 없음)")

        try:
            return self._parse_dpkt(data, parse_warnings)
        except Exception as exc:
            msg = f"dpkt parse failed ({type(exc).__name__}: {exc}), trying scapy"
            logger.debug(msg)
            if parse_warnings is not None:
                parse_warnings.append(msg)

        try:
            return self._parse_scapy(data, parse_warnings)
        except Exception as exc:
            msg = f"scapy parse failed ({type(exc).__name__}: {exc}), using struct parser"
            logger.debug(msg)
            if parse_warnings is not None:
                parse_warnings.append(msg)

        return self._parse_struct(data, parse_warnings)

    # ─── dpkt ────────────────────────────────────────────────────────

    def _parse_dpkt(
        self,
        data: bytes,
        parse_warnings: list[str] | None,
    ) -> tuple[list[SessionModel], dict[str, list]]:
        import dpkt  # noqa: PLC0415

        f = io.BytesIO(data)
        try:
            pcap = dpkt.pcap.Reader(f)
        except Exception:
            f.seek(0)
            pcap = dpkt.pcapng.Reader(f)

        flow_map: dict[tuple, dict] = {}
        pkt_map: dict[tuple, list]  = {}

        for ts, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                if not isinstance(eth.data, dpkt.ip.IP):
                    continue
                ip = eth.data

                if isinstance(ip.data, dpkt.tcp.TCP):
                    t       = ip.data
                    proto   = "TCP"
                    rst     = bool(t.flags & dpkt.tcp.TH_RST)
                    seq     = t.seq
                    ack_num = t.ack
                    flags_s = _tcp_flags_str(t.flags)
                    payload = bytes(t.data)
                    sport, dport = t.sport, t.dport
                elif isinstance(ip.data, dpkt.udp.UDP):
                    t       = ip.data
                    proto   = "UDP"
                    rst     = False
                    seq     = 0
                    ack_num = 0
                    flags_s = ""
                    payload = bytes(t.data)
                    sport, dport = t.sport, t.dport
                elif isinstance(ip.data, dpkt.icmp.ICMP):
                    t       = ip.data
                    proto   = "ICMP"
                    rst     = False
                    seq     = 0
                    ack_num = 0
                    flags_s = f"{t.type}/{t.code}"
                    payload = bytes(t.data) if hasattr(t, "data") else b""
                    # sport/dport=0 고정: _update_flow 양방향 매칭이 Request↔Reply를 같은 flow로 묶음
                    sport, dport = 0, 0
                else:
                    continue

                src_ip  = socket.inet_ntoa(ip.src)
                dst_ip  = socket.inet_ntoa(ip.dst)
                pkt_len = len(buf)
                fts     = float(ts)

                canonical, direction = self._update_flow(
                    flow_map, fts, src_ip, dst_ip, sport, dport, proto, pkt_len, rst
                )
                self._record_packet(
                    pkt_map, canonical,
                    PacketRecord(
                        ts=fts, direction=direction, proto=proto,
                        seq=seq, ack=ack_num, flags=flags_s,
                        length=pkt_len, payload_len=len(payload),
                        payload_hex=payload[:_PAYLOAD_CAPTURE_BYTES].hex(),
                    ),
                )
            except Exception as exc:
                if parse_warnings is not None:
                    parse_warnings.append(f"dpkt packet error: {type(exc).__name__}: {exc}")

        return self._to_sessions(flow_map, pkt_map)

    # ─── scapy ───────────────────────────────────────────────────────

    def _parse_scapy(
        self,
        data: bytes,
        parse_warnings: list[str] | None,
    ) -> tuple[list[SessionModel], dict[str, list]]:
        import os, tempfile
        import scapy.all as scapy  # noqa: PLC0415

        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
            tmp.write(data)
            tmp_path = tmp.name
        try:
            packets = scapy.rdpcap(tmp_path)
        finally:
            os.unlink(tmp_path)

        flow_map: dict[tuple, dict] = {}
        pkt_map: dict[tuple, list]  = {}

        for pkt in packets:
            try:
                if not pkt.haslayer(scapy.IP):
                    continue
                ip = pkt[scapy.IP]
                if pkt.haslayer(scapy.TCP):
                    t = pkt[scapy.TCP]
                    proto, rst = "TCP", bool(t.flags & 0x04)
                    sport, dport = t.sport, t.dport
                    seq, ack_num = t.seq, t.ack
                    flags_s = _tcp_flags_str(int(t.flags))
                    payload = bytes(t.payload)
                elif pkt.haslayer(scapy.UDP):
                    t = pkt[scapy.UDP]
                    proto, rst = "UDP", False
                    sport, dport = t.sport, t.dport
                    seq, ack_num, flags_s = 0, 0, ""
                    payload = bytes(t.payload)
                elif pkt.haslayer(scapy.ICMP):
                    t = pkt[scapy.ICMP]
                    proto, rst = "ICMP", False
                    sport, dport = 0, 0  # 고정: Request↔Reply 같은 flow로 묶음
                    seq, ack_num = 0, 0
                    flags_s = f"{t.type}/{t.code}"
                    payload = bytes(t.payload) if hasattr(t, "payload") else b""
                else:
                    continue

                fts     = float(pkt.time)
                pkt_len = len(pkt)

                canonical, direction = self._update_flow(
                    flow_map, fts, ip.src, ip.dst, sport, dport, proto, pkt_len, rst
                )
                self._record_packet(
                    pkt_map, canonical,
                    PacketRecord(
                        ts=fts, direction=direction, proto=proto,
                        seq=seq, ack=ack_num, flags=flags_s,
                        length=pkt_len, payload_len=len(payload),
                        payload_hex=payload[:_PAYLOAD_CAPTURE_BYTES].hex(),
                    ),
                )
            except Exception as exc:
                if parse_warnings is not None:
                    parse_warnings.append(f"scapy packet error: {type(exc).__name__}: {exc}")

        return self._to_sessions(flow_map, pkt_map)

    # ─── struct fallback ─────────────────────────────────────────────

    def _parse_struct(
        self,
        data: bytes,
        parse_warnings: list[str] | None,
    ) -> tuple[list[SessionModel], dict[str, list]]:
        magic = struct.unpack_from("<I", data, 0)[0]
        if magic == _MAGIC_PCAPNG:
            if parse_warnings is not None:
                parse_warnings.append(
                    "PCAPNG 형식은 dpkt 없이는 파싱할 수 없습니다. "
                    "dpkt가 설치되어 있는지 확인하세요."
                )
            return [], {}

        if magic in {_MAGIC_LE, _MAGIC_NS_LE}:
            big_endian, nanosec = False, magic == _MAGIC_NS_LE
        elif magic in {_MAGIC_BE, _MAGIC_NS_BE}:
            big_endian, nanosec = True, magic == _MAGIC_NS_BE
        else:
            raise ValueError("유효하지 않은 pcap magic number")

        flow_map: dict[tuple, dict] = {}
        pkt_map: dict[tuple, list]  = {}
        offset = 24

        while offset + 16 <= len(data):
            try:
                ts_sec   = self._u32(data, offset, big_endian)
                ts_frac  = self._u32(data, offset + 4, big_endian)
                incl_len = self._u32(data, offset + 8, big_endian)
                pkt_ts   = ts_sec + (ts_frac / 1e9 if nanosec else ts_frac / 1e6)
                offset  += 16
                if offset + incl_len > len(data):
                    break
                pkt      = data[offset: offset + incl_len]
                offset  += incl_len

                if len(pkt) < 14:
                    continue
                eth_type = struct.unpack_from("!H", pkt, 12)[0]
                l3_off   = 14
                while eth_type in _VLAN_ETHERTYPES:
                    if len(pkt) < l3_off + 4:
                        break
                    eth_type = struct.unpack_from("!H", pkt, l3_off + 2)[0]
                    l3_off  += 4
                if eth_type != 0x0800 or len(pkt) < l3_off + 20:
                    continue
                ip_proto = pkt[l3_off + 9]
                if ip_proto not in (6, 17, 1):
                    continue
                src_ip   = ".".join(str(b) for b in pkt[l3_off + 12: l3_off + 16])
                dst_ip   = ".".join(str(b) for b in pkt[l3_off + 16: l3_off + 20])
                ihl      = (pkt[l3_off] & 0x0F) * 4
                if ihl < 20 or ihl > 60 or len(pkt) < l3_off + ihl + 4:
                    continue
                t_off    = l3_off + ihl
                pkt_len  = len(pkt)

                if ip_proto == 6:  # TCP
                    sport  = struct.unpack_from("!H", pkt, t_off)[0]
                    dport  = struct.unpack_from("!H", pkt, t_off + 2)[0]
                    proto  = "TCP"
                    rst    = len(pkt) >= t_off + 14 and bool(pkt[t_off + 13] & 0x04)
                    if len(pkt) >= t_off + 20:
                        seq         = struct.unpack_from("!I", pkt, t_off + 4)[0]
                        ack_num     = struct.unpack_from("!I", pkt, t_off + 8)[0]
                        flags_byte  = pkt[t_off + 13]
                        flags_s     = _tcp_flags_str(flags_byte)
                        tcp_hdr_len = ((pkt[t_off + 12] >> 4) & 0xF) * 4
                        p_start     = t_off + tcp_hdr_len
                        payload     = pkt[p_start:] if len(pkt) > p_start else b""
                    else:
                        seq, ack_num, flags_s, payload = 0, 0, "", b""
                elif ip_proto == 17:  # UDP
                    sport   = struct.unpack_from("!H", pkt, t_off)[0]
                    dport   = struct.unpack_from("!H", pkt, t_off + 2)[0]
                    proto   = "UDP"
                    rst     = False
                    seq, ack_num, flags_s = 0, 0, ""
                    p_start = t_off + 8
                    payload = pkt[p_start:] if len(pkt) > p_start else b""
                else:  # ICMP (ip_proto == 1)
                    icmp_type = pkt[t_off] if len(pkt) > t_off else 0
                    icmp_code = pkt[t_off + 1] if len(pkt) > t_off + 1 else 0
                    sport, dport = 0, 0  # 고정: Request↔Reply 같은 flow로 묶음
                    proto   = "ICMP"
                    rst     = False
                    seq, ack_num = 0, 0
                    flags_s = f"{icmp_type}/{icmp_code}"
                    payload = pkt[t_off + 4:] if len(pkt) > t_off + 4 else b""

                canonical, direction = self._update_flow(
                    flow_map, pkt_ts, src_ip, dst_ip, sport, dport, proto, pkt_len, rst
                )
                self._record_packet(
                    pkt_map, canonical,
                    PacketRecord(
                        ts=pkt_ts, direction=direction, proto=proto,
                        seq=seq, ack=ack_num, flags=flags_s,
                        length=pkt_len, payload_len=len(payload),
                        payload_hex=payload[:_PAYLOAD_CAPTURE_BYTES].hex(),
                    ),
                )
            except (struct.error, IndexError) as exc:
                msg = f"struct packet error (offset={offset}): {type(exc).__name__}: {exc}"
                logger.warning(msg)
                if parse_warnings is not None:
                    parse_warnings.append(msg)

        return self._to_sessions(flow_map, pkt_map)

    # ─── helpers ─────────────────────────────────────────────────────

    @staticmethod
    def _u32(data: bytes, offset: int, big_endian: bool) -> int:
        return struct.unpack_from(">I" if big_endian else "<I", data, offset)[0]

    @staticmethod
    def _update_flow(
        flow_map: dict,
        ts: float,
        src_ip: str, dst_ip: str,
        sport: int, dport: int,
        proto: str,
        pkt_len: int,
        rst: bool,
    ) -> tuple[tuple, str]:
        """flow_map 갱신 후 (canonical_key, direction) 반환."""
        key = (src_ip, dst_ip, sport, dport, proto)
        rev = (dst_ip, src_ip, dport, sport, proto)

        if key in flow_map:
            e = flow_map[key]
            e["end_ts"] = max(e["end_ts"], ts)
            e["bytes_sent"]   += pkt_len
            e["packet_count"] += 1
            if rst: e["rst"] = True
            return key, "fwd"
        elif rev in flow_map:
            e = flow_map[rev]
            e["end_ts"] = max(e["end_ts"], ts)
            e["bytes_recv"]   += pkt_len
            e["packet_count"] += 1
            if rst: e["rst"] = True
            return rev, "rev"
        else:
            flow_map[key] = {
                "start_ts": ts, "end_ts": ts,
                "bytes_sent": pkt_len, "bytes_recv": 0,
                "packet_count": 1, "rst": rst,
            }
            return key, "fwd"

    @staticmethod
    def _record_packet(
        pkt_map: dict,
        canonical: tuple,
        record: PacketRecord,
    ) -> None:
        pkts = pkt_map.setdefault(canonical, [])
        if len(pkts) < _MAX_PKTS_PER_FLOW:
            pkts.append(record)

    @staticmethod
    def _to_sessions(
        flow_map: dict,
        pkt_map: dict,
    ) -> tuple[list[SessionModel], dict[str, list]]:
        sessions: list[SessionModel]     = []
        session_pkt_map: dict[str, list] = {}

        for (src_ip, dst_ip, src_port, dst_port, proto), v in flow_map.items():
            sid = str(uuid.uuid4())
            sessions.append(SessionModel(
                session_id=sid,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=proto,
                start_ts=v["start_ts"],
                end_ts=v["end_ts"],
                bytes_sent=v["bytes_sent"],
                bytes_recv=v["bytes_recv"],
                packet_count=v["packet_count"],
                payload_length=0,
                confidence="normal",
                rst=v["rst"],
            ))
            key = (src_ip, dst_ip, src_port, dst_port, proto)
            session_pkt_map[sid] = pkt_map.get(key, [])

        return sessions, session_pkt_map
