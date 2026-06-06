"""PcapParser — dpkt primary, scapy fallback, struct tertiary."""
import io
import logging
import socket
import struct
import uuid

from models.session import SessionModel
from utils.constants import MAX_UPLOAD_BYTES

logger = logging.getLogger(__name__)

_MAGIC_LE = 0xA1B2C3D4
_MAGIC_BE = 0xD4C3B2A1
_MAGIC_NS_LE = 0xA1B23C4D
_MAGIC_NS_BE = 0x4D3CB2A1
_MAGIC_PCAPNG = 0x0A0D0D0A

_VALID_MAGICS_LE = {_MAGIC_LE, _MAGIC_BE, _MAGIC_NS_LE, _MAGIC_NS_BE, _MAGIC_PCAPNG}
_STRUCT_MAGICS = {_MAGIC_LE, _MAGIC_BE, _MAGIC_NS_LE, _MAGIC_NS_BE}

_VLAN_ETHERTYPES = {0x8100, 0x88A8}


class PcapParser:
    def detect(self, data: bytes) -> bool:
        if len(data) < 4:
            return False
        magic = struct.unpack_from("<I", data, 0)[0]
        return magic in _VALID_MAGICS_LE

    def parse(self, data: bytes, parse_warnings: list[str] | None = None) -> list[SessionModel]:
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

    def _parse_dpkt(self, data: bytes, parse_warnings: list[str] | None) -> list[SessionModel]:
        import dpkt  # noqa: PLC0415

        f = io.BytesIO(data)
        try:
            pcap = dpkt.pcap.Reader(f)
        except Exception:
            f.seek(0)
            pcap = dpkt.pcapng.Reader(f)

        flow_map: dict[tuple, dict] = {}
        for ts, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                if not isinstance(eth.data, dpkt.ip.IP):
                    continue
                ip = eth.data
                if isinstance(ip.data, dpkt.tcp.TCP):
                    transport = ip.data
                    proto = "TCP"
                    rst = bool(transport.flags & dpkt.tcp.TH_RST)
                elif isinstance(ip.data, dpkt.udp.UDP):
                    transport = ip.data
                    proto = "UDP"
                    rst = False
                else:
                    continue
                src_ip = socket.inet_ntoa(ip.src)
                dst_ip = socket.inet_ntoa(ip.dst)
                self._update_flow(flow_map, float(ts), src_ip, dst_ip,
                                  transport.sport, transport.dport, proto, len(buf), rst)
            except Exception as exc:
                if parse_warnings is not None:
                    parse_warnings.append(f"dpkt packet error: {type(exc).__name__}: {exc}")

        return self._to_sessions(flow_map)

    # ─── scapy ───────────────────────────────────────────────────────

    def _parse_scapy(self, data: bytes, parse_warnings: list[str] | None) -> list[SessionModel]:
        import os
        import tempfile

        import scapy.all as scapy  # noqa: PLC0415

        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
            tmp.write(data)
            tmp_path = tmp.name
        try:
            packets = scapy.rdpcap(tmp_path)
        finally:
            os.unlink(tmp_path)

        flow_map: dict[tuple, dict] = {}
        for pkt in packets:
            try:
                if not pkt.haslayer(scapy.IP):
                    continue
                ip = pkt[scapy.IP]
                if pkt.haslayer(scapy.TCP):
                    t = pkt[scapy.TCP]
                    proto, rst = "TCP", bool(t.flags & 0x04)
                    sport, dport = t.sport, t.dport
                elif pkt.haslayer(scapy.UDP):
                    t = pkt[scapy.UDP]
                    proto, rst = "UDP", False
                    sport, dport = t.sport, t.dport
                else:
                    continue
                self._update_flow(flow_map, float(pkt.time), ip.src, ip.dst,
                                  sport, dport, proto, len(pkt), rst)
            except Exception as exc:
                if parse_warnings is not None:
                    parse_warnings.append(f"scapy packet error: {type(exc).__name__}: {exc}")

        return self._to_sessions(flow_map)

    # ─── struct fallback ─────────────────────────────────────────────

    def _parse_struct(self, data: bytes, parse_warnings: list[str] | None) -> list[SessionModel]:
        magic = struct.unpack_from("<I", data, 0)[0]
        if magic == _MAGIC_PCAPNG:
            # pcapng requires dpkt/scapy; struct parser cannot decode it
            if parse_warnings is not None:
                parse_warnings.append(
                    "PCAPNG 형식은 dpkt 없이는 파싱할 수 없습니다. "
                    "dpkt가 설치되어 있는지 확인하세요."
                )
            return []

        if magic in {_MAGIC_LE, _MAGIC_NS_LE}:
            big_endian, nanosec = False, magic == _MAGIC_NS_LE
        elif magic in {_MAGIC_BE, _MAGIC_NS_BE}:
            big_endian, nanosec = True, magic == _MAGIC_NS_BE
        else:
            raise ValueError("유효하지 않은 pcap magic number")

        flow_map: dict[tuple, dict] = {}
        offset = 24
        while offset + 16 <= len(data):
            try:
                ts_sec = self._u32(data, offset, big_endian)
                ts_frac = self._u32(data, offset + 4, big_endian)
                incl_len = self._u32(data, offset + 8, big_endian)
                pkt_ts = ts_sec + (ts_frac / 1e9 if nanosec else ts_frac / 1e6)
                offset += 16
                if offset + incl_len > len(data):
                    break
                pkt = data[offset: offset + incl_len]
                offset += incl_len

                if len(pkt) < 14:
                    continue
                eth_type = struct.unpack_from("!H", pkt, 12)[0]
                l3_off = 14
                while eth_type in _VLAN_ETHERTYPES:
                    if len(pkt) < l3_off + 4:
                        break
                    eth_type = struct.unpack_from("!H", pkt, l3_off + 2)[0]
                    l3_off += 4
                if eth_type != 0x0800 or len(pkt) < l3_off + 20:
                    continue
                ip_proto = pkt[l3_off + 9]
                if ip_proto not in (6, 17):
                    continue
                src_ip = ".".join(str(b) for b in pkt[l3_off + 12: l3_off + 16])
                dst_ip = ".".join(str(b) for b in pkt[l3_off + 16: l3_off + 20])
                ihl = (pkt[l3_off] & 0x0F) * 4
                if ihl < 20 or ihl > 60 or len(pkt) < l3_off + ihl + 4:
                    continue
                t_off = l3_off + ihl
                src_port = struct.unpack_from("!H", pkt, t_off)[0]
                dst_port = struct.unpack_from("!H", pkt, t_off + 2)[0]
                proto = "TCP" if ip_proto == 6 else "UDP"
                rst = (proto == "TCP" and len(pkt) >= t_off + 14
                       and bool(pkt[t_off + 13] & 0x04))
                self._update_flow(flow_map, pkt_ts, src_ip, dst_ip,
                                  src_port, dst_port, proto, len(pkt), rst)
            except (struct.error, IndexError) as exc:
                msg = f"struct packet error (offset={offset}): {type(exc).__name__}: {exc}"
                logger.warning(msg)
                if parse_warnings is not None:
                    parse_warnings.append(msg)

        return self._to_sessions(flow_map)

    # ─── helpers ─────────────────────────────────────────────────────

    @staticmethod
    def _u32(data: bytes, offset: int, big_endian: bool) -> int:
        return struct.unpack_from(">I" if big_endian else "<I", data, offset)[0]

    @staticmethod
    def _update_flow(
        flow_map: dict,
        ts: float,
        src_ip: str, dst_ip: str,
        src_port: int, dst_port: int,
        proto: str,
        pkt_len: int,
        rst: bool,
    ) -> None:
        key = (src_ip, dst_ip, src_port, dst_port, proto)
        rev = (dst_ip, src_ip, dst_port, src_port, proto)
        if key in flow_map:
            e = flow_map[key]
            e["end_ts"] = max(e["end_ts"], ts)
            e["bytes_sent"] += pkt_len
            e["packet_count"] += 1
            if rst:
                e["rst"] = True
        elif rev in flow_map:
            e = flow_map[rev]
            e["end_ts"] = max(e["end_ts"], ts)
            e["bytes_recv"] += pkt_len
            e["packet_count"] += 1
            if rst:
                e["rst"] = True
        else:
            flow_map[key] = {
                "start_ts": ts, "end_ts": ts,
                "bytes_sent": pkt_len, "bytes_recv": 0,
                "packet_count": 1, "rst": rst,
            }

    @staticmethod
    def _to_sessions(flow_map: dict) -> list[SessionModel]:
        sessions = []
        for (src_ip, dst_ip, src_port, dst_port, proto), v in flow_map.items():
            sessions.append(SessionModel(
                session_id=str(uuid.uuid4()),
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
        return sessions
