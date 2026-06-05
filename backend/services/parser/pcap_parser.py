"""PcapParser — libpcap 형식 파서."""
import logging
import struct
import uuid

from models.session import SessionModel
from utils.constants import MAX_UPLOAD_BYTES

logger = logging.getLogger(__name__)

_MAGIC_LE = 0xA1B2C3D4  # microseconds LE
_MAGIC_BE = 0xD4C3B2A1  # microseconds BE
_MAGIC_NS_LE = 0xA1B23C4D
_MAGIC_NS_BE = 0x4D3CB2A1

_VALID_MAGICS = {_MAGIC_LE, _MAGIC_BE, _MAGIC_NS_LE, _MAGIC_NS_BE}

_VLAN_ETHERTYPES = {0x8100, 0x88A8}  # 802.1Q, QinQ


def _read_uint32(data: bytes, offset: int, big_endian: bool) -> int:
    fmt = ">I" if big_endian else "<I"
    return struct.unpack_from(fmt, data, offset)[0]


def _read_uint16(data: bytes, offset: int, big_endian: bool) -> int:
    fmt = ">H" if big_endian else "<H"
    return struct.unpack_from(fmt, data, offset)[0]


class PcapParser:
    def detect(self, data: bytes) -> bool:
        if len(data) < 4:
            return False
        magic = struct.unpack_from("<I", data, 0)[0]
        if magic in _VALID_MAGICS:
            return True
        magic_be = struct.unpack_from(">I", data, 0)[0]
        return magic_be in _VALID_MAGICS

    def parse(self, data: bytes, parse_warnings: list[str] | None = None) -> list[SessionModel]:
        if len(data) > MAX_UPLOAD_BYTES:
            raise ValueError(f"입력 크기 {len(data)} 바이트가 50 MB 제한 초과")

        if len(data) < 24:
            raise ValueError("pcap 파일이 너무 짧습니다 (global header 없음)")

        magic = struct.unpack_from("<I", data, 0)[0]
        if magic in {_MAGIC_LE, _MAGIC_NS_LE}:
            big_endian = False
            nanosec = magic == _MAGIC_NS_LE
        elif magic in {_MAGIC_BE, _MAGIC_NS_BE}:
            big_endian = True
            nanosec = magic == _MAGIC_NS_BE
        else:
            raise ValueError("유효하지 않은 pcap magic number")

        sessions: list[SessionModel] = []
        offset = 24  # global header 크기
        flow_map: dict[tuple, dict] = {}

        while offset + 16 <= len(data):
            try:
                ts_sec = _read_uint32(data, offset, big_endian)
                ts_frac = _read_uint32(data, offset + 4, big_endian)
                incl_len = _read_uint32(data, offset + 8, big_endian)
                pkt_ts = ts_sec + (ts_frac / 1_000_000_000.0 if nanosec else ts_frac / 1_000_000.0)
                offset += 16
                if offset + incl_len > len(data):
                    break

                pkt = data[offset: offset + incl_len]
                offset += incl_len

                if len(pkt) < 14:
                    continue

                eth_type = struct.unpack_from("!H", pkt, 12)[0]
                l3_offset = 14

                # 802.1Q VLAN / QinQ 태그 스킵
                while eth_type in _VLAN_ETHERTYPES:
                    if len(pkt) < l3_offset + 4:
                        break
                    eth_type = struct.unpack_from("!H", pkt, l3_offset + 2)[0]
                    l3_offset += 4

                if eth_type != 0x0800:
                    continue

                if len(pkt) < l3_offset + 20:
                    continue

                ip_proto = pkt[l3_offset + 9]
                if ip_proto not in (6, 17):
                    continue

                src_ip = ".".join(str(b) for b in pkt[l3_offset + 12:l3_offset + 16])
                dst_ip = ".".join(str(b) for b in pkt[l3_offset + 16:l3_offset + 20])

                ihl = (pkt[l3_offset] & 0x0F) * 4
                if ihl < 20 or ihl > 60 or len(pkt) < l3_offset + ihl:
                    continue
                transport_off = l3_offset + ihl
                if len(pkt) < transport_off + 4:
                    continue

                src_port = struct.unpack_from("!H", pkt, transport_off)[0]
                dst_port = struct.unpack_from("!H", pkt, transport_off + 2)[0]
                proto = "TCP" if ip_proto == 6 else "UDP"

                rst = False
                if proto == "TCP" and len(pkt) >= transport_off + 14:
                    flags = pkt[transport_off + 13]
                    rst = bool(flags & 0x04)

                key = (src_ip, dst_ip, src_port, dst_port, proto)
                rev_key = (dst_ip, src_ip, dst_port, src_port, proto)

                if key in flow_map:
                    entry = flow_map[key]
                    entry["end_ts"] = max(entry["end_ts"], pkt_ts)
                    entry["bytes_sent"] += len(pkt)
                    entry["packet_count"] += 1
                    if rst:
                        entry["rst"] = True
                elif rev_key in flow_map:
                    # 역방향 패킷 → 원래 플로우의 bytes_recv에 누적
                    entry = flow_map[rev_key]
                    entry["end_ts"] = max(entry["end_ts"], pkt_ts)
                    entry["bytes_recv"] += len(pkt)
                    entry["packet_count"] += 1
                    if rst:
                        entry["rst"] = True
                else:
                    flow_map[key] = {
                        "start_ts": pkt_ts,
                        "end_ts": pkt_ts,
                        "bytes_sent": len(pkt),
                        "bytes_recv": 0,
                        "packet_count": 1,
                        "rst": rst,
                    }
            except (struct.error, IndexError) as exc:
                msg = f"패킷 파싱 오류 (offset={offset}): {type(exc).__name__}: {exc}"
                logger.warning(msg)
                if parse_warnings is not None:
                    parse_warnings.append(msg)
                continue

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
