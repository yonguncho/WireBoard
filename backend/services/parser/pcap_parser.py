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

# 공개 상수 — 테스트에서 import 가능 (bytes 형식으로 노출)
PCAP_MAGIC   = struct.pack("<I", _MAGIC_LE)    # b'\xd4\xc3\xb2\xa1' LE
PCAPNG_MAGIC = struct.pack("<I", _MAGIC_PCAPNG)  # b'\x0a\x0d\x0d\x0a'

# MAX_BYTES 별칭 — 일부 테스트에서 import
MAX_BYTES = MAX_UPLOAD_BYTES

_VALID_MAGICS_LE = {_MAGIC_LE, _MAGIC_BE, _MAGIC_NS_LE, _MAGIC_NS_BE, _MAGIC_PCAPNG}
_STRUCT_MAGICS   = {_MAGIC_LE, _MAGIC_BE, _MAGIC_NS_LE, _MAGIC_NS_BE}

_VLAN_ETHERTYPES = {0x8100, 0x88A8}

# 흐름당 최대 기록 패킷 수 (메모리 상한)
_MAX_PKTS_PER_FLOW = 200
# 패킷당 저장 payload 바이트 수 (YARA 탐지 + 세션 재생 품질 향상)
_PAYLOAD_CAPTURE_BYTES = 128
# TLS 핸드셰이크는 SNI/cipher가 128B 이후에 위치할 수 있어 더 길게 저장
_TLS_PAYLOAD_CAPTURE_BYTES = 1024


def _capture_payload_hex(payload: bytes) -> str:
    """TLS 핸드셰이크 레코드(0x16 0x03)는 더 많은 바이트를 보존해 SNI·cipher 추출을 보장."""
    if len(payload) >= 3 and payload[0] == 0x16 and payload[1] == 0x03:
        return payload[:_TLS_PAYLOAD_CAPTURE_BYTES].hex()
    return payload[:_PAYLOAD_CAPTURE_BYTES].hex()
# 단일 캡처에서 허용할 최대 고유 플로우(세션) 수
_MAX_FLOW_COUNT = 50_000
# parse_warnings 목록의 최대 항목 수
_MAX_PARSE_WARNINGS = 500

# ICMP 에러 타입 → 레이블 매핑
_ICMP_LABELS: dict[tuple[int, int], str] = {
    (11, 0): "ttl_expired",
    (11, 1): "fragment_timeout",
    (3,  0): "net_unreachable",
    (3,  1): "host_unreachable",
    (3,  3): "port_unreachable",
    (3, 13): "admin_prohibited",
}


def _icmp_label(icmp_type: int, icmp_code: int) -> str:
    return _ICMP_LABELS.get(
        (icmp_type, icmp_code),
        "ttl_expired" if icmp_type == 11 else "unreachable",
    )


def _fmt_mac(mac: bytes) -> str:
    """이더넷 MAC 바이트 → 'aa:bb:cc:dd:ee:ff'. 유효하지 않으면 빈 문자열."""
    if not mac or len(mac) != 6:
        return ""
    return ":".join(f"{b:02x}" for b in mac)


def _parse_icmp_embedded(payload: bytes) -> tuple[str, int]:
    """ICMP 에러 페이로드(임베디드 IP 헤더)에서 (orig_dst_ip, orig_dst_port) 추출."""
    if len(payload) < 20:
        return "", 0
    try:
        ihl = (payload[0] & 0x0F) * 4
        proto = payload[9]
        orig_dst = socket.inet_ntoa(payload[16:20])
        orig_dst_port = 0
        if len(payload) >= ihl + 4 and proto in (6, 17):  # TCP/UDP
            orig_dst_port = struct.unpack_from("!H", payload, ihl + 2)[0]
        return orig_dst, orig_dst_port
    except (IndexError, struct.error, OSError):
        return "", 0


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
    def __init__(self) -> None:
        self._icmp_events: list[dict] = []

    @property
    def icmp_events(self) -> list[dict]:
        return self._icmp_events

    def detect(self, data: bytes) -> bool:
        if len(data) < 4:
            return False
        magic = struct.unpack_from("<I", data, 0)[0]
        return magic in _VALID_MAGICS_LE

    def parse(
        self,
        data: bytes,
        parse_warnings: list[str] | None = None,
        max_bytes: int = MAX_UPLOAD_BYTES,
    ) -> tuple[list[SessionModel], dict[str, list]]:
        """(sessions, packet_map) 튜플 반환. packet_map: session_id -> list[PacketRecord]
        ICMP 에러 이벤트는 self.icmp_events 에 수집된다.

        max_bytes: 직접 업로드 바이너리 pcap 은 기본 50 MB. 텍스트 hex 로그에서
        변환된 pcap 은 호출부에서 상향 한도를 넘겨 받는다."""
        self._icmp_events = []
        if len(data) > max_bytes:
            raise ValueError(f"입력 크기 {len(data)} 바이트가 {max_bytes // (1024 * 1024)} MB 제한 초과")
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
        import dpkt.ip6  # noqa: PLC0415  — IPv6 지원
        try:
            import dpkt.icmp6  # noqa: PLC0415
        except Exception:
            dpkt.icmp6 = None  # type: ignore

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
                eth_src_mac = _fmt_mac(eth.src)
                l3 = eth.data
                # L3: IPv4 또는 IPv6 (둘 다 지원 — 듀얼스택 캡처 손실 방지)
                if isinstance(l3, dpkt.ip.IP):
                    ip = l3
                    ip_ttl = int(ip.ttl)
                    ip_id  = int(ip.id)
                    ip_df  = bool(getattr(ip, "df", 0))
                    src_ip = socket.inet_ntoa(ip.src)
                    dst_ip = socket.inet_ntoa(ip.dst)
                elif isinstance(l3, dpkt.ip6.IP6):
                    ip = l3
                    ip_ttl = int(getattr(ip, "hlim", 0))  # IPv6 hop limit
                    ip_id  = 0                              # IPv6에는 IP ID 없음
                    ip_df  = True                           # IPv6은 라우터 단편화 없음(항상 DF)
                    src_ip = socket.inet_ntop(socket.AF_INET6, ip.src)
                    dst_ip = socket.inet_ntop(socket.AF_INET6, ip.dst)
                else:
                    continue

                l4 = ip.data
                syn_wscale = None
                if isinstance(l4, dpkt.tcp.TCP):
                    t       = l4
                    proto   = "TCP"
                    rst     = bool(t.flags & dpkt.tcp.TH_RST)
                    seq     = t.seq
                    ack_num = t.ack
                    flags_s = _tcp_flags_str(t.flags)
                    payload = bytes(t.data)
                    sport, dport = t.sport, t.dport
                    win     = int(t.win)
                    # SYN 옵션에서 window scale shift 추출 (실제 window 계산용)
                    if (t.flags & dpkt.tcp.TH_SYN) and t.opts:
                        try:
                            for otype, odata in dpkt.tcp.parse_opts(t.opts):
                                if otype == dpkt.tcp.TCP_OPT_WSCALE and odata:
                                    syn_wscale = odata[0]
                                    break
                        except Exception:
                            pass
                elif isinstance(l4, dpkt.udp.UDP):
                    t       = l4
                    proto   = "UDP"
                    rst     = False
                    seq     = 0
                    ack_num = 0
                    flags_s = ""
                    payload = bytes(t.data)
                    sport, dport = t.sport, t.dport
                    win     = 0
                elif isinstance(l4, dpkt.icmp.ICMP):
                    t       = l4
                    proto   = "ICMP"
                    rst     = False
                    seq     = 0
                    ack_num = 0
                    flags_s = f"{t.type}/{t.code}"
                    payload = bytes(t.data) if hasattr(t, "data") else b""
                    # sport/dport=0 고정: _update_flow 양방향 매칭이 Request↔Reply를 같은 flow로 묶음
                    sport, dport = 0, 0
                    win     = 0
                    # ICMP 에러 메시지 이벤트 수집 (type 3/11: 임베디드 IP 헤더 파싱)
                    if t.type in (3, 11) and hasattr(t, "data"):
                        try:
                            # dpkt ICMP 에러: t.data = 4바이트 unused + 임베디드 IP
                            inner = bytes(t.data)[4:]
                            orig_dst, orig_dst_port = _parse_icmp_embedded(inner)
                            if orig_dst:
                                self._icmp_events.append({
                                    "ts": float(ts),
                                    "src_ip": src_ip,
                                    "dst_ip": dst_ip,
                                    "orig_dst": orig_dst,
                                    "orig_dst_port": orig_dst_port,
                                    "icmp_type": t.type,
                                    "icmp_code": t.code,
                                    "label": _icmp_label(t.type, t.code),
                                })
                        except Exception:
                            pass
                elif dpkt.icmp6 is not None and isinstance(l4, dpkt.icmp6.ICMP6):
                    t       = l4
                    proto   = "ICMP6"
                    rst     = False
                    seq     = 0
                    ack_num = 0
                    flags_s = f"{t.type}/{t.code}"
                    payload = bytes(t.data) if hasattr(t, "data") else b""
                    sport, dport = 0, 0
                    win     = 0
                else:
                    continue

                pkt_len = len(buf)
                fts     = float(ts)

                flow_result = self._update_flow(
                    flow_map, fts, src_ip, dst_ip, sport, dport, proto, pkt_len, rst
                )
                if flow_result is None:
                    continue
                canonical, direction = flow_result
                # window scale는 방향별 SYN에서만 협상됨 → flow에 기록
                if syn_wscale is not None:
                    flow_map[canonical][f"wscale_{direction}"] = syn_wscale
                # 방향별 첫 관측 소스 MAC (L2 장비 식별용)
                if eth_src_mac:
                    flow_map[canonical].setdefault(f"mac_{direction}", eth_src_mac)
                self._record_packet(
                    pkt_map, canonical,
                    PacketRecord(
                        ts=fts, direction=direction, proto=proto,
                        seq=seq, ack=ack_num, flags=flags_s,
                        length=pkt_len, payload_len=len(payload),
                        payload_hex=_capture_payload_hex(payload),
                        window=win,
                        ttl=ip_ttl,
                        ip_id=ip_id,
                        df=ip_df,
                    ),
                )
            except Exception as exc:
                if parse_warnings is not None and len(parse_warnings) < _MAX_PARSE_WARNINGS:
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
                # L3: IPv4 또는 IPv6
                if pkt.haslayer(scapy.IP):
                    ip = pkt[scapy.IP]
                    ip_ver = 4
                elif pkt.haslayer(scapy.IPv6):
                    ip = pkt[scapy.IPv6]
                    ip_ver = 6
                else:
                    continue
                if pkt.haslayer(scapy.TCP):
                    t = pkt[scapy.TCP]
                    proto, rst = "TCP", bool(t.flags & 0x04)
                    sport, dport = t.sport, t.dport
                    seq, ack_num = t.seq, t.ack
                    flags_s = _tcp_flags_str(int(t.flags))
                    payload = bytes(t.payload)
                    win = int(t.window)
                elif pkt.haslayer(scapy.UDP):
                    t = pkt[scapy.UDP]
                    proto, rst = "UDP", False
                    sport, dport = t.sport, t.dport
                    seq, ack_num, flags_s = 0, 0, ""
                    payload = bytes(t.payload)
                    win = 0
                elif pkt.haslayer(scapy.ICMP):
                    t = pkt[scapy.ICMP]
                    proto, rst = "ICMP", False
                    sport, dport = 0, 0  # 고정: Request↔Reply 같은 flow로 묶음
                    seq, ack_num = 0, 0
                    flags_s = f"{t.type}/{t.code}"
                    payload = bytes(t.payload) if hasattr(t, "payload") else b""
                    win = 0
                    # ICMP 에러 이벤트 수집 (type 3/11: payload = 임베디드 IP 헤더)
                    if t.type in (3, 11):
                        try:
                            orig_dst, orig_dst_port = _parse_icmp_embedded(bytes(t.payload))
                            if orig_dst:
                                self._icmp_events.append({
                                    "ts": float(pkt.time),
                                    "src_ip": ip.src,
                                    "dst_ip": ip.dst,
                                    "orig_dst": orig_dst,
                                    "orig_dst_port": orig_dst_port,
                                    "icmp_type": t.type,
                                    "icmp_code": t.code,
                                    "label": _icmp_label(t.type, t.code),
                                })
                        except Exception:
                            pass
                else:
                    continue

                fts     = float(pkt.time)
                pkt_len = len(pkt)

                flow_result = self._update_flow(
                    flow_map, fts, ip.src, ip.dst, sport, dport, proto, pkt_len, rst
                )
                if flow_result is None:
                    continue
                canonical, direction = flow_result
                self._record_packet(
                    pkt_map, canonical,
                    PacketRecord(
                        ts=fts, direction=direction, proto=proto,
                        seq=seq, ack=ack_num, flags=flags_s,
                        length=pkt_len, payload_len=len(payload),
                        payload_hex=_capture_payload_hex(payload),
                        window=win,
                        ttl=int(ip.hlim if ip_ver == 6 else ip.ttl),
                        ip_id=int(0 if ip_ver == 6 else ip.id),
                        df=bool(True if ip_ver == 6 else (int(ip.flags) & 0x2)),
                    ),
                )
            except Exception as exc:
                if parse_warnings is not None and len(parse_warnings) < _MAX_PARSE_WARNINGS:
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
                _vlan_depth = 0
                while eth_type in _VLAN_ETHERTYPES and _vlan_depth < 4:  # QinQ 최대 4중 상한
                    if len(pkt) < l3_off + 4:
                        break
                    eth_type = struct.unpack_from("!H", pkt, l3_off + 2)[0]
                    l3_off  += 4
                    _vlan_depth += 1
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

                # 공통 IP 헤더 필드 (IPv4)
                ip_ttl = pkt[l3_off + 8]
                ip_id  = struct.unpack_from("!H", pkt, l3_off + 4)[0]
                ip_df  = bool(pkt[l3_off + 6] & 0x40)
                win    = 0

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
                        win         = struct.unpack_from("!H", pkt, t_off + 14)[0]
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
                    # ICMP 에러 이벤트 수집 (type 3/11: t_off+8부터 임베디드 IP 헤더)
                    if icmp_type in (3, 11) and len(pkt) > t_off + 8:
                        try:
                            orig_dst, orig_dst_port = _parse_icmp_embedded(pkt[t_off + 8:])
                            if orig_dst:
                                self._icmp_events.append({
                                    "ts": pkt_ts,
                                    "src_ip": src_ip,
                                    "dst_ip": dst_ip,
                                    "orig_dst": orig_dst,
                                    "orig_dst_port": orig_dst_port,
                                    "icmp_type": icmp_type,
                                    "icmp_code": icmp_code,
                                    "label": _icmp_label(icmp_type, icmp_code),
                                })
                        except Exception:
                            pass

                flow_result = self._update_flow(
                    flow_map, pkt_ts, src_ip, dst_ip, sport, dport, proto, pkt_len, rst
                )
                if flow_result is None:
                    continue
                canonical, direction = flow_result
                self._record_packet(
                    pkt_map, canonical,
                    PacketRecord(
                        ts=pkt_ts, direction=direction, proto=proto,
                        seq=seq, ack=ack_num, flags=flags_s,
                        length=pkt_len, payload_len=len(payload),
                        payload_hex=_capture_payload_hex(payload),
                        window=win, ttl=ip_ttl, ip_id=ip_id, df=ip_df,
                    ),
                )
            except (struct.error, IndexError) as exc:
                msg = f"struct packet error (offset={offset}): {type(exc).__name__}: {exc}"
                logger.warning(msg)
                if parse_warnings is not None and len(parse_warnings) < _MAX_PARSE_WARNINGS:
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
    ) -> tuple[tuple, str] | None:
        """flow_map 갱신 후 (canonical_key, direction) 반환.
        신규 플로우가 상한(_MAX_FLOW_COUNT)을 초과하면 None 반환."""
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
        elif len(flow_map) >= _MAX_FLOW_COUNT:
            return None
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
            meta: dict = {}
            if "wscale_fwd" in v:
                meta["wscale_fwd"] = v["wscale_fwd"]
            if "wscale_rev" in v:
                meta["wscale_rev"] = v["wscale_rev"]
            if "mac_fwd" in v:
                meta["mac_src"] = v["mac_fwd"]
            if "mac_rev" in v:
                meta["mac_dst"] = v["mac_rev"]
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
                meta=meta or None,
            ))
            key = (src_ip, dst_ip, src_port, dst_port, proto)
            session_pkt_map[sid] = pkt_map.get(key, [])

        return sessions, session_pkt_map
