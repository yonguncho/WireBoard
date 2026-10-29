"""raw_pcap_converter — FortiGate/tcpdump verbose hex dump → pcap 변환기.

FortiGate `diagnose sniffer packet ... 2/3/5/6` 또는 tcpdump `-X`/`-XX` 출력처럼
패킷 헤더 줄 + 16진수 덤프(`0xNNNN ...`)로 구성된 원본 텍스트 로그를 libpcap 으로 변환한다.
규칙은 웹 도구 `web/sniffer2pcap/converter.js` 와 같다.

설계 메모
- 패킷 경계는 오프셋 0x0000 hex 줄. 헤더 줄은 다음 패킷의 시각만 제공한다.
- 오프셋이 끊기면(줄 유실) 그 패킷은 버린다. 추측으로 이어붙이지 않는다.
- 링크타입은 패킷 바이트로 판정한다(Fortinet: verbose 3/6 은 이더넷부터·가능한 경우, 2/5 는 IP부터).
- 결과는 두 가지:
  * internal_pcap — WireBoard 내부 재파싱용. PcapParser 가 이더넷만 읽으므로 raw IP 는
    0 MAC 이더넷으로 감싼다. **사용자에게 내보내지 않는다.**
  * export_pcap   — 다운로드용. 전부 이더넷이면 LINKTYPE_ETHERNET, 아니면 LINKTYPE_RAW(101)로
    이더넷 헤더를 벗기고 비IP 프레임은 뺀다. 가짜 MAC 없음.
- 16진수가 전혀 없으면(헤더만 있는 verbose 1/4) None.
"""
import logging
import re
import struct
from dataclasses import dataclass
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
_SNAPLEN = 262144

_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b[()][A-Za-z0-9]|\x1b[=>]")
_LINE_PREFIX_RE = re.compile(r"^\[[^\]]{4,40}\]\s?")   # SecureCRT 등 줄 앞 타임스탬프
_CMD_RE = re.compile(r"\bdiag\w*\s+sni\w*\s+pac\w*\s+(\S+)(?:\s+('[^']*'|\"[^\"]*\"|\S+))?(?:\s+(\d))?", re.I)

# 헤더 줄 타임스탬프
_FORTI_ABS_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})\.(\d{1,9})\s+(.*)$")
_EPOCH_TS_RE = re.compile(r"^(\d{9,})\.(\d{1,9})\s")                 # tcpdump -tt
_FORTI_REL_RE = re.compile(r"^(\d{1,8})\.(\d{1,9})\s+(.*)$")        # FortiGate 상대시간
_TCPDUMP_TS_RE = re.compile(r"^(\d{2}):(\d{2}):(\d{2})\.(\d{1,9})\s")  # tcpdump 시각만
_IFACE_RE = re.compile(r"^\S+\s+(?:in|out|--)\s+")
_PKT_DESC_RE = re.compile(r"->|\barp\b|who-has|\b802\.1q\b|\bllc\b|\bstp\b", re.I)

_HEX_LINE_RE = re.compile(r"^0x([0-9a-fA-F]{4,8}):?[\t ]+(.*)$")
_HEX_TOKEN_RE = re.compile(r"^[0-9a-fA-F]+$")
_ASCII_SEP_RE = re.compile(r"\t| {2,}")

_KNOWN_ETHERTYPES = {0x0800, 0x86DD, 0x0806, 0x8035, 0x8100, 0x88A8, 0x8847, 0x8848,
                     0x8863, 0x8864, 0x88CC, 0x888E, 0x8809}


@dataclass
class RawConversion:
    internal_pcap: bytes
    export_pcap: bytes
    export_linktype: int
    packet_count: int


@dataclass
class _Pkt:
    sec: int
    usec: int
    data: bytes
    kind: str          # eth | ip | unknown
    ip_offset: int     # IP 헤더 시작 (eth 비IP 는 -1)
    wire_len: int
    ambiguous: bool


def _decode(data: bytes) -> str:
    if data[:2] == b"\xff\xfe":
        return data[2:].decode("utf-16-le", errors="replace")
    if data[:2] == b"\xfe\xff":
        return data[2:].decode("utf-16-be", errors="replace")
    return data.decode("utf-8", errors="replace")


def _clean(line: str) -> str:
    s = _ANSI_RE.sub("", line) if "\x1b" in line else line
    s = s.strip()
    if s.startswith("["):
        s = _LINE_PREFIX_RE.sub("", s).strip()
    return s


def _usec(frac: str) -> int:
    return int((frac + "000000")[:6])


def _parse_header(s: str) -> tuple[int, int] | None:
    """헤더 줄이면 (sec, usec). 아니면 None."""
    m = _FORTI_ABS_RE.match(s)
    if m:
        try:
            dt = datetime.strptime(f"{m.group(1)} {m.group(2)}", "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return None
        return int(dt.replace(tzinfo=timezone.utc).timestamp()), _usec(m.group(3))
    m = _EPOCH_TS_RE.match(s)
    if m:
        return int(m.group(1)), _usec(m.group(2))
    m = _FORTI_REL_RE.match(s)
    if m:
        rest = m.group(3)
        # 숫자로 시작하는 잡음과 구분: 패킷 설명처럼 보일 때만 헤더로 인정
        if _IFACE_RE.match(rest) or _PKT_DESC_RE.search(rest):
            return int(m.group(1)), _usec(m.group(2))
        return None
    m = _TCPDUMP_TS_RE.match(s)
    if m:
        # 날짜 정보 없음 → 자정 기준 초 (상대 순서만 보존)
        h, mm, sec = int(m.group(1)), int(m.group(2)), int(m.group(3))
        return h * 3600 + mm * 60 + sec, _usec(m.group(4))
    return None


def _parse_hex_body(body: str) -> tuple[list[int], bool]:
    """hex 줄 본문 → (bytes, partial). ASCII 열은 탭/2칸+ 공백으로 구분, hex 영역은 최대 39자."""
    cut = _ASCII_SEP_RE.search(body)
    hex_part = (body[:cut.start()] if cut else body)[:39]
    out: list[int] = []
    partial = False
    for tok in hex_part.split(" "):
        if not tok:
            continue
        if not _HEX_TOKEN_RE.match(tok) or len(tok) > 4:
            break
        if len(tok) % 2:
            partial = True
            break
        out += bytes.fromhex(tok)
        if len(tok) == 2 or len(out) >= 16:
            break
    return out, partial


def _ip_length(d: bytes, o: int, version: int = 0) -> int:
    if len(d) - o < 20:
        return 0
    v = d[o] >> 4
    if version and v != version:
        return 0
    if v == 4:
        ihl = (d[o] & 0x0F) * 4
        if ihl < 20:
            return 0
        tl = int.from_bytes(d[o + 2:o + 4], "big")
        return tl if tl >= ihl else 0
    if v == 6 and len(d) - o >= 40:
        return 40 + int.from_bytes(d[o + 4:o + 6], "big")
    return 0


def _classify(d: bytes, prefer_ip: bool = False) -> tuple[str, int, int, int, bool]:
    """→ (kind, ip_offset, ip_end, wire_len, ambiguous)."""
    eth_hdr, eth_type, eth_ip_len = 0, -1, 0
    if len(d) >= 14:
        o = 12
        eth_type = int.from_bytes(d[12:14], "big")
        while eth_type in (0x8100, 0x88A8) and len(d) >= o + 6:
            o += 4
            eth_type = int.from_bytes(d[o:o + 2], "big")
        eth_hdr = o + 2
        if eth_type == 0x0800:
            eth_ip_len = _ip_length(d, eth_hdr, 4)
        elif eth_type == 0x86DD:
            eth_ip_len = _ip_length(d, eth_hdr, 6)
    raw_ip_len = _ip_length(d, 0)
    if prefer_ip and raw_ip_len:
        return "ip", 0, raw_ip_len, max(len(d), raw_ip_len), False
    if eth_ip_len:
        end = eth_hdr + eth_ip_len
        return "eth", eth_hdr, end, max(len(d), end), bool(raw_ip_len)
    if raw_ip_len:
        return "ip", 0, raw_ip_len, max(len(d), raw_ip_len), False
    if eth_type in _KNOWN_ETHERTYPES:
        return "eth", -1, 0, len(d), False
    return "unknown", -1, 0, len(d), False


def _iter_packets(text: str):
    """(sec, usec, bytes, last_line_odd) 를 순서대로 yield. 유실·조각 패킷은 건너뛴다."""
    pending = None           # 다음 hex 블록에 붙일 (sec, usec)
    cur: dict | None = None
    for raw in text.splitlines():
        s = _clean(raw)
        if not s:
            continue
        hm = _HEX_LINE_RE.match(s)
        if hm:
            off = int(hm.group(1), 16)
            data, partial = _parse_hex_body(hm.group(2))
            if off == 0:
                if cur and not cur["bad"] and cur["buf"]:
                    yield cur["ts"][0], cur["ts"][1], bytes(cur["buf"]), cur["odd"]
                cur = {"ts": pending, "buf": bytearray(), "bad": pending is None, "partial": False, "odd": False}
                pending = None
            elif cur is None:
                continue  # 로그가 패킷 중간에서 시작
            if cur["bad"]:
                continue
            if off != len(cur["buf"]) or cur["partial"]:
                cur["bad"] = True  # hex 줄 유실 또는 중간 줄 잘림 → 패킷 폐기
                continue
            cur["buf"] += bytes(data)
            cur["partial"] = partial
            cur["odd"] = len(data) % 2 == 1
            continue
        hdr = _parse_header(s)
        if hdr is not None:
            if cur and not cur["bad"] and cur["buf"]:
                yield cur["ts"][0], cur["ts"][1], bytes(cur["buf"]), cur["odd"]
            cur = None
            pending = hdr
    if cur and not cur["bad"] and cur["buf"]:
        yield cur["ts"][0], cur["ts"][1], bytes(cur["buf"]), cur["odd"]


def _verbose_hint(text: str) -> int | None:
    for line in text.splitlines()[:200]:
        m = _CMD_RE.search(line)
        if m and m.group(3):
            return int(m.group(3))
    return None


def _build(records: list[tuple[int, int, bytes, int]], linktype: int) -> bytes:
    out = bytearray(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, _SNAPLEN, linktype))
    for sec, usec, data, wire_len in records:
        out += struct.pack("<IIII", sec & 0xFFFFFFFF, usec, len(data), wire_len)
        out += data
    return bytes(out)


def build_pcap(packets: list[tuple[float, bytes]], linktype: int) -> bytes:
    """(ts, data) 리스트 → libpcap(.pcap) 바이트. (기존 공개 API 유지)"""
    recs = []
    for ts, data in packets:
        sec = int(ts)
        usec = min(999_999, max(0, int(round((ts - sec) * 1e6))))
        recs.append((sec, usec, data, len(data)))
    return _build(recs, linktype)


def convert_raw_log(data: bytes) -> RawConversion | None:
    """원본 텍스트 로그 → RawConversion. 16진수 덤프가 없으면 None."""
    try:
        text = _decode(data)
    except Exception:
        return None
    if "\r" in text:
        text = text.replace("\r\n", "\n").replace("\r", "\n")

    verbose = _verbose_hint(text)
    prefer_ip = verbose in (2, 5)
    pkts: list[_Pkt] = []
    for sec, usec, d, odd in _iter_packets(text):
        kind, ip_off, ip_end, wire, amb = _classify(d, prefer_ip)
        # 마지막 줄이 2자리 토큰으로 끝났는데 IP 길이 밖이면 ASCII 열을 hex 로 읽은 것 → 버림
        if odd and ip_end and len(d) > ip_end:
            d = d[:-1]
            kind, ip_off, ip_end, wire, amb = _classify(d, prefer_ip)
        pkts.append(_Pkt(sec, usec, d, kind, ip_off, wire, amb))
    if not pkts:
        return None

    # 이더넷/IP 둘 다로 읽히는 패킷은 확실한 패킷들의 다수결로 정한다
    sure_eth = sum(1 for p in pkts if p.kind == "eth" and not p.ambiguous)
    sure_ip = sum(1 for p in pkts if p.kind == "ip")
    if sure_ip > sure_eth:
        for p in pkts:
            if p.ambiguous:
                p.kind, p.ip_offset, _, p.wire_len, p.ambiguous = _classify(p.data, True)

    # 내부 재파싱용: raw IP 를 0 MAC 이더넷으로 감쌈 (내보내지 않음)
    internal = []
    for p in pkts:
        if p.kind == "ip":
            et = b"\x86\xdd" if (p.data[0] >> 4) == 6 else b"\x08\x00"
            internal.append((p.sec, p.usec, b"\x00" * 12 + et + p.data, p.wire_len + 14))
        else:
            internal.append((p.sec, p.usec, p.data, p.wire_len))

    # 다운로드용: 가짜 MAC 없음
    if not any(p.kind == "ip" for p in pkts):
        export_lt = LINKTYPE_ETHERNET
        export = [(p.sec, p.usec, p.data, p.wire_len) for p in pkts]
    else:
        export_lt = LINKTYPE_RAW
        export = []
        for p in pkts:
            if p.kind == "ip":
                export.append((p.sec, p.usec, p.data, p.wire_len))
            elif p.kind == "eth" and p.ip_offset >= 0:
                export.append((p.sec, p.usec, p.data[p.ip_offset:], p.wire_len - p.ip_offset))
        dropped = len(pkts) - len(export)
        if dropped:
            logger.info("raw→pcap 내보내기: 이더넷 헤더 없는 패킷이 섞여 RAW IP 로 저장, 비IP %d개 제외", dropped)

    return RawConversion(_build(internal, LINKTYPE_ETHERNET), _build(export, export_lt), export_lt, len(pkts))


def convert_raw_log_to_pcap(data: bytes) -> tuple[bytes, int] | None:
    """(내부 재파싱용 pcap, 패킷 수). 항상 LINKTYPE_ETHERNET. (기존 공개 API 유지)"""
    conv = convert_raw_log(data)
    return None if conv is None else (conv.internal_pcap, conv.packet_count)
