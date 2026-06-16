"""raw_pcap_converter — FortiGate/tcpdump verbose hex dump → pcap 변환기.

FortiGate `diagnose sniffer packet ... 6` (verbose 6) 또는 tcpdump `-X`/`-XX`
출력처럼 패킷 요약 줄 + 16진수 덤프(`0xNNNN ...`)로 구성된 원본 텍스트 로그를
표준 libpcap(.pcap) 바이트로 변환한다.

설계 메모
- 요약 줄(타임스탬프로 시작)이 새 패킷 블록의 경계 역할을 한다.
- 각 `0xNNNN` 줄에서 16진수만 추출하여 패킷 바이트를 복원한다.
- 첫 패킷을 보고 link-layer 타입을 추정한다(이더넷 vs raw IP).
- 16진수가 전혀 없으면(요약만 있는 verbose 1~3) None 을 반환한다.
"""
import logging
import re
import struct
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# pcap link type (출력은 항상 이더넷)
LINKTYPE_ETHERNET = 1

# 요약 줄: FortiGate 절대 타임스탬프 "YYYY-MM-DD HH:MM:SS.ffffff"
_FORTI_TS_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+)")
# 요약 줄: tcpdump 시간 전용 "HH:MM:SS.ffffff "
_TCPDUMP_TS_RE = re.compile(r"^(\d{2}:\d{2}:\d{2}\.\d+)\s")
# 요약 줄: tcpdump unix epoch "1710766911.308714 "
_EPOCH_TS_RE = re.compile(r"^(\d{9,}\.\d+)\s")

# 16진수 덤프 줄: "0xNNNN" 또는 "0xNNNN:" 접두사
_HEX_PREFIX_RE = re.compile(r"^0x[0-9a-fA-F]+:?\s+")
_HEX_GROUP_RE = re.compile(r"^[0-9a-fA-F]+$")


def _parse_timestamp(summary: str) -> float | None:
    """요약 줄에서 epoch(float) 타임스탬프 추출. 실패 시 None."""
    m = _FORTI_TS_RE.match(summary)
    if m:
        try:
            dt = datetime.strptime(m.group(1).strip(), "%Y-%m-%d %H:%M:%S.%f")
            return dt.replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            return None
    m = _EPOCH_TS_RE.match(summary)
    if m:
        try:
            return float(m.group(1))
        except ValueError:
            return None
    m = _TCPDUMP_TS_RE.match(summary)
    if m:
        # 날짜 정보 없음 → 자정 기준 초로 환산 (상대 순서만 보존)
        try:
            hms, frac = m.group(1).split(".")
            h, mm, s = (int(x) for x in hms.split(":"))
            usec = int((frac + "000000")[:6])
            return h * 3600 + mm * 60 + s + usec / 1e6
        except ValueError:
            return None
    return None


def _is_summary_line(line: str) -> bool:
    return bool(
        _FORTI_TS_RE.match(line)
        or _TCPDUMP_TS_RE.match(line)
        or _EPOCH_TS_RE.match(line)
    )


def _extract_hex(line: str) -> bytes | None:
    """`0xNNNN ...` 덤프 줄에서 패킷 바이트 추출. 덤프 줄이 아니면 None."""
    s = line.rstrip("\n")
    m = _HEX_PREFIX_RE.match(s.lstrip())
    if not m:
        return None
    body = s.lstrip()[m.end():]
    # FortiGate: 탭이 16진수와 ASCII를 구분. tcpdump: 2칸 이상 공백이 구분.
    if "\t" in body:
        body = body.split("\t", 1)[0]
    else:
        body = re.split(r" {2,}", body, maxsplit=1)[0]
    out = bytearray()
    for grp in body.split():
        if _HEX_GROUP_RE.match(grp) and len(grp) % 2 == 0:
            out += bytes.fromhex(grp)
        else:
            break  # ASCII 영역 침범 → 중단
    return bytes(out) if out else b""


def _is_raw_ip(pkt: bytes) -> bool:
    """패킷이 이더넷 헤더 없는 raw IP 데이터그램인지 헤더 정합성으로 판정.

    오프셋 12~13의 ethertype만 보면 src IP가 8.0.x.x(=0x0800) 같은 경우
    raw IPv4를 이더넷으로 오판한다. IP 헤더 자체의 version·IHL·total_length
    정합성을 검사해 이를 피한다. 이더넷 프레임은 선두 12바이트가 MAC이라
    유효한 IP 헤더를 이룰 확률이 거의 없다.
    """
    if len(pkt) < 20:
        return False
    ver = pkt[0] >> 4
    if ver == 4:
        ihl = (pkt[0] & 0x0F) * 4
        if ihl < 20 or ihl > len(pkt):
            return False
        total_len = int.from_bytes(pkt[2:4], "big")
        # total_length 는 최소 헤더 길이 이상(캡처 잘림으로 len 초과 가능)
        return total_len >= ihl
    if ver == 6 and len(pkt) >= 40:
        return True
    return False


def _iter_blocks(text: str):
    """(timestamp, packet_bytes) 블록을 순서대로 yield."""
    cur_ts: float | None = None
    cur_buf = bytearray()
    have_block = False

    for line in text.splitlines():
        if _is_summary_line(line):
            if have_block and cur_buf:
                yield (cur_ts if cur_ts is not None else 0.0, bytes(cur_buf))
            cur_ts = _parse_timestamp(line)
            cur_buf = bytearray()
            have_block = True
            continue
        if not have_block:
            continue
        hx = _extract_hex(line)
        if hx:
            cur_buf += hx
    if have_block and cur_buf:
        yield (cur_ts if cur_ts is not None else 0.0, bytes(cur_buf))


def build_pcap(packets: list[tuple[float, bytes]], linktype: int) -> bytes:
    """(ts, data) 리스트 → libpcap(.pcap) 바이트."""
    out = bytearray()
    out += struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype)
    for ts, data in packets:
        sec = int(ts)
        usec = int(round((ts - sec) * 1e6))
        if usec >= 1_000_000:
            sec += 1
            usec -= 1_000_000
        if usec < 0:
            usec = 0
        out += struct.pack("<IIII", sec & 0xFFFFFFFF, usec, len(data), len(data))
        out += data
    return bytes(out)


# 합성 이더넷 헤더(dst/src MAC = 00:..:00). raw IP 패킷을 이더넷으로 감쌀 때 사용.
_FAKE_ETH = b"\x00" * 12


def _wrap_raw_ip(pkt: bytes) -> bytes:
    """raw IP 패킷에 합성 이더넷 헤더를 붙여 이더넷 프레임으로 변환."""
    ethertype = b"\x86\xdd" if (pkt and (pkt[0] >> 4) == 6) else b"\x08\x00"
    return _FAKE_ETH + ethertype + pkt


def convert_raw_log_to_pcap(data: bytes) -> tuple[bytes, int] | None:
    """원본 텍스트 로그 → (pcap_bytes, packet_count). 16진수 덤프가 없으면 None.

    항상 LINKTYPE_ETHERNET pcap을 생성한다. tcpdump -X 처럼 raw IP 덤프인 경우
    합성 이더넷 헤더를 붙여 표준 pcap 도구·내부 PcapParser가 모두 읽을 수 있게 한다.
    """
    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        return None

    packets = [(ts, pkt) for ts, pkt in _iter_blocks(text) if pkt]
    if not packets:
        return None

    # 패킷별로 raw IP 여부를 판정해 raw IP 만 합성 이더넷으로 감싼다.
    # (첫 패킷만으로 전체를 판정하던 기존 로직은 혼재·오판에 취약했다)
    packets = [(ts, _wrap_raw_ip(pkt) if _is_raw_ip(pkt) else pkt) for ts, pkt in packets]

    pcap_bytes = build_pcap(packets, LINKTYPE_ETHERNET)
    return pcap_bytes, len(packets)
