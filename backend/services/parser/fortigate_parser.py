"""FortigateParser — FortiGate `diagnose sniffer packet` 헤더 줄 파서 (verbose 1~6).

hex 덤프가 있는 로그는 upload 에서 raw_pcap_converter 로 pcap 변환 후 재파싱하므로,
이 파서는 hex 없는 로그(verbose 1/4)와 변환 실패 시의 요약 세션을 담당한다.

헤더 줄 형식 (FortiOS):
  <ts> [<iface> <in|out|-->] <src>[.<sport>] -> <dst>[.<dport>]: <설명>
  ts   : 절대 "2026-06-04 10:00:00.123456" (a/l 옵션) 또는 상대 "3.462208"
  설명 : TCP 는 플래그+순번("syn 1000", "psh 1001 ack 5001"), UDP 는 "udp <길이>",
         ICMP 는 "icmp: echo request". 일부 도구 출력의 "tcp <길이>" 형식도 받는다.
"""
import ipaddress
import logging
import os
import re
import uuid
from datetime import datetime, timedelta, timezone

from models.session import SessionModel

logger = logging.getLogger(__name__)

# FortiGate sniffer 타임스탬프는 장비 로컬 타임존으로 찍힌다(로그에 TZ 정보 없음).
# 기본은 UTC 가정이지만, WIREBOARD_LOG_TZ_OFFSET(시간 단위, 예: 9 또는 -5)로
# 장비 타임존을 지정하면 UTC로 정규화한다. 파싱 실패는 무시(UTC 유지).
try:
    _LOG_TZ_OFFSET_H = float(os.environ.get("WIREBOARD_LOG_TZ_OFFSET", "0") or "0")
except ValueError:
    _LOG_TZ_OFFSET_H = 0.0
_LOG_TZ = timezone(timedelta(hours=_LOG_TZ_OFFSET_H))

_LINE_RE = re.compile(
    r"^(?:(?P<abs>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+)|(?P<rel>\d{1,8}\.\d+))"  # timestamp
    r"\s+(?:(?P<iface>\S+)\s+(?:in|out|--)\s+)?"                                      # [iface dir]
    r"(?P<src>[0-9A-Fa-f:.]+?)\s*->\s*(?P<dst>[0-9A-Fa-f:.]+?):\s+"                  # src -> dst:
    r"(?P<rest>\S.*)$"
)

# 단순 형식: IP:port -> IP:port proto (타임스탬프 없음)
# 예: "192.168.1.1:1234 -> 10.0.0.1:80 tcp"
_SIMPLE_LINE_RE = re.compile(
    r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)"                 # src_ip:src_port
    r"\s*->\s*"
    r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)"                  # dst_ip:dst_port
    r"\s+(\w+)"                                                      # proto
)

# 단순 형식 detect 정규식
_DETECT_SIMPLE_RE = re.compile(
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+\s*->\s*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+\s+\w+",
)

# 터미널 로그 잡음: ANSI 색 코드, SecureCRT 등의 줄 앞 "[..] " 타임스탬프
_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
_LINE_PREFIX_RE = re.compile(r"^\[[^\]]{4,40}\]\s?")

_TCP_FLAGS = {"syn", "ack", "fin", "rst", "psh", "urg", "ece", "cwr"}
_IP_PROTO_NAMES = {47: "GRE", 50: "ESP", 51: "AH", 132: "SCTP", 2: "IGMP"}
_DETECT_MAX_LINES = 500  # 터미널 로그 앞부분 잡음(배너·명령 출력)이 길어도 감지되게


def _clean(line: str) -> str:
    s = _ANSI_RE.sub("", line).strip()
    if s.startswith("["):
        s = _LINE_PREFIX_RE.sub("", s).strip()
    return s


def _split_addr(token: str) -> tuple[str, int] | None:
    """'10.0.0.1.443' / '10.0.0.1' / '2001:db8::1.546' → (ip, port). 실패 시 None."""
    try:
        return str(ipaddress.ip_address(token)), 0
    except ValueError:
        pass
    head, sep, tail = token.rpartition(".")
    if not sep or not tail.isdigit():
        return None
    try:
        ip = str(ipaddress.ip_address(head))
    except ValueError:
        return None
    port = int(tail)
    return (ip, port) if port <= 65535 else None


def _classify(rest: str) -> tuple[str, int] | None:
    """헤더 설명 → (프로토콜, 페이로드 길이). TCP 플래그 줄의 숫자는 순번이라 길이로 쓰지 않는다."""
    low = rest.lower()
    if low.startswith("icmp6") or low.startswith("icmp:"):
        return ("ICMP6" if low.startswith("icmp6") else "ICMP"), 0
    words = low.replace(",", " ").split()
    if not words:
        return None
    if words[0] in _TCP_FLAGS:
        return "TCP", 0
    # "ip-proto-50 72" — ESP/AH/GRE 등 포트 없는 IP 프로토콜
    m = re.match(r"^ip-proto-(\d+)(?:\s+(\d+))?", low)
    if m:
        num = int(m.group(1))
        return _IP_PROTO_NAMES.get(num, f"IP-PROTO-{num}"), int(m.group(2) or 0)
    m = re.match(r"^(\w+)\s+(\d+)", rest)
    if m:
        return m.group(1).upper(), int(m.group(2))
    return None


class FortigateParser:
    """FortiGate sniffer verbose 1~6 헤더 파서 (FortiGateParser 별칭 지원)."""
    def detect(self, data: bytes) -> bool:
        try:
            text = data[:262144].decode("utf-8-sig", errors="replace")
        except UnicodeDecodeError:
            return False
        for line in text.splitlines()[:_DETECT_MAX_LINES]:
            s = _clean(line)
            if _DETECT_SIMPLE_RE.search(s):
                return True
            m = _LINE_RE.match(s)
            # 정규식 모양만이 아니라 주소·설명까지 실제로 해석돼야 FortiGate 로 인정
            # ("1.0 add -> bad: x" 같은 문장이 감지돼 tcpdump 파서 기회를 뺏던 오탐 방지)
            if m and _split_addr(m.group("src")) and _split_addr(m.group("dst")) and _classify(m.group("rest")):
                return True
        return False

    def parse(self, data: bytes, parse_warnings: list[str] | None = None) -> list[SessionModel]:
        try:
            text = data.decode("utf-8-sig", errors="replace")
        except UnicodeDecodeError as exc:
            raise ValueError(f"UTF-8 디코딩 실패: {exc}") from exc

        sessions: list[SessionModel] = []
        now_ts = datetime.now(tz=timezone.utc).timestamp()
        for line in text.splitlines():
            stripped = _clean(line)
            m = _LINE_RE.match(stripped)
            if m:
                src = _split_addr(m.group("src"))
                dst = _split_addr(m.group("dst"))
                cls = _classify(m.group("rest"))
                if src is None or dst is None or cls is None:
                    continue
                (src_ip, src_port), (dst_ip, dst_port) = src, dst
                proto, payload_len = cls

                if m.group("abs"):
                    try:
                        # 로그 시각을 장비 타임존으로 해석 후 UTC epoch로 변환
                        # %f 는 6자리까지 — 나노초(9자리) 타임스탬프는 잘라서 해석
                        base, frac = m.group("abs").strip().rsplit(".", 1)
                        dt = datetime.strptime(f"{base}.{frac[:6]}", "%Y-%m-%d %H:%M:%S.%f").replace(tzinfo=_LOG_TZ)
                        start_ts = dt.timestamp()
                    except ValueError:
                        start_ts = now_ts
                else:
                    # 상대시간(캡처 시작부터 초) — 절대 시각 정보가 없으므로 그대로 둔다
                    start_ts = float(m.group("rel"))

                # TCP 플래그 줄: 포트가 있으면 normal (길이 정보는 원래 없음)
                # "<proto> <길이>" 줄: 길이 0 이면 verbose 정보 부족으로 low
                # ICMP: 포트 개념이 없으므로 normal
                if proto in ("ICMP", "ICMP6"):
                    confidence = "normal"
                elif src_port == 0 or dst_port == 0:
                    confidence = "low"
                elif proto == "TCP" and payload_len == 0 and m.group("rest").split()[0].lower() in _TCP_FLAGS:
                    confidence = "normal"
                else:
                    confidence = "low" if payload_len == 0 else "normal"

                sessions.append(SessionModel(
                    session_id=str(uuid.uuid4()),
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=proto,
                    start_ts=start_ts,
                    end_ts=start_ts,
                    bytes_sent=0,
                    bytes_recv=0,
                    packet_count=1,
                    payload_length=payload_len if confidence == "normal" else 0,
                    confidence=confidence,
                ))
                continue

            # 단순 형식: IP:port -> IP:port proto
            sm = _SIMPLE_LINE_RE.match(stripped)
            if sm:
                src_ip, src_port_str, dst_ip, dst_port_str, proto_str = sm.groups()
                src_port = int(src_port_str)
                dst_port = int(dst_port_str)

                try:
                    ipaddress.ip_address(src_ip)
                    ipaddress.ip_address(dst_ip)
                except ValueError:
                    continue

                if not (0 <= src_port <= 65535 and 0 <= dst_port <= 65535):
                    continue

                sessions.append(SessionModel(
                    session_id=str(uuid.uuid4()),
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=proto_str.upper(),
                    start_ts=now_ts,
                    end_ts=now_ts,
                    bytes_sent=0,
                    bytes_recv=0,
                    packet_count=1,
                    payload_length=0,
                    confidence="normal",
                ))

        return sessions


# 별칭 — PascalCase 형식 import 지원
FortiGateParser = FortigateParser
