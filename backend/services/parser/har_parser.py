"""HarParser — HAR (HTTP Archive) 형식 파서."""
import ipaddress
import json
import logging
import random
import uuid
from datetime import datetime
from urllib.parse import urlparse

from models.packet import PacketRecord
from models.session import SessionModel

logger = logging.getLogger(__name__)

# 도메인 호스트명을 매핑할 placeholder IP 베이스 (RFC2544 벤치마킹용 198.18.0.0/15,
# 라우팅되지 않는 예약 대역 → 실제 트래픽과 혼동되지 않으면서 호스트마다 고유 IP 부여 가능)
_PLACEHOLDER_BASE = int(ipaddress.ip_address("198.18.0.1"))
_PLACEHOLDER_MAX = 131070  # /15 대역 크기 한도
_PAYLOAD_CAP = 1024        # 합성 패킷 페이로드 ASCII 최대 바이트
# HAR timings 단계 (워터폴 표시용). -1 은 HAR 표준상 '해당 없음'
_TIMING_PHASES = ("blocked", "dns", "ssl", "connect", "send", "wait", "receive")


class HarParser:
    def __init__(self) -> None:
        self.packet_map: dict[str, list[PacketRecord]] = {}

    def detect(self, data: bytes) -> bool:
        try:
            text = data.decode("utf-8", errors="replace")
            if not text.strip().startswith("{"):
                return False
            obj = json.loads(text)
            return isinstance(obj.get("log"), dict) and "entries" in obj["log"]
        except (json.JSONDecodeError, UnicodeDecodeError):
            return False

    def parse(self, data: bytes, parse_warnings: list[str] | None = None) -> list[SessionModel]:
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError(f"UTF-8 디코딩 실패: {exc}") from exc

        obj = json.loads(text)
        log = obj.get("log") or {}
        if "entries" not in log:
            raise KeyError("HAR log에 'entries' 키가 없습니다")
        entries = log["entries"]

        self.packet_map = {}
        host_ip: dict[str, str] = {}  # hostname -> placeholder IP (호스트별 고유 배정)
        sessions: list[SessionModel] = []
        for i, entry in enumerate(entries):
            req = entry["request"]
            url = req.get("url", "")
            method = req.get("method", "GET")
            parsed = urlparse(url)

            host = parsed.hostname or ""
            scheme = parsed.scheme or "http"
            port = parsed.port or (443 if scheme == "https" else 80)

            # hostname이 이미 IP면 dst_ip로 직접 사용, 아니면 호스트별 고유 placeholder 배정.
            # (예전엔 모든 도메인을 203.0.113.1 하나로 합쳐 IP 순위·대화 분석이 무의미했음)
            try:
                ipaddress.ip_address(host)
                dst_ip = host
                unresolved = False
            except ValueError:
                dst_ip = self._placeholder_ip(host, host_ip)
                unresolved = True

            started = entry.get("startedDateTime", "")
            time_ms = float(entry.get("time") or 0)

            try:
                start_ts = datetime.fromisoformat(started.replace("Z", "+00:00")).timestamp()
            except (ValueError, AttributeError):
                start_ts = datetime.now().timestamp() + i * 0.001
            end_ts = start_ts + time_ms / 1000.0

            resp = entry.get("response") or {}
            req_body = max(0, req.get("bodySize") or 0)
            resp_body = max(0, resp.get("bodySize") or 0)
            session_id = str(uuid.uuid4())

            packets = self._build_packets(req, resp, parsed, host, start_ts, end_ts)
            if packets:
                self.packet_map[session_id] = packets

            timings_raw = entry.get("timings") or {}
            timings = {p: timings_raw.get(p, -1) for p in _TIMING_PHASES}
            mime = (resp.get("content") or {}).get("mimeType", "") or ""

            sessions.append(SessionModel(
                session_id=session_id,
                src_ip="127.0.0.1",
                dst_ip=dst_ip,
                src_port=random.randint(49152, 65535),
                dst_port=port,
                protocol="TCP",
                start_ts=start_ts,
                end_ts=end_ts,
                bytes_sent=req_body,
                bytes_recv=resp_body,
                packet_count=max(1, len(packets)),
                payload_length=resp_body,
                confidence="low" if unresolved else "normal",
                meta={
                    "method": method,
                    "url": url,
                    "status_code": resp.get("status") or 0,
                    "hostname": host,
                    "time_ms": round(time_ms, 1),
                    "resp_size": resp_body,
                    "mime": mime,
                    "timings": timings,
                },
            ))

        return sessions

    @staticmethod
    def _placeholder_ip(host: str, cache: dict[str, str]) -> str:
        if host in cache:
            return cache[host]
        idx = len(cache)
        if idx > _PLACEHOLDER_MAX:
            idx = idx % _PLACEHOLDER_MAX  # 극단적으로 호스트가 많으면 wrap (충돌 허용)
        ip = str(ipaddress.ip_address(_PLACEHOLDER_BASE + idx))
        cache[host] = ip
        return ip

    @staticmethod
    def _build_packets(req: dict, resp: dict, parsed, host: str, start_ts: float, end_ts: float) -> list[PacketRecord]:
        """HAR 엔트리를 요청/응답 2개의 합성 패킷으로 변환 → Flow 뷰어에서 표시 가능."""
        packets: list[PacketRecord] = []

        # ── 요청 패킷 (fwd) ──
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        http_ver = req.get("httpVersion") or "HTTP/1.1"
        lines = [f"{req.get('method', 'GET')} {path} {http_ver}"]
        if host:
            lines.append(f"Host: {host}")
        for h in req.get("headers") or []:
            name = h.get("name", "")
            if name and name.lower() != "host":
                lines.append(f"{name}: {h.get('value', '')}")
        req_text = ("\r\n".join(lines) + "\r\n\r\n")
        req_bytes = req_text.encode("utf-8", errors="replace")[:_PAYLOAD_CAP]
        packets.append(PacketRecord(
            ts=start_ts, direction="fwd", proto="TCP", seq=0, ack=0,
            flags="PSH+ACK", length=len(req_bytes), payload_len=len(req_bytes),
            payload_hex=req_bytes.hex(),
        ))

        # ── 응답 패킷 (rev) ──
        status = resp.get("status") or 0
        status_text = resp.get("statusText") or ""
        resp_ver = resp.get("httpVersion") or "HTTP/1.1"
        rlines = [f"{resp_ver} {status} {status_text}".rstrip()]
        for h in resp.get("headers") or []:
            name = h.get("name", "")
            if name:
                rlines.append(f"{name}: {h.get('value', '')}")
        resp_text = "\r\n".join(rlines) + "\r\n\r\n"
        content = resp.get("content") or {}
        body = content.get("text")
        # base64 인코딩 본문은 바이너리일 수 있어 텍스트로 붙이지 않음
        if isinstance(body, str) and content.get("encoding") != "base64":
            resp_text += body
        resp_bytes = resp_text.encode("utf-8", errors="replace")[:_PAYLOAD_CAP]
        if status or resp.get("headers"):
            packets.append(PacketRecord(
                ts=end_ts, direction="rev", proto="TCP", seq=0, ack=0,
                flags="PSH+ACK", length=len(resp_bytes), payload_len=len(resp_bytes),
                payload_hex=resp_bytes.hex(),
            ))

        return packets
