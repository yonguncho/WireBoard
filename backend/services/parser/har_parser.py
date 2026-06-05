"""HarParser — HAR (HTTP Archive) 형식 파서."""
import ipaddress
import json
import logging
import uuid
from datetime import datetime
from urllib.parse import urlparse

from models.session import SessionModel

logger = logging.getLogger(__name__)


class HarParser:
    def detect(self, data: bytes) -> bool:
        try:
            text = data.decode("utf-8", errors="replace")
            if not text.strip().startswith("{"):
                return False
            obj = json.loads(text)
            return "log" in obj
        except (json.JSONDecodeError, UnicodeDecodeError):
            return False

    def parse(self, data: bytes, parse_warnings: list[str] | None = None) -> list[SessionModel]:
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError(f"UTF-8 디코딩 실패: {exc}") from exc

        obj = json.loads(text)
        log = obj["log"]
        entries = log["entries"]

        sessions: list[SessionModel] = []
        for i, entry in enumerate(entries):
            req = entry["request"]
            url = req.get("url", "")
            method = req.get("method", "GET")
            parsed = urlparse(url)

            host = parsed.hostname or ""
            scheme = parsed.scheme or "http"
            port = parsed.port or (443 if scheme == "https" else 80)

            # hostname이 이미 IPv4면 dst_ip로 직접 사용, 아니면 placeholder
            try:
                ipaddress.ip_address(host)
                dst_ip = host
            except ValueError:
                dst_ip = "203.0.113.1"  # RFC 5737 TEST-NET-3 placeholder for unresolvable hosts

            started = entry.get("startedDateTime", "")
            time_ms = float(entry.get("time") or 0)

            try:
                start_ts = datetime.fromisoformat(started.replace("Z", "+00:00")).timestamp()
            except (ValueError, AttributeError):
                start_ts = float(1_748_000_000 + i)

            resp = entry.get("response", {})
            sessions.append(SessionModel(
                session_id=str(uuid.uuid4()),
                src_ip="127.0.0.1",
                dst_ip=dst_ip,
                src_port=(50000 + i) % 65536,
                dst_port=port,
                protocol="TCP",
                start_ts=start_ts,
                end_ts=start_ts + time_ms / 1000.0,
                bytes_sent=max(0, req.get("bodySize") or 0),
                bytes_recv=max(0, resp.get("bodySize") or 0),
                packet_count=1,
                payload_length=max(0, resp.get("bodySize") or 0),
                confidence="normal",
                meta={"method": method, "url": url, "status_code": resp.get("status") or 0, "hostname": host},
            ))

        return sessions
