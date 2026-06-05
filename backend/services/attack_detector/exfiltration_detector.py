"""ExfiltrationDetector — T1041 데이터 유출 탐지."""
import ipaddress
from collections import defaultdict

from models.session import SessionModel
from services.attack_detector.base import AttackResult

_MB = 1_048_576
_BYTES_HIGH = 500 * _MB
_BYTES_MEDIUM = 100 * _MB
_CONN_HIGH = 20
_CONN_MEDIUM = 5

_RFC1918 = [
    ipaddress.ip_network("10.0.0.1/8", strict=False),
    ipaddress.ip_network("172.16.0.1/12", strict=False),
    ipaddress.ip_network("192.168.0.1/16", strict=False),
]

_SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3}


def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _RFC1918)
    except ValueError:
        return False


def _rank(s: str) -> int:
    return _SEVERITY_RANK.get(s, 0)


class ExfiltrationDetector:
    def detect(self, sessions: list[SessionModel]) -> AttackResult | None:
        if not sessions:
            return None

        by_src: dict[str, list[SessionModel]] = defaultdict(list)
        for s in sessions:
            if not _is_private(s.dst_ip):
                by_src[s.src_ip].append(s)

        best: AttackResult | None = None

        for src_ip, grp in by_src.items():
            connections = len(grp)
            bytes_out = sum(s.bytes_sent for s in grp)

            if connections > _CONN_HIGH or bytes_out > _BYTES_HIGH:
                severity = "high"
            elif connections > _CONN_MEDIUM and bytes_out > _BYTES_MEDIUM:
                severity = "medium"
            else:
                continue

            result = AttackResult(
                attack_type="Exfiltration",
                severity=severity,
                mitre_id="T1041",
                description=f"{src_ip}: {connections}개 외부 연결, {bytes_out // _MB} MB 전송",
            )

            if any(s.confidence == "low" for s in grp):
                result = result.downgrade()

            if best is None or _rank(result.severity) > _rank(best.severity):
                best = result

        return best
