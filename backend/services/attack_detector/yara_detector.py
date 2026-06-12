"""YARA 서명 기반 페이로드 탐지."""
import binascii
import logging
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

_RULES_FILE = Path(__file__).parent / "yara_rules.yar"


@dataclass
class YaraMatch:
    rule: str
    description: str
    severity: str
    mitre: str
    session_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    matched_strings: list[str] = field(default_factory=list)


class YaraDetector:
    def __init__(self) -> None:
        self._rules = None
        self._load_rules()

    def _load_rules(self) -> None:
        try:
            import yara
            self._rules = yara.compile(str(_RULES_FILE))
            logger.info("YARA 룰 로드 완료: %s", _RULES_FILE)
        except ImportError:
            logger.warning("yara-python 패키지 없음 — YARA 탐지 비활성화")
        except Exception as e:
            logger.error("YARA 룰 컴파일 실패: %s", e)

    @property
    def available(self) -> bool:
        return self._rules is not None

    def scan_capture(self, capture) -> list[dict]:
        """ParsedCapture의 패킷 페이로드 전체를 스캔하여 매치 목록 반환."""
        if not self._rules:
            return []

        matches: list[dict] = []
        seen: set[str] = set()

        packet_map = getattr(capture, "packet_map", {})

        for session in capture.sessions:
            sid = session.session_id
            packets = packet_map.get(sid, [])
            for pkt in packets:
                if not getattr(pkt, "payload_hex", None):
                    continue
                try:
                    data = binascii.unhexlify(pkt.payload_hex.replace(" ", ""))
                except Exception:
                    continue

                try:
                    hits = self._rules.match(data=data)
                except Exception:
                    continue

                for hit in hits:
                    key = f"{sid}:{hit.rule}"
                    if key in seen:
                        continue
                    seen.add(key)

                    meta = hit.meta or {}
                    matched_strs = []
                    for s in hit.strings[:5]:
                        try:
                            matched_strs.append(str(s).encode("utf-8", errors="replace").decode("utf-8"))
                        except Exception:
                            matched_strs.append(repr(s)[:120])

                    matches.append({
                        "rule": hit.rule,
                        "description": meta.get("description", hit.rule),
                        "severity": meta.get("severity", "medium"),
                        "mitre": meta.get("mitre", ""),
                        "session_id": sid,
                        "src_ip": session.src_ip,
                        "dst_ip": session.dst_ip,
                        "src_port": session.src_port,
                        "dst_port": session.dst_port,
                        "matched_strings": matched_strs,
                    })

                    if len(matches) >= 200:
                        return matches

        return matches
