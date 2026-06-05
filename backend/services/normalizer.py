"""SessionNormalizer — 파서 출력을 정규화·중복 제거."""
import uuid
from collections import defaultdict

from models.session import SessionModel


class SessionNormalizer:
    def normalize(self, sessions: list[SessionModel]) -> list[SessionModel]:
        """같은 4-tuple을 하나의 세션으로 합친다.

        FortiGate verbose3 출력처럼 src_port=0/dst_port=0인 세션은
        병합하면 비컨 타이밍이 파괴되므로 session_id로 고유 키를 부여해
        개별 세션을 그대로 보존한다.
        """
        groups: dict[tuple, list[SessionModel]] = defaultdict(list)
        for s in sessions:
            if s.src_port == 0 and s.dst_port == 0:
                key = (s.src_ip, s.dst_ip, s.src_port, s.dst_port, s.protocol, s.session_id)
            else:
                key = (s.src_ip, s.dst_ip, s.src_port, s.dst_port, s.protocol, None)
            groups[key].append(s)

        result: list[SessionModel] = []
        for key, group in groups.items():
            src_ip, dst_ip, src_port, dst_port, proto, _ = key
            start_ts = min(s.start_ts for s in group)
            end_ts = max(s.end_ts for s in group)
            bytes_sent = sum(s.bytes_sent for s in group)
            bytes_recv = sum(s.bytes_recv for s in group)
            packet_count = sum(s.packet_count for s in group)
            payload_length = sum(s.payload_length for s in group)
            rst = any(s.rst for s in group)
            confidence = "low" if any(s.confidence == "low" for s in group) else "normal"
            meta = group[0].meta

            result.append(SessionModel(
                session_id=str(uuid.uuid4()),
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=proto,
                start_ts=start_ts,
                end_ts=end_ts,
                bytes_sent=bytes_sent,
                bytes_recv=bytes_recv,
                packet_count=packet_count,
                payload_length=payload_length,
                confidence=confidence,
                rst=rst,
                meta=meta,
            ))

        return result
