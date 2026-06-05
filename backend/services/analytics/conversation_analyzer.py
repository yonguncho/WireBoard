"""ConversationAnalyzer — Panel 9: IP 대화 분석."""
from collections import defaultdict
from dataclasses import dataclass, field

from models.session import SessionModel
from utils.net_utils import is_private as _is_private


@dataclass
class ConversationResult:
    top_conversations: list = field(default_factory=list)
    inbound_bytes: int = 0
    outbound_bytes: int = 0


class ConversationAnalyzer:
    def analyze(
        self, sessions: list[SessionModel], target_ip: str | None = None
    ) -> ConversationResult:
        pair_bytes: dict[tuple[str, str], int] = defaultdict(int)

        inbound = 0
        outbound = 0

        for s in sessions:
            pair_bytes[(s.src_ip, s.dst_ip)] += s.bytes_sent + s.bytes_recv
            if target_ip:
                if s.dst_ip == target_ip:
                    inbound += s.bytes_recv
                if s.src_ip == target_ip:
                    outbound += s.bytes_sent

        sorted_pairs = sorted(pair_bytes.items(), key=lambda x: -x[1])
        top = []
        for (src, dst), bytes_total in sorted_pairs[:20]:
            top.append({
                "src": src,
                "dst": dst,
                "bytes_total": bytes_total,
                "is_src_private": _is_private(src),
                "is_dst_private": _is_private(dst),
            })

        return ConversationResult(
            top_conversations=top,
            inbound_bytes=inbound,
            outbound_bytes=outbound,
        )
